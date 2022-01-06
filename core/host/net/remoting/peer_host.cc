// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/peer_host.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "build/build_config.h"
#include "jingle/glue/thread_wrapper.h"
#include "core/host/net/constants.h"
#include "core/host/net/logging.h"
//#include "core/host/net/desktop_environment.h"
#include "core/host/net/host_config.h"
//#include "core/host/net/input_injector.h"
#include "core/host/net/client_stub.h"
#include "core/host/net/host_stub.h"
#include "core/host/net/ice_peer_connection.h"
//#include "core/host/net/input_stub.h"
#include "core/host/net/transport_context.h"
#include "core/host/net/webrtc_peer_connection.h"
#include "core/host/ipc/ipc_peer_connection.h"

namespace host {

PeerHost::PeerHost(
  std::unique_ptr<SessionManager> session_manager,
  scoped_refptr<TransportContext> transport_context):
   session_manager_(std::move(session_manager)),
   transport_context_(transport_context),
   status_monitor_(new HostStatusMonitor()),
   weak_factory_(this) {
  
}

PeerHost::~PeerHost() {
  // Disconnect all of the clients.
  while (!clients_.empty()) {
    clients_.front()->DisconnectSession(OK);
  }

  // Destroy the session manager to make sure that |signal_strategy_| does not
  // have any listeners registered.
  session_manager_.reset();

  // Notify observers.
  if (started_) {
    for (auto& observer : status_monitor_->observers())
      observer.OnShutdown();
  }
}

void PeerHost::Start(const std::string& host_owner_email) {
  started_ = true;
  
  for (auto& observer : status_monitor_->observers())
    observer.OnStart(host_owner_email);

  session_manager_->AcceptIncoming(
      base::Bind(&PeerHost::OnIncomingSession, base::Unretained(this)));
}

void PeerHost::SetAuthenticatorFactory(
      std::unique_ptr<AuthenticatorFactory> authenticator_factory) {
  session_manager_->set_authenticator_factory(std::move(authenticator_factory));
}

void PeerHost::SetMaximumSessionDuration(
    const base::TimeDelta& max_session_duration) {
  max_session_duration_ = max_session_duration;
}

void PeerHost::OnSessionAuthenticating(PeerSession* client) {}

void PeerHost::OnSessionAuthenticated(PeerSession* client) {
  // Disconnect all clients, except |client|.
  base::WeakPtr<PeerHost> self = weak_factory_.GetWeakPtr();
  while (clients_.size() > 1) {
    clients_[(clients_.front().get() == client) ? 1 : 0]->DisconnectSession(OK);

    // Quit if the host was destroyed.
    if (!self)
      return;
  }

  // Disconnects above must have destroyed all other clients.
  DCHECK_EQ(clients_.size(), 1U);
  DCHECK(clients_.front().get() == client);

  // Notify observers that there is at least one authenticated client.
  for (auto& observer : status_monitor_->observers())
    observer.OnClientAuthenticated(client->peer_jid());
}

void PeerHost::OnSessionChannelsConnected(PeerSession* client) {
  for (auto& observer : status_monitor_->observers())
    observer.OnClientConnected(client->peer_jid());
}

void PeerHost::OnSessionAuthenticationFailed(PeerSession* client) {
  for (auto& observer : status_monitor_->observers())
    observer.OnAccessDenied(client->peer_jid());
}

void PeerHost::OnSessionClosed(PeerSession* client) {
  PeerSessions::iterator it =
      std::find_if(clients_.begin(), clients_.end(),
                   [client](const std::unique_ptr<PeerSession>& item) {
                     return item.get() == client;
                   });
  //CHECK(it != clients_.end());

  bool was_authenticated = client->is_authenticated();
  std::string jid = client->peer_jid();
  clients_.erase(it);

  if (was_authenticated) {
    for (auto& observer : status_monitor_->observers())
      observer.OnClientDisconnected(jid);
  }
}

void PeerHost::OnSessionRouteChange(
      PeerSession* client,
      const std::string& channel_name,
      const TransportRoute& route) {
  for (auto& observer : status_monitor_->observers()) {
    observer.OnClientRouteChange(client->peer_jid(), channel_name, route);
  }
}

void PeerHost::OnIncomingSession(
  Session* session,
  SessionManager::IncomingSessionResponse* response) {
  // if (login_backoff_.ShouldRejectRequest()) {
  //   LOG(WARNING) << "Rejecting connection due to"
  //                   " an overload of failed login attempts.";
  //   *response = protocol::SessionManager::OVERLOAD;
  //   return;
  // }

  *response = SessionManager::ACCEPT;

  DLOG(INFO) << "PeerHost::OnIncomingSession: client connected: " << session->jid();

  // Create either IceConnectionToClient or WebrtcConnectionToClient.
  // TODO(sergeyu): Move this logic to the protocol layer.
  std::unique_ptr<PeerConnection> connection;
  if (session->config().protocol() == SessionConfig::Protocol::WEBRTC) {
    connection.reset(new WebrtcPeerConnection(
        base::WrapUnique(session), transport_context_));
  } else if(session->config().protocol() == SessionConfig::Protocol::IPC) {
    connection.reset(new IPCPeerConnection(
        base::WrapUnique(session), transport_context_));
  } else {
    connection.reset(new IcePeerConnection(
        base::WrapUnique(session), transport_context_));
  }

  // Create a PeerSession object.
  clients_.push_back(std::make_unique<PeerSession>(
      this, std::move(connection), max_session_duration_));
}

}