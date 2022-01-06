// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PEER_HOST_H_
#define MUMBA_HOST_NET_PEER_HOST_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/sequence_checker.h"
#include "base/threading/thread.h"
#include "net/base/backoff_entry.h"
#include "core/host/net/peer_session.h"
#include "core/host/net/host_status_monitor.h"
#include "core/host/net/host_status_observer.h"
#include "core/host/net/authenticator.h"
#include "core/host/net/peer_connection.h"
#include "core/host/net/pairing_registry.h"
#include "core/host/net/session_manager.h"
#include "core/host/net/session.h"

namespace host {
class TransportContext;

class PeerHost : public PeerSession::EventHandler {
public:
  typedef std::vector<std::unique_ptr<PeerSession>> PeerSessions;

  PeerHost(
    std::unique_ptr<SessionManager> session_manager,
    scoped_refptr<TransportContext> transport_context);
 
  ~PeerHost() override;

  void Start(const std::string& host_owner_email);

  void SetMaximumSessionDuration(
    const base::TimeDelta& max_session_duration);

  void SetAuthenticatorFactory(
      std::unique_ptr<AuthenticatorFactory> authenticator_factory);

  scoped_refptr<PairingRegistry> pairing_registry() const {
    return pairing_registry_;
  }

  void set_pairing_registry(
      scoped_refptr<PairingRegistry> pairing_registry) {
    pairing_registry_ = pairing_registry;
  }

  scoped_refptr<HostStatusMonitor> status_monitor() { 
    return status_monitor_; 
  }

  // PeerSession::EventHandler
  void OnSessionAuthenticating(PeerSession* client) override;
  void OnSessionAuthenticated(PeerSession* client) override;
  void OnSessionChannelsConnected(PeerSession* client) override;
  void OnSessionAuthenticationFailed(PeerSession* client) override;
  void OnSessionClosed(PeerSession* client) override;
  void OnSessionRouteChange(
      PeerSession* client,
      const std::string& channel_name,
      const TransportRoute& route) override;

   void OnIncomingSession(
      Session* session,
      SessionManager::IncomingSessionResponse* response);

private:

  std::unique_ptr<SessionManager> session_manager_;
  
  scoped_refptr<TransportContext> transport_context_;
  
  scoped_refptr<HostStatusMonitor> status_monitor_;

  // The connections to remote clients.
  PeerSessions clients_;

  // True if the host has been started.
  bool started_ = false;

  // The maximum duration of any session.
  base::TimeDelta max_session_duration_;

   // The pairing registry for PIN-less authentication.
  scoped_refptr<PairingRegistry> pairing_registry_;

  base::WeakPtrFactory<PeerHost> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(PeerHost);
};

}

#endif