// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PEER_SESSION_H_
#define MUMBA_HOST_NET_PEER_SESSION_H_

#include <cstdint>
#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "base/sequenced_task_runner_helpers.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "core/host/net/peer_session_control.h"
#include "core/host/net/peer_session_details.h"
#include "core/host/net/host_stub.h"
#include "core/host/net/data_channel_manager.h"
#include "core/host/net/peer_connection.h"

namespace host {

class PeerSession : public HostStub,
                    public PeerConnection::EventHandler,
                    public PeerSessionControl,
                    public PeerSessionDetails {
public:
  
  enum State {
    // Created, but not connecting yet.
    INITIALIZING,

    // Sent session-initiate, but haven't received session-accept.
    CONNECTING,

    // Received session-initiate, but haven't sent session-accept.
    ACCEPTING,

    // Session has been accepted and is pending authentication.
    ACCEPTED,

    // Session has started authenticating.
    AUTHENTICATING,

    // Session has been connected and authenticated.
    AUTHENTICATED,

    // Session has been closed.
    CLOSED,

    // Connection has failed.
    FAILED,
  };

  class EventHandler {
  public:
    virtual ~EventHandler() {}
    virtual void OnSessionAuthenticating(PeerSession* client) = 0;
    virtual void OnSessionAuthenticated(PeerSession* client) = 0;
    virtual void OnSessionChannelsConnected(PeerSession* client) = 0;
    virtual void OnSessionAuthenticationFailed(PeerSession* client) = 0;
    virtual void OnSessionClosed(PeerSession* client) = 0;
    virtual void OnSessionRouteChange(
        PeerSession* client,
        const std::string& channel_name,
        const TransportRoute& route) = 0;
  };

  PeerSession(EventHandler* event_handler, 
      std::unique_ptr<PeerConnection> connection,
      const base::TimeDelta& max_duration);
  ~PeerSession();

  EventHandler* event_handler() const {
    return event_handler_;
  }

  PeerSessionControl* session_control() override;
  uint32_t desktop_session_id() const override;

  const std::string& peer_jid() const override;
  void DisconnectSession(ErrorCode error) override;

  // PeerConnection::EventHandler
  void OnConnectionAuthenticating() override;
  void OnConnectionAuthenticated() override;
  //void CreateMediaStreams() override;
  void OnConnectionChannelsConnected() override;
  void OnConnectionClosed(ErrorCode error) override;
  void OnChannelChange(const std::string& channel_name,
                     const TransportRoute& route) override;
  void OnIncomingDataChannel(const std::string& channel_name,
                             std::unique_ptr<protocol::MessagePipe> pipe) override;

  // HostStub
  void RequestPairing(const protocol::PairingRequest& pairing_request) override;

  bool is_authenticated() { return is_authenticated_; }

  void RegisterCreateHandlerCallback(
    const std::string& prefix,
    DataChannelManager::CreateHandlerCallback constructor);

private:
  
  EventHandler* event_handler_;

  std::unique_ptr<PeerConnection> connection_;
  
  base::TimeDelta max_duration_;

  base::OneShotTimer max_duration_timer_;

  std::unique_ptr<std::string> client_capabilities_;

  std::string host_capabilities_;

  std::string capabilities_;

  std::string peer_jid_;

  DataChannelManager data_channel_manager_;

  bool is_authenticated_;

  bool channels_connected_;

  base::WeakPtrFactory<PeerSession> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(PeerSession);
};

}

#endif