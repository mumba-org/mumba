// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_IPC_PEER_CONNECTION_H_
#define MUMBA_HOST_IPC_IPC_PEER_CONNECTION_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "core/host/net/channel_dispatcher_base.h"
#include "core/host/net/peer_connection.h"
#include "core/host/net/peer_session.h"
#include "core/host/net/session.h"
#include "core/host/ipc/ipc_transport.h"

namespace host {
class HostControlDispatcher;

class IPCPeerConnection : public PeerConnection,
                          public Session::EventHandler,
                          public IPCTransport::EventHandler,
                          public ChannelDispatcherBase::EventHandler {
public:

  IPCPeerConnection(
    std::unique_ptr<Session> session,
    scoped_refptr<TransportContext> transport_context);
  
  ~IPCPeerConnection() override;

   // ConnectionToClient interface.
  void SetEventHandler(
      PeerConnection::EventHandler* event_handler) override;

  Session* session() const override;
  void Disconnect(ErrorCode error) override;
  ClientStub* client_stub() override;
  void set_host_stub(HostStub* host_stub) override;
  void ApplySessionOptions(const SessionOptions& options) override;

  // Session::EventHandler interface.
  void OnSessionStateChange(Session::State state) override;

  // IPCTransport::EventHandler interface
  void OnIPCTransportConnecting() override;
  void OnIPCTransportConnected() override;
  void OnIPCTransportError(ErrorCode error) override;
  void OnIPCTransportIncomingDataChannel(
      const std::string& name,
      std::unique_ptr<protocol::MessagePipe> pipe) override;
  
  // ChannelDispatcherBase::EventHandler interface.
  void OnChannelInitialized(ChannelDispatcherBase* channel_dispatcher) override;
  void OnChannelClosed(ChannelDispatcherBase* channel_dispatcher) override;

private:
  
  PeerConnection::EventHandler* event_handler_ = nullptr;

  std::unique_ptr<IPCTransport> transport_;

  std::unique_ptr<Session> session_;

  SessionOptions session_options_;

  std::unique_ptr<HostControlDispatcher> control_dispatcher_;
  //std::unique_ptr<HostEventDispatcher> event_dispatcher_;
  
  base::WeakPtrFactory<IPCPeerConnection> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IPCPeerConnection);
};

}

#endif