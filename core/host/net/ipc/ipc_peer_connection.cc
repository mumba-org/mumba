// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ipc/ipc_peer_connection.h"

#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "jingle/glue/thread_wrapper.h"
#include "net/base/io_buffer.h"
#include "core/host/net/host_control_dispatcher.h"
#include "core/host/net/host_stub.h"
#include "core/common/protocol/message_pipe.h"
#include "core/host/net/transport_context.h"
#include "core/host/ipc/ipc_transport.h"

namespace host {

IPCPeerConnection::IPCPeerConnection(
    std::unique_ptr<Session> session,
    scoped_refptr<TransportContext> transport_context):
    transport_(
          new IPCTransport(transport_context, this)),
      session_(std::move(session)),
      control_dispatcher_(new HostControlDispatcher()),
      weak_factory_(this) {

  session_->SetEventHandler(this);
  session_->SetTransport(transport_.get());
}
  
IPCPeerConnection::~IPCPeerConnection() {

}

void IPCPeerConnection::SetEventHandler(PeerConnection::EventHandler* event_handler) {
  event_handler_ = event_handler;
}

Session* IPCPeerConnection::session() const {
  return session_.get();
}

void IPCPeerConnection::Disconnect(ErrorCode error) {
  session_->Close(error);
}

ClientStub* IPCPeerConnection::client_stub() {
  return control_dispatcher_.get();
}

void IPCPeerConnection::set_host_stub(HostStub* host_stub) {
  control_dispatcher_->set_host_stub(host_stub);
}

void IPCPeerConnection::ApplySessionOptions(const SessionOptions& options) {
  session_options_ = options;
  //DCHECK(transport_);
  //transport_->ApplySessionOptions(options);
}

void IPCPeerConnection::OnSessionStateChange(Session::State state) {
    switch (state) {
    case Session::INITIALIZING:
    case Session::CONNECTING:
    case Session::ACCEPTING:
    case Session::ACCEPTED:
      break;
    case Session::AUTHENTICATING:
      event_handler_->OnConnectionAuthenticating();
      break;
    case Session::AUTHENTICATED: {
      //base::WeakPtr<IPCPeerConnection> self = weak_factory_.GetWeakPtr();
      event_handler_->OnConnectionAuthenticated();

      // OnConnectionAuthenticated() call above may result in the connection
      // being torn down.
      //if (self)
      //  event_handler_->CreateMediaStreams();
      break;
    }

    case Session::CLOSED:
    case Session::FAILED:
      control_dispatcher_.reset();
      //event_dispatcher_.reset();
      transport_->Close(state == Session::CLOSED ? OK : session_->error());
      transport_.reset();
      event_handler_->OnConnectionClosed(
          state == Session::CLOSED ? OK : session_->error());
      break;
  } 
}

void IPCPeerConnection::OnIPCTransportConnecting() {
  control_dispatcher_->Init(
      transport_->CreateOutgoingChannel(control_dispatcher_->channel_name()),
      this); 
}

void IPCPeerConnection::OnIPCTransportConnected() {
  
}

void IPCPeerConnection::OnIPCTransportError(ErrorCode error) {
  
}

void IPCPeerConnection::OnIPCTransportIncomingDataChannel(
    const std::string& name,
    std::unique_ptr<protocol::MessagePipe> pipe) {
  event_handler_->OnIncomingDataChannel(name, std::move(pipe));
}
  
void IPCPeerConnection::OnChannelInitialized(ChannelDispatcherBase* channel_dispatcher) {
  if (control_dispatcher_ && control_dispatcher_->is_connected()) { //&&
    event_handler_->OnConnectionChannelsConnected();
  }
}

void IPCPeerConnection::OnChannelClosed(ChannelDispatcherBase* channel_dispatcher) {
  LOG(ERROR) << "Channel " << channel_dispatcher->channel_name()
             << " was closed unexpectedly.";
  Disconnect(INCOMPATIBLE_PROTOCOL);
}

}