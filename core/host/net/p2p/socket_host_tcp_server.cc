// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/p2p/socket_host_tcp_server.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "core/host/net/p2p/socket_host_tcp.h"
#include "core/shared/common/p2p_messages.h"
#include "net/base/address_list.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/socket/stream_socket.h"

namespace {
const int kListenBacklog = 5;
}  // namespace

namespace host {

P2PSocketHostTcpServer::P2PSocketHostTcpServer(Delegate* delegate,
                                               base::WeakPtr<IPC::Sender> message_sender,
                                               int socket_id,
                                               common::P2PSocketType client_type)
    : P2PSocketHost(delegate, std::move(message_sender), socket_id, P2PSocketHost::TCP),
      client_type_(client_type),
      socket_(new net::TCPServerSocket(nullptr, net::NetLogSource())),
      accept_callback_(base::Bind(&P2PSocketHostTcpServer::OnAccepted,
                                  base::Unretained(this))),
      incoming_socket_id_(-1) {
}

P2PSocketHostTcpServer::~P2PSocketHostTcpServer() {
  if (state_ == STATE_OPEN) {
    DCHECK(socket_.get());
    socket_.reset();
  }
}

// TODO(guidou): Add support for port range.
bool P2PSocketHostTcpServer::Init(const common::P2PSocketOptions& options) {
  DCHECK_EQ(state_, STATE_UNINITIALIZED);

  int result = socket_->Listen(options.local_address, kListenBacklog);
  if (result < 0) {
    LOG(ERROR) << "Listen() failed: " << result;
    OnError();
    return false;
  }

  result = socket_->GetLocalAddress(&local_address_);
  if (result < 0) {
    LOG(ERROR) << "P2PSocketHostTcpServer::Init(): can't to get local address: "
               << result;
    OnError();
    return false;
  }
  VLOG(1) << "Local address: " << local_address_.ToString();

  state_ = STATE_OPEN;
  // NOTE: Remote address can be empty as socket is just listening
  // in this state.
  message_sender_->Send(new P2PMsg_OnSocketCreated(
      id_, local_address_, options.remote_address.ip_address));
  DoAccept();
  return true;
}

void P2PSocketHostTcpServer::OnError() {
  socket_.reset();

  if (state_ == STATE_UNINITIALIZED || state_ == STATE_OPEN)
    message_sender_->Send(new P2PMsg_OnError(id_));

  state_ = STATE_ERROR;
}

void P2PSocketHostTcpServer::DoAccept() {
  while (true) {
    int result = socket_->Accept(&accept_socket_, accept_callback_);
    DLOG(INFO) << "P2PSocketHostTcpServer::DoAccept: incoming connection";  
    if (result == net::ERR_IO_PENDING) {
      break;
    } else {
      HandleAcceptResult(result);
    }
  }
}

void P2PSocketHostTcpServer::ReceiveRpcMessage(int call_id, int method_type) {}
void P2PSocketHostTcpServer::SendRpcMessage(int call_id, int method_type, std::vector<char> data) {}
void P2PSocketHostTcpServer::SendRpcMessageNow(int call_id, int method_type, std::vector<char> data) {}
void P2PSocketHostTcpServer::SendRpcStatus(int call_id, int status_code) {}

void P2PSocketHostTcpServer::HandleAcceptResult(int result) {
  //DLOG(INFO) << "P2PSocketHostTcpServer::HandleAcceptResult: result = " << result;
  if (result < 0) {
    if (result != net::ERR_IO_PENDING)
      OnError();
    return;
  }

  net::IPEndPoint address;

  if (accept_socket_->GetPeerAddress(&address) != net::OK) {
    LOG(ERROR) << "Failed to get address of an accepted socket.";
    accept_socket_.reset();
    return;
  }

  incoming_socket_id_ = delegate_->GetNextSocketId();

  //DLOG(INFO) << "P2PSocketHostTcpServer::HandleAcceptResult: address = " << address.ToString();

  accepted_sockets_[address] = std::move(accept_socket_);
  message_sender_->Send(
      new P2PMsg_OnIncomingTcpConnection(id_, address, incoming_socket_id_));
}

void P2PSocketHostTcpServer::OnAccepted(int result) {
  HandleAcceptResult(result);
  if (result == net::OK)
    DoAccept();
}

void P2PSocketHostTcpServer::Send(
    const net::IPEndPoint& to,
    const std::vector<char>& data,
    const rtc::PacketOptions& options,
    uint64_t packet_id,
    const net::NetworkTrafficAnnotationTag traffic_annotation) {
  NOTREACHED();
  OnError();
}

std::unique_ptr<P2PSocketHost>
P2PSocketHostTcpServer::AcceptIncomingTcpConnection(
    const net::IPEndPoint& remote_address) {
  DLOG(INFO) << "P2PSocketHostTcpServer::AcceptIncomingTcpConnection";
  auto it = accepted_sockets_.find(remote_address);
  if (it == accepted_sockets_.end())
    return nullptr;

  std::unique_ptr<net::StreamSocket> socket = std::move(it->second);
  accepted_sockets_.erase(it);

  std::unique_ptr<P2PSocketHostTcpBase> result;
  if (client_type_ == common::P2P_SOCKET_TCP_CLIENT) {
    result.reset(new P2PSocketHostTcp(delegate_, message_sender_, incoming_socket_id_, client_type_,
                                      nullptr, nullptr));
  } else {
    result.reset(new P2PSocketHostStunTcp(delegate_, message_sender_, incoming_socket_id_, client_type_,
                                          nullptr, nullptr));
  }
  if (!result->InitAccepted(remote_address, std::move(socket)))
    return nullptr;
  
  DLOG(INFO) << "P2PSocketHostTcpServer::AcceptIncomingTcpConnection: new P2PSocketHost (client) created";
  
  return std::move(result);
}

bool P2PSocketHostTcpServer::SetOption(common::P2PSocketOption option,
                                       int value) {
  // Currently we don't have use case tcp server sockets are used for p2p.
  return false;
}

}  // namespace host
