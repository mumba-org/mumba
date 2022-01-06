// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "NetHelper.h"
#include "crypto/random.h"
#include "net/base/net_errors.h"
#include "core/shared/domain/net/socket_dispatcher.h"
#include "core/shared/common/p2p_messages.h"

namespace {

uint64_t GetUniqueId(uint32_t random_socket_id, uint32_t packet_id) {
  uint64_t uid = random_socket_id;
  uid <<= 32;
  uid |= packet_id;
  return uid;
}

}  // namespace

struct IPCSocketShim {
  scoped_refptr<IPCSocket> handle;
  IPCSocketShim(scoped_refptr<IPCSocket> _handle): handle(std::move(_handle)) {}
  IPCSocketShim(domain::P2PSocketDispatcher* dispatcher,
    SocketCallbacks callbacks,
    void* state): handle(base::MakeRefCounted<IPCSocket>(dispatcher, callbacks, state)) {}
};

IPCSocket::IPCSocket(domain::P2PSocketDispatcher* dispatcher,
                     SocketCallbacks callbacks,
                     void* state):
  callbacks_(callbacks),
  state_(state),
  dispatcher_(dispatcher),
  ipc_task_runner_(dispatcher->task_runner()),
  socket_id_(0),
  random_socket_id_(0),
  next_packet_id_(0),
  traffic_annotation_{0} {

}

IPCSocket::~IPCSocket() {}

void IPCSocket::Init(common::P2PSocketType type,
                     const net::IPEndPoint& local_address,
                     uint16_t min_port,
                     uint16_t max_port,
                     const common::P2PHostAndIPEndPoint& remote_address) {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCSocket::DoInit, base::Unretained(this), type, local_address,
                     min_port, max_port, remote_address));
}

void IPCSocket::Init(common::P2PSocketType type,
            const net::IPEndPoint& local_address,
            uint16_t min_port,
            uint16_t max_port,
            const common::P2PHostAndIPEndPoint& remote_address,
            const std::string& package,
            const std::string& name) {
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&IPCSocket::DoInitRPC, base::Unretained(this), type, local_address,
                     min_port, max_port, remote_address, package, name));
}

void IPCSocket::DoInit(common::P2PSocketType type,
                       const net::IPEndPoint& local_address,
                       uint16_t min_port,
                       uint16_t max_port,
                       const common::P2PHostAndIPEndPoint& remote_address) {
  socket_id_ = dispatcher_->RegisterClient(this);
  common::P2PSocketOptions options(local_address, common::P2PPortRange(min_port, max_port),
      remote_address);
  dispatcher_->SendP2PMessage(new P2PHostMsg_CreateSocket(
      type, socket_id_, options));
}

void IPCSocket::DoInitRPC(common::P2PSocketType type,
                       const net::IPEndPoint& local_address,
                       uint16_t min_port,
                       uint16_t max_port,
                       const common::P2PHostAndIPEndPoint& remote_address,
                       const std::string& package,
                       const std::string& name) {
  socket_id_ = dispatcher_->RegisterClient(this);
  common::P2PSocketOptions options(local_address, common::P2PPortRange(min_port, max_port),
      remote_address, package, name);
  dispatcher_->SendP2PMessage(new P2PHostMsg_CreateSocket(
      type, socket_id_, options));
}

uint64_t IPCSocket::Send(const net::IPEndPoint& address,
                    const std::vector<char>& data,
                    const rtc::PacketOptions& options) {
  uint64_t unique_id = GetUniqueId(random_socket_id_, ++next_packet_id_);
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&IPCSocket::SendWithPacketId, this,
                                  address, data, options, unique_id));
    return unique_id;
  }

  // Can send data only when the socket is open.
  //DCHECK(state_ == STATE_OPEN || state_ == STATE_ERROR);
  //if (state_ == STATE_OPEN) {
    SendWithPacketId(address, data, options, unique_id);
  //}

  return unique_id;
}

void IPCSocket::SendWithPacketId(const net::IPEndPoint& address,
                                 const std::vector<char>& data,
                                 const rtc::PacketOptions& options,
                                 uint64_t packet_id) {
  dispatcher_->SendP2PMessage(new P2PHostMsg_Send(
      socket_id_, data, common::P2PPacketInfo(address, options, packet_id),
      net::MutableNetworkTrafficAnnotationTag(traffic_annotation_)));
}

void IPCSocket::SetOption(common::P2PSocketOption option, int value) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IPCSocket::SetOption, this, option, value));
    return;
  }

  //DCHECK(state_ == STATE_OPEN || state_ == STATE_ERROR);
  //if (state_ == STATE_OPEN) {
    dispatcher_->SendP2PMessage(new P2PHostMsg_SetOption(socket_id_,
                                                         option, value));
  //}
}

void IPCSocket::Close() {
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&IPCSocket::DoClose, this));
}

void IPCSocket::ReceiveRPCMessage(int call_id, int method_type) {
  if (dispatcher_) {
    dispatcher_->ReceiveRPCMessage(socket_id_, call_id, method_type);
  }
}

void IPCSocket::SendRPCMessage(int call_id, const std::vector<char>& data, int method_type) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IPCSocket::SendRPCMessage, this, call_id, data, method_type));
    return;
  }
  dispatcher_->SendP2PMessage(new P2PHostMsg_RPCSendMessage(socket_id_, call_id, data, method_type));
}

void IPCSocket::SendRPCMessageNow(int call_id, const std::vector<char>& data, int method_type) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IPCSocket::SendRPCMessageNow, this, call_id, data, method_type));
    return;
  }
  dispatcher_->SendP2PMessage(new P2PHostMsg_RPCSendMessageNow(socket_id_, call_id, data, method_type));
}

void IPCSocket::SendRPCStatus(int call_id, int status) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&IPCSocket::SendRPCStatus, this, call_id, status));
    return;
  }
  dispatcher_->SendP2PMessage(new P2PHostMsg_RPCSendStatus(socket_id_, call_id, status));
}

void IPCSocket::DoClose() {
  if (dispatcher_) {
    //if (state_ == STATE_OPEN || state_ == STATE_OPENING ||
    //    state_ == STATE_ERROR) {
      dispatcher_->SendP2PMessage(new P2PHostMsg_DestroySocket(socket_id_));
    //}
    dispatcher_->UnregisterClient(socket_id_);
  }

  //state_ = STATE_LOSED;
}

int IPCSocket::GetSocketID() const {
  return socket_id_;
}

void IPCSocket::SetDelegate(domain::P2PSocketClientDelegate* delegate) {
  //LOG(INFO) << "IPCSocket::SetDelegate";
}

void IPCSocket::OnSocketCreated(const net::IPEndPoint& local_address,
                                const net::IPEndPoint& remote_address) {
  callbacks_.OnSocketCreate(state_, socket_id_, net::OK);
}

void IPCSocket::OnIncomingTcpConnection(const net::IPEndPoint& address, int connecting_socket_id) {
  // TODO: we have a real problem here with state
  // because what we want/need is the state of the 
  // TCPClientConnection and not this -> the server

  scoped_refptr<IPCSocket> new_client =
      new IPCSocket(dispatcher_, callbacks_, nullptr);
  
  //int new_socket_id = 
  dispatcher_->RegisterClient(connecting_socket_id, new_client.get());
  new_client->socket_id_ = connecting_socket_id;//new_socket_id;
  //new_client->state_ = STATE_OPEN;
  //new_client->delegate_task_runner_ = delegate_task_runner_;
  IPCSocketShim* handle_shim = new IPCSocketShim(std::move(new_client));
  // note the ownership is considered 'passed' here
  // and the client need to release it
  
  //sockets_.emplace(std::make_pair(connecting_socket_id, handle_shim));

  int result = callbacks_.OnAccept(state_, handle_shim, connecting_socket_id);
  
  if (result == net::OK) {
    dispatcher_->SendP2PMessage(new P2PHostMsg_AcceptIncomingTcpConnection(
      socket_id_, address));
  }

  // delegate_task_runner_->PostTask(
  //    FROM_HERE,
  //    base::BindOnce(&P2PSocketClientImpl::DeliverOnIncomingTcpConnection, this,
  //                   address, new_client));
}

void IPCSocket::OnSendComplete(const common::P2PSendPacketMetrics& send_metrics) {
  //LOG(INFO) << "IPCSocket::OnSendComplete";
}

void IPCSocket::OnError() {
  callbacks_.OnError(state_);
}

void IPCSocket::OnDataReceived(const net::IPEndPoint& address,
                  const std::vector<char>& data,
                  const base::TimeTicks& timestamp) {
  callbacks_.OnDataReceived(state_, address.address().bytes().data(), address.address().size(), address.port(), reinterpret_cast<const uint8_t *>(&data[0]), data.size());
}

void IPCSocket::Detach() {
  dispatcher_ = nullptr;
}

void IPCSocket::OnRPCBegin(
  int call_id,
  const std::string& method,
  const std::string& caller,
  const std::string& host) {
  
  //sockets_.find();
  callbacks_.OnRPCBegin(state_, call_id, method.c_str(), caller.c_str(), host.c_str());
}

void IPCSocket::OnRPCStreamRead(int call_id, const std::vector<char>& data) {
  callbacks_.OnRPCStreamRead(state_, call_id, reinterpret_cast<const uint8_t *>(&data[0]), data.size()); 
}

void IPCSocket::OnRPCStreamReadEOF(int call_id) {
  callbacks_.OnRPCStreamReadEOF(state_, call_id); 
}

void IPCSocket::OnRPCStreamWrite(int call_id) {
  callbacks_.OnRPCStreamWrite(state_, call_id);
}

void IPCSocket::OnRPCUnaryRead(int call_id, const std::vector<char>& data) {
  callbacks_.OnRPCUnaryRead(state_, call_id, reinterpret_cast<const uint8_t *>(&data[0]), data.size());
}

void IPCSocket::OnRPCEnd(int call_id) {
  callbacks_.OnRPCEnd(state_, call_id);
}

void IPCSocket::OnRPCSendMessageAck(int call_id, int status) {
  callbacks_.OnRPCSendMessageAck(state_, call_id, status);
}

