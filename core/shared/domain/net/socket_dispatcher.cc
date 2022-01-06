// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/net/socket_dispatcher.h"

#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/memory/ref_counted.h"
//#include "core/shared/common/child_process.h"
#include "core/shared/common/p2p_messages.h"
#include "core/shared/domain/net/host_address_request.h"
#include "core/shared/domain/net/network_list_observer.h"
#include "core/shared/domain/net/socket_client.h"
//#include "content/renderer/render_view_impl.h"
#include "ipc/ipc_sender.h"

namespace domain {

P2PSocketDispatcher::P2PSocketDispatcher(
    base::SingleThreadTaskRunner* ipc_task_runner)
    : ipc_task_runner_(ipc_task_runner),
      network_notifications_started_(false),
      network_list_observers_(
          new base::ObserverListThreadSafe<NetworkListObserver>()),
      sender_(nullptr),
      max_socket_id_(0) {}

P2PSocketDispatcher::~P2PSocketDispatcher() {
  network_list_observers_->AssertEmpty();
  for (base::IDMap<P2PSocketClient*>::iterator i(&clients_); !i.IsAtEnd();
       i.Advance()) {
    i.GetCurrentValue()->Detach();
  }
}

void P2PSocketDispatcher::AddNetworkListObserver(
    NetworkListObserver* network_list_observer) {
  network_list_observers_->AddObserver(network_list_observer);
  network_notifications_started_ = true;
  SendP2PMessage(new P2PHostMsg_StartNetworkNotifications());
}

void P2PSocketDispatcher::RemoveNetworkListObserver(
    NetworkListObserver* network_list_observer) {
  network_list_observers_->RemoveObserver(network_list_observer);
}

void P2PSocketDispatcher::Send(IPC::Message* message) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  if (!sender_) {
    //DLOG(WARNING) << "P2PSocketDispatcher::Send() - Sender closed.";
    delete message;
    return;
  }

  sender_->Send(message);
}

bool P2PSocketDispatcher::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(P2PSocketDispatcher, message)
    IPC_MESSAGE_HANDLER(P2PMsg_NetworkListChanged, OnNetworkListChanged)
    IPC_MESSAGE_HANDLER(P2PMsg_GetHostAddressResult, OnGetHostAddressResult)
    IPC_MESSAGE_HANDLER(P2PMsg_OnSocketCreated, OnSocketCreated)
    IPC_MESSAGE_HANDLER(P2PMsg_OnIncomingTcpConnection, OnIncomingTcpConnection)
    IPC_MESSAGE_HANDLER(P2PMsg_OnSendComplete, OnSendComplete)
    IPC_MESSAGE_HANDLER(P2PMsg_OnError, OnError)
    IPC_MESSAGE_HANDLER(P2PMsg_OnDataReceived, OnDataReceived)
    IPC_MESSAGE_HANDLER(P2PMsg_OnRPCBegin, OnRPCBegin)
    IPC_MESSAGE_HANDLER(P2PMsg_OnRPCStreamRead, OnRPCStreamRead)
    IPC_MESSAGE_HANDLER(P2PMsg_OnRPCStreamWrite, OnRPCStreamWrite)
    IPC_MESSAGE_HANDLER(P2PMsg_OnRPCUnaryRead, OnRPCUnaryRead)
    IPC_MESSAGE_HANDLER(P2PMsg_OnRPCEnd, OnRPCEnd)
    IPC_MESSAGE_HANDLER(P2PMsg_RPCSendMessageAck, OnRPCSendMessageAck)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

void P2PSocketDispatcher::OnFilterAdded(IPC::Channel* channel) {
  DVLOG(1) << "P2PSocketDispatcher::OnFilterAdded()";
  sender_ = channel;
}

void P2PSocketDispatcher::OnFilterRemoved() {
  sender_ = nullptr;
}

void P2PSocketDispatcher::OnChannelConnected(int32_t peer_id) {
  connected_ = true;
}

void P2PSocketDispatcher::OnChannelClosing() {
  sender_ = nullptr;
  connected_ = false;
}

base::SingleThreadTaskRunner* P2PSocketDispatcher::task_runner() {
  return ipc_task_runner_.get();
}

void P2PSocketDispatcher::RegisterClient(int connecting_socket_id, P2PSocketClient* client) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  max_socket_id_ = connecting_socket_id > max_socket_id_ ? connecting_socket_id : max_socket_id_;
  clients_.AddWithID(client, connecting_socket_id);
}

int P2PSocketDispatcher::RegisterClient(P2PSocketClient* client) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  max_socket_id_++;
  clients_.AddWithID(client, max_socket_id_);
  return max_socket_id_;
}

void P2PSocketDispatcher::UnregisterClient(int id) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  clients_.Remove(id);
}

void P2PSocketDispatcher::SendP2PMessage(IPC::Message* msg) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&P2PSocketDispatcher::Send, this, msg));
    return;
  }
  Send(msg);
}

int P2PSocketDispatcher::RegisterHostAddressRequest(
    P2PAsyncAddressResolver* request) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  return host_address_requests_.Add(request);
}

void P2PSocketDispatcher::UnregisterHostAddressRequest(int id) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  host_address_requests_.Remove(id);
}

void P2PSocketDispatcher::OnNetworkListChanged(
    const net::NetworkInterfaceList& networks,
    const net::IPAddress& default_ipv4_local_address,
    const net::IPAddress& default_ipv6_local_address) {
  network_list_observers_->Notify(
      FROM_HERE, &NetworkListObserver::OnNetworkListChanged, networks,
      default_ipv4_local_address, default_ipv6_local_address);
}

void P2PSocketDispatcher::OnGetHostAddressResult(
    int32_t request_id,
    const net::IPAddressList& addresses) {
  P2PAsyncAddressResolver* request = host_address_requests_.Lookup(request_id);
  if (!request) {
    DVLOG(1) << "Received P2P message for socket that doesn't exist.";
    return;
  }

  request->OnResponse(addresses);
}

void P2PSocketDispatcher::OnSocketCreated(
    int socket_id,
    const net::IPEndPoint& local_address,
    const net::IPEndPoint& remote_address) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    client->OnSocketCreated(local_address, remote_address);
  }
}

void P2PSocketDispatcher::OnIncomingTcpConnection(
    int socket_id, 
    const net::IPEndPoint& address,
    int connecting_socket_id) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    client->OnIncomingTcpConnection(address, connecting_socket_id);
  }
}

void P2PSocketDispatcher::OnSendComplete(
    int socket_id,
    const common::P2PSendPacketMetrics& send_metrics) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    client->OnSendComplete(send_metrics);
  }
}

void P2PSocketDispatcher::OnError(int socket_id) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    client->OnError();
  }
}

void P2PSocketDispatcher::OnDataReceived(
    int socket_id, const net::IPEndPoint& address,
    const std::vector<char>& data,
    const base::TimeTicks& timestamp) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    client->OnDataReceived(address, data, timestamp);
  }
}

void P2PSocketDispatcher::OnRPCBegin(
  int socket_id,
  int call_id,
  const std::string& method,
  const std::string& caller,
  const std::string& host) { 
  P2PSocketClient* client = GetClient(socket_id);
  
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      {base::MayBlock()},
      base::Bind(
        &P2PSocketClient::OnRPCBegin, 
        client,
        call_id,
        method, 
        caller, 
        host));
  }
}

void P2PSocketDispatcher::OnRPCStreamRead(int socket_id, int call_id, const std::vector<char>& data) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCStreamRead, client, call_id, data));
  }
}

void P2PSocketDispatcher::OnRPCStreamReadEOF(int socket_id, int call_id) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCStreamReadEOF, client, call_id));
  }
}

void P2PSocketDispatcher::OnRPCStreamWrite(int socket_id, int call_id) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCStreamWrite, client, call_id));
  }
}

void P2PSocketDispatcher::OnRPCUnaryRead(int socket_id, int call_id, const std::vector<char>& data) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCUnaryRead, 
        client,
        call_id, 
        data));
  }
}

void P2PSocketDispatcher::OnRPCEnd(int socket_id, int call_id) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCEnd, 
        client,
        call_id));
  }
}

void P2PSocketDispatcher::OnRPCSendMessageAck(int socket_id, int call_id, int status) {
  P2PSocketClient* client = GetClient(socket_id);
  if (client) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock() },
      base::Bind(&P2PSocketClient::OnRPCSendMessageAck, 
        client,
        call_id,
        status));
  }
}

P2PSocketClient* P2PSocketDispatcher::GetClient(int socket_id) {
  P2PSocketClient* client = clients_.Lookup(socket_id);
  if (client == nullptr) {
    // This may happen if the socket was closed, but the browser side
    // hasn't processed the close message by the time it sends the
    // message to the renderer.
    DVLOG(1) << "Received P2P message for socket that doesn't exist.";
    return nullptr;
  }
  return client;
}

void P2PSocketDispatcher::ReceiveRPCMessage(int socket_id, int call_id, int method_type) {
  IPC::Message* msg = new P2PHostMsg_RPCReceiveMessage(socket_id, call_id, method_type);
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&P2PSocketDispatcher::Send, this, msg));
    return;
  }
  Send(msg);
}

}  // namespace domain
