// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/p2p/socket_dispatcher_host.h"

#include <stddef.h>

#include <algorithm>

#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/bad_message.h"
#include "core/shared/common/p2p_messages.h"
#include "core/host/host_thread.h"
#include "net/base/address_list.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/base/network_interfaces.h"
#include "net/base/sys_addrinfo.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/datagram_client_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/proxy_resolving_client_socket_factory.h"
#include "core/host/workspace/workspace.h"

namespace host {

namespace {

// Used by GetDefaultLocalAddress as the target to connect to for getting the
// default local address. They are public DNS servers on the internet.
const uint8_t kPublicIPv4Host[] = {8, 8, 8, 8};
const uint8_t kPublicIPv6Host[] = {
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88};
const int kPublicPort = 53;  // DNS port.

// Experimentation shows that creating too many sockets creates odd problems
// because of resource exhaustion in the Unix sockets domain.
// Trouble has been seen on Linux at 3479 sockets in test, so leave a margin.
const int kMaxSimultaneousSockets = 3000;

std::unique_ptr<net::HostResolver> CreateHostResolver(net::NetLog* net_log) {
  return net::HostResolver::CreateSystemResolver(net::HostResolver::Options(), net_log);
}

}  // namespace

const size_t kMaximumPacketSize = 32768;

class P2PSocketDispatcherHost::DnsRequest {
 public:
  typedef base::Callback<void(const net::IPAddressList&)> DoneCallback;

  DnsRequest(int32_t request_id, net::HostResolver* host_resolver)
      : request_id_(request_id), resolver_(host_resolver) {}

  void Resolve(const std::string& host_name,
               const DoneCallback& done_callback) {
    DCHECK(!done_callback.is_null());

    host_name_ = host_name;
    done_callback_ = done_callback;

    // Return an error if it's an empty string.
    if (host_name_.empty()) {
      net::IPAddressList address_list;
      done_callback_.Run(address_list);
      return;
    }

    // Add period at the end to make sure that we only resolve
    // fully-qualified names.
    if (host_name_.back() != '.')
      host_name_ += '.';

    net::HostResolver::RequestInfo info(net::HostPortPair(host_name_, 0));
    int result = resolver_->Resolve(
        info, net::DEFAULT_PRIORITY, &addresses_,
        base::Bind(&P2PSocketDispatcherHost::DnsRequest::OnDone,
                   base::Unretained(this)),
        &request_, net::NetLogWithSource());
    if (result != net::ERR_IO_PENDING)
      OnDone(result);
  }

  int32_t request_id() { return request_id_; }

 private:
  void OnDone(int result) {
    net::IPAddressList list;
    if (result != net::OK) {
      LOG(ERROR) << "Failed to resolve address for " << host_name_
                 << ", errorcode: " << result;
      done_callback_.Run(list);
      return;
    }

    DCHECK(!addresses_.empty());
    for (net::AddressList::iterator iter = addresses_.begin();
         iter != addresses_.end(); ++iter) {
      list.push_back(iter->address());
    }
    done_callback_.Run(list);
  }

  int32_t request_id_;
  net::AddressList addresses_;

  std::string host_name_;
  net::HostResolver* resolver_;
  std::unique_ptr<net::HostResolver::Request> request_;

  DoneCallback done_callback_;
};

P2PSocketDispatcherHost::P2PSocketDispatcherHost(
    scoped_refptr<Workspace> workspace,
    Domain* shell,
    net::URLRequestContextGetter* url_context,
    const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner)
    : HostMessageFilter(P2PMsgStart),
      //resource_context_(resource_context),
      workspace_(workspace),
      domain_(shell),
      url_context_(url_context),
      monitoring_networks_(false),
      dump_incoming_rtp_packet_(false),
      dump_outgoing_rtp_packet_(false),
      host_resolver_(CreateHostResolver(&net_log_)),
      network_list_task_runner_(base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE})),
      acceptor_task_runner_(acceptor_task_runner),
      weak_ptr_factory_(this) {
      //acceptor_thread_("SocketAcceptorThread") {
  //base::Thread::Options options;
  //options.message_loop_type = base::MessageLoop::TYPE_IO;
  //acceptor_thread_.StartWithOptions(options);
}

void P2PSocketDispatcherHost::OnChannelClosing() {
  acceptor_task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketDispatcherHost::DestroySocketsOnThread, 
    base::Unretained(this)));
    
  dns_requests_.clear();

  if (monitoring_networks_) {
    net::NetworkChangeNotifier::RemoveNetworkChangeObserver(this);
    monitoring_networks_ = false;
  }
}

void P2PSocketDispatcherHost::DestroySocketsOnThread() {
   // Since the IPC sender is gone, close pending connections.
  sockets_.clear();
}

void P2PSocketDispatcherHost::OnDestruct() const {
  acceptor_task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&P2PSocketDispatcherHost::DestructOnAcceptor, base::Unretained(const_cast<P2PSocketDispatcherHost *>(this))));
}

void P2PSocketDispatcherHost::DestructOnAcceptor() {
  weak_ptr_factory_.InvalidateWeakPtrs();
  HostThread::DeleteOnIOThread::Destruct(this);
}

bool P2PSocketDispatcherHost::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(P2PSocketDispatcherHost, message)
    IPC_MESSAGE_HANDLER(P2PHostMsg_StartNetworkNotifications,
                        OnStartNetworkNotifications)
    IPC_MESSAGE_HANDLER(P2PHostMsg_StopNetworkNotifications,
                        OnStopNetworkNotifications)
    IPC_MESSAGE_HANDLER(P2PHostMsg_GetHostAddress, OnGetHostAddress)
    IPC_MESSAGE_HANDLER(P2PHostMsg_CreateSocket, OnCreateSocket)
    IPC_MESSAGE_HANDLER(P2PHostMsg_AcceptIncomingTcpConnection,
                        OnAcceptIncomingTcpConnection)
    IPC_MESSAGE_HANDLER(P2PHostMsg_Send, OnSend)
    IPC_MESSAGE_HANDLER(P2PHostMsg_SetOption, OnSetOption)
    IPC_MESSAGE_HANDLER(P2PHostMsg_DestroySocket, OnDestroySocket)
    IPC_MESSAGE_HANDLER(P2PHostMsg_RPCReceiveMessage, OnRpcReceiveMessage)
    IPC_MESSAGE_HANDLER(P2PHostMsg_RPCSendMessage, OnRpcSendMessage)
    IPC_MESSAGE_HANDLER(P2PHostMsg_RPCSendMessageNow, OnRpcSendMessageNow)
    IPC_MESSAGE_HANDLER(P2PHostMsg_RPCSendStatus, OnRpcSendStatus)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

int P2PSocketDispatcherHost::GetNextSocketId() {
  int next_id = id_gen_.GetNext() + 1;
  while (IsSocketIdAlreadyRegistered(next_id)) {
    next_id = id_gen_.GetNext() + 1;
  }
  return next_id;
}

scoped_refptr<Workspace> P2PSocketDispatcherHost::workspace() {
  return workspace_;
}

Domain* P2PSocketDispatcherHost::shell() {
  return domain_;
}

bool P2PSocketDispatcherHost::IsSocketIdAlreadyRegistered(int id) {
  for (auto it = registered_socket_ids_.begin(); it != registered_socket_ids_.end(); ++it) {
    if (*it == id) {
      return true;
    }
  }
  return false;
}

void P2PSocketDispatcherHost::OnNetworkChanged(
    net::NetworkChangeNotifier::ConnectionType type) {
  // NetworkChangeNotifier always emits CONNECTION_NONE notification whenever
  // network configuration changes. All other notifications can be ignored.
  if (type != net::NetworkChangeNotifier::CONNECTION_NONE)
    return;

  // Notify the renderer about changes to list of network interfaces.
  network_list_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&P2PSocketDispatcherHost::DoGetNetworkList, this));
}

void P2PSocketDispatcherHost::StartRtpDump(
    bool incoming,
    bool outgoing,
    const WebRtcRtpPacketCallback& packet_callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if ((!dump_incoming_rtp_packet_ && incoming) ||
      (!dump_outgoing_rtp_packet_ && outgoing)) {
    if (incoming)
      dump_incoming_rtp_packet_ = true;

    if (outgoing)
      dump_outgoing_rtp_packet_ = true;

    packet_callback_ = packet_callback;
    for (SocketsMap::iterator it = sockets_.begin(); it != sockets_.end(); ++it)
      it->second->StartRtpDump(incoming, outgoing, packet_callback);
  }
}

void P2PSocketDispatcherHost::StopRtpDumpOnUIThread(bool incoming,
                                                    bool outgoing) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&P2PSocketDispatcherHost::StopRtpDumpOnIOThread, this,
                     incoming, outgoing));
}

P2PSocketDispatcherHost::~P2PSocketDispatcherHost() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  //DCHECK(sockets_.empty());
  //DCHECK(dns_requests_.empty());

  if (monitoring_networks_)
    net::NetworkChangeNotifier::RemoveNetworkChangeObserver(this);
  
  //acceptor_thread_.Stop();
}

P2PSocketHost* P2PSocketDispatcherHost::LookupSocket(int socket_id) {
  SocketsMap::iterator it = sockets_.find(socket_id);
  return (it == sockets_.end()) ? nullptr : it->second.get();
}

void P2PSocketDispatcherHost::OnStartNetworkNotifications() {
  if (!monitoring_networks_) {
    net::NetworkChangeNotifier::AddNetworkChangeObserver(this);
    monitoring_networks_ = true;
  }

  network_list_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&P2PSocketDispatcherHost::DoGetNetworkList, this));
}

void P2PSocketDispatcherHost::OnStopNetworkNotifications() {
  if (monitoring_networks_) {
    net::NetworkChangeNotifier::RemoveNetworkChangeObserver(this);
    monitoring_networks_ = false;
  }
}

void P2PSocketDispatcherHost::OnGetHostAddress(const std::string& host_name,
                                               int32_t request_id) {
  std::unique_ptr<DnsRequest> request = std::make_unique<DnsRequest>(
      request_id, host_resolver_.get());//resource_context_->GetHostResolver());
  DnsRequest* request_ptr = request.get();
  dns_requests_.insert(std::move(request));
  request_ptr->Resolve(host_name,
                       base::Bind(&P2PSocketDispatcherHost::OnAddressResolved,
                                  base::Unretained(this), request_ptr));
}

void P2PSocketDispatcherHost::OnCreateSocket(
    common::P2PSocketType type,
    int socket_id,
    const common::P2PSocketOptions& options) {

  if (options.port_range.min_port > options.port_range.max_port ||
      (options.port_range.min_port == 0 && options.port_range.max_port != 0)) {
    bad_message::ReceivedBadMessage(this, bad_message::SDH_INVALID_PORT_RANGE);
    return;
  }

  if (LookupSocket(socket_id)) {
    LOG(ERROR) << "Received P2PHostMsg_CreateSocket for socket "
        "that already exists.";
    return;
  }

  if (!proxy_resolving_socket_factory_) {
    proxy_resolving_socket_factory_ =
        std::make_unique<network::ProxyResolvingClientSocketFactory>(
            nullptr, url_context_->GetURLRequestContext());
  }

  if (sockets_.size() > kMaxSimultaneousSockets) {
    LOG(ERROR) << "Too many sockets created";
    Send(new P2PMsg_OnError(socket_id));
    return;
  }

  registered_socket_ids_.push_back(socket_id);

  acceptor_task_runner_->PostTask(
     FROM_HERE, 
     base::BindOnce(&P2PSocketDispatcherHost::CreateSocket,
      base::Unretained(this),
      type,
      socket_id,
      options));

}

void P2PSocketDispatcherHost::CreateSocket(
    common::P2PSocketType type,
    int socket_id,
    const common::P2PSocketOptions& options) {
  
  //printf("local_address: '%s'\n", local_address.address().ToString().c_str());
  std::unique_ptr<P2PSocketHost> socket(
    P2PSocketHost::Create(
      this, 
      weak_ptr_factory_.GetWeakPtr(), 
      socket_id, type, 
      url_context_.get(),
      proxy_resolving_socket_factory_.get(), &throttler_, 
      acceptor_task_runner_));

  if (!socket) {
    Send(new P2PMsg_OnError(socket_id));
    return;
  }
  
  if (socket->Init(options)) {
    sockets_[socket_id] = std::move(socket);

    if (dump_incoming_rtp_packet_ || dump_outgoing_rtp_packet_) {
      sockets_[socket_id]->StartRtpDump(dump_incoming_rtp_packet_,
                                        dump_outgoing_rtp_packet_,
                                        packet_callback_);
    }
  }
}

void P2PSocketDispatcherHost::OnAcceptIncomingTcpConnection(
    int listen_socket_id, const net::IPEndPoint& remote_address) {
      
  acceptor_task_runner_->PostTask(  
     FROM_HERE, 
     base::BindOnce(&P2PSocketDispatcherHost::AcceptIncomingTcpConnection,
      base::Unretained(this),
      listen_socket_id,
      remote_address));
  
  //AcceptIncomingTcpConnection(listen_socket_id, remote_address, connected_socket_id);
}

void P2PSocketDispatcherHost::AcceptIncomingTcpConnection(
    int listen_socket_id, 
    const net::IPEndPoint& remote_address) {
  
   //int connected_socket_id = //id_gen_.GetNext() + 1;

  P2PSocketHost* socket = LookupSocket(listen_socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_AcceptIncomingTcpConnection "
        "for invalid listen_socket_id.";
    return;
  }
  
 // if (LookupSocket(connected_socket_id) != nullptr) {
  //   LOG(ERROR) << "Received P2PHostMsg_AcceptIncomingTcpConnection "
   //      "for duplicated connected_socket_id.";
   //  return;
   //}

  std::unique_ptr<P2PSocketHost> accepted_connection(
      socket->AcceptIncomingTcpConnection(remote_address));
  int connected_socket_id = accepted_connection->id();
  if (accepted_connection) {
    sockets_[connected_socket_id] = std::move(accepted_connection);
  }
}

void P2PSocketDispatcherHost::OnSend(
    int socket_id,
    const std::vector<char>& data,
    const common::P2PPacketInfo& packet_info,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  acceptor_task_runner_->PostTask(
     FROM_HERE, 
     base::BindOnce(&P2PSocketDispatcherHost::DoSend,
      base::Unretained(this),
      socket_id,
      data,
      packet_info,
      traffic_annotation));
}

void P2PSocketDispatcherHost::DoSend(
    int socket_id,
    const std::vector<char>& data,
    const common::P2PPacketInfo& packet_info,
    const net::MutableNetworkTrafficAnnotationTag& traffic_annotation) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_Send for invalid socket_id = " << socket_id;
    return;
  }

  if (data.size() > kMaximumPacketSize) {
    LOG(ERROR) << "Received P2PHostMsg_Send with a packet that is too big: "
               << data.size();
    Send(new P2PMsg_OnError(socket_id));
    sockets_.erase(socket_id);  // deletes the socket
    return;
  }

  socket->Send(packet_info.destination, data, packet_info.packet_options,
               packet_info.packet_id,
               net::NetworkTrafficAnnotationTag(traffic_annotation));
}

void P2PSocketDispatcherHost::OnSetOption(int socket_id,
                                          common::P2PSocketOption option,
                                          int value) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_SetOption for invalid socket_id.";
    return;
  }

  socket->SetOption(option, value);
}

void P2PSocketDispatcherHost::Shutdown() {
  SocketsMap::iterator it = sockets_.begin();
  while (it != sockets_.end()) {
    sockets_.erase(it);
    ++it;
  }
}

void P2PSocketDispatcherHost::DisposeSocket(P2PSocketHost* socket) {
//  LOG(ERROR) << "P2PSocketDispatcherHost::DisposeSocket";
}

void P2PSocketDispatcherHost::OnDestroySocket(int socket_id) {
  //LOG(ERROR) << "P2PSocketDispatcherHost::OnDestroySocket " << socket_id;
  SocketsMap::iterator it = sockets_.find(socket_id);
  if (it != sockets_.end()) {
    sockets_.erase(it);  // deletes the socket
  } else {
    LOG(ERROR) << "Received P2PHostMsg_DestroySocket for invalid socket_id.";
  }
}

void P2PSocketDispatcherHost::OnRpcReceiveMessage(int socket_id, int call_id, int method_type) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_RPCReceiveMessage for invalid socket_id = " << socket_id;
    return;
  }
  socket->ReceiveRpcMessage(call_id, method_type);
}

void P2PSocketDispatcherHost::OnRpcSendMessage(int socket_id, int call_id, const std::vector<char>& data, int method_type) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_RPCReceiveMessage for invalid socket_id = " << socket_id;
    return;
  }
  socket->SendRpcMessage(call_id, method_type, data);
}

void P2PSocketDispatcherHost::OnRpcSendMessageNow(int socket_id, int call_id, const std::vector<char>& data, int method_type) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_RPCReceiveMessage for invalid socket_id = " << socket_id;
    return;
  }
  socket->SendRpcMessageNow(call_id, method_type, data);
}

void P2PSocketDispatcherHost::OnRpcSendStatus(int socket_id, int call_id, int status_code) {
  P2PSocketHost* socket = LookupSocket(socket_id);
  if (!socket) {
    LOG(ERROR) << "Received P2PHostMsg_RPCSendStatus for invalid socket_id = " << socket_id;
    return;
  }
  socket->SendRpcStatus(call_id, status_code);
}

void P2PSocketDispatcherHost::DoGetNetworkList() {
  net::NetworkInterfaceList list;
  if (!net::GetNetworkList(&list, net::EXCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES)) {
    LOG(ERROR) << "GetNetworkList failed.";
    return;
  }
  default_ipv4_local_address_ = GetDefaultLocalAddress(AF_INET);
  default_ipv6_local_address_ = GetDefaultLocalAddress(AF_INET6);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&P2PSocketDispatcherHost::SendNetworkList, this, list,
                     default_ipv4_local_address_, default_ipv6_local_address_));
}

void P2PSocketDispatcherHost::SendNetworkList(
    const net::NetworkInterfaceList& list,
    const net::IPAddress& default_ipv4_local_address,
    const net::IPAddress& default_ipv6_local_address) {
  Send(new P2PMsg_NetworkListChanged(list, default_ipv4_local_address,
                                     default_ipv6_local_address));
}

scoped_refptr<base::SingleThreadTaskRunner> P2PSocketDispatcherHost::acceptor_task_runner() const {
  return acceptor_task_runner_;
}

net::IPAddress P2PSocketDispatcherHost::GetDefaultLocalAddress(int family) {
  DCHECK(family == AF_INET || family == AF_INET6);

  // Creation and connection of a UDP socket might be janky.
  DCHECK(network_list_task_runner_->RunsTasksInCurrentSequence());

  auto socket =
      net::ClientSocketFactory::GetDefaultFactory()->CreateDatagramClientSocket(
          net::DatagramSocket::DEFAULT_BIND, nullptr, net::NetLogSource());

  net::IPAddress ip_address;
  if (family == AF_INET) {
    ip_address = net::IPAddress(kPublicIPv4Host);
  } else {
    ip_address = net::IPAddress(kPublicIPv6Host);
  }

  if (socket->Connect(net::IPEndPoint(ip_address, kPublicPort)) != net::OK) {
    return net::IPAddress();
  }

  net::IPEndPoint local_address;
  if (socket->GetLocalAddress(&local_address) != net::OK)
    return net::IPAddress();

  return local_address.address();
}

void P2PSocketDispatcherHost::OnAddressResolved(
    DnsRequest* request,
    const net::IPAddressList& addresses) {
  Send(new P2PMsg_GetHostAddressResult(request->request_id(), addresses));

  dns_requests_.erase(
      std::find_if(dns_requests_.begin(), dns_requests_.end(),
                   [request](const std::unique_ptr<DnsRequest>& ptr) {
                     return ptr.get() == request;
                   }));
}

void P2PSocketDispatcherHost::StopRtpDumpOnIOThread(bool incoming,
                                                    bool outgoing) {
  if ((dump_incoming_rtp_packet_ && incoming) ||
      (dump_outgoing_rtp_packet_ && outgoing)) {
    if (incoming)
      dump_incoming_rtp_packet_ = false;

    if (outgoing)
      dump_outgoing_rtp_packet_ = false;

    if (!dump_incoming_rtp_packet_ && !dump_outgoing_rtp_packet_)
      packet_callback_.Reset();

    for (SocketsMap::iterator it = sockets_.begin(); it != sockets_.end(); ++it)
      it->second->StopRtpDump(incoming, outgoing);
  }
}

}  // namespace host
