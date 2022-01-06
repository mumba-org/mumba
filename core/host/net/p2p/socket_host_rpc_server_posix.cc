// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/p2p/socket_host_rpc_server.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/p2p_messages.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_thread.h"
#include "net/rpc/server/rpc_service.h"
#include "core/host/rpc/server/ipc_rpc_handler.h"
#include "core/host/net/p2p/socket_host_rpc.h"
#include "net/base/address_list.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_socket.h"
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/sync.h>
#include <rpc/support/useful.h>
#include "rpc/ext/filters/http/server/http_server_filter.h"
#include "rpc/ext/transport/chttp2/transport/chttp2_transport.h"
#include "rpc/ext/transport/chttp2/transport/internal.h"
#include "rpc/channel/channel_args.h"
#include "rpc/channel/handshaker.h"
#include "rpc/channel/handshaker_registry.h"
#include "rpc/iomgr/endpoint.h"
#include "rpc/iomgr/resolve_address.h"
#include "rpc/iomgr/tcp_server.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/server.h"
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/sync.h>
#include <rpc/support/time.h>
#include <rpc/support/useful.h>
#include "rpc/channel/channel_args.h"
#include "rpc/iomgr/resolve_address.h"
#include "rpc/iomgr/sockaddr.h"
#include "rpc/iomgr/sockaddr_utils.h"
#include "rpc/support/string.h"
#include "net/socket/tcp_socket_posix.h"
#include "net/socket/socket_posix.h"
#include "rpc/iomgr/socket_utils_posix.h"
#include "rpc/iomgr/tcp_posix.h"
#include "rpc/iomgr/tcp_server_utils_posix.h"
#include "rpc/iomgr/unix_sockets_posix.h"

namespace host {

namespace {

void finish_shutdown(grpc_exec_ctx* exec_ctx, grpc_tcp_server* s) {
  gpr_mu_lock(&s->mu);
  GPR_ASSERT(s->shutdown);
  gpr_mu_unlock(&s->mu);
  if (s->shutdown_complete != nullptr) {
    GRPC_CLOSURE_SCHED(exec_ctx, s->shutdown_complete, GRPC_ERROR_NONE);
  }

  gpr_mu_destroy(&s->mu);

  while (s->head) {
    grpc_tcp_listener* sp = s->head;
    s->head = sp->next;
    gpr_free(sp);
  }
  grpc_channel_args_destroy(exec_ctx, s->channel_args);

  gpr_free(s);
}

void destroyed_port(grpc_exec_ctx* exec_ctx, void* server,
                           grpc_error* error) {
  grpc_tcp_server* s = (grpc_tcp_server*)server;
  gpr_mu_lock(&s->mu);
  s->destroyed_ports++;
  if (s->destroyed_ports == s->nports) {
    gpr_mu_unlock(&s->mu);
    finish_shutdown(exec_ctx, s);
  } else {
    GPR_ASSERT(s->destroyed_ports < s->nports);
    gpr_mu_unlock(&s->mu);
  }
}

void deactivated_all_ports(grpc_exec_ctx* exec_ctx, grpc_tcp_server* s) {
  /* delete ALL the things */
  gpr_mu_lock(&s->mu);

  GPR_ASSERT(s->shutdown);

  if (s->head) {
    grpc_tcp_listener* sp;
    for (sp = s->head; sp; sp = sp->next) {
      grpc_unlink_if_unix_domain_socket(&sp->addr);
      GRPC_CLOSURE_INIT(&sp->destroyed_closure, destroyed_port, s,
                        grpc_schedule_on_exec_ctx);
      grpc_fd_orphan(exec_ctx, sp->emfd, &sp->destroyed_closure, nullptr,
                     false /* already_closed */, "tcp_listener_shutdown");
    }
    gpr_mu_unlock(&s->mu);
  } else {
    gpr_mu_unlock(&s->mu);
    finish_shutdown(exec_ctx, s);
  }
}

void on_read(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* err) {
  grpc_tcp_listener* sp = reinterpret_cast<grpc_tcp_listener*>(arg);
  
  if (err != GRPC_ERROR_NONE) {
    //goto error;
    gpr_mu_lock(&sp->server->mu);
    if (0 == --sp->server->active_ports && sp->server->shutdown) {
      gpr_mu_unlock(&sp->server->mu);
      deactivated_all_ports(exec_ctx, sp->server);
    } else {
      gpr_mu_unlock(&sp->server->mu);
    }
    return;
  }
  //gpr_mu_lock(&sp->server->mu);
  //P2PSocketHostRpcServer* rpc_server = reinterpret_cast<P2PSocketHostRpcServer*>(sp->state);
  //rpc_server->OnRead(exec_ctx, sp, err);
  //gpr_mu_unlock(&sp->server->mu);
  for (;;) {
    grpc_resolved_address addr;
    addr.len = sizeof(struct sockaddr_storage);
    int fd = grpc_accept4(sp->fd, &addr, 1, 1);
    if (fd < 0) {
      switch (errno) {
        case EINTR:
          continue;
        case EAGAIN:
          grpc_fd_notify_on_read(exec_ctx, sp->emfd, &sp->read_closure);
          return;
      }
    } else {
      P2PSocketHostRpcServer* rpc_server = reinterpret_cast<P2PSocketHostRpcServer*>(sp->state);
      grpc_set_socket_no_sigpipe_if_possible(fd);
      rpc_server->OnAccept(exec_ctx, sp, err, fd, std::move(addr));
    }
  }
}

}

P2PSocketHostRpcServer::P2PSocketHostRpcServer(Delegate* delegate,
                                               base::WeakPtr<IPC::Sender> message_sender,
                                               int socket_id,
                                               common::P2PSocketType client_type)
    : P2PSocketHost(delegate, std::move(message_sender), socket_id, P2PSocketHost::TCP),
      client_type_(client_type),
      rpc_service_(nullptr),
     // accept_callback_(base::Bind(&P2PSocketHostRpcServer::OnAccepted,
     //                             base::Unretained(this))),
      //next_socket_id_(-1),
      //first_time_(true),
      exec_ctx_(nullptr),
      listener_(nullptr),
      service_started_(false),
      wait_service_start_before_accept_(
        base::WaitableEvent::ResetPolicy::MANUAL, 
        base::WaitableEvent::InitialState::NOT_SIGNALED) {
      //socket_(new net::TCPServerSocket(nullptr, net::NetLogSource())),
}

P2PSocketHostRpcServer::~P2PSocketHostRpcServer() {
  if (rpc_service_) {
    // not very cool to block on destructor but it happen before
    // the whole process destruction, when shell process wants
    // or when the shell process who owns this is gone
    if (rpc_service_->state() == net::RpcServiceState::kSTARTED) {
      base::WaitableEvent wait_for_shutdown{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      rpc_service_->Stop(&wait_for_shutdown);
      wait_for_shutdown.Wait();  
    }
    rpc_service_ = nullptr;
  }
  accept_socket_.reset();
  socket_.reset();
  socket_host_.reset();
  acceptor_thread_ = nullptr;
}

bool P2PSocketHostRpcServer::Init(const common::P2PSocketOptions& options) {
  DCHECK_EQ(state_, STATE_UNINITIALIZED);
  //net::SocketDescriptor server_fd = net::kInvalidSocket;

  local_address_ = options.local_address;
  acceptor_thread_ = base::ThreadTaskRunnerHandle::Get();

  scoped_refptr<Workspace> workspace =  delegate_->workspace();
  
  rpc_service_ = workspace->CreateService(
//    delegate_->shell(),
    options.package,
    options.name,
    options.local_address.address().ToString(),
    options.local_address.port(), 
    net::RpcTransportType::kHTTP,
    acceptor_thread_,
    std::make_unique<IPCRPCHandler>(message_sender_, delegate_->acceptor_task_runner()));

  if (!rpc_service_) {
    LOG(ERROR) << "Rpc server: Unable to create service '" << options.package << "." << options.name << "'";
    return false;
  }

  // TODO: this is nasty.. just fix
  net::RpcServiceOptions& service_options = rpc_service_->options();
  service_options.state = this;
  service_options.read_callback = &on_read;

  //next_socket_id_ = delegate_->GetNextSocketId();

  int result = rpc_service_->Start(
    //next_socket_id_,
  base::Bind(
      &P2PSocketHostRpcServer::OnRpcServiceStarted, 
      base::Unretained(this),
      options.remote_address));//&server_fd);
  // if (result < 0) {
  //   LOG(ERROR) << "Listen() failed: " << result;
  //   OnError();
  //   return false;
  // }

  // socket_.reset(new net::TCPServerSocket(nullptr, net::NetLogSource()));
  // static_cast<net::TCPServerSocket *>(socket_.get())->AdoptSocket(std::move(server_fd));

  // state_ = STATE_OPEN;
  // // NOTE: Remote address can be empty as socket is just listening
  // // in this state.
  // message_sender_->Send(new P2PMsg_OnSocketCreated(
  //     id_, local_address_, remote_address.ip_address));
  //DoAccept();
  return result == 0;//true;
}

void P2PSocketHostRpcServer::OnError() {
  //rpc_service_.reset();
  rpc_service_ = nullptr;

  if (state_ == STATE_UNINITIALIZED || state_ == STATE_OPEN)
    message_sender_->Send(new P2PMsg_OnError(id_));

  state_ = STATE_ERROR;
}

void P2PSocketHostRpcServer::ReceiveRpcMessage(int call_id, int method_type) {}
void P2PSocketHostRpcServer::SendRpcMessage(int call_id, int method_type, std::vector<char> data) {}
void P2PSocketHostRpcServer::SendRpcMessageNow(int call_id, int method_type, std::vector<char> data) {}
void P2PSocketHostRpcServer::SendRpcStatus(int call_id, int status_code) {}

// void P2PSocketHostRpcServer::OnAccept(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err) {  
//   listener_ = sp;
//   exec_ctx_ = exec_ctx;

  
//   //acceptor_thread_->PostTask(
//   //  FROM_HERE,
//   //  base::BindOnce(&P2PSocketHostRpcServer::DoAccept, 
//   //  base::Unretained(this)));

//   //DoAccept();
// }

void P2PSocketHostRpcServer::Send(
    const net::IPEndPoint& to,
    const std::vector<char>& data,
    const rtc::PacketOptions& options,
    uint64_t packet_id,
    const net::NetworkTrafficAnnotationTag traffic_annotation) {
  NOTREACHED();
  OnError();
}

void P2PSocketHostRpcServer::OnAccept(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err, int fd, grpc_resolved_address addr) {
  //DCHECK(service_started_);
  listener_ = sp;
  exec_ctx_ = exec_ctx;
  if (!service_started_) {
    wait_service_start_before_accept_.Wait();
  }

  int port = 0;
  const struct sockaddr* saddr = (const struct sockaddr*)addr.addr;
  if (saddr->sa_family == AF_INET) {
    const struct sockaddr_in* addr4 = (const struct sockaddr_in*)saddr;
    port = ntohs(addr4->sin_port);
  } else if (saddr->sa_family == AF_INET6) {
    const struct sockaddr_in6* addr6 = (const struct sockaddr_in6*)saddr;
    port = ntohs(addr6->sin6_port);
  }
  net::IPEndPoint peer_address(net::IPAddress(reinterpret_cast<const uint8_t *>(addr.addr), net::IPAddress::kIPv4AddressSize), port);
  std::unique_ptr<net::TCPSocket> accepted_socket(new net::TCPSocket(nullptr, nullptr, net::NetLogSource()));
  int rv = accepted_socket->AdoptConnectedSocket(fd, peer_address);
  if (rv != net::OK) {
    HandleAcceptResult(rv);
    return;
  }
  accept_socket_.reset(new net::TCPClientSocket(std::move(accepted_socket), peer_address));
  HandleAcceptResult(rv);
}

void P2PSocketHostRpcServer::HandleAcceptResult(int result) {
  char* name = nullptr;

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

  int next_socket_id = delegate_->GetNextSocketId();
  
  socket_host_.reset(
    new P2PSocketHostRpc(delegate_, message_sender_, next_socket_id, client_type_, nullptr, nullptr, acceptor_thread_));

  grpc_pollset* read_notifier_pollset =
   listener_->server->pollsets[(size_t)gpr_atm_no_barrier_fetch_add(
                             &listener_->server->next_pollset_to_assign, 1) %
                         listener_->server->pollset_count];

  net::TCPClientSocket* client_socket = static_cast<net::TCPClientSocket*>(accept_socket_.get());

  grpc_set_socket_no_sigpipe_if_possible(client_socket->GetSocketDescriptor());

  gpr_asprintf(&name, "tcp-server-connection:%s", address.ToString().c_str());

  grpc_fd* fdobj = grpc_fd_create(client_socket->GetSocketDescriptor(), name);

  grpc_pollset_add_fd(exec_ctx_, read_notifier_pollset, fdobj);

  //Create acceptor.
  grpc_tcp_server_acceptor* acceptor = (grpc_tcp_server_acceptor*)gpr_malloc(sizeof(*acceptor));
  acceptor->from_server = listener_->server;
  acceptor->port_index = listener_->port_index;
  acceptor->fd_index = listener_->fd_index;

  if (!socket_host_->InitAccepted(
      rpc_service_,
      address, 
      std::move(accept_socket_),
      exec_ctx_,
      reinterpret_cast<server_state *>(listener_->server->on_accept_cb_arg),
      grpc_tcp_create(exec_ctx_, fdobj, listener_->server->channel_args, address.ToString().c_str()),
      read_notifier_pollset, acceptor)) {
    
    return;
  }
    
  rpc_service_->RegisterSocket(socket_host_->socket_.get());

  gpr_free(name);

  delegate_->acceptor_task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &P2PSocketHostRpcServer::SendIncomingTcpConnectionOnIO, 
      base::Unretained(this),
      base::Passed(std::move(address)), 
      next_socket_id));
}

void P2PSocketHostRpcServer::SendIncomingTcpConnectionOnIO(net::IPEndPoint address, int next_socket_id) {
  message_sender_->Send(
      new P2PMsg_OnIncomingTcpConnection(id_, address, next_socket_id));
}

std::unique_ptr<P2PSocketHost> P2PSocketHostRpcServer::AcceptIncomingTcpConnection(
    const net::IPEndPoint& remote_address) {
  //DLOG(INFO) << "P2PSocketHostRpcServer::AcceptIncomingRpcConnection. new socket id = " << id;
  // bind back to the "acceptor" thread
  socket_host_->DetachFromThread();

  return std::move(socket_host_);
}

bool P2PSocketHostRpcServer::SetOption(common::P2PSocketOption option,
                                       int value) {

  printf("P2PSocketHostRpcServer::SetOption called\n");
  // Currently we don't have use case tcp server sockets are used for p2p.
  return false;
}

void P2PSocketHostRpcServer::OnRpcServiceStarted(
  const common::P2PHostAndIPEndPoint& remote_address,
  int result, 
  net::SocketDescriptor server_fd) {
  
  if (result < 0) {
    LOG(ERROR) << "net::RpcService initialization failed: " << result;
    OnError();
    return;
  }

  socket_.reset(new net::TCPServerSocket(nullptr, net::NetLogSource()));
  static_cast<net::TCPServerSocket *>(socket_.get())->AdoptSocket(std::move(server_fd));

  state_ = STATE_OPEN;
  service_started_ = true;
  // NOTE: Remote address can be empty as socket is just listening
  // in this state.
  message_sender_->Send(new P2PMsg_OnSocketCreated(
      id_, local_address_, remote_address.ip_address));

  wait_service_start_before_accept_.Signal();
}

}  // namespace host
