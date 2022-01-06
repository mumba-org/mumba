// Copyright (c) 2019 Mumba. All rights reserved.
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
#include "rpc/support/log_windows.h"
#include "net/socket/tcp_socket_win.h"
#include "rpc/iomgr/tcp_windows.h"
#include "rpc/iomgr/iocp_windows.h"
#include "rpc/iomgr/socket_windows.h"
#include "rpc/iomgr/tcp_server_windows.h"

namespace host {

namespace {

void destroy_server(grpc_exec_ctx* exec_ctx, void* arg,
                           grpc_error* error) {
  grpc_tcp_server* s = (grpc_tcp_server*)arg;

  /* Now that the accepts have been aborted, we can destroy the sockets.
     The IOCP won't get notified on these, so we can flag them as already
     closed by the system. */
  while (s->head) {
    grpc_tcp_listener* sp = s->head;
    s->head = sp->next;
    sp->next = NULL;
    grpc_winsocket_destroy(sp->socket);
    gpr_free(sp);
  }
  grpc_channel_args_destroy(exec_ctx, s->channel_args);
  gpr_free(s);
}

void finish_shutdown_locked(grpc_exec_ctx* exec_ctx,
                                   grpc_tcp_server* s) {
  if (s->shutdown_complete != NULL) {
    GRPC_CLOSURE_SCHED(exec_ctx, s->shutdown_complete, GRPC_ERROR_NONE);
  }

  GRPC_CLOSURE_SCHED(
      exec_ctx,
      GRPC_CLOSURE_CREATE(destroy_server, s, grpc_schedule_on_exec_ctx),
      GRPC_ERROR_NONE);
}

void decrement_active_ports_and_notify_locked(grpc_exec_ctx* exec_ctx,
                                                     grpc_tcp_listener* sp) {
  sp->shutting_down = 0;
  GPR_ASSERT(sp->server->active_ports > 0);
  if (0 == --sp->server->active_ports) {
    finish_shutdown_locked(exec_ctx, sp->server);
  }
}
grpc_error* start_accept_locked(grpc_exec_ctx* exec_ctx,
                                grpc_tcp_listener* port) {
  SOCKET sock = INVALID_SOCKET;
  BOOL success;
  DWORD addrlen = sizeof(struct sockaddr_in6) + 16;
  DWORD bytes_received = 0;
  grpc_error* error = GRPC_ERROR_NONE;

  if (port->shutting_down) {
    return GRPC_ERROR_NONE;
  }

  sock = WSASocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                   WSA_FLAG_OVERLAPPED);
  if (sock == INVALID_SOCKET) {
    error = GRPC_WSA_ERROR(WSAGetLastError(), "WSASocket");
    goto failure;
  }

  error = grpc_tcp_prepare_socket(sock);
  if (error != GRPC_ERROR_NONE) goto failure;

  /* Start the "accept" asynchronously. */
  success = port->AcceptEx(port->socket->socket, sock, port->addresses, 0,
                           addrlen, addrlen, &bytes_received,
                           &port->socket->read_info.overlapped);

  /* It is possible to get an accept immediately without delay. However, we
     will still get an IOCP notification for it. So let's just ignore it. */
  if (!success) {
    int last_error = WSAGetLastError();
    if (last_error != ERROR_IO_PENDING) {
      error = GRPC_WSA_ERROR(last_error, "AcceptEx");
      goto failure;
    }
  }

  /* We're ready to do the accept. Calling grpc_socket_notify_on_read may
     immediately process an accept that happened in the meantime. */
  port->new_socket = sock;
  grpc_socket_notify_on_read(exec_ctx, port->socket, &port->read_closure);
  port->outstanding_calls++;
  return error;

failure:
  GPR_ASSERT(error != GRPC_ERROR_NONE);
  if (sock != INVALID_SOCKET) closesocket(sock);
  return error;
}

void on_read(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  grpc_tcp_listener* sp = (grpc_tcp_listener*)arg;
  SOCKET sock = sp->new_socket;
  grpc_winsocket_callback_info* info = &sp->socket->read_info;
  grpc_endpoint* ep = NULL;
  grpc_resolved_address peer_name;
  char* peer_name_string;
  char* fd_name;
  DWORD transfered_bytes;
  DWORD flags;
  BOOL wsa_success;
  int err;

  gpr_mu_lock(&sp->server->mu);

  peer_name.len = sizeof(struct sockaddr_storage);

  /* The general mechanism for shutting down is to queue abortion calls. While
     this is necessary in the read/write case, it's useless for the accept
     case. We only need to adjust the pending callback count */
  if (error != GRPC_ERROR_NONE) {
    const char* msg = grpc_error_string(error);
    gpr_log(GPR_INFO, "Skipping on_accept due to error: %s", msg);

    gpr_mu_unlock(&sp->server->mu);
    return;
  }

  /* The IOCP notified us of a completed operation. Let's grab the results,
     and act accordingly. */
  transfered_bytes = 0;
  wsa_success = WSAGetOverlappedResult(sock, &info->overlapped,
                                       &transfered_bytes, FALSE, &flags);
  if (!wsa_success) {
    if (!sp->shutting_down) {
      char* utf8_message = gpr_format_message(WSAGetLastError());
      gpr_log(GPR_ERROR, "on_accept error: %s", utf8_message);
      gpr_free(utf8_message);
    }
    closesocket(sock);
  } else {
    /* The only time we should call our callback, is where we successfully
     managed to accept a connection, and created an endpoint. */
  
    P2PSocketHostRpcServer* rpc_server = reinterpret_cast<P2PSocketHostRpcServer*>(sp->state);
    rpc_server->OnRead(exec_ctx, sp, error);
  }

   /* As we were notified from the IOCP of one and exactly one accept,
     the former socked we created has now either been destroy or assigned
     to the new connection. We need to create a new one for the next
     connection. */
  GPR_ASSERT(
      GRPC_LOG_IF_ERROR("start_accept", start_accept_locked(exec_ctx, sp)));
  if (0 == --sp->outstanding_calls) {
    decrement_active_ports_and_notify_locked(exec_ctx, sp);
  }
  gpr_mu_unlock(&sp->server->mu);
}

}

P2PSocketHostRpcServer::P2PSocketHostRpcServer(Delegate* delegate,
                                               base::WeakPtr<IPC::Sender> message_sender,
                                               int socket_id,
                                               common::P2PSocketType client_type)
    : P2PSocketHost(delegate, message_sender, socket_id, P2PSocketHost::TCP),
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
    std::make_unique<IPCRPCHandler>(message_sender_));

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

void P2PSocketHostRpcServer::OnRead(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err) {  
  DLOG(INFO) << "P2PSocketHostRpcServer::OnRead ";
  listener_ = sp;
  exec_ctx_ = exec_ctx;

  DoAccept();
}

void P2PSocketHostRpcServer::Send(
    const net::IPEndPoint& to,
    const std::vector<char>& data,
    const rtc::PacketOptions& options,
    uint64_t packet_id,
    const net::NetworkTrafficAnnotationTag traffic_annotation) {
  NOTREACHED();
  OnError();
}

void P2PSocketHostRpcServer::DoAccept() {
  DLOG(INFO) << "P2PSocketHostRpcServer::DoAccept";
  if (!service_started_) {
    DLOG(INFO) << " rpc accept: waiting on service start..";
    wait_service_start_before_accept_.Wait();
    DLOG(INFO) << " rpc accept: done.";
  }
  
  SOCKET sock = listener_->new_socket;
  grpc_resolved_address addr;
  int err;

  addr.len = sizeof(struct sockaddr_storage);

  if (!listener_->shutting_down) {
    //peer_name_string = NULL;
    err = setsockopt(sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                      (char*)&listener_->socket->socket, sizeof(listener_->socket->socket));
    if (err) {
      char* utf8_message = gpr_format_message(WSAGetLastError());
      gpr_log(GPR_ERROR, "setsockopt error: %s", utf8_message);
      gpr_free(utf8_message);
    }
    int peer_name_len = (int)addr.len;
    err = getpeername(sock, (struct sockaddr*)addr.addr, &peer_name_len);
    addr.len = (size_t)peer_name_len;
    // if (!err) {
    //   peer_name_string = grpc_sockaddr_to_uri(&peer_name);
    // } else {
    //   char* utf8_message = gpr_format_message(WSAGetLastError());
    //   gpr_log(GPR_ERROR, "getpeername error: %s", utf8_message);
    //   gpr_free(utf8_message);
    // }
    //gpr_asprintf(&fd_name, "tcp_server:%s", peer_name_string);
    //ep = grpc_tcp_create(exec_ctx, grpc_winsocket_create(sock, fd_name),
    //                      sp->server->channel_args, peer_name_string);
    //grpc_iomgr_register_object(&r->iomgr_object, final_name);
    
    //TODO we are not using IOCP on Windows as GRpc is
    // we need to fix this

    //HANDLE ret = CreateIoCompletionPort((HANDLE)sock, g_iocp, (uintptr_t)sock, 0);
    net::IPEndPoint peer_address(net::IPAddress(reinterpret_cast<const uint8_t *>(addr.addr), net::IPAddress::kIPv4AddressSize), 9999);
    std::unique_ptr<net::TCPSocket> accepted_socket(new net::TCPSocket(nullptr, nullptr, net::NetLogSource()));
    int rv = accepted_socket->AdoptConnectedSocket(sock, peer_address);
    if (rv != net::OK) {
      HandleAcceptResult(rv);
      return;
    }
    accept_socket_.reset(new net::TCPClientSocket(std::move(accepted_socket), peer_address));
    HandleAcceptResult(rv);
  } else {
    closesocket(sock);
  }
 
}

void P2PSocketHostRpcServer::HandleAcceptResult(int result) {
  DLOG(INFO) << "P2PSocketHostRpcServer::HandleAcceptResult";
 
  char* name = nullptr;
  char* fd_name = nullptr;

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

  //grpc_pollset* read_notifier_pollset =
  // listener_->server->pollsets[(size_t)gpr_atm_no_barrier_fetch_add(
  //                           &listener_->server->next_pollset_to_assign, 1) %
  //                       listener_->server->pollset_count];

  net::TCPClientSocket* client_socket = static_cast<net::TCPClientSocket*>(accept_socket_.get());

  //grpc_set_socket_no_sigpipe_if_possible(client_socket->GetSocketDescriptor());

  gpr_asprintf(&name, "tcp-server-connection:%s", address.ToString().c_str());

  //grpc_fd* fdobj = grpc_fd_create(client_socket->GetSocketDescriptor(), name);

  //grpc_pollset_add_fd(exec_ctx_, read_notifier_pollset, fdobj);

  //Create acceptor.
  grpc_tcp_server_acceptor* acceptor = (grpc_tcp_server_acceptor*)gpr_malloc(sizeof(*acceptor));
  acceptor->from_server = listener_->server;
  acceptor->port_index = listener_->port_index;
  
  gpr_asprintf(&fd_name, "tcp_server:%s", address.ToString().c_str());
       
  if (!socket_host_->InitAccepted(
      rpc_service_,
      address, 
      std::move(accept_socket_),
      exec_ctx_,
      reinterpret_cast<server_state *>(listener_->server->on_accept_cb_arg),
      grpc_tcp_create(exec_ctx_, grpc_winsocket_create(client_socket->GetSocketDescriptor(), fd_name), listener_->server->channel_args, address.ToString().c_str()),
      nullptr,
      acceptor)) {
    gpr_free(fd_name);
    return;
  }

  rpc_service_->RegisterSocket(socket_host_->socket_.get());

  message_sender_->Send(
      new P2PMsg_OnIncomingTcpConnection(id_, address, next_socket_id));

  gpr_free(name);
  gpr_free(fd_name);
  
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
