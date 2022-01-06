// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/workspace_service_dispatcher.h"

#include "core/host/workspace/workspace.h"
#include "core/host/rpc/services/mumba_services.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/task_scheduler/post_task.h"
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

//const char kWorkspaceServiceDispatcherHostName[] = "localhost";
//const int kWorkspaceServiceDispatcherDefaultPort = 27761;

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
  //WorkspaceServiceDispatcher* dispatcher = reinterpret_cast<WorkspaceServiceDispatcher*>(sp->state);
  //dispatcher->OnRead(exec_ctx, sp, err);
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
      WorkspaceServiceDispatcher* dispatcher = reinterpret_cast<WorkspaceServiceDispatcher*>(sp->state);
      grpc_set_socket_no_sigpipe_if_possible(fd);
      dispatcher->OnAccept(exec_ctx, sp, err, fd, std::move(addr));
    }
  }
  //gpr_mu_unlock(&sp->server->mu);
}

}

WorkspaceServiceDispatcher::WorkspaceServiceDispatcher(scoped_refptr<Workspace> workspace, const std::string& service_host, int service_port):
 workspace_(workspace),
 mumba_services_(new MumbaServices()),
 exec_ctx_(nullptr),
 listener_(nullptr),
 proto_installed_(false),
 initialized_(false),
 service_host_(service_host),
 service_port_(service_port),
 weak_factory_(this) {

}

WorkspaceServiceDispatcher::~WorkspaceServiceDispatcher() {

}

void WorkspaceServiceDispatcher::AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler) {

}

bool WorkspaceServiceDispatcher::Init() {
  if (initialized_) {
    return true;
  }
   
  if (!proto_installed_ && !InstallSchemaFromBundle()) {
    LOG(ERROR) << "Workspace: error creating workspace services: failed to install proto file from disk";
    return false;
  }

  AddServiceHandlers();

  bool mumba_service_started = mumba_services_->Init(
    workspace_,
    service_host_,
    service_port_,
    this,
    &on_read,
    base::Bind(
      &WorkspaceServiceDispatcher::OnRpcServiceStarted, 
      base::Unretained(this)));

  if (!mumba_service_started) {
    LOG(ERROR) << "Unable to start service 'mumba.MumbaManager'";
    return false;
  }

  initialized_ = true;
  return true;
}

void WorkspaceServiceDispatcher::Shutdown() {
  mumba_services_->Shutdown();
}

void WorkspaceServiceDispatcher::OnAccept(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err, int fd, grpc_resolved_address addr) {
  listener_ = sp;
  exec_ctx_ = exec_ctx;
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

// void WorkspaceServiceDispatcher::DoAccept() {
//   DLOG(INFO) << "WorkspaceServiceDispatcher:DoAccept";
//   while (true) {
//     grpc_resolved_address addr;
//     addr.len = sizeof(struct sockaddr_storage);

//     int fd = grpc_accept4(static_cast<net::TCPServerSocket *>(socket_.get())->GetSocketDescriptor(), &addr, 1, 1);
//     if (fd < 0) {
//       DLOG(INFO) << "WorkspaceServiceDispatcher:DoAccept: grpc_accept: fd error -> " << fd << " " << strerror(errno);
//       switch (errno) {
//         case EINTR:
//           continue;
//         case EAGAIN:
//           DLOG(INFO) << "WorkspaceServiceDispatcher:DoAccept: grpc_accept: EAGAIN -> grpc_fd_notify_on_read()";
//           //grpc_fd_notify_on_read(exec_ctx_, listener_->emfd, &listener_->read_closure);
//           continue;
//           //return;
//       }
//     } 
//     net::IPEndPoint peer_address(net::IPAddress(reinterpret_cast<const uint8_t *>(addr.addr), net::IPAddress::kIPv4AddressSize), addr.port);
//     std::unique_ptr<net::TCPSocket> accepted_socket(new net::TCPSocket(nullptr, nullptr, net::NetLogSource()));
//     int rv = accepted_socket->AdoptConnectedSocket(fd, peer_address);
//     if (rv != net::OK) {
//       DLOG(INFO) << "WorkspaceServiceDispatcher:DoAccept: accepted_socket->AdoptConnectedSocket() error -> " << rv;
//       HandleAcceptResult(rv);
//       return;
//     }
//     accept_socket_.reset(new net::TCPClientSocket(std::move(accepted_socket), peer_address));
//     DLOG(INFO) << "WorkspaceServiceDispatcher:DoAccept: HandleAcceptResult() -> " << rv;
//     HandleAcceptResult(rv);
//   }
// }

void WorkspaceServiceDispatcher::HandleAcceptResult(int result) {
  char* name = nullptr;

  if (result < 0) {
    if (result != net::ERR_IO_PENDING) {
      //OnError();
    }
    return;
  }

  net::IPEndPoint address;

  if (accept_socket_->GetPeerAddress(&address) != net::OK) {
    LOG(ERROR) << "Failed to get address of an accepted socket.";
    accept_socket_.reset();
    return;
  }

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

  // TODO: Ideally, we would want to see from which port this came from
  //       and see wich service is mapped to that particular port
  //       to define the service we need to dispatch to. As we can
  //       have more than one system rpc service here for each workspace
  if (!mumba_services_->Accept(
      address, 
      std::move(accept_socket_),
      exec_ctx_,
      reinterpret_cast<server_state *>(listener_->server->on_accept_cb_arg),
      grpc_tcp_create(exec_ctx_, fdobj, listener_->server->channel_args, address.ToString().c_str()),
      read_notifier_pollset, acceptor)) {
    gpr_free(name);
    return;
  }

  gpr_free(name);
}

void WorkspaceServiceDispatcher::OnRpcServiceStarted(
  int result, 
  net::SocketDescriptor server_fd) {
  
  if (result < 0) {
    LOG(ERROR) << "net::RpcService initialization failed: " << result;
    //OnError();
    return;
  }

  socket_.reset(new net::TCPServerSocket(nullptr, net::NetLogSource()));
  static_cast<net::TCPServerSocket *>(socket_.get())->AdoptSocket(std::move(server_fd));

  //state_ = STATE_OPEN;
  
}

bool WorkspaceServiceDispatcher::InstallSchemaFromBundle() {
  std::string filename("mumba.proto");
  std::string obj_filename("objects.proto");
  if (!workspace_->InstallSchemaFromBundle(std::move(filename), IDR_MUMBA_PROTO)) {
    return false;
  }
  if (!workspace_->InstallSchemaFromBundle(std::move(obj_filename), IDR_OBJECTS_PROTO)) {
    DLOG(ERROR) << "failed to insert objects.proto to the schema registry";
    return false;
  }
  proto_installed_ = true;
  return true;
}

void WorkspaceServiceDispatcher::AddServiceHandlers() {
  mumba_services_->AddDefaultServices();
}

bool WorkspaceServiceDispatcher::InstallPackagedApp() {
  if (!workspace_->InstallApplicationFromBundle("world", IDR_WORLD_APP)) {
    return false;
  }
  return true;
}

}