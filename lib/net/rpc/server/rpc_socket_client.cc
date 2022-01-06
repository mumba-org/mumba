// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_socket_client.h"

#include <stddef.h>
#include <utility>

#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/sys_byteorder.h"
#include "base/threading/thread_task_runner_handle.h"
//#include "net/rpc/server/ipc_rpc_handler.h"
#include "ipc/ipc_sender.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_getter.h"
#include "url/gurl.h"
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

#if defined(OS_POSIX)
#include "rpc/iomgr/socket_utils_posix.h"
#include "rpc/iomgr/tcp_posix.h"
#include "rpc/iomgr/tcp_server_utils_posix.h"
#include "rpc/iomgr/unix_sockets_posix.h"
#endif

#if defined(OS_WIN)
#include "net/socket/tcp_socket_win.h"
#include "rpc/iomgr/tcp_windows.h"
#include "rpc/iomgr/iocp_windows.h"
#include "rpc/iomgr/socket_windows.h"
#include "rpc/iomgr/tcp_server_windows.h"
#endif


#if defined(OS_LINUX)
#include "rpc/iomgr/ev_poll_posix.h"
#endif


namespace net {

namespace {

typedef uint16_t PacketLength;

void server_connection_state_unref(
    grpc_exec_ctx* exec_ctx, server_connection_state* connection_state) {
  if (gpr_unref(&connection_state->refs)) {
    if (connection_state->transport != nullptr) {
      GRPC_CHTTP2_UNREF_TRANSPORT(exec_ctx, connection_state->transport,
                                  "receive settings timeout");
    }
    gpr_free(connection_state);
  }
}

void on_timeout(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* error) {
  server_connection_state* connection_state = (server_connection_state*)arg;
  // Note that we may be called with GRPC_ERROR_NONE when the timer fires
  // or with an error indicating that the timer system is being shut down.
  if (error != GRPC_ERROR_CANCELLED) {
    grpc_transport_op* op = grpc_make_transport_op(nullptr);
    op->disconnect_with_error = GRPC_ERROR_CREATE_FROM_STATIC_STRING(
        "Did not receive HTTP/2 settings before handshake timeout");
    grpc_transport_perform_op(exec_ctx, &connection_state->transport->base, op);
  }
  server_connection_state_unref(exec_ctx, connection_state);
}

void on_receive_settings(grpc_exec_ctx* exec_ctx, void* arg,
                         grpc_error* error) {
  server_connection_state* connection_state = (server_connection_state*)arg;
  if (error == GRPC_ERROR_NONE) {
    grpc_timer_cancel(exec_ctx, &connection_state->timer);
  }
  server_connection_state_unref(exec_ctx, connection_state);
}

void on_handshake_done(grpc_exec_ctx* exec_ctx, void* arg,
                              grpc_error* error) {
  grpc_handshaker_args* args = (grpc_handshaker_args*)arg;
  server_connection_state* connection_state =
      (server_connection_state*)args->user_data;
  gpr_mu_lock(&connection_state->svr_state->mu);
  if (error != GRPC_ERROR_NONE || connection_state->svr_state->shutdown) {
    const char* error_str = grpc_error_string(error);
    gpr_log(GPR_DEBUG, "Handshaking failed: %s", error_str);
    if (error == GRPC_ERROR_NONE && args->endpoint != nullptr) {
      // We were shut down after handshaking completed successfully, so
      // destroy the endpoint here.
      // TODO(ctiller): It is currently necessary to shutdown endpoints
      // before destroying them, even if we know that there are no
      // pending read/write callbacks.  This should be fixed, at which
      // point this can be removed.
      grpc_endpoint_shutdown(exec_ctx, args->endpoint, GRPC_ERROR_NONE);
      grpc_endpoint_destroy(exec_ctx, args->endpoint);
      grpc_channel_args_destroy(exec_ctx, args->args);
      grpc_slice_buffer_destroy_internal(exec_ctx, args->read_buffer);
      gpr_free(args->read_buffer);
    }
  } else {
    // If the handshaking succeeded but there is no endpoint, then the
    // handshaker may have handed off the connection to some external
    // code, so we can just clean up here without creating a transport.
    if (args->endpoint != nullptr) {
      grpc_transport* transport = grpc_create_chttp2_transport(
          exec_ctx, args->args, args->endpoint, false);
      grpc_server_setup_transport(
          exec_ctx, connection_state->svr_state->server, transport,
          connection_state->accepting_pollset, args->args);
      // Use notify_on_receive_settings callback to enforce the
      // handshake deadline.
      connection_state->transport = (grpc_chttp2_transport*)transport;
      gpr_ref(&connection_state->refs);
      GRPC_CLOSURE_INIT(&connection_state->on_receive_settings,
                        on_receive_settings, connection_state,
                        grpc_schedule_on_exec_ctx);
      grpc_chttp2_transport_start_reading(
          exec_ctx, transport, args->read_buffer,
          &connection_state->on_receive_settings);
      grpc_channel_args_destroy(exec_ctx, args->args);
      gpr_ref(&connection_state->refs);
      GRPC_CHTTP2_REF_TRANSPORT((grpc_chttp2_transport*)transport,
                                "receive settings timeout");
      GRPC_CLOSURE_INIT(&connection_state->on_timeout, on_timeout,
                        connection_state, grpc_schedule_on_exec_ctx);
      grpc_timer_init(exec_ctx, &connection_state->timer,
                      connection_state->deadline,
                      &connection_state->on_timeout);
    }
  }
  grpc_handshake_manager_pending_list_remove(
      &connection_state->svr_state->pending_handshake_mgrs,
      connection_state->handshake_mgr);
  gpr_mu_unlock(&connection_state->svr_state->mu);
  grpc_handshake_manager_destroy(exec_ctx, connection_state->handshake_mgr);
  gpr_free(connection_state->acceptor);
  grpc_tcp_server_unref(exec_ctx, connection_state->svr_state->tcp_server);

  //host::P2PSocketHostRpc* rpc_socket = reinterpret_cast<host::P2PSocketHostRpc*>(connection_state->svr_state->state);
  // DLOG(INFO) << "on_handshake_done: calling Read()";
   //rpc_socket->Read();

  server_connection_state_unref(exec_ctx, connection_state);
}

}  // namespace

RpcSocketClient::RpcSocketClient(int id): id_(id) {

}

RpcSocketClient::~RpcSocketClient() {
  
}

bool RpcSocketClient::InitAccepted(
    RpcService* service,
    const net::IPEndPoint& remote_address,
    std::unique_ptr<net::StreamSocket> socket,
    grpc_exec_ctx* exec_ctx, 
    server_state* state,
    grpc_endpoint* tcp,
    grpc_pollset* accepting_pollset,
    grpc_tcp_server_acceptor* acceptor) {
  DCHECK(socket);
//  DCHECK_EQ(state_, STATE_UNINITIALIZED);

  //remote_address_.ip_address = remote_address;
  ip_address_ = remote_address;
  socket_.reset(new RpcSocket(this, service, id_, std::move(socket)));
  //state_ = STATE_OPEN;
  DoHandshake(exec_ctx, state, tcp, accepting_pollset, acceptor);
  return true;//state_ != STATE_ERROR;
}

void RpcSocketClient::DoHandshake(grpc_exec_ctx* exec_ctx, 
                            server_state* state,
                            grpc_endpoint* tcp,
                            grpc_pollset* accepting_pollset,
                            grpc_tcp_server_acceptor* acceptor) {
  gpr_mu_lock(&state->mu);

  if (state->shutdown) {
    gpr_mu_unlock(&state->mu);
    grpc_endpoint_shutdown(exec_ctx, tcp, GRPC_ERROR_NONE);
    grpc_endpoint_destroy(exec_ctx, tcp);
    gpr_free(acceptor);
    return;
  }

  state->state = this;

  grpc_handshake_manager* handshake_mgr = grpc_handshake_manager_create();
  grpc_handshake_manager_pending_list_add(&state->pending_handshake_mgrs,
                                          handshake_mgr);
  gpr_mu_unlock(&state->mu);
  grpc_tcp_server_ref(state->tcp_server);
  server_connection_state* connection_state =
      (server_connection_state*)gpr_zalloc(sizeof(*connection_state));
  gpr_ref_init(&connection_state->refs, 1);
  connection_state->svr_state = state;
  connection_state->accepting_pollset = accepting_pollset;
  connection_state->acceptor = acceptor;
  connection_state->handshake_mgr = handshake_mgr;
  grpc_handshakers_add(exec_ctx, HANDSHAKER_SERVER, state->args,
                       connection_state->handshake_mgr);
  const grpc_arg* timeout_arg =
      grpc_channel_args_find(state->args, GRPC_ARG_SERVER_HANDSHAKE_TIMEOUT_MS);
  connection_state->deadline =
      grpc_exec_ctx_now(exec_ctx) +
      grpc_channel_arg_get_integer(timeout_arg,
                                   {120 * GPR_MS_PER_SEC, 1, INT_MAX});

  grpc_handshake_manager_do_handshake(exec_ctx, connection_state->handshake_mgr,
                                      nullptr /* interested_parties */, tcp,
                                      state->args, connection_state->deadline,
                                      acceptor, on_handshake_done,
                                      connection_state);
}

void RpcSocketClient::OnRpcCallDestroyed(net::RpcSocket* socket, int call_id) {
  //socket_->Disconnect();
  //socket_.reset();
}


}