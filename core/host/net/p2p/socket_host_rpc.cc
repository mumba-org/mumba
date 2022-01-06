// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/p2p/socket_host_rpc.h"

#include <stddef.h>
#include <utility>

#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/sys_byteorder.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/shared/common/p2p_messages.h"
#include "core/host/rpc/server/ipc_rpc_handler.h"
#include "core/host/host_thread.h"
#include "ipc/ipc_sender.h"
#include "jingle/glue/fake_ssl_client_socket.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/proxy_resolving_client_socket.h"
#include "services/network/proxy_resolving_client_socket_factory.h"
#include "third_party/webrtc/media/base/rtputils.h"
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
#elif defined(OS_WIN)
#include "net/socket/tcp_socket_win.h"
#include "rpc/iomgr/tcp_windows.h"
#include "rpc/iomgr/iocp_windows.h"
#include "rpc/iomgr/socket_windows.h"
#endif
#if defined(OS_LINUX)
#include "rpc/iomgr/ev_poll_posix.h"
#endif

namespace {

typedef uint16_t PacketLength;
//const int kPacketHeaderSize = sizeof(PacketLength);
const int kTcpReadBufferSize = 4096;
//const int kPacketLengthOffset = 2;
//const int kTurnChannelDataHeaderSize = 4;
const int kTcpRecvSocketBufferSize = 128 * 1024;
const int kTcpSendSocketBufferSize = 128 * 1024;

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

namespace host {

P2PSocketHostRpc::SendBuffer::SendBuffer() : rtc_packet_id(-1) {}
P2PSocketHostRpc::SendBuffer::SendBuffer(
    int32_t rtc_packet_id,
    scoped_refptr<net::DrainableIOBuffer> buffer,
    const net::NetworkTrafficAnnotationTag traffic_annotation)
    : rtc_packet_id(rtc_packet_id),
      buffer(buffer),
      traffic_annotation(traffic_annotation) {}
P2PSocketHostRpc::SendBuffer::SendBuffer(const SendBuffer& rhs) = default;
P2PSocketHostRpc::SendBuffer::~SendBuffer() {}

P2PSocketHostRpc::P2PSocketHostRpc(
    P2PSocketHost::Delegate* delegate,
    base::WeakPtr<IPC::Sender> message_sender,
    int socket_id,
    common::P2PSocketType type,
    net::URLRequestContextGetter* url_context,
    network::ProxyResolvingClientSocketFactory* proxy_resolving_socket_factory,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : P2PSocketHost(delegate, std::move(message_sender), socket_id, P2PSocketHost::TCP),
      write_pending_(false),
      connected_(false),
      type_(type),
      url_context_(url_context),
      proxy_resolving_socket_factory_(proxy_resolving_socket_factory),
      task_runner_(task_runner),
      weak_ptr_factory_(this) {}

P2PSocketHostRpc::~P2PSocketHostRpc() {
  // DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  //  if (state_ == STATE_OPEN) {
  //   DCHECK(socket_.get());
  //   socket_->Disconnect();
  //   socket_.reset();
  // }
  task_runner_ = nullptr;
}

net::StreamSocket* P2PSocketHostRpc::socket() const {
  if (!socket_)
    return nullptr;
    
  return socket_->socket();
}

bool P2PSocketHostRpc::InitAccepted(
    net::RpcService* service,
    const net::IPEndPoint& remote_address,
    std::unique_ptr<net::StreamSocket> socket,
    grpc_exec_ctx* exec_ctx, 
    server_state* state,
    grpc_endpoint* tcp,
    grpc_pollset* accepting_pollset,
    grpc_tcp_server_acceptor* acceptor) {
  DCHECK(socket);
  DCHECK_EQ(state_, STATE_UNINITIALIZED);

  remote_address_.ip_address = remote_address;
  socket_.reset(new net::RpcSocket(this, service, id_, std::move(socket)));
  state_ = STATE_OPEN;
  DoHandshake(exec_ctx, state, tcp, accepting_pollset, acceptor);
  return state_ != STATE_ERROR;
}

bool P2PSocketHostRpc::Init(const common::P2PSocketOptions& options) {
  DCHECK_EQ(state_, STATE_UNINITIALIZED);
  remote_address_ = options.remote_address;
  state_ = STATE_CONNECTING;
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(&P2PSocketHostRpc::ConnnectOnIOThread, 
      weak_ptr_factory_.GetWeakPtr(), 
      options,
      base::ThreadTaskRunnerHandle::Get()));
  return true;
}

void P2PSocketHostRpc::ConnnectOnIOThread(const common::P2PSocketOptions& options, scoped_refptr<base::SingleThreadTaskRunner> reply_task_runner) {
  net::HostPortPair dest_host_port_pair;
  // If there is a domain name, let's try it first, it's required by some proxy
  // to only take hostname for CONNECT. If it has been DNS resolved, the result
  // is likely cached and shouldn't cause 2nd DNS resolution in the case of
  // direct connect (i.e. no proxy).
  if (!options.remote_address.hostname.empty()) {
    dest_host_port_pair = net::HostPortPair(options.remote_address.hostname,
                                            options.remote_address.ip_address.port());
  } else {
    DCHECK(!options.remote_address.ip_address.address().empty());
    dest_host_port_pair = net::HostPortPair::FromIPEndPoint(
        options.remote_address.ip_address);
  }

  // TODO(mallinath) - We are ignoring local_address altogether. We should
  // find a way to inject this into ProxyResolvingClientSocket. This could be
  // a problem on multi-homed host.

  // The default SSLConfig is good enough for us for now.
  const net::SSLConfig ssl_config;

  auto socket = proxy_resolving_socket_factory_->CreateSocket(
      ssl_config, GURL("rpc://" + dest_host_port_pair.ToString()),
      false /*use_tls*/);

  socket_.reset(new net::RpcSocket(this, id_, std::move(socket)));

  int status = socket_->Connect(
       base::Bind(&P2PSocketHostRpc::OnConnected,
                  weak_ptr_factory_.GetWeakPtr()));
   if (status != net::ERR_IO_PENDING) {
     DLOG(INFO) << "P2PSocketHostRpc::Init: socket_->Connect != IO_PENDING. calling manually";
  //   // We defer execution of ProcessConnectDone instead of calling it
  //   // directly here as the caller may not expect an error/close to
  //   // happen here.  This is okay, as from the caller's point of view,
  //   // the connect always happens asynchronously.
    //  task_runner_->PostTask(
    //      FROM_HERE, base::BindOnce(&P2PSocketHostRpc::OnConnected,
    //                                base::Unretained(this),
    //                                status));
    OnConnected(status);
  }

  //DLOG(INFO) << "P2PSocketHostRpc::Init: NOT IMPLEMENTED! no remote connection";
}

void P2PSocketHostRpc::DoHandshake(grpc_exec_ctx* exec_ctx, 
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

  // (mumba) force flush: scheduled closures execution
  //grpc_exec_ctx_finish(exec_ctx);
  //if (grpc_exec_ctx_has_work(exec_ctx)) {
  //  gpr_mu_lock(&accepting_pollset->mu);
  //  grpc_exec_ctx_flush(exec_ctx);
  //  gpr_mu_unlock(&accepting_pollset->mu);
  //}
}

void P2PSocketHostRpc::Read() {
  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::DoRead, base::Unretained(this)));
}

void P2PSocketHostRpc::ReceiveRpcMessage(int call_id, int method_type) {
  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::DoReceiveRpcMessage, base::Unretained(this), call_id, method_type));
}

void P2PSocketHostRpc::DoReceiveRpcMessage(int call_id, int method_type) {
  socket_->ReceiveMessage(call_id, method_type);
}

void P2PSocketHostRpc::SendRpcMessage(int call_id, int method_type, std::vector<char> data) {
  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::DoSendRpcMessage,
      base::Unretained(this),
      call_id, 
      method_type,
      base::Passed(std::move(data))));
}

void P2PSocketHostRpc::DoSendRpcMessage(int call_id, int method_type, std::vector<char> data) {
  socket_->SendMessage(call_id, std::move(data), method_type);
}

void P2PSocketHostRpc::SendRpcMessageNow(int call_id, int method_type, std::vector<char> data) {
  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::DoSendRpcMessageNow,
      base::Unretained(this),
      call_id, 
      method_type,
      base::Passed(std::move(data))));
}

void P2PSocketHostRpc::DoSendRpcMessageNow(int call_id, int method_type, std::vector<char> data) {
  socket_->SendMessageNow(call_id, std::move(data), method_type);
}

void P2PSocketHostRpc::SendRpcStatus(int call_id, int status_code) {
  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::DoSendRpcStatus,
      base::Unretained(this),
      call_id, 
      status_code));
}

void P2PSocketHostRpc::DoSendRpcStatus(int call_id, int status_code) {
  socket_->SendRpcStatus(call_id, status_code);
  //socket_->Disconnect();
}

void P2PSocketHostRpc::OnError() {
  socket_.reset();

  if (state_ == STATE_UNINITIALIZED || state_ == STATE_CONNECTING ||
      state_ == STATE_TLS_CONNECTING || state_ == STATE_OPEN) {
    task_runner_->PostTask(FROM_HERE, base::BindOnce(&P2PSocketHostRpc::PostError, base::Unretained(this)));
  }

  state_ = STATE_ERROR;
}

void P2PSocketHostRpc::PostError() {
  message_sender_->Send(new P2PMsg_OnError(id_));
}

void P2PSocketHostRpc::OnConnected(int result) {
  DCHECK_EQ(state_, STATE_CONNECTING);
  DCHECK_NE(result, net::ERR_IO_PENDING);

  if (result != net::OK) {
    LOG(WARNING) << "Error from connecting socket, result=" << result;
    OnError();
    return;
  }
  
  net::IPEndPoint local_address;
  int rc = socket_->GetLocalAddress(&local_address);
  if (rc < 0) {
    LOG(ERROR) << "P2PSocketHostRpc::OnConnected: unable to get local"
               << " address: " << rc;
    OnError();
    return;
  }

  VLOG(1) << "Local address: " << local_address.ToString();

  net::IPEndPoint remote_address;

  // GetPeerAddress returns ERR_NAME_NOT_RESOLVED if the socket is connected
  // through a proxy.
  rc = socket_->GetPeerAddress(&remote_address);
  if (rc < 0 && rc != net::ERR_NAME_NOT_RESOLVED) {
    LOG(ERROR) << "P2PSocketHostRpc::OnConnected: unable to get peer"
               << " address: " << rc;
    OnError();
    return;
  }

  if (!remote_address.address().empty()) {
    VLOG(1) << "Remote address: " << remote_address.ToString();
    if (remote_address_.ip_address.address().empty()) {
      // Save |remote_address| if address is empty.
      remote_address_.ip_address = remote_address;
    }
  } else {
    VLOG(1) << "Remote address is unknown since connection is proxied";
  }

  // if (!task_runner_->RunsTasksInCurrentSequence()) {
  //   DLOG(WARNING) << "not running on task_runner => redirecting";
  //   task_runner_->PostTask(
  //     FROM_HERE,
  //     base::BindOnce(&P2PSocketHostRpc::OnOpen, 
  //                    base::Unretained(this), 
  //                    base::Passed(std::move(local_address)),
  //                    base::Passed(std::move(remote_address))));
  //   return;
  // }

  // if (IsTlsClientSocket(type_)) {
  //   state_ = STATE_TLS_CONNECTING;
  //   StartTls();
  // } else if (IsPseudoTlsClientSocket(type_)) {
  //   std::unique_ptr<net::StreamSocket> transport_socket = std::move(socket_);
  //   socket_.reset(
  //       new jingle_glue::FakeSSLClientSocket(std::move(transport_socket)));
  //   state_ = STATE_TLS_CONNECTING;
  //   int status = socket_->Connect(
  //       base::Bind(&P2PSocketHostRpc::ProcessTlsSslConnectDone,
  //                  base::Unretained(this)));
  //   if (status != net::ERR_IO_PENDING) {
  //     ProcessTlsSslConnectDone(status);
  //   }
  // } else {
    // If we are not doing TLS, we are ready to send data now.
    // In case of TLS, SignalConnect will be sent only after TLS handshake is
    // successful. So no buffering will be done at socket handlers if any
    // packets sent before that by the application.
    OnOpen(std::move(local_address), std::move(remote_address));
  //}
}

void P2PSocketHostRpc::StartTls() {
  DCHECK_EQ(state_, STATE_TLS_CONNECTING);
  DCHECK(socket_.get());

  // std::unique_ptr<net::ClientSocketHandle> socket_handle(
  //     new net::ClientSocketHandle());
  // socket_handle->SetSocket(std::move(socket_));

  // const net::URLRequestContext* url_request_context =
  //     url_context_->GetURLRequestContext();
  // net::SSLClientSocketContext context(
  //     url_request_context->cert_verifier(),
  //     nullptr, /* TODO(rkn): ChannelIDService is not thread safe. */
  //     url_request_context->transport_security_state(),
  //     url_request_context->cert_transparency_verifier(),
  //     url_request_context->ct_policy_enforcer(),
  //     std::string() /* TODO(rsleevi): Ensure a proper unique shard. */);

  // // Default ssl config.
  // const net::SSLConfig ssl_config;
  // net::HostPortPair dest_host_port_pair;

  // // Calling net::HostPortPair::FromIPEndPoint will crash if the IP address is
  // // empty.
  // if (!remote_address_.ip_address.address().empty()) {
  //   net::HostPortPair::FromIPEndPoint(remote_address_.ip_address);
  // } else {
  //   dest_host_port_pair.set_port(remote_address_.ip_address.port());
  // }
  // if (!remote_address_.hostname.empty())
  //   dest_host_port_pair.set_host(remote_address_.hostname);

  // net::ClientSocketFactory* socket_factory =
  //     net::ClientSocketFactory::GetDefaultFactory();
  // DCHECK(socket_factory);

  // socket_ = socket_factory->CreateSSLClientSocket(
  //     std::move(socket_handle), dest_host_port_pair, ssl_config, context);
  // int status = socket_->Connect(
  //     base::Bind(&P2PSocketHostRpc::ProcessTlsSslConnectDone,
  //                base::Unretained(this)));

  // if (status != net::ERR_IO_PENDING) {
  //   ProcessTlsSslConnectDone(status);
  // }
}

void P2PSocketHostRpc::ProcessTlsSslConnectDone(int status) {
  // DCHECK_NE(status, net::ERR_IO_PENDING);
  // DCHECK_EQ(state_, STATE_TLS_CONNECTING);
  // if (status != net::OK) {
  //   LOG(WARNING) << "Error from connecting TLS socket, status=" << status;
  //   OnError();
  //   return;
  // }
  // OnOpen();
}

void P2PSocketHostRpc::OnRpcCallDestroyed(net::RpcSocket* socket, int call_id) {
  // socket_->Disconnect();
  // socket_.reset();
  delegate_->DisposeSocket(this);
}

void P2PSocketHostRpc::OnOpen(net::IPEndPoint local_address, net::IPEndPoint remote_address) {
  state_ = STATE_OPEN;
  // Setting socket send and receive buffer size.
  if (net::OK != socket_->SetReceiveBufferSize(kTcpRecvSocketBufferSize)) {
    LOG(WARNING) << "Failed to set socket receive buffer size to "
                 << kTcpRecvSocketBufferSize;
  }

  if (net::OK != socket_->SetSendBufferSize(kTcpSendSocketBufferSize)) {
    LOG(WARNING) << "Failed to set socket send buffer size to "
                 << kTcpSendSocketBufferSize;
  }

   if (!task_runner_->RunsTasksInCurrentSequence()) {
    DLOG(WARNING) << "not running on task_runner => redirecting";
    task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&P2PSocketHostRpc::DoSendSocketCreateMsg, 
                     base::Unretained(this), 
                     base::Passed(std::move(local_address)),
                     base::Passed(std::move(remote_address))));
  }

  DCHECK_EQ(state_, STATE_OPEN);
  DoRead();
}

void P2PSocketHostRpc::DoSendSocketCreateMsg(net::IPEndPoint local_address, net::IPEndPoint remote_address) {
  // If we are not doing TLS, we are ready to send data now.
  // In case of TLS SignalConnect will be sent only after TLS handshake is
  // successful. So no buffering will be done at socket handlers if any
  // packets sent before that by the application.
  message_sender_->Send(new P2PMsg_OnSocketCreated(
      id_, local_address, remote_address));
}

void P2PSocketHostRpc::DoRead() {
  int result;
  do {
    if (!read_buffer_.get()) {
      read_buffer_ = new net::GrowableIOBuffer();
      read_buffer_->SetCapacity(kTcpReadBufferSize);
    } else if (read_buffer_->RemainingCapacity() < kTcpReadBufferSize) {
      // Make sure that we always have at least kTcpReadBufferSize of
      // remaining capacity in the read buffer. Normally all packets
      // are smaller than kTcpReadBufferSize, so this is not really
      // required.
      read_buffer_->SetCapacity(read_buffer_->capacity() + kTcpReadBufferSize -
                                read_buffer_->RemainingCapacity());
    }
    result = socket_->Read(
        read_buffer_.get(),
        read_buffer_->RemainingCapacity(),
        base::Bind(&P2PSocketHostRpc::OnRead, base::Unretained(this)));
    DidCompleteRead(result);
  } while (result > 0);
}

void P2PSocketHostRpc::OnRead(int result) {
  DidCompleteRead(result);
  if (state_ == STATE_OPEN) {
    DoRead();
  }
}

void P2PSocketHostRpc::DetachFromThread() {
  socket_->DetachFromThread();
}

void P2PSocketHostRpc::OnPacket(const std::vector<char>& data) {
  if (!connected_) {
    //P2PSocketHost::StunMessageType type;
    //bool stun = GetStunPacketType(&*data.begin(), data.size(), &type);
    //if (stun && IsRequestOrResponse(type)) {
    connected_ = true;
    //} else if (!stun || type == STUN_DATA_INDICATION) {
    //  LOG(ERROR) << "Received unexpected data packet from "
    //             << remote_address_.ip_address.ToString()
    //             << " before STUN binding is finished. "
    //             << "Terminating connection.";
    //  OnError();
    //  return;
  //  }
  }
  
  message_sender_->Send(new P2PMsg_OnDataReceived(
      id_, remote_address_.ip_address, data, base::TimeTicks::Now()));

  if (dump_incoming_rtp_packet_)
    DumpRtpPacket(&data[0], data.size(), true);
}

// Note: dscp is not actually used on TCP sockets as this point,
// but may be honored in the future.
void P2PSocketHostRpc::Send(
    const net::IPEndPoint& to,
    const std::vector<char>& data,
    const rtc::PacketOptions& options,
    uint64_t packet_id,
    const net::NetworkTrafficAnnotationTag traffic_annotation) {
  if (!socket_) {
    // The Send message may be sent after the an OnError message was
    // sent by hasn't been processed the renderer.
    return;
  }

  //if (!(to == remote_address_.ip_address)) {
    // Renderer should use this socket only to send data to |remote_address_|.
 //   NOTREACHED();
 //   OnError();
 //   return;
 // }

  //if (!connected_) {
  //  P2PSocketHost::StunMessageType type = P2PSocketHost::StunMessageType();
  //  bool stun = GetStunPacketType(&*data.begin(), data.size(), &type);
   // if (!stun || type == STUN_DATA_INDICATION) {
    //  LOG(ERROR) << "Page tried to send a data packet to " << to.ToString()
     //            << " before STUN binding is finished.";
    //  OnError();
   //   return;
   // }
  //}
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(&P2PSocketHostRpc::DoSend, weak_ptr_factory_.GetWeakPtr(), data, options, traffic_annotation));
}

void P2PSocketHostRpc::WriteOrQueue(SendBuffer& send_buffer) {
  IncrementTotalSentPackets();
  if (write_buffer_.buffer.get()) {
    write_queue_.push(send_buffer);
    IncrementDelayedPackets();
    IncrementDelayedBytes(send_buffer.buffer->size());
    return;
  }

  write_buffer_ = send_buffer;
  DoWrite();
}

void P2PSocketHostRpc::DoWrite() {
  while (write_buffer_.buffer.get() && state_ == STATE_OPEN &&
         !write_pending_) {
    int result = socket_->Write(
        write_buffer_.buffer.get(), write_buffer_.buffer->BytesRemaining(),
        base::Bind(&P2PSocketHostRpc::OnWritten, base::Unretained(this)),
        net::NetworkTrafficAnnotationTag(write_buffer_.traffic_annotation));
    HandleWriteResult(result);
  }
}

void P2PSocketHostRpc::OnWritten(int result) {
  DCHECK(write_pending_);
  DCHECK_NE(result, net::ERR_IO_PENDING);

  write_pending_ = false;
  HandleWriteResult(result);
  DoWrite();
}

void P2PSocketHostRpc::HandleWriteResult(int result) {
  DCHECK(write_buffer_.buffer.get());
  if (result >= 0) {
    write_buffer_.buffer->DidConsume(result);
    if (write_buffer_.buffer->BytesRemaining() == 0) {
      base::TimeTicks send_time = base::TimeTicks::Now();
      task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&P2PSocketHostRpc::PostSendComplete, base::Unretained(this), send_time));
      if (write_queue_.empty()) {
        write_buffer_.buffer = nullptr;
        write_buffer_.rtc_packet_id = -1;
      } else {
        write_buffer_ = write_queue_.front();
        write_queue_.pop();
        // Update how many bytes are still waiting to be sent.
        DecrementDelayedBytes(write_buffer_.buffer->size());
      }
    }
  } else if (result == net::ERR_IO_PENDING) {
    write_pending_ = true;
  } else {
    ReportSocketError(result, "WebRTC.ICE.TcpSocketWriteErrorCode");

    LOG(ERROR) << "Error when sending data in TCP socket: " << result;
    OnError();
  }
}

void P2PSocketHostRpc::PostSendComplete(const base::TimeTicks& send_time) {
  message_sender_->Send(new P2PMsg_OnSendComplete(
    id_,
    common::P2PSendPacketMetrics(0, write_buffer_.rtc_packet_id, send_time)));
}

std::unique_ptr<P2PSocketHost>
P2PSocketHostRpc::AcceptIncomingTcpConnection(
    const net::IPEndPoint& remote_address) {
  NOTREACHED();
  OnError();
  return nullptr;
}

void P2PSocketHostRpc::DidCompleteRead(int result) {
  DCHECK_EQ(state_, STATE_OPEN);
  if (result == net::ERR_IO_PENDING) {
    return;
  } else if (result < 0) {
    LOG(ERROR) << "Error when reading from TCP socket: " << result;
    OnError();
    return;
  } else if (result == 0) {
    LOG(WARNING) << "Remote peer has shutdown TCP socket. TODO: pass a int code";
    OnError();
    return;
  }

  read_buffer_->set_offset(read_buffer_->offset() + result);
  char* head = read_buffer_->StartOfBuffer();  // Purely a convenience.
  int pos = 0;
  while (pos <= read_buffer_->offset() && state_ == STATE_OPEN) {
    int consumed = ProcessInput(head + pos, read_buffer_->offset() - pos);
    if (!consumed)
      break;
    pos += consumed;
  }
  // We've consumed all complete packets from the buffer; now move any remaining
  // bytes to the head of the buffer and set offset to reflect this.
  if (pos && pos <= read_buffer_->offset()) {
    memmove(head, head + pos, read_buffer_->offset() - pos);
    read_buffer_->set_offset(read_buffer_->offset() - pos);
  }
}

bool P2PSocketHostRpc::SetOption(common::P2PSocketOption option, int value) {
  if (state_ != STATE_OPEN) {
    DCHECK_EQ(state_, STATE_ERROR);
    return false;
  }

  switch (option) {
    case common::P2P_SOCKET_OPT_RCVBUF:
      return socket_->SetReceiveBufferSize(value) == net::OK;
    case common::P2P_SOCKET_OPT_SNDBUF:
      return socket_->SetSendBufferSize(value) == net::OK;
    case common::P2P_SOCKET_OPT_DSCP:
      return false;  // For TCP sockets DSCP setting is not available.
    default:
      NOTREACHED();
      return false;
  }
}

int P2PSocketHostRpc::ProcessInput(char* input, int input_len) {
  //if (input_len < kPacketHeaderSize)
  //  return 0;
  //int packet_size = base::NetToHost16(*reinterpret_cast<uint16_t*>(input));
  //if (input_len < packet_size + kPacketHeaderSize)
  //  return 0;

  //int consumed = kPacketHeaderSize;
  //char* cur = input + consumed;
  std::vector<char> data(input, input + input_len);//(cur, cur + packet_size);

  task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&P2PSocketHostRpc::OnPacket,
      base::Unretained(this),
      base::Passed(std::move(data))));
  //OnPacket(data);
  //consumed += packet_size;
  return input_len;//consumed;
}

void P2PSocketHostRpc::DoSend(
    //const net::IPEndPoint& to,
    const std::vector<char>& data,
    const rtc::PacketOptions& options,
    const net::NetworkTrafficAnnotationTag traffic_annotation) {
  int size = data.size();//kPacketHeaderSize + data.size();
  SendBuffer send_buffer(
      options.packet_id,
      new net::DrainableIOBuffer(new net::IOBuffer(size), size),
      traffic_annotation);
  //*reinterpret_cast<uint16_t*>(send_buffer.buffer->data()) =
  //    base::HostToNet16(data.size());
  memcpy(send_buffer.buffer->data(), &data[0], data.size());

  cricket::ApplyPacketOptions(
      reinterpret_cast<uint8_t*>(send_buffer.buffer->data()), //+
    //      kPacketHeaderSize,
      send_buffer.buffer->BytesRemaining(), //- kPacketHeaderSize,
      options.packet_time_params,
      (base::TimeTicks::Now() - base::TimeTicks()).InMicroseconds());

  WriteOrQueue(send_buffer);
}

}  // namespace host
