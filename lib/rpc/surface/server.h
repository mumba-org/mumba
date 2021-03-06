/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPC_CORE_LIB_SURFACE_SERVER_H
#define GRPC_CORE_LIB_SURFACE_SERVER_H

#include <rpc/grpc.h>
#include "rpc/channel/channel_stack.h"
#include "rpc/debug/trace.h"
#include "rpc/transport/transport.h"

extern const grpc_channel_filter grpc_server_top_filter;

/** Lightweight tracing of server channel state */
extern grpc_core::TraceFlag grpc_server_channel_trace;

/* Add a listener to the server: when the server starts, it will call start,
   and when it shuts down, it will call destroy */
GRPCAPI void grpc_server_add_listener(
    grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
    void (*read_cb)(grpc_exec_ctx*, void*, grpc_error*),
    void (*start)(void (*)(grpc_exec_ctx*, void*, grpc_error*),
                  grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
                  grpc_pollset** pollsets, size_t npollsets),
    void(*destroy)(grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg, grpc_closure* on_done));

/* Setup a transport - creates a channel stack, binds the transport to the
   server */
GRPCAPI void grpc_server_setup_transport(grpc_exec_ctx* exec_ctx, grpc_server* server,
                                 grpc_transport* transport,
                                 grpc_pollset* accepting_pollset,
                                 const grpc_channel_args* args);

GRPCAPI const grpc_channel_args* grpc_server_get_channel_args(grpc_server* server);

GRPCAPI int grpc_server_has_open_connections(grpc_server* server);

/* Do not call this before grpc_server_start. Returns the pollsets and the
 * number of pollsets via 'pollsets' and 'pollset_count'. */
GRPCAPI void grpc_server_get_pollsets(grpc_server* server, grpc_pollset*** pollsets,
                              size_t* pollset_count);

#endif /* GRPC_CORE_LIB_SURFACE_SERVER_H */
