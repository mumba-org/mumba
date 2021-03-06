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

#ifndef GRPC_CORE_LIB_IOMGR_TCP_SERVER_H
#define GRPC_CORE_LIB_IOMGR_TCP_SERVER_H

#include <rpc/grpc.h>

#include "rpc/iomgr/closure.h"
#include "rpc/iomgr/endpoint.h"
#include "rpc/iomgr/resolve_address.h"
#include <rpc/impl/codegen/port_platform.h>

/* Forward decl of grpc_tcp_server */
typedef struct grpc_tcp_server grpc_tcp_server;

typedef struct grpc_tcp_server_acceptor {
  /* grpc_tcp_server_cb functions share a ref on from_server that is valid
     until the function returns. */
  grpc_tcp_server* from_server;
  /* Indices that may be passed to grpc_tcp_server_port_fd(). */
  unsigned port_index;
  unsigned fd_index;
} grpc_tcp_server_acceptor;

/* Called for newly connected TCP connections.
   Takes ownership of acceptor. */
typedef void (*grpc_tcp_server_cb)(grpc_exec_ctx* exec_ctx, void* arg,
                                   grpc_endpoint* ep,
                                   grpc_pollset* accepting_pollset,
                                   grpc_tcp_server_acceptor* acceptor);

/* Create a server, initially not bound to any ports. The caller owns one ref.
   If shutdown_complete is not NULL, it will be used by
   grpc_tcp_server_unref() when the ref count reaches zero. */
GRPCAPI grpc_error* grpc_tcp_server_create(void* state, grpc_exec_ctx* exec_ctx,
                                   grpc_closure* shutdown_complete,
                                   const grpc_channel_args* args,
                                   grpc_tcp_server** server);

/* Start listening to bound ports */
GRPCAPI void grpc_tcp_server_start(grpc_exec_ctx* exec_ctx, grpc_tcp_server* server,
                           grpc_pollset** pollsets, size_t pollset_count,
                           void* state,
                           void (*read_cb) (grpc_exec_ctx*, void*, grpc_error*),
                           void* cb_arg);

/* Add a port to the server, returning the newly allocated port on success, or
   -1 on failure.

   The :: and 0.0.0.0 wildcard addresses are treated identically, accepting
   both IPv4 and IPv6 connections, but :: is the preferred style.  This usually
   creates one socket, but possibly two on systems which support IPv6,
   but not dualstack sockets. */
/* TODO(ctiller): deprecate this, and make grpc_tcp_server_add_ports to handle
                  all of the multiple socket port matching logic in one place */
GRPCAPI grpc_error* grpc_tcp_server_add_port(grpc_tcp_server* s,
                                     const grpc_resolved_address* addr,
                                     int* out_port);

/* Number of fds at the given port_index, or 0 if port_index is out of
   bounds. */
GRPCAPI unsigned grpc_tcp_server_port_fd_count(grpc_tcp_server* s, unsigned port_index);

/* Returns the file descriptor of the Mth (fd_index) listening socket of the Nth
   (port_index) call to add_port() on this server, or -1 if the indices are out
   of bounds. The file descriptor remains owned by the server, and will be
   cleaned up when the ref count reaches zero. */
GRPCAPI int grpc_tcp_server_port_fd(grpc_tcp_server* s, unsigned port_index,
                            unsigned fd_index);

/* Ref s and return s. */
GRPCAPI grpc_tcp_server* grpc_tcp_server_ref(grpc_tcp_server* s);

/* shutdown_starting is called when ref count has reached zero and the server is
   about to be destroyed. The server will be deleted after it returns. Calling
   grpc_tcp_server_ref() from it has no effect. */
GRPCAPI void grpc_tcp_server_shutdown_starting_add(grpc_tcp_server* s,
                                           grpc_closure* shutdown_starting);

/* If the refcount drops to zero, enqueue calls on exec_ctx to
   shutdown_listeners and delete s. */
GRPCAPI void grpc_tcp_server_unref(grpc_exec_ctx* exec_ctx, grpc_tcp_server* s);

/* Shutdown the fds of listeners. */
GRPCAPI void grpc_tcp_server_shutdown_listeners(grpc_exec_ctx* exec_ctx,
                                        grpc_tcp_server* s);

#endif /* GRPC_CORE_LIB_IOMGR_TCP_SERVER_H */
