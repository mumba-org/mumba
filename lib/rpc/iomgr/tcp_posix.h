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

#ifndef GRPC_CORE_LIB_IOMGR_TCP_POSIX_H
#define GRPC_CORE_LIB_IOMGR_TCP_POSIX_H
/*
   Low level TCP "bottom half" implementation, for use by transports built on
   top of a TCP connection.

   Note that this file does not (yet) include APIs for creating the socket in
   the first place.

   All calls passing slice transfer ownership of a slice refcount unless
   otherwise specified.
*/

#include "rpc/debug/trace.h"
#include "rpc/iomgr/endpoint.h"
#include "rpc/iomgr/ev_posix.h"

extern grpc_core::TraceFlag grpc_tcp_trace;

/* Create a tcp endpoint given a file desciptor and a read slice size.
   Takes ownership of fd. */
GRPCAPI grpc_endpoint* grpc_tcp_create(grpc_exec_ctx* exec_ctx, grpc_fd* fd,
                               const grpc_channel_args* args,
                               const char* peer_string);

/* Return the tcp endpoint's fd, or -1 if this is not available. Does not
   release the fd.
   Requires: ep must be a tcp endpoint.
 */
GRPCAPI int grpc_tcp_fd(grpc_endpoint* ep);

/* Destroy the tcp endpoint without closing its fd. *fd will be set and done
 * will be called when the endpoint is destroyed.
 * Requires: ep must be a tcp endpoint and fd must not be NULL. */
GRPCAPI void grpc_tcp_destroy_and_release_fd(grpc_exec_ctx* exec_ctx, grpc_endpoint* ep,
                                     int* fd, grpc_closure* done);

#endif /* GRPC_CORE_LIB_IOMGR_TCP_POSIX_H */
