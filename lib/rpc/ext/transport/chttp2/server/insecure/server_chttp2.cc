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

#include <rpc/grpc.h>

#include <rpc/support/log.h>

#include "rpc/ext/transport/chttp2/server/chttp2_server.h"
#include "rpc/channel/channel_args.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/server.h"

int grpc_server_add_insecure_http2_port(
  grpc_server* server, 
  const char* addr, 
  void* state,
  void (*read_cb)(grpc_exec_ctx*, void*, grpc_error*)) {
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  int port_num = 0;
  GRPC_API_TRACE("grpc_server_add_insecure_http2_port(server=%p, addr=%s)", 2,
                 (server, addr));
  grpc_error* err = grpc_chttp2_server_add_port(
      state,
      &exec_ctx, server, addr,
      grpc_channel_args_copy(grpc_server_get_channel_args(server)), 
      read_cb,
      &port_num);
  if (err != GRPC_ERROR_NONE) {
    const char* msg = grpc_error_string(err);
    gpr_log(GPR_ERROR, "%s", msg);

    GRPC_ERROR_UNREF(err);
  }
  grpc_exec_ctx_finish(&exec_ctx);
  return port_num;
}
