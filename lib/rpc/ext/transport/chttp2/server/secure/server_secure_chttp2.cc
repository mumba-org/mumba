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

#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>

#include "rpc/ext/transport/chttp2/server/chttp2_server.h"

#include "rpc/ext/transport/chttp2/transport/chttp2_transport.h"
#include "rpc/channel/channel_args.h"
#include "rpc/channel/handshaker.h"
#include "rpc/security/context/security_context.h"
#include "rpc/security/credentials/credentials.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/server.h"

int grpc_server_add_secure_http2_port(grpc_server* server, const char* addr,
                                      grpc_server_credentials* creds,
                                      void* state,
                                      void (*read_cb)(grpc_exec_ctx*, void*, grpc_error*)) {
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  grpc_error* err = GRPC_ERROR_NONE;
  grpc_server_security_connector* sc = nullptr;
  int port_num = 0;
  grpc_security_status status;
  grpc_channel_args* args = nullptr;
  GRPC_API_TRACE(
      "grpc_server_add_secure_http2_port("
      "server=%p, addr=%s, creds=%p)",
      3, (server, addr, creds));
  // Create security context.
  if (creds == nullptr) {
    err = GRPC_ERROR_CREATE_FROM_STATIC_STRING(
        "No credentials specified for secure server port (creds==NULL)");
    goto done;
  }
  status =
      grpc_server_credentials_create_security_connector(&exec_ctx, creds, &sc);
  if (status != GRPC_SECURITY_OK) {
    char* msg;
    gpr_asprintf(&msg,
                 "Unable to create secure server with credentials of type %s.",
                 creds->type);
    err = grpc_error_set_int(GRPC_ERROR_CREATE_FROM_COPIED_STRING(msg),
                             GRPC_ERROR_INT_SECURITY_STATUS, status);
    gpr_free(msg);
    goto done;
  }
  // Create channel args.
  grpc_arg args_to_add[2];
  args_to_add[0] = grpc_server_credentials_to_arg(creds);
  args_to_add[1] = grpc_security_connector_to_arg(&sc->base);
  args =
      grpc_channel_args_copy_and_add(grpc_server_get_channel_args(server),
                                     args_to_add, GPR_ARRAY_SIZE(args_to_add));
  // Add server port.
  err = grpc_chttp2_server_add_port(state, &exec_ctx, server, addr, args, read_cb, &port_num);
done:
  if (sc != nullptr) {
    GRPC_SECURITY_CONNECTOR_UNREF(&exec_ctx, &sc->base, "server");
  }
  grpc_exec_ctx_finish(&exec_ctx);
  if (err != GRPC_ERROR_NONE) {
    const char* msg = grpc_error_string(err);
    gpr_log(GPR_ERROR, "%s", msg);

    GRPC_ERROR_UNREF(err);
  }
  return port_num;
}
