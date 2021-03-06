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
#include <rpc/support/string_util.h>

#include "rpc/ext/filters/client_channel/client_channel.h"
#include "rpc/ext/filters/client_channel/resolver_registry.h"
#include "rpc/ext/transport/chttp2/client/chttp2_connector.h"
#include "rpc/channel/channel_args.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/channel.h"

static void client_channel_factory_ref(
    grpc_client_channel_factory* cc_factory) {}

static void client_channel_factory_unref(
    grpc_exec_ctx* exec_ctx, grpc_client_channel_factory* cc_factory) {}

static grpc_subchannel* client_channel_factory_create_subchannel(
    grpc_exec_ctx* exec_ctx, grpc_client_channel_factory* cc_factory,
    const grpc_subchannel_args* args) {
  grpc_connector* connector = grpc_chttp2_connector_create();
  grpc_subchannel* s = grpc_subchannel_create(exec_ctx, connector, args);
  grpc_connector_unref(exec_ctx, connector);
  return s;
}

static grpc_channel* client_channel_factory_create_channel(
    grpc_exec_ctx* exec_ctx, grpc_client_channel_factory* cc_factory,
    const char* target, grpc_client_channel_type type,
    const grpc_channel_args* args) {
  if (target == nullptr) {
    gpr_log(GPR_ERROR, "cannot create channel with NULL target name");
    return nullptr;
  }
  // Add channel arg containing the server URI.
  grpc_arg arg = grpc_channel_arg_string_create(
      (char*)GRPC_ARG_SERVER_URI,
      grpc_resolver_factory_add_default_prefix_if_needed(exec_ctx, target));
  const char* to_remove[] = {GRPC_ARG_SERVER_URI};
  grpc_channel_args* new_args =
      grpc_channel_args_copy_and_add_and_remove(args, to_remove, 1, &arg, 1);
  gpr_free(arg.value.string);
  grpc_channel* channel = grpc_channel_create(exec_ctx, target, new_args,
                                              GRPC_CLIENT_CHANNEL, nullptr);
  grpc_channel_args_destroy(exec_ctx, new_args);
  return channel;
}

static const grpc_client_channel_factory_vtable client_channel_factory_vtable =
    {client_channel_factory_ref, client_channel_factory_unref,
     client_channel_factory_create_subchannel,
     client_channel_factory_create_channel};

static grpc_client_channel_factory client_channel_factory = {
    &client_channel_factory_vtable};

/* Create a client channel:
   Asynchronously: - resolve target
                   - connect to it (trying alternatives as presented)
                   - perform handshakes */
grpc_channel* grpc_insecure_channel_create(const char* target,
                                           const grpc_channel_args* args,
                                           void* reserved) {
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  GRPC_API_TRACE(
      "grpc_insecure_channel_create(target=%s, args=%p, reserved=%p)", 3,
      (target, args, reserved));
  GPR_ASSERT(reserved == nullptr);
  // Add channel arg containing the client channel factory.
  grpc_arg arg =
      grpc_client_channel_factory_create_channel_arg(&client_channel_factory);
  grpc_channel_args* new_args = grpc_channel_args_copy_and_add(args, &arg, 1);
  // Create channel.
  grpc_channel* channel = client_channel_factory_create_channel(
      &exec_ctx, &client_channel_factory, target,
      GRPC_CLIENT_CHANNEL_TYPE_REGULAR, new_args);
  // Clean up.
  grpc_channel_args_destroy(&exec_ctx, new_args);
  grpc_exec_ctx_finish(&exec_ctx);
  return channel != nullptr ? channel
                            : grpc_lame_client_channel_create(
                                  target, GRPC_STATUS_INTERNAL,
                                  "Failed to create client channel");
}
