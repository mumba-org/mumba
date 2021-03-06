/*
 *
 * Copyright 2017 gRPC authors.
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

#include <rpc/support/alloc.h>
#include <rpc/support/string_util.h>

#include "rpc/ext/filters/client_channel/client_channel.h"
#include "rpc/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.h"
#include "rpc/channel/channel_args.h"
#include "rpc/iomgr/sockaddr_utils.h"
#include "rpc/security/credentials/credentials.h"
#include "rpc/security/transport/lb_targets_info.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/support/string.h"

grpc_channel* grpc_lb_policy_grpclb_create_lb_channel(
    grpc_exec_ctx* exec_ctx, const char* lb_service_target_addresses,
    grpc_client_channel_factory* client_channel_factory,
    grpc_channel_args* args) {
  grpc_channel_args* new_args = args;
  grpc_channel_credentials* channel_credentials =
      grpc_channel_credentials_find_in_args(args);
  if (channel_credentials != nullptr) {
    /* Substitute the channel credentials with a version without call
     * credentials: the load balancer is not necessarily trusted to handle
     * bearer token credentials */
    static const char* keys_to_remove[] = {GRPC_ARG_CHANNEL_CREDENTIALS};
    grpc_channel_credentials* creds_sans_call_creds =
        grpc_channel_credentials_duplicate_without_call_credentials(
            channel_credentials);
    GPR_ASSERT(creds_sans_call_creds != nullptr);
    grpc_arg args_to_add[] = {
        grpc_channel_credentials_to_arg(creds_sans_call_creds)};
    /* Create the new set of channel args */
    new_args = grpc_channel_args_copy_and_add_and_remove(
        args, keys_to_remove, GPR_ARRAY_SIZE(keys_to_remove), args_to_add,
        GPR_ARRAY_SIZE(args_to_add));
    grpc_channel_credentials_unref(exec_ctx, creds_sans_call_creds);
  }
  grpc_channel* lb_channel = grpc_client_channel_factory_create_channel(
      exec_ctx, client_channel_factory, lb_service_target_addresses,
      GRPC_CLIENT_CHANNEL_TYPE_LOAD_BALANCING, new_args);
  if (channel_credentials != nullptr) {
    grpc_channel_args_destroy(exec_ctx, new_args);
  }
  return lb_channel;
}

grpc_channel_args* grpc_lb_policy_grpclb_build_lb_channel_args(
    grpc_exec_ctx* exec_ctx, grpc_slice_hash_table* targets_info,
    grpc_fake_resolver_response_generator* response_generator,
    const grpc_channel_args* args) {
  const grpc_arg to_add[] = {
      grpc_lb_targets_info_create_channel_arg(targets_info),
      grpc_fake_resolver_response_generator_arg(response_generator)};
  /* We remove:
   *
   * - The channel arg for the LB policy name, since we want to use the default
   *   (pick_first) in this case.
   *
   * - The channel arg for the resolved addresses, since that will be generated
   *   by the name resolver used in the LB channel.  Note that the LB channel
   *   will use the fake resolver, so this won't actually generate a query
   *   to DNS (or some other name service).  However, the addresses returned by
   *   the fake resolver will have is_balancer=false, whereas our own
   *   addresses have is_balancer=true.  We need the LB channel to return
   *   addresses with is_balancer=false so that it does not wind up recursively
   *   using the grpclb LB policy, as per the special case logic in
   *   client_channel.c.
   *
   * - The channel arg for the server URI, since that will be different for the
   *   LB channel than for the parent channel (the client channel factory will
   *   re-add this arg with the right value).
   *
   * - The fake resolver generator, because we are replacing it with the one
   *   from the grpclb policy, used to propagate updates to the LB channel. */
  static const char* keys_to_remove[] = {
      GRPC_ARG_LB_POLICY_NAME, GRPC_ARG_LB_ADDRESSES, GRPC_ARG_SERVER_URI,
      GRPC_ARG_FAKE_RESOLVER_RESPONSE_GENERATOR};
  /* Add the targets info table to be used for secure naming */
  return grpc_channel_args_copy_and_add_and_remove(
      args, keys_to_remove, GPR_ARRAY_SIZE(keys_to_remove), to_add,
      GPR_ARRAY_SIZE(to_add));
}
