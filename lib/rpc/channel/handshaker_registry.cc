/*
 *
 * Copyright 2016 gRPC authors.
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

#include "rpc/channel/handshaker_registry.h"

#include <string.h>

#include <rpc/support/alloc.h>

//
// grpc_handshaker_factory_list
//

typedef struct {
  grpc_handshaker_factory** list;
  size_t num_factories;
} grpc_handshaker_factory_list;

static void grpc_handshaker_factory_list_register(
    grpc_handshaker_factory_list* list, bool at_start,
    grpc_handshaker_factory* factory) {
  list->list = (grpc_handshaker_factory**)gpr_realloc(
      list->list, (list->num_factories + 1) * sizeof(grpc_handshaker_factory*));
  if (at_start) {
    memmove(list->list + 1, list->list,
            sizeof(grpc_handshaker_factory*) * list->num_factories);
    list->list[0] = factory;
  } else {
    list->list[list->num_factories] = factory;
  }
  ++list->num_factories;
}

static void grpc_handshaker_factory_list_add_handshakers(
    grpc_exec_ctx* exec_ctx, grpc_handshaker_factory_list* list,
    const grpc_channel_args* args, grpc_handshake_manager* handshake_mgr) {
  for (size_t i = 0; i < list->num_factories; ++i) {
    grpc_handshaker_factory_add_handshakers(exec_ctx, list->list[i], args,
                                            handshake_mgr);
  }
}

static void grpc_handshaker_factory_list_destroy(
    grpc_exec_ctx* exec_ctx, grpc_handshaker_factory_list* list) {
  for (size_t i = 0; i < list->num_factories; ++i) {
    grpc_handshaker_factory_destroy(exec_ctx, list->list[i]);
  }
  gpr_free(list->list);
}

//
// plugin
//

static grpc_handshaker_factory_list
    g_handshaker_factory_lists[NUM_HANDSHAKER_TYPES];

void grpc_handshaker_factory_registry_init() {
  memset(g_handshaker_factory_lists, 0, sizeof(g_handshaker_factory_lists));
}

void grpc_handshaker_factory_registry_shutdown(grpc_exec_ctx* exec_ctx) {
  for (size_t i = 0; i < NUM_HANDSHAKER_TYPES; ++i) {
    grpc_handshaker_factory_list_destroy(exec_ctx,
                                         &g_handshaker_factory_lists[i]);
  }
}

void grpc_handshaker_factory_register(bool at_start,
                                      grpc_handshaker_type handshaker_type,
                                      grpc_handshaker_factory* factory) {
  grpc_handshaker_factory_list_register(
      &g_handshaker_factory_lists[handshaker_type], at_start, factory);
}

void grpc_handshakers_add(grpc_exec_ctx* exec_ctx,
                          grpc_handshaker_type handshaker_type,
                          const grpc_channel_args* args,
                          grpc_handshake_manager* handshake_mgr) {
  grpc_handshaker_factory_list_add_handshakers(
      exec_ctx, &g_handshaker_factory_lists[handshaker_type], args,
      handshake_mgr);
}
