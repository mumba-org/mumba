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

#ifndef GRPC_CORE_LIB_CHANNEL_HANDSHAKER_REGISTRY_H
#define GRPC_CORE_LIB_CHANNEL_HANDSHAKER_REGISTRY_H

#include <rpc/impl/codegen/grpc_types.h>

#include "rpc/channel/handshaker_factory.h"
#include "rpc/iomgr/exec_ctx.h"

typedef enum {
  HANDSHAKER_CLIENT = 0,
  HANDSHAKER_SERVER,
  NUM_HANDSHAKER_TYPES,  // Must be last.
} grpc_handshaker_type;

void GRPCAPI grpc_handshaker_factory_registry_init();
void GRPCAPI grpc_handshaker_factory_registry_shutdown(grpc_exec_ctx* exec_ctx);

/// Registers a new handshaker factory.  Takes ownership.
/// If \a at_start is true, the new handshaker will be at the beginning of
/// the list.  Otherwise, it will be added to the end.
void GRPCAPI grpc_handshaker_factory_register(bool at_start,
                                      grpc_handshaker_type handshaker_type,
                                      grpc_handshaker_factory* factory);

void GRPCAPI grpc_handshakers_add(grpc_exec_ctx* exec_ctx,
                          grpc_handshaker_type handshaker_type,
                          const grpc_channel_args* args,
                          grpc_handshake_manager* handshake_mgr);

#endif /* GRPC_CORE_LIB_CHANNEL_HANDSHAKER_REGISTRY_H */
