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

#ifndef GRPC_CORE_LIB_SECURITY_TRANSPORT_SECURITY_HANDSHAKER_H
#define GRPC_CORE_LIB_SECURITY_TRANSPORT_SECURITY_HANDSHAKER_H

#include "rpc/channel/handshaker.h"
#include "rpc/iomgr/exec_ctx.h"
#include "rpc/security/transport/security_connector.h"

/// Creates a security handshaker using \a handshaker.
grpc_handshaker* grpc_security_handshaker_create(
    grpc_exec_ctx* exec_ctx, tsi_handshaker* handshaker,
    grpc_security_connector* connector);

/// Registers security handshaker factories.
void grpc_security_register_handshaker_factories();

#endif /* GRPC_CORE_LIB_SECURITY_TRANSPORT_SECURITY_HANDSHAKER_H */
