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

/* This header transitively includes other headers that care about include
 * order, so it should be included first. As a consequence, it should not be
 * included in any other header. */

#ifndef GRPC_CORE_LIB_IOMGR_SOCKADDR_H
#define GRPC_CORE_LIB_IOMGR_SOCKADDR_H

#include "rpc/iomgr/port.h"

#ifdef GRPC_UV
#include <uv.h>
#endif

#ifdef GPR_WINDOWS
#include "rpc/iomgr/sockaddr_windows.h"
#endif

#ifdef GRPC_POSIX_SOCKETADDR
#include "rpc/iomgr/sockaddr_posix.h"
#endif

#endif /* GRPC_CORE_LIB_IOMGR_SOCKADDR_H */
