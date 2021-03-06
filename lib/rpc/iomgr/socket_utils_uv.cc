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

#include "rpc/iomgr/port.h"

#ifdef GRPC_UV

#include <uv.h>

#include "rpc/iomgr/socket_utils.h"

#include <rpc/support/log.h>

const char* grpc_inet_ntop(int af, const void* src, char* dst, size_t size) {
  uv_inet_ntop(af, src, dst, size);
  return dst;
}

#endif /* GRPC_UV */
