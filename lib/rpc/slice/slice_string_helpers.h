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

#ifndef GRPC_CORE_LIB_SLICE_SLICE_STRING_HELPERS_H
#define GRPC_CORE_LIB_SLICE_SLICE_STRING_HELPERS_H

#include <stdbool.h>
#include <stddef.h>

#include <rpc/slice.h>
#include <rpc/slice_buffer.h>
#include <rpc/support/port_platform.h>

#include "rpc/support/string.h"

/* Calls gpr_dump on a slice. */
char* grpc_dump_slice(grpc_slice slice, uint32_t flags);

/** Split \a str by the separator \a sep. Results are stored in \a dst, which
 * should be a properly initialized instance. */
void grpc_slice_split(grpc_slice str, const char* sep, grpc_slice_buffer* dst);

bool grpc_parse_slice_to_uint32(grpc_slice str, uint32_t* result);

#endif /* GRPC_CORE_LIB_SLICE_SLICE_STRING_HELPERS_H */
