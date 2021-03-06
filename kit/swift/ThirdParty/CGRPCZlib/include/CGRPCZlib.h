/*
 * Copyright 2020, gRPC Authors All rights reserved.
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
 */
#ifndef C_GRPC_ZLIB_H_
#define C_GRPC_ZLIB_H_

#include "globals.h"
#include "third_party/zlib/zlib.h"

EXPORT int CGRPCZlib_deflateInit2(z_streamp stream, int level, int method, int windowBits, int memLevel, int strategy);
EXPORT unsigned long CGRPCZlib_deflateBound(z_streamp strm, unsigned long sourceLen);
EXPORT int CGRPCZlib_deflate(z_streamp strm, int flush);
EXPORT int CGRPCZlib_deflateReset(z_streamp strm);
EXPORT int CGRPCZlib_deflateEnd(z_streamp strm);
EXPORT int CGRPCZlib_inflateInit2(z_streamp stream, int windowBits);
EXPORT int CGRPCZlib_inflate(z_streamp strm, int flush);
EXPORT int CGRPCZlib_inflateReset(z_streamp strm);
EXPORT int CGRPCZlib_inflateEnd(z_streamp strm);
EXPORT Bytef *CGRPCZlib_castVoidToBytefPointer(void *in);

#endif  // C_GRPC_ZLIB_H_
