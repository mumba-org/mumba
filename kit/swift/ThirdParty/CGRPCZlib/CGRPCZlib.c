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

#include "kit/swift/ThirdParty/CGRPCZlib/include/CGRPCZlib.h"
#include "third_party/zlib/zlib.h"

int CGRPCZlib_deflateInit2(z_streamp stream, int level, int method, int windowBits,
                                         int memLevel, int strategy) {
  return deflateInit2(stream, level, method, windowBits, memLevel, strategy);
}

unsigned long CGRPCZlib_deflateBound(z_streamp strm, unsigned long sourceLen) {
  return deflateBound(strm, sourceLen);
}

int CGRPCZlib_deflate(z_streamp strm, int flush) {
  return deflate(strm, flush);
}

int CGRPCZlib_deflateReset(z_streamp strm) {
  return deflateReset(strm);
}

int CGRPCZlib_deflateEnd(z_streamp strm) {
  return deflateEnd(strm);
}

int CGRPCZlib_inflateInit2(z_streamp stream, int windowBits) {
  return inflateInit2(stream, windowBits);
}

int CGRPCZlib_inflate(z_streamp strm, int flush) {
  return inflate(strm, flush);
}

int CGRPCZlib_inflateReset(z_streamp strm) {
  return inflateReset(strm);
}

int CGRPCZlib_inflateEnd(z_streamp strm) {
  return inflateEnd(strm);
}

Bytef *CGRPCZlib_castVoidToBytefPointer(void *in) {
  return (Bytef *) in;
}
