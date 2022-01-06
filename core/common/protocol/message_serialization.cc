// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/protocol/message_serialization.h"

#include <stdint.h>

#include "base/containers/hash_tables.h"
#include "base/logging.h"
#include "net/base/io_buffer.h"
#include "third_party/webrtc/rtc_base/byteorder.h"

namespace protocol {

scoped_refptr<net::IOBufferWithSize> SerializeAndFrameMessage(
    const google::protobuf::MessageLite& msg) {
  // Create a buffer with 4 extra bytes. This is used as prefix to write an
  // int32_t of the serialized message size for framing.
  const int kExtraBytes = sizeof(int32_t);
  int size = msg.ByteSize() + kExtraBytes;
  scoped_refptr<net::IOBufferWithSize> buffer(new net::IOBufferWithSize(size));
  rtc::SetBE32(buffer->data(), msg.GetCachedSize());
  msg.SerializeWithCachedSizesToArray(
      reinterpret_cast<uint8_t*>(buffer->data()) + kExtraBytes);
  return buffer;
}

scoped_refptr<net::IOBufferWithSize> SerializeMessage(
    const google::protobuf::MessageLite& msg) {
  int size = msg.ByteSize();
  scoped_refptr<net::IOBufferWithSize> buffer(new net::IOBufferWithSize(size));
  msg.SerializeWithCachedSizesToArray(
      reinterpret_cast<uint8_t*>(buffer->data()));
  return buffer;
}

bool SerializeAndFrameMessageAsString(
    const google::protobuf::MessageLite& msg, std::string* out) {
  const int kExtraBytes = sizeof(int32_t);
  int size = msg.ByteSize() + kExtraBytes;

  std::unique_ptr<uint8_t[]> buf(new uint8_t[size]);
  rtc::SetBE32(buf.get(), msg.GetCachedSize());
  msg.SerializeWithCachedSizesToArray(buf.get() + kExtraBytes);
  out->assign(reinterpret_cast<char *>(buf.release()), size);
  return true;
}

}  // namespace protocol