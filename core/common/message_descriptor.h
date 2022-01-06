// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_MESSAGE_DESCRIPTOR_H_
#define COMMON_MESSAGE_DESCRIPTOR_H_

#include <string>

#include "base/sha1.h"
#include "base/memory/shared_memory.h"

namespace common {

enum MessageEncoding {
 kENCODING_NONE = -1,
 kENCODING_BINARY = 0,
 kENCODING_UTF8 = 1,
 kENCODING_UTF16 = 2,
 kENCODING_FLATBUFFERS = 3,
};

struct MessageDescriptor {
  base::SharedMemoryHandle handle;
  bool shared;
  std::string sha1_checksum;
  std::string body;
  uint32_t body_size;
  int body_encoding;

  MessageDescriptor();
  MessageDescriptor(MessageDescriptor&);
  MessageDescriptor(uint8_t* buffer, uint32_t size, MessageEncoding encoding);
  ~MessageDescriptor();

  bool is_corrupt() const {
    uint8_t hash[20] = { 0 };
    base::SHA1HashBytes(reinterpret_cast<const uint8_t *>(body.c_str()), body.size(), &hash[0]);
    return memcmp(hash, reinterpret_cast<const uint8_t *>(sha1_checksum.data()), 20) != 0;
  }

  void CalculateHash() {
    uint8_t hash[20] = { 0 };
    base::SHA1HashBytes(reinterpret_cast<const uint8_t *>(body.c_str()), body.size(), &hash[0]);
    sha1_checksum.assign(reinterpret_cast<const char *>(hash), 20);
  }
};

}

#endif