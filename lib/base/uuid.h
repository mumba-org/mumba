// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// portions of this code from libuuid

/*
 *
 * Copyright (C) 1996, 1997 Theodore Ts'o.
 *
 * %Begin-Header%
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef MUMBA_BASE_UUID_H_
#define MUMBA_BASE_UUID_H_

#include "build/build_config.h"

#include <string>

#include "base/hash.h"
#include "base/rand_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"

namespace base {

struct _uuid {
  uint32_t time_low;
  uint16_t time_mid;
  uint16_t time_hi_and_version;
  uint16_t clock_seq;
  uint8_t node[6];
};

struct UUID {

 uint8_t data[16];

 static UUID generate() {
  uint8_t buf[16];
  _uuid uu;
  uint8_t out[16];
  int i, n = 1;

  for (i = 0; i < n; i++) {
    base::RandBytes(buf, sizeof(buf));
    UUID::unpack(buf, uu);

    uu.clock_seq = (uu.clock_seq & 0x3FFF) | 0x8000;
    uu.time_hi_and_version = (uu.time_hi_and_version & 0x0FFF)
      | 0x4000;
    UUID::pack(uu, &out[0]);
    //out += sizeof(uint8_t[16]);
  }

  return UUID(out);
 }

 static void pack(const _uuid& uu, uint8_t* out) {
  uint32_t tmp;

  tmp = uu.time_low;
  out[3] = (unsigned char) tmp;
  tmp >>= 8;
  out[2] = (unsigned char) tmp;
  tmp >>= 8;
  out[1] = (unsigned char) tmp;
  tmp >>= 8;
  out[0] = (unsigned char) tmp;

  tmp = uu.time_mid;
  out[5] = (unsigned char) tmp;
  tmp >>= 8;
  out[4] = (unsigned char) tmp;

  tmp = uu.time_hi_and_version;
  out[7] = (unsigned char) tmp;
  tmp >>= 8;
  out[6] = (unsigned char) tmp;

  tmp = uu.clock_seq;
  out[9] = (unsigned char) tmp;
  tmp >>= 8;
  out[8] = (unsigned char) tmp;

  memcpy(out+10, uu.node, 6);
 }

 static void unpack(const uint8_t* in, _uuid& uu) {
  const uint8_t *ptr = in;
  uint32_t    tmp;

  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  tmp = (tmp << 8) | *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu.time_low = tmp;

  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu.time_mid = tmp;

  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu.time_hi_and_version = tmp;

  tmp = *ptr++;
  tmp = (tmp << 8) | *ptr++;
  uu.clock_seq = tmp;

  memcpy(uu.node, ptr, 6);
 }

  static bool IsUUID(const std::string& uuid, size_t len) {
    size_t i;
    const char *cp;
    const char* in = uuid.c_str();

    if (uuid.size() < len) {
      return false;
    }

    for (i=0, cp = in; i <= len; i++, cp++) {

      if (i == len && *cp == 0)
        continue;

      if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
        if (*cp == '-')
          continue;
        else
          return false;
      }

      if (!base::IsHexDigit(*cp)) {
        return false;
      }
    }

    return true;
  }

 static std::string to_string(const UUID& in) { // const UUID uu, char *out, const char *fmt
  _uuid uuid;
  std::string out;

  UUID::unpack(in.data, uuid);
  out = base::StringPrintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
    uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
    uuid.node[0], uuid.node[1], uuid.node[2],
    uuid.node[3], uuid.node[4], uuid.node[5]);

  return out;
 }

 static std::string to_compact_string(const UUID& in) { // const UUID uu, char *out, const char *fmt
  _uuid uuid;
  std::string out;

  UUID::unpack(in.data, uuid);
  out = base::StringPrintf("%08x", uuid.time_low);

  return out;
 }

 static UUID from_string(const std::string& uuid_str, bool* ok) {
  _uuid uuid;
  uint8_t out[16];
  int i;
  const char *cp;
  const char* in = uuid_str.c_str(); 
  char buf[3];
  *ok = true;

  if (!UUID::IsUUID(uuid_str, 36)) {
    *ok = false;
    return UUID(); 
  }

  // for (i=0, cp = in; i <= 36; i++,cp++) {
  //   if ((i == 8) || (i == 13) || (i == 18) ||
  //       (i == 23)) {
  //     if (*cp == '-') {
  //       continue;
  //     } else {
  //       DLOG(ERROR) << "expected '-'";
  //       *ok = false;
  //       return UUID();
  //     }
  //   }
  //   if (i== 36)
  //     if (*cp == 0)
  //       continue;
  //   if (!base::IsHexDigit(*cp)) {
  //     DLOG(ERROR) << "expected hex digit on pos: " << i;
  //     *ok = false;
  //     return UUID();
  //   }
  // }
  uuid.time_low = strtoul(in, NULL, 16);
  uuid.time_mid = strtoul(in+9, NULL, 16);
  uuid.time_hi_and_version = strtoul(in+14, NULL, 16);
  uuid.clock_seq = strtoul(in+19, NULL, 16);
  cp = in+24;
  buf[2] = 0;
  for (i=0; i < 6; i++) {
    buf[0] = *cp++;
    buf[1] = *cp++;
    uuid.node[i] = strtoul(buf, NULL, 16);
  }

  UUID::pack(uuid, out);
  
  return UUID(out);
 }

 UUID(): data{0} {}
 
 UUID(const UUID& other) {
  memcpy(data, other.data, 16);
 }

 UUID(const uint8_t* buf) {
  memcpy(data, buf, 16);
 }

 UUID(uint8_t u0, uint8_t u1, uint8_t u2, uint8_t u3, uint8_t u4, uint8_t u5, uint8_t u6, uint8_t u7, uint8_t u8, uint8_t u9, uint8_t u10, uint8_t u11, uint8_t u12, uint8_t u13, uint8_t u14, uint8_t u15):
  data{u0,u1,u2,u3,u4,u5,u6,u7,u8,u9,u10,u11,u12,u13,u14,u15} {}

 std::string to_string() const {
  return UUID::to_string(*this);
 }

 std::string compact_string() const {
  return UUID::to_compact_string(*this);
 }

 const UUID& operator=(const UUID& rhs) {
  memcpy(data, rhs.data, 16);
  return *this;
 }

 inline bool operator==(const UUID& other) const {
  return memcmp(data, other.data, 16) == 0;
 }

  inline bool operator!=(const UUID& other) const {
    return !(other == *this);
  }

  inline bool StartsWith(const std::string& x, size_t len) const {
    DCHECK(len == 8); // we will only deal with this for now
    uint32_t time_low;
    _uuid uuid;
    const char* in = x.c_str();

    if (!UUID::IsUUID(x, len))
      return false;

    time_low = strtoul(in, NULL, 16);

    UUID::unpack(data, uuid);

    return uuid.time_low == time_low;
  }

  bool IsNull() const {
    return *this == UUID();
  }
  // just automate this
  std::string string() const {
    return std::string(reinterpret_cast<const char *>(data), 16);
  }

  std::string c_string() const {
    return std::string(
    { data[0], data[1], data[2], data[3],
      data[4], data[5], data[6], data[7], 
      data[8], data[9], data[10], data[11],
      data[12], data[13], data[14], data[15], 
      0 }, 
     17);
  }

};


}

namespace std {

  template <>
  struct hash<base::UUID>
  {
    std::size_t operator()(const base::UUID& uuid) const
    {
      return static_cast<std::size_t>(base::Hash(reinterpret_cast<const char *>(&uuid.data[0]), 16));
    }
  };

}
//using UUID = base::UUID;

#endif