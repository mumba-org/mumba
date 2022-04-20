// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IO_HANDLER_H_
#define SHILL_NET_IO_HANDLER_H_

#include <string>

#include <base/callback.h>

#include "shill/net/shill_export.h"

namespace shill {

struct SHILL_EXPORT InputData {
  InputData() : buf(nullptr), len(0) {}
  InputData(const unsigned char* in_buf, ssize_t in_len)
      : buf(in_buf), len(in_len) {}

  const unsigned char* buf;
  ssize_t len;
};

class SHILL_EXPORT IOHandler {
 public:
  enum ReadyMode { kModeInput, kModeOutput };

  using ErrorCallback = base::Callback<void(const std::string&)>;
  using InputCallback = base::Callback<void(InputData*)>;
  using ReadyCallback = base::Callback<void(int)>;

  // Data buffer size in bytes.
  static const int kDataBufferSize = 4096;

  IOHandler() = default;
  virtual ~IOHandler() = default;

  virtual void Start() {}
  virtual void Stop() {}
};

}  // namespace shill

#endif  // SHILL_NET_IO_HANDLER_H_
