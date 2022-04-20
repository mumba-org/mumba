// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/logging.h>

#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/l2tp_ipsec_driver.h"

namespace shill {

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  IPsecConnection::CipherSuite ike_cipher, esp_cipher;
  L2TPIPsecDriver::ParseStrokeStatusAllOutput(
      {reinterpret_cast<const char*>(data), size}, &ike_cipher, &esp_cipher);

  return 0;
}

}  // namespace shill
