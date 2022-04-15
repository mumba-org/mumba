// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include <base/check.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "brillo/cryptohome.h"
#include "brillo/secure_blob.h"

namespace brillo {
namespace cryptohome {
namespace home {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);

  const std::string username = fuzzed_data_provider.ConsumeRandomLengthString();
  const auto salt =
      SecureBlob(fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>());

  const std::string sanitized = SanitizeUserNameWithSalt(username, salt);
  CHECK(IsSanitizedUserName(sanitized));

  return 0;
}

}  // namespace home
}  // namespace cryptohome
}  // namespace brillo
