// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/cryptohome.h>

#include <algorithm>
#include <numeric>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

namespace brillo {

namespace cryptohome {

namespace home {

TEST(cryptohome, SanitzeUsername) {
  std::string username = "fakeuser";
  SecureBlob salt = SecureBlob("01234567890123456789");

  EXPECT_EQ("856b54169cd5d2d6ca9a4b258ada5e3bee242829",
            SanitizeUserNameWithSalt(username, salt));
}

TEST(cryptohome, SanitzeUsernameMixedCase) {
  std::string username = "fakeuser";
  SecureBlob salt = SecureBlob("01234567890123456789");

  EXPECT_EQ("856b54169cd5d2d6ca9a4b258ada5e3bee242829",
            SanitizeUserNameWithSalt(username, salt));
}

}  // namespace home
}  // namespace cryptohome
}  // namespace brillo
