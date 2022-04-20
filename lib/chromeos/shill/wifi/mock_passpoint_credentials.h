// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_PASSPOINT_CREDENTIALS_H_
#define SHILL_WIFI_MOCK_PASSPOINT_CREDENTIALS_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/wifi/passpoint_credentials.h"

namespace shill {

class MockPasspointCredentials : public PasspointCredentials {
 public:
  explicit MockPasspointCredentials(std::string id)
      : PasspointCredentials(id) {}
  MockPasspointCredentials(const MockPasspointCredentials&) = delete;
  MockPasspointCredentials& operator=(const MockPasspointCredentials&) = delete;

  ~MockPasspointCredentials() = default;

  MOCK_METHOD(bool,
              ToSupplicantProperties,
              (KeyValueStore*),
              (const, override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_PASSPOINT_CREDENTIALS_H_
