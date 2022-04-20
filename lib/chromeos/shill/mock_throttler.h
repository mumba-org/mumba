// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_THROTTLER_H_
#define SHILL_MOCK_THROTTLER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/throttler.h"

namespace shill {

class MockThrottler : public Throttler {
 public:
  MockThrottler();
  MockThrottler(const MockThrottler&) = delete;
  MockThrottler& operator=(const MockThrottler&) = delete;

  ~MockThrottler() override;

  MOCK_METHOD(bool,
              DisableThrottlingOnAllInterfaces,
              (const ResultCallback&),
              (override));
  MOCK_METHOD(bool,
              ThrottleInterfaces,
              (const ResultCallback&, uint32_t, uint32_t),
              (override));
  MOCK_METHOD(bool,
              ApplyThrottleToNewInterface,
              (const std::string&),
              (override));
  MOCK_METHOD(bool,
              StartTCForCommands,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(bool,
              Throttle,
              (const ResultCallback&, const std::string&, uint32_t, uint32_t),
              (override));
  MOCK_METHOD(void, WriteTCCommands, (int), (override));
  MOCK_METHOD(void, OnProcessExited, (int), (override));
  MOCK_METHOD(void,
              Done,
              (const ResultCallback&, Error::Type, const std::string&),
              (override));
  MOCK_METHOD(std::string, GetNextInterface, (), (override));
  MOCK_METHOD(void, ClearTCState, (), (override));
  MOCK_METHOD(void, ClearThrottleStatus, (), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_THROTTLER_H_
