// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_MK_TESTRUNNER_H_
#define COMMON_MK_TESTRUNNER_H_

#include <memory>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/test/test_timeouts.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace platform2 {

// The TestRunner class allows platform2 components to override the default
// testrunner behavior if they have special requirements.
//
// For example, if your test already instantiates a base::AtExitManager, you
// can tell TestRunner not to instantiate another one (multiple instances
// will result in an assert):
//
//  // your_testrunner.cc
//  #include "common-mk/testrunner.h"
//  int main(int argc, char** argv) {
//    platform2::TestRunner::Options opts;
//    opts.instantiate_exit_manager = false;
//    auto runner = platform2::TestRunner(argc, argv, opts);
//    return runner.Run();
//  }
class TestRunner {
 public:
  struct Options {
    Options() {}
    bool instantiate_exit_manager = true;
    bool instantiate_test_timeouts = true;
  };

  TestRunner(int argc, char** argv, const Options& opts = Options()) {
    base::CommandLine::Init(argc, argv);
    logging::InitLogging(logging::LoggingSettings());

    if (opts.instantiate_exit_manager) {
      exit_manager_ = std::make_unique<base::AtExitManager>();
    }

    if (opts.instantiate_test_timeouts) {
      TestTimeouts::Initialize();
    }

    testing::InitGoogleTest(&argc, argv);
    testing::GTEST_FLAG(throw_on_failure) = true;
    testing::InitGoogleMock(&argc, argv);
  }

  int Run() { return RUN_ALL_TESTS(); }

 private:
  std::unique_ptr<base::AtExitManager> exit_manager_;
};

}  // namespace platform2

#endif  // COMMON_MK_TESTRUNNER_H_
