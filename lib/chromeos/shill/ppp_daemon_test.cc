// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/external_task.h"
#include "shill/mock_control.h"
#include "shill/mock_process_manager.h"
#include "shill/ppp_daemon.h"
#include "shill/rpc_task.h"

namespace shill {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::Test;
using testing::WithArg;

class PPPDaemonTest : public Test, public RpcTaskDelegate {
 public:
  PPPDaemonTest() : weak_ptr_factory_(this) {}
  PPPDaemonTest(const PPPDaemonTest&) = delete;
  PPPDaemonTest& operator=(const PPPDaemonTest&) = delete;

  ~PPPDaemonTest() override = default;

  std::unique_ptr<ExternalTask> Start(const PPPDaemon::Options& options,
                                      const std::string& device,
                                      Error* error) {
    PPPDaemon::DeathCallback callback(
        base::Bind(&PPPDaemonTest::DeathCallback, base::Unretained(this)));
    return PPPDaemon::Start(&control_, &process_manager_,
                            weak_ptr_factory_.GetWeakPtr(), options, device,
                            callback, error);
  }

  bool CaptureArgv(const std::vector<std::string>& argv) {
    argv_ = argv;
    return true;
  }

  MOCK_METHOD(void, GetLogin, (std::string*, std::string*), (override));
  MOCK_METHOD(void,
              Notify,
              (const std::string&, (const std::map<std::string, std::string>&)),
              (override));

 protected:
  MockControl control_;
  MockProcessManager process_manager_;

  std::vector<std::string> argv_;
  base::WeakPtrFactory<PPPDaemonTest> weak_ptr_factory_;

  MOCK_METHOD(void, DeathCallback, (pid_t, int));
};

TEST_F(PPPDaemonTest, PluginUsed) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _))
      .WillOnce(WithArg<2>(Invoke(this, &PPPDaemonTest::CaptureArgv)));

  Error error;
  PPPDaemon::Options options;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  for (size_t i = 0; i < argv_.size(); ++i) {
    if (argv_[i] == "plugin") {
      EXPECT_EQ(argv_[i + 1], PPPDaemon::kShimPluginPath);
    }
  }
}

TEST_F(PPPDaemonTest, OptionsConverted) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _))
      .WillOnce(WithArg<2>(Invoke(this, &PPPDaemonTest::CaptureArgv)));

  PPPDaemon::Options options;
  options.no_detach = true;
  options.no_default_route = true;
  options.use_peer_dns = true;
  options.lcp_echo_interval = 1;
  options.lcp_echo_failure = 1;
  options.max_fail = 1;
  options.use_ipv6 = true;

  Error error;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  std::set<std::string> expected_arguments = {
      "nodetach",         "nodefaultroute", "usepeerdns", "lcp-echo-interval",
      "lcp-echo-failure", "maxfail",        "+ipv6",      "ipv6cp-use-ipaddr",
  };
  for (const auto& argument : argv_) {
    expected_arguments.erase(argument);
  }
  EXPECT_TRUE(expected_arguments.empty());
}

TEST_F(PPPDaemonTest, ErrorPropagated) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _))
      .WillOnce(Return(-1));

  PPPDaemon::Options options;
  Error error;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  EXPECT_NE(error.type(), Error::kSuccess);
  EXPECT_EQ(nullptr, task);
}

}  // namespace shill
