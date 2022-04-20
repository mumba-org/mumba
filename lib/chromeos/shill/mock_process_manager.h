// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_PROCESS_MANAGER_H_
#define SHILL_MOCK_PROCESS_MANAGER_H_

#include "shill/process_manager.h"

#include <map>
#include <string>
#include <vector>

#include <base/location.h>
#include <gmock/gmock.h>

namespace shill {

class MockProcessManager : public ProcessManager {
 public:
  MockProcessManager();
  MockProcessManager(const MockProcessManager&) = delete;
  MockProcessManager& operator=(const MockProcessManager&) = delete;

  ~MockProcessManager() override;

  MOCK_METHOD(void, Init, (EventDispatcher*), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(pid_t,
              StartProcess,
              (const base::Location&,
               const base::FilePath&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&),
               bool,
               ExitCallback),
              (override));
  MOCK_METHOD(pid_t,
              StartProcessInMinijail,
              (const base::Location&,
               const base::FilePath&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&),
               const MinijailOptions&,
               base::OnceCallback<void(int)>),
              (override));
  MOCK_METHOD(pid_t,
              StartProcessInMinijailWithPipes,
              (const base::Location&,
               const base::FilePath&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&),
               const MinijailOptions&,
               base::OnceCallback<void(int)>,
               struct std_file_descriptors),
              (override));
  MOCK_METHOD(pid_t,
              StartProcessInMinijailWithStdout,
              (const base::Location&,
               const base::FilePath&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&),
               const MinijailOptions&,
               ExitWithStdoutCallback),
              (override));
  MOCK_METHOD(bool, StopProcess, (pid_t), (override));
  MOCK_METHOD(bool, StopProcessAndBlock, (pid_t), (override));
  MOCK_METHOD(bool, UpdateExitCallback, (pid_t, ExitCallback), (override));
};

// Custom matchers for MinijailOptions.
MATCHER_P2(MinijailOptionsMatchUserGroup, user, group, "") {
  return arg.user == user && arg.group == group;
}

MATCHER_P(MinijailOptionsMatchCapMask, capmask, "") {
  return arg.capmask == capmask;
}

MATCHER_P(MinijailOptionsMatchInheritSupplumentaryGroup,
          inherit_supplementary_groups,
          "") {
  return arg.inherit_supplementary_groups == inherit_supplementary_groups;
}

MATCHER_P(MinijailOptionsMatchCloseNonstdFDs, close_nonstd_fds, "") {
  return arg.close_nonstd_fds == close_nonstd_fds;
}

}  // namespace shill

#endif  // SHILL_MOCK_PROCESS_MANAGER_H_
