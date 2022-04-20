// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/helper_process.h"

#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

//#include <base/check.h>
//#include <base/check_op.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <brillo/syslog_logging.h>

namespace patchpanel {
namespace {
constexpr int kMaxRestarts = 5;
}  // namespace

void HelperProcess::Start(int argc, char* argv[], const std::string& fd_arg) {
  CHECK_GE(argc, 1);
  for (int i = 0; i < argc; i++) {
    argv_.push_back(argv[i]);
  }
  fd_arg_ = fd_arg;
  Launch();
}

bool HelperProcess::Restart() {
  if (++restarts_ > kMaxRestarts) {
    LOG(ERROR) << "Maximum number of restarts exceeded";
    return false;
  }
  LOG(INFO) << "Restarting...";
  Launch();
  return true;
}

void HelperProcess::Launch() {
  int control[2];

  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, control) != 0) {
    PLOG(FATAL) << "socketpair failed";
  }

  base::ScopedFD control_fd(control[0]);
  msg_dispatcher_ =
      std::make_unique<MessageDispatcher>(std::move(control_fd), false);
  const int subprocess_fd = control[1];

  std::vector<std::string> child_argv = argv_;
  child_argv.push_back(fd_arg_ + "=" + std::to_string(subprocess_fd));

  base::FileHandleMappingVector fd_mapping;
  fd_mapping.push_back({subprocess_fd, subprocess_fd});

  base::LaunchOptions options;
  options.fds_to_remap = std::move(fd_mapping);

  base::Process p = base::LaunchProcess(child_argv, options);
  CHECK(p.IsValid());
  pid_ = p.Pid();
}

void HelperProcess::SendMessage(
    const google::protobuf::MessageLite& proto) const {
  if (!msg_dispatcher_) {
    return;
  }
  msg_dispatcher_->SendMessage(proto);
}

void HelperProcess::Listen() {
  if (!msg_dispatcher_) {
    return;
  }
  msg_dispatcher_->Start();
}

void HelperProcess::RegisterNDProxyMessageHandler(
    base::RepeatingCallback<void(const NDProxyMessage&)> handler) {
  if (!msg_dispatcher_) {
    return;
  }
  msg_dispatcher_->RegisterNDProxyMessageHandler(std::move(handler));
}

}  // namespace patchpanel
