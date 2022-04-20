// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <utility>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "patchpanel/adb_proxy.h"
#include "patchpanel/helper_process.h"
#include "patchpanel/manager.h"
#include "patchpanel/multicast_proxy.h"
#include "patchpanel/ndproxy.h"
#include "patchpanel/socket.h"

int main(int argc, char* argv[]) {
  DEFINE_bool(log_to_stderr, false, "Log to both syslog and stderr");
  DEFINE_int32(
      adb_proxy_fd, -1,
      "Control socket for starting the ADB proxy subprocess. Used internally.");
  DEFINE_int32(mcast_proxy_fd, -1,
               "Control socket for starting the multicast proxy "
               "subprocess. Used internally.");
  DEFINE_int32(
      nd_proxy_fd, -1,
      "Control socket for starting the ND proxy subprocess. Used internally.");

  brillo::FlagHelper::Init(argc, argv, "ARC network daemon");

  int flags = brillo::kLogToSyslog | brillo::kLogHeader;
  if (FLAGS_log_to_stderr)
    flags |= brillo::kLogToStderr;
  brillo::InitLog(flags);

  if (FLAGS_adb_proxy_fd >= 0) {
    LOG(INFO) << "Spawning adb proxy";
    base::ScopedFD fd(FLAGS_adb_proxy_fd);
    patchpanel::AdbProxy adb_proxy(std::move(fd));
    return adb_proxy.Run();
  }

  if (FLAGS_nd_proxy_fd >= 0) {
    LOG(INFO) << "Spawning nd proxy";
    base::ScopedFD fd(FLAGS_nd_proxy_fd);
    patchpanel::NDProxyDaemon nd_proxy(std::move(fd));
    return nd_proxy.Run();
  }

  if (FLAGS_mcast_proxy_fd >= 0) {
    LOG(INFO) << "Spawning multicast proxy";
    base::ScopedFD fd(FLAGS_mcast_proxy_fd);
    patchpanel::MulticastProxy mcast_proxy(std::move(fd));
    return mcast_proxy.Run();
  }

  auto adb_proxy = std::make_unique<patchpanel::HelperProcess>();
  adb_proxy->Start(argc, argv, "--adb_proxy_fd");

  auto mcast_proxy = std::make_unique<patchpanel::HelperProcess>();
  mcast_proxy->Start(argc, argv, "--mcast_proxy_fd");

  auto nd_proxy = std::make_unique<patchpanel::HelperProcess>();
  nd_proxy->Start(argc, argv, "--nd_proxy_fd");

  LOG(INFO) << "Starting patchpanel manager";
  patchpanel::Manager manager(std::move(adb_proxy), std::move(mcast_proxy),
                              std::move(nd_proxy));
  return manager.Run();
}
