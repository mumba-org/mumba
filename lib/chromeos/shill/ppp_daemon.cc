// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ppp_daemon.h"

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_number_conversions.h>

#include "shill/control_interface.h"
#include "shill/error.h"
#include "shill/external_task.h"
#include "shill/ppp_device.h"

namespace shill {

namespace {

const char kDaemonPath[] = "/usr/sbin/pppd";
const uint32_t kUnspecifiedValue = UINT32_MAX;

}  // namespace

PPPDaemon::Options::Options()
    : debug(false),
      no_detach(false),
      no_default_route(false),
      use_peer_dns(false),
      use_shim_plugin(true),
      lcp_echo_interval(kUnspecifiedValue),
      lcp_echo_failure(kUnspecifiedValue),
      max_fail(kUnspecifiedValue),
      use_ipv6(false) {}

const char PPPDaemon::kShimPluginPath[] = SHIMDIR "/shill-pppd-plugin.so";

std::unique_ptr<ExternalTask> PPPDaemon::Start(
    ControlInterface* control_interface,
    ProcessManager* process_manager,
    const base::WeakPtr<RpcTaskDelegate>& task_delegate,
    const PPPDaemon::Options& options,
    const std::string& device,
    const PPPDaemon::DeathCallback& death_callback,
    Error* error) {
  std::vector<std::string> arguments;

  // pppd runs under the non-root 'shill' group, so we need to explicitly tell
  // pppd to allow certain privileged options.
  arguments.push_back("privgroup");
  arguments.push_back("shill");

  if (options.debug) {
    arguments.push_back("debug");
  }
  if (options.no_detach) {
    arguments.push_back("nodetach");
  }
  if (options.no_default_route) {
    arguments.push_back("nodefaultroute");
  }
  if (options.use_peer_dns) {
    arguments.push_back("usepeerdns");
  }
  if (options.use_shim_plugin) {
    arguments.push_back("plugin");
    arguments.push_back(kShimPluginPath);
  }
  if (options.lcp_echo_interval != kUnspecifiedValue) {
    arguments.push_back("lcp-echo-interval");
    arguments.push_back(base::NumberToString(options.lcp_echo_interval));
  }
  if (options.lcp_echo_failure != kUnspecifiedValue) {
    arguments.push_back("lcp-echo-failure");
    arguments.push_back(base::NumberToString(options.lcp_echo_failure));
  }
  if (options.max_fail != kUnspecifiedValue) {
    arguments.push_back("maxfail");
    arguments.push_back(base::NumberToString(options.max_fail));
  }
  if (options.use_ipv6) {
    arguments.push_back("+ipv6");
    arguments.push_back("ipv6cp-use-ipaddr");
  }

  arguments.push_back(device);

  auto task = std::make_unique<ExternalTask>(control_interface, process_manager,
                                             task_delegate, death_callback);

  std::map<std::string, std::string> environment;
  if (task->Start(base::FilePath(kDaemonPath), arguments, environment, true,
                  error)) {
    return task;
  }
  return nullptr;
}

}  // namespace shill
