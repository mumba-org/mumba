// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_PPP_DAEMON_H_
#define SHILL_PPP_DAEMON_H_

#include <memory>
#include <string>

#include <base/callback.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>

#include "shill/external_task.h"

namespace shill {

class ControlInterface;
class Error;
class ProcessManager;

// PPPDaemon provides control over the configuration and instantiation of pppd
// processes.  All pppd instances created through PPPDaemon will use shill's
// pppd plugin.
class PPPDaemon {
 public:
  // The type of callback invoked when an ExternalTask wrapping a pppd instance
  // dies.  The first argument is the pid of the process, the second is the exit
  // code.
  using DeathCallback = base::Callback<void(pid_t, int)>;

  // Provides options used when preparing a pppd task for execution.  These map
  // to pppd command-line options.  Refer to https://ppp.samba.org/pppd.html for
  // more details about the meaning of each.
  struct Options {
    Options();

    // Causes pppd to emit log messages useful for debugging connectivity.
    bool debug;

    // Causes pppd to not fork and daemonize, remaining attached to the
    // controlling terminal that spawned it.
    bool no_detach;

    // Stops pppd from modifying the routing table.
    bool no_default_route;

    // Instructs pppd to request DNS servers from the remote server.
    bool use_peer_dns;

    // If set, will cause the shill pppd plugin to be used at the creation of
    // the pppd instace.  This will result in connectivity events being plumbed
    // over D-Bus to the RpcTaskDelegate provided during PPPDaemon::Start.
    bool use_shim_plugin;

    // The number of seconds between sending LCP echo requests.
    uint32_t lcp_echo_interval;

    // The number of missed LCP echo responses tolerated before disconnecting.
    uint32_t lcp_echo_failure;

    // The number of allowed failed consecutive connection attempts before
    // giving up.  A value of 0 means there is no limit.
    uint32_t max_fail;

    // Instructs pppd to request an IPv6 address from the remote server.
    bool use_ipv6;
  };

  // The path to the pppd plugin provided by shill.
  static const char kShimPluginPath[];

  // Starts a pppd instance.  |options| provides the configuration for the
  // instance to be started, |device| specifies which device the PPP connection
  // is to be established on, |death_callback| will be invoked when the
  // underlying pppd process dies.  |error| is populated if the task cannot be
  // started, and nullptr is returned.
  static std::unique_ptr<ExternalTask> Start(
      ControlInterface* control_interface,
      ProcessManager* process_manager,
      const base::WeakPtr<RpcTaskDelegate>& task_delegate,
      const Options& options,
      const std::string& device,
      const DeathCallback& death_callback,
      Error* error);

 private:
  FRIEND_TEST(PPPDaemonTest, PluginUsed);

  PPPDaemon();
  PPPDaemon(const PPPDaemon&) = delete;
  PPPDaemon& operator=(const PPPDaemon&) = delete;

  ~PPPDaemon();
};

}  // namespace shill

#endif  // SHILL_PPP_DAEMON_H_
