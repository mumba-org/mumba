// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DAEMON_TASK_H_
#define SHILL_DAEMON_TASK_H_

#include <memory>
#include <string>
#include <vector>

#include <base/callback.h>

#include "shill/event_dispatcher.h"

namespace shill {

class Config;
class ControlInterface;
class DHCPProvider;
class Error;
class Manager;
class Metrics;
class ProcessManager;
class RoutingTable;
class RTNLHandler;

#if !defined(DISABLE_WIFI)
class NetlinkManager;
#endif  // !defined(DISABLE_WIFI)

// DaemonTask contains most of the logic used in ShillDaemon (e.g.
// init/shutdown, start/stop). This class is kept separate from ShillDaemon to
// ensure that it does not inherit brillo::Daemon. This is necessary for
// DaemonTask unit tests to run, since the base::ExitManager inherited from
// brillo::Daemon cannot coexist with the base::ExitManager used by shill's
// test_runner.cc.
class DaemonTask {
 public:
  // Run-time settings retrieved from command line.
  struct Settings {
    Settings()
        : ignore_unknown_ethernet(false),
          minimum_mtu(0),
          passive_mode(false),
          use_portal_list(false) {}
    std::string accept_hostname_from;
    std::string default_technology_order;
    std::vector<std::string> devices_blocked;
    std::vector<std::string> devices_allowed;
    bool ignore_unknown_ethernet;
    int minimum_mtu;
    bool passive_mode;
    std::string portal_list;
    bool use_portal_list;
  };

  DaemonTask(const Settings& settings, Config* config);
  DaemonTask(const DaemonTask&) = delete;
  DaemonTask& operator=(const DaemonTask&) = delete;

  virtual ~DaemonTask();

  void Init();

  // Starts the termination actions in the manager. Returns true if
  // termination actions have completed synchronously, and false
  // otherwise. Arranges for |completion_callback| to be invoked after
  // all asynchronous work completes, but ignores
  // |completion_callback| if no asynchronous work is required.
  virtual bool Quit(const base::Closure& completion_callback);

  // Break the termination loop started in DaemonTask::OnShutdown. Invoked
  // after shill completes its termination tasks during shutdown.
  void BreakTerminationLoop();

 private:
  friend class DaemonTaskTest;
  friend class DaemonTaskForTest;

  void Start();

  // Apply run-time settings to the manager.
  void ApplySettings();

  // Called when the termination actions are completed.
  void TerminationActionsCompleted(const Error& error);

  // Calls Stop() and then causes the dispatcher message loop to terminate and
  // return to the main function which started the daemon.
  void StopAndReturnToMain();

  void Stop();

  Settings settings_;
  Config* config_;
  std::unique_ptr<EventDispatcher> dispatcher_;
  std::unique_ptr<ControlInterface> control_;
  std::unique_ptr<Metrics> metrics_;
  RTNLHandler* rtnl_handler_;
  RoutingTable* routing_table_;
  DHCPProvider* dhcp_provider_;
#if !defined(DISABLE_WIFI)
  NetlinkManager* netlink_manager_;
#endif  // !defined(DISABLE_WIFI)
  ProcessManager* process_manager_;
  std::unique_ptr<Manager> manager_;
  base::Closure termination_completed_callback_;
};

}  // namespace shill

#endif  // SHILL_DAEMON_TASK_H_
