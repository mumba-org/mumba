// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_POWER_MANAGER_PROXY_INTERFACE_H_
#define SHILL_POWER_MANAGER_PROXY_INTERFACE_H_

#include <string>

#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

namespace shill {

// This class provides events from the power manager.  To use this class, create
// a subclass from PowerManagerProxyDelegate and implement its member functions.
// Call ProxyFactory::CreatePowerManagerProxy() to create an instance of this
// proxy, passing it a pointer to the delegate you created.  When an event from
// the power manager is received, your delegate's member function will be
// called. You retain ownership of the delegate and must ensure that the proxy
// is deleted before the delegate.
class PowerManagerProxyInterface {
 public:
  virtual ~PowerManagerProxyInterface() = default;

  // Sends a request to the power manager to wait for this client for up to
  // |timeout| before suspending the system.  |description| is a
  // human-readable string describing the delay's purpose.  Assigns an ID
  // corresponding to the registered delay to |delay_id_out| and returns
  // true on success.
  virtual bool RegisterSuspendDelay(base::TimeDelta timeout,
                                    const std::string& description,
                                    int* delay_id_out) = 0;

  // Unregisters a previously-registered suspend delay.  Returns true on
  // success.
  virtual bool UnregisterSuspendDelay(int delay_id) = 0;

  // Calls the power manager's HandleSuspendReadiness method.  |delay_id| should
  // contain the ID returned via RegisterSuspendDelay() and |suspend_id| should
  // contain the ID from OnSuspendImminent().  Returns true on success.
  virtual bool ReportSuspendReadiness(int delay_id, int suspend_id) = 0;

  // Sends a request to the power manager to wait for this client for up to
  // |timeout| before suspending the system from a dark resume. Arguments
  // are as explained for |RegisterSuspendDelay|. Returns true on success.
  virtual bool RegisterDarkSuspendDelay(base::TimeDelta timeout,
                                        const std::string& description,
                                        int* delay_id_out) = 0;

  // Unregisters a previously-registered dark suspend delay. Returns true on
  // success.
  virtual bool UnregisterDarkSuspendDelay(int delay_id) = 0;

  // Calls the power manager's HandleDarkSuspendReadiness method. Arguments are
  // as explained for ReportSuspendReadiness. Returns true on success.
  virtual bool ReportDarkSuspendReadiness(int delay_id, int suspend_id) = 0;

  // Calls the power manager's RecordDarkResumeWakeReason method to record the
  // wake reason for the current dark resume. Returns true on success.
  virtual bool RecordDarkResumeWakeReason(const std::string& wake_reason) = 0;

  virtual bool ChangeRegDomain(power_manager::WifiRegDomainDbus domain) = 0;
};

// PowerManager signal delegate to be associated with the proxy.
class PowerManagerProxyDelegate {
 public:
  virtual ~PowerManagerProxyDelegate() = default;

  // Broadcast by the power manager when it's about to suspend. Delegates
  // that have registered through RegisterSuspendDelay() should tell the power
  // manager that they're ready to suspend by calling ReportSuspendReadiness()
  // with the delay ID returned by RegisterSuspendDelay() and |suspend_id|.
  virtual void OnSuspendImminent(int suspend_id) = 0;

  // Broadcast by the power manager when a suspend attempt has completed.
  virtual void OnSuspendDone(int suspend_id, int64_t suspend_duration_us) = 0;

  // Broadcast by the power manager when the system enters dark resume.
  // Delegates that have registered through RegisterDarkSuspendDelay() should
  // tell the power manager when they are ready to suspend from the dark resume
  // by calling ReportDarkSuspendResume() with the delay ID returned by
  // RegisterDarkSuspendDelay() and |suspend_id|.
  virtual void OnDarkSuspendImminent(int suspend_id) = 0;
};

}  // namespace shill

#endif  // SHILL_POWER_MANAGER_PROXY_INTERFACE_H_
