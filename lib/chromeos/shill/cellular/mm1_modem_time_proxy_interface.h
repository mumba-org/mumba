// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MM1_MODEM_TIME_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_MM1_MODEM_TIME_PROXY_INTERFACE_H_

#include <string>

#include "shill/callbacks.h"

namespace shill {
class Error;

namespace mm1 {

using NetworkTimeChangedSignalCallback =
    base::Callback<void(const std::string&)>;

// These are the methods that an org.freedesktop.ModemManager1.Modem.Time
// proxy must support. The interface is provided so that it can be mocked
// in tests. All calls are made asynchronously. Call completion is signalled
// via callbacks passed to the methods.
class ModemTimeProxyInterface {
 public:
  virtual ~ModemTimeProxyInterface() = default;

  virtual void GetNetworkTime(Error* error,
                              const StringCallback& callback,
                              int timeout) = 0;

  virtual void set_network_time_changed_callback(
      const NetworkTimeChangedSignalCallback& callback) = 0;
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MM1_MODEM_TIME_PROXY_INTERFACE_H_
