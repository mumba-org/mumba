// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_SERVICE_WATCHER_H_
#define SHILL_DBUS_DBUS_SERVICE_WATCHER_H_

#include <memory>
#include <string>

#include <brillo/dbus/dbus_service_watcher.h>

namespace shill {

// Wrapper for brillo::dbus::DBusServiceWatcher for monitoring remote
// DBus service.
class DBusServiceWatcher {
 public:
  DBusServiceWatcher(scoped_refptr<dbus::Bus> bus,
                     const std::string& connection_name,
                     const base::Closure& on_connection_vanished);
  DBusServiceWatcher(const DBusServiceWatcher&) = delete;
  DBusServiceWatcher& operator=(const DBusServiceWatcher&) = delete;

  ~DBusServiceWatcher();

 protected:
  DBusServiceWatcher() = default;  // for mocking.

 private:
  std::unique_ptr<brillo::dbus_utils::DBusServiceWatcher> watcher_;
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_SERVICE_WATCHER_H_
