// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_H_
#define SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_H_

namespace shill {

class MockDBusServiceWatcher : public DBusServiceWatcher {
 public:
  MockDBusServiceWatcher() = default;
};

}  // namespace shill

#endif  // SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_H_
