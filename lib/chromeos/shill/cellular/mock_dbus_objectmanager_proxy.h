// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_DBUS_OBJECTMANAGER_PROXY_H_
#define SHILL_CELLULAR_MOCK_DBUS_OBJECTMANAGER_PROXY_H_

#include <gmock/gmock.h>

#include "shill/cellular/dbus_objectmanager_proxy_interface.h"

namespace shill {

class MockDBusObjectManagerProxy : public DBusObjectManagerProxyInterface {
 public:
  MockDBusObjectManagerProxy();
  MockDBusObjectManagerProxy(const MockDBusObjectManagerProxy&) = delete;
  MockDBusObjectManagerProxy& operator=(const MockDBusObjectManagerProxy&) =
      delete;

  ~MockDBusObjectManagerProxy() override;

  MOCK_METHOD(void,
              GetManagedObjects,
              (Error*, const ManagedObjectsCallback&, int),
              (override));
  MOCK_METHOD(void,
              set_interfaces_added_callback,
              (const InterfacesAddedSignalCallback&),
              (override));
  MOCK_METHOD(void,
              set_interfaces_removed_callback,
              (const InterfacesRemovedSignalCallback&),
              (override));
  void IgnoreSetCallbacks();
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_DBUS_OBJECTMANAGER_PROXY_H_
