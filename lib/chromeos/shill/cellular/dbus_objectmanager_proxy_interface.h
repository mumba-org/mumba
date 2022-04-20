// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_
#define SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_

#include <map>
#include <string>
#include <vector>

#include <base/callback.h>

#include "shill/store/key_value_store.h"

namespace shill {

class Error;

using InterfaceToProperties = std::map<std::string, KeyValueStore>;
using ObjectsWithProperties = std::map<RpcIdentifier, InterfaceToProperties>;
using ManagedObjectsCallback =
    base::Callback<void(const ObjectsWithProperties&, const Error&)>;
using InterfaceAndPropertiesCallback =
    base::Callback<void(const InterfaceToProperties&, const Error&)>;
using InterfacesAddedSignalCallback =
    base::Callback<void(const RpcIdentifier&, const InterfaceToProperties&)>;
using InterfacesRemovedSignalCallback =
    base::Callback<void(const RpcIdentifier&, const std::vector<std::string>&)>;

// These are the methods that a org.freedesktop.DBus.ObjectManager
// proxy must support.  The interface is provided so that it can be
// mocked in tests.  All calls are made asynchronously. Call completion
// is signalled via the callbacks passed to the methods.
class DBusObjectManagerProxyInterface {
 public:
  virtual ~DBusObjectManagerProxyInterface() = default;
  virtual void GetManagedObjects(Error* error,
                                 const ManagedObjectsCallback& callback,
                                 int timeout) = 0;
  virtual void set_interfaces_added_callback(
      const InterfacesAddedSignalCallback& callback) = 0;
  virtual void set_interfaces_removed_callback(
      const InterfacesRemovedSignalCallback& callback) = 0;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_DBUS_OBJECTMANAGER_PROXY_INTERFACE_H_
