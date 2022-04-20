// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_FACTORY_H_
#define SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_FACTORY_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include "shill/dbus/dbus_service_watcher_factory.h"

namespace shill {

class MockDBusServiceWatcherFactory : public DBusServiceWatcherFactory {
 public:
  MockDBusServiceWatcherFactory() = default;
  MockDBusServiceWatcherFactory(const MockDBusServiceWatcherFactory&) = delete;
  MockDBusServiceWatcherFactory& operator=(
      const MockDBusServiceWatcherFactory&) = delete;

  virtual ~MockDBusServiceWatcherFactory() = default;

  MOCK_METHOD(std::unique_ptr<DBusServiceWatcher>,
              CreateDBusServiceWatcher,
              (scoped_refptr<dbus::Bus>,
               const std::string&,
               const base::Closure&),
              (override));
};

}  // namespace shill

#endif  // SHILL_DBUS_MOCK_DBUS_SERVICE_WATCHER_FACTORY_H_
