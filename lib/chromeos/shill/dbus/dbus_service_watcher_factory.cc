// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_service_watcher_factory.h"

#include <memory>

#include "shill/dbus/dbus_service_watcher.h"

namespace shill {

DBusServiceWatcherFactory::DBusServiceWatcherFactory() = default;
DBusServiceWatcherFactory::~DBusServiceWatcherFactory() = default;

DBusServiceWatcherFactory* DBusServiceWatcherFactory::GetInstance() {
  static base::NoDestructor<DBusServiceWatcherFactory> instance;
  return instance.get();
}

std::unique_ptr<DBusServiceWatcher>
DBusServiceWatcherFactory::CreateDBusServiceWatcher(
    scoped_refptr<dbus::Bus> bus,
    const std::string& connection_name,
    const base::Closure& on_connection_vanish) {
  return std::make_unique<DBusServiceWatcher>(bus, connection_name,
                                              on_connection_vanish);
}

}  // namespace shill
