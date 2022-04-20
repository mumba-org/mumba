// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_SERVICE_WATCHER_FACTORY_H_
#define SHILL_DBUS_DBUS_SERVICE_WATCHER_FACTORY_H_

#include <memory>
#include <string>

#include <base/callback.h>
#include <base/no_destructor.h>
#include <dbus/bus.h>

namespace shill {

class DBusServiceWatcher;

class DBusServiceWatcherFactory {
 public:
  virtual ~DBusServiceWatcherFactory();

  // This is a singleton. Use DBusServiceWatcherFactory::GetInstance()->Foo().
  static DBusServiceWatcherFactory* GetInstance();

  virtual std::unique_ptr<DBusServiceWatcher> CreateDBusServiceWatcher(
      scoped_refptr<dbus::Bus> bus,
      const std::string& connection_name,
      const base::Closure& on_connection_vanish);

 protected:
  DBusServiceWatcherFactory();
  DBusServiceWatcherFactory(const DBusServiceWatcherFactory&) = delete;
  DBusServiceWatcherFactory& operator=(const DBusServiceWatcherFactory&) =
      delete;

 private:
  friend class base::NoDestructor<DBusServiceWatcherFactory>;
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_SERVICE_WATCHER_FACTORY_H_
