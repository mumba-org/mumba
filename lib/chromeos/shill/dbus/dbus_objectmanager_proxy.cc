// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_objectmanager_proxy.h"

#include "shill/cellular/cellular_error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const dbus::ObjectPath* p) {
  return p->value();
}
}  // namespace Logging

DBusObjectManagerProxy::DBusObjectManagerProxy(
    EventDispatcher* dispatcher,
    const scoped_refptr<dbus::Bus>& bus,
    const RpcIdentifier& path,
    const std::string& service,
    const base::Closure& service_appeared_callback,
    const base::Closure& service_vanished_callback)
    : proxy_(
          new org::freedesktop::DBus::ObjectManagerProxy(bus, service, path)),
      dispatcher_(dispatcher),
      service_appeared_callback_(service_appeared_callback),
      service_vanished_callback_(service_vanished_callback),
      service_available_(false) {
  // Register signal handlers.
  proxy_->RegisterInterfacesAddedSignalHandler(
      base::Bind(&DBusObjectManagerProxy::InterfacesAdded,
                 weak_factory_.GetWeakPtr()),
      base::Bind(&DBusObjectManagerProxy::OnSignalConnected,
                 weak_factory_.GetWeakPtr()));
  proxy_->RegisterInterfacesRemovedSignalHandler(
      base::Bind(&DBusObjectManagerProxy::InterfacesRemoved,
                 weak_factory_.GetWeakPtr()),
      base::Bind(&DBusObjectManagerProxy::OnSignalConnected,
                 weak_factory_.GetWeakPtr()));

  // Monitor service owner changes. This callback lives for the lifetime of
  // the ObjectProxy.
  proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(
      base::Bind(&DBusObjectManagerProxy::OnServiceOwnerChanged,
                 weak_factory_.GetWeakPtr()));

  // One time callback when service becomes available.
  proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(base::Bind(
      &DBusObjectManagerProxy::OnServiceAvailable, weak_factory_.GetWeakPtr()));
}

DBusObjectManagerProxy::~DBusObjectManagerProxy() = default;

void DBusObjectManagerProxy::GetManagedObjects(
    Error* error, const ManagedObjectsCallback& callback, int timeout) {
  if (!service_available_) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          "Service not available");
    return;
  }
  proxy_->GetManagedObjectsAsync(
      base::Bind(&DBusObjectManagerProxy::OnGetManagedObjectsSuccess,
                 weak_factory_.GetWeakPtr(), callback),
      base::Bind(&DBusObjectManagerProxy::OnGetManagedObjectsFailure,
                 weak_factory_.GetWeakPtr(), callback),
      timeout);
}

void DBusObjectManagerProxy::OnServiceAvailable(bool available) {
  LOG(INFO) << __func__ << ": " << available;

  // The callback might invoke calls to the ObjectProxy, so defer the callback
  // to event loop.
  if (available && !service_appeared_callback_.is_null()) {
    dispatcher_->PostTask(FROM_HERE, service_appeared_callback_);
  } else if (!available && !service_vanished_callback_.is_null()) {
    dispatcher_->PostTask(FROM_HERE, service_vanished_callback_);
  }
  service_available_ = available;
}

void DBusObjectManagerProxy::OnServiceOwnerChanged(
    const std::string& old_owner, const std::string& new_owner) {
  LOG(INFO) << __func__ << " old: " << old_owner << " new: " << new_owner;
  if (new_owner.empty()) {
    OnServiceAvailable(false);
  } else {
    OnServiceAvailable(true);
  }
}

void DBusObjectManagerProxy::OnSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << ": interface: " << interface_name
      << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

void DBusObjectManagerProxy::InterfacesAdded(
    const dbus::ObjectPath& object_path,
    const DBusInterfaceToProperties& dbus_interface_to_properties) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << "(" << object_path.value() << ")";
  InterfaceToProperties interface_to_properties;
  ConvertDBusInterfaceProperties(dbus_interface_to_properties,
                                 &interface_to_properties);
  interfaces_added_callback_.Run(object_path, interface_to_properties);
}

void DBusObjectManagerProxy::InterfacesRemoved(
    const dbus::ObjectPath& object_path,
    const std::vector<std::string>& interfaces) {
  SLOG(&proxy_->GetObjectPath(), 2)
      << __func__ << "(" << object_path.value() << ")";
  interfaces_removed_callback_.Run(object_path, interfaces);
}

void DBusObjectManagerProxy::OnGetManagedObjectsSuccess(
    const ManagedObjectsCallback& callback,
    const DBusObjectsWithProperties& dbus_objects_with_properties) {
  SLOG(&proxy_->GetObjectPath(), 2) << __func__;
  ObjectsWithProperties objects_with_properties;
  for (const auto& object : dbus_objects_with_properties) {
    InterfaceToProperties interface_to_properties;
    ConvertDBusInterfaceProperties(object.second, &interface_to_properties);
    objects_with_properties.emplace(object.first.value(),
                                    interface_to_properties);
  }
  callback.Run(objects_with_properties, Error());
}

void DBusObjectManagerProxy::OnGetManagedObjectsFailure(
    const ManagedObjectsCallback& callback, brillo::Error* dbus_error) {
  Error error;
  CellularError::FromMM1ChromeosDBusError(dbus_error, &error);
  callback.Run(ObjectsWithProperties(), error);
}

void DBusObjectManagerProxy::ConvertDBusInterfaceProperties(
    const DBusInterfaceToProperties& dbus_interface_to_properties,
    InterfaceToProperties* interface_to_properties) {
  for (const auto& interface : dbus_interface_to_properties) {
    KeyValueStore properties =
        KeyValueStore::ConvertFromVariantDictionary(interface.second);
    interface_to_properties->emplace(interface.first, properties);
  }
}

}  // namespace shill
