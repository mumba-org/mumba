// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_SERVICE_CONFIG_H_
#define CHROMEOS_DBUS_BINDINGS_SERVICE_CONFIG_H_

#include <string>
#include <vector>

namespace chromeos_dbus_bindings {

// General D-Bus service configuration settings used by Adaptor/Proxy code
// generators.
struct ServiceConfig {
  // D-Bus service name to be used when constructing proxy objects.
  // If omitted (empty), the service name parameter will be added to the
  // constructor of generated proxy class(es).
  std::string service_name;
  // Object Manager settings.
  struct {
    // The name of the Object Manager class to use. If empty, no object manager
    // is generated in the proxy code (this also disables property support on
    // proxy objects).
    // This is a "fake" name used to generate namespaces and the actual class
    // name for the object manager proxy. This name has no relationship to the
    // actual D-Bus properties of the actual object manager.
    std::string name;
    // The D-Bus path to Object Manager instance.
    std::string object_path;
  } object_manager;

  // A list of interfaces we should ignore and not generate any adaptors and
  // proxies for.
  std::vector<std::string> ignore_interfaces;
};

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_SERVICE_CONFIG_H_
