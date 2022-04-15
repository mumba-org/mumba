// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_DBUS_INTROSPECTABLE_HELPER_H_
#define LIBBRILLO_BRILLO_DBUS_INTROSPECTABLE_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/brillo_export.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>

namespace brillo {
namespace dbus_utils {

// Note that brillo/dbus/dbus_object.h include files that include this file, so
// we'll need this forward declaration.
// class DBusObject;

// This is a helper class that is used for creating the DBus Introspectable
// Interface. Each of the interfaces that is exported under a DBus Object will
// add its dbus interface introspection XML to this class, and then the user of
// this class will call RegisterWithDBusObject on the DBus object. Then this
// class can be freed. Note that this class is usually used in conjunction with
// the chromeos-dbus-bindings tool. Simply pass the string returned by
// GetIntrospectionXML() of the generated adaptor. Usage example:
// {
//   IntrospectableInterfaceHelper helper;
//   helper.AddInterfaceXML("<interface...> ...</interface>");
//   helper.AddInterfaceXML("<interface...> ...</interface>");
//   helper.AddInterfaceXML(XXXAdaptor::GetIntrospect());
//   helper.RegisterWithDBusObject(object);
// }
class BRILLO_EXPORT IntrospectableInterfaceHelper {
 public:
  IntrospectableInterfaceHelper() = default;

  // Add the Introspection XML for an interface to this class. The |xml| string
  // should contain an interface XML tag and its content.
  void AddInterfaceXml(std::string xml);

  // Register the Introspectable Interface with a DBus object. Note that this
  // class can be freed after registering with DBus object.
  void RegisterWithDBusObject(DBusObject* object);

 private:
  // Internal alias for convenience.
  using StringResponse = std::unique_ptr<DBusMethodResponse<std::string>>;
  using IntrospectCallback = base::Callback<void(StringResponse)>;

  // Create the method handler for Introspect method call.
  IntrospectCallback GetHandler();

  // Get the complete introspection XML.
  std::string GetXmlString();

  // Stores the list of introspection XMLs for each of the interfaces that was
  // added to this class.
  std::vector<std::string> interface_xmls;
};

}  // namespace dbus_utils
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_DBUS_INTROSPECTABLE_HELPER_H_
