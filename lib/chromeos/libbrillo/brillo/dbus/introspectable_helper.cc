// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/dbus/introspectable_helper.h>

#include <memory>

#include <base/bind.h>
#include <dbus/dbus-shared.h>

namespace brillo {
namespace dbus_utils {

using base::Bind;
using std::string;
using std::unique_ptr;

void IntrospectableInterfaceHelper::AddInterfaceXml(string xml) {
  interface_xmls.push_back(xml);
}

void IntrospectableInterfaceHelper::RegisterWithDBusObject(DBusObject* object) {
  DBusInterface* itf = object->AddOrGetInterface(DBUS_INTERFACE_INTROSPECTABLE);

  itf->AddMethodHandler("Introspect", GetHandler());
}

IntrospectableInterfaceHelper::IntrospectCallback
IntrospectableInterfaceHelper::GetHandler() {
  return Bind(
      [](const string& xml, StringResponse response) { response->Return(xml); },
      GetXmlString());
}

string IntrospectableInterfaceHelper::GetXmlString() {
  constexpr const char header[] =
      "<!DOCTYPE node PUBLIC "
      "\"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
      "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
      "\n"
      "<node>\n"
      "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
      "    <method name=\"Introspect\">\n"
      "      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
      "    </method>\n"
      "  </interface>\n"
      "  <interface name=\"org.freedesktop.DBus.Properties\">\n"
      "    <method name=\"Get\">\n"
      "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
      "      <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
      "      <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
      "    </method>\n"
      "    <method name=\"Set\">\n"
      "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
      "      <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
      "      <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
      "    </method>\n"
      "    <method name=\"GetAll\">\n"
      "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
      "      <arg name=\"props\" direction=\"out\" type=\"a{sv}\"/>\n"
      "    </method>\n"
      "  </interface>\n";
  constexpr const char footer[] = "</node>\n";

  size_t result_len = strlen(header) + strlen(footer);
  for (const string& xml : interface_xmls) {
    result_len += xml.size();
  }

  string result = header;
  result.reserve(result_len + 1);  // +1 for null terminator
  for (const string& xml : interface_xmls) {
    result.append(xml);
  }
  result.append(footer);
  return result;
}

}  // namespace dbus_utils
}  // namespace brillo
