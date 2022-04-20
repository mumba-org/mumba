// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_ADAPTOR_GENERATOR_H_
#define CHROMEOS_DBUS_BINDINGS_ADAPTOR_GENERATOR_H_

#include <string>
#include <vector>

#include <base/macros.h>

#include "chromeos-dbus-bindings/indented_text.h"

namespace base {

class FilePath;

}  // namespace base

namespace chromeos_dbus_bindings {

class IndentedText;
struct Interface;

class AdaptorGenerator {
 public:
  AdaptorGenerator();
  AdaptorGenerator(const AdaptorGenerator&) = delete;
  AdaptorGenerator& operator=(const AdaptorGenerator&) = delete;

  bool GenerateAdaptors(const std::vector<Interface>& interfaces,
                        const base::FilePath& output_file);

 private:
  friend class AdaptorGeneratorTest;

  // Generates one interface adaptor.
  void GenerateInterfaceAdaptor(const Interface& interface, IndentedText* text);

  // Generates the method prototypes for an interface declaration.
  void AddInterfaceMethods(const Interface& interface, IndentedText* text);

  // Generates the constructor for the adaptor.
  void AddConstructor(const Interface& interface,
                      const std::string& class_name,
                      const std::string& itf_name,
                      IndentedText* text);

  // Generates RegisterWithDBusObject() method.
  void AddRegisterWithDBusObject(const std::string& itf_name,
                                 const Interface& interface,
                                 IndentedText* text);

  // Generates the code to register the interface with a D-Bus object.
  void RegisterInterface(const std::string& itf_name,
                         const Interface& interface,
                         IndentedText* text);

  // Generates adaptor methods to send the signals.
  void AddSendSignalMethods(const Interface& interface, IndentedText* text);

  // Generates DBusSignal data members for the signals.
  void AddSignalDataMembers(const Interface& interface, IndentedText* text);

  // Generates adaptor accessor methods for the properties.
  void AddPropertyMethodImplementation(const Interface& interface,
                                       IndentedText* text);

  // Generate ExportProperty data members for the properties.
  void AddPropertyDataMembers(const Interface& interface, IndentedText* text);

  // Generate a static method that returns a const char* that contains the
  // introspection interface for this particular interface.
  void GenerateQuotedIntrospectionForInterface(const Interface& interface,
                                               IndentedText* text);
};

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_ADAPTOR_GENERATOR_H_
