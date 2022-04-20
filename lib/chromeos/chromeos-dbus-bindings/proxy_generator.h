// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_PROXY_GENERATOR_H_
#define CHROMEOS_DBUS_BINDINGS_PROXY_GENERATOR_H_

#include <string>
#include <vector>

#include <base/macros.h>

#include "chromeos-dbus-bindings/indented_text.h"
#include "chromeos-dbus-bindings/interface.h"
#include "chromeos-dbus-bindings/service_config.h"

namespace base {

class FilePath;

}  // namespace base

namespace chromeos_dbus_bindings {

class IndentedText;
struct Interface;

class ProxyGenerator {
 public:
  ProxyGenerator();
  ProxyGenerator(const ProxyGenerator&) = delete;
  ProxyGenerator& operator=(const ProxyGenerator&) = delete;

  bool GenerateProxies(const ServiceConfig& config,
                       const std::vector<Interface>& interfaces,
                       const base::FilePath& output_file);

  bool GenerateMocks(const ServiceConfig& config,
                     const std::vector<Interface>& interfaces,
                     const base::FilePath& mock_file,
                     const base::FilePath& proxy_file,
                     bool use_literal_proxy_file);

 private:
  friend class ProxyGeneratorTest;

  // Generates an abstract interface for one D-Bus interface proxy.
  void GenerateInterfaceProxyInterface(const ServiceConfig& config,
                                       const Interface& interface,
                                       IndentedText* text);

  // Generates one interface proxy.
  void GenerateInterfaceProxy(const ServiceConfig& config,
                              const Interface& interface,
                              IndentedText* text);

  // Generates one interface mock object.
  void GenerateInterfaceMock(const ServiceConfig& config,
                             const Interface& interface,
                             IndentedText* text);

  // Generates the constructor and destructor for the proxy.
  void AddConstructor(const ServiceConfig& config,
                      const Interface& interface,
                      const std::string& class_name,
                      IndentedText* text);
  void AddDestructor(const std::string& class_name, IndentedText* text);

  // Generates ReleaseObjectProxy() method to release ownership
  // of the object proxy.
  void AddReleaseObjectProxy(IndentedText* text);

  // Generates AddGetObjectPath() method.
  void AddGetObjectPath(IndentedText* text);

  // Generates GetObjectProxy() method.
  void AddGetObjectProxy(IndentedText* text);

  // Generates InitializeProperties() method and callback.
  void AddInitializeProperties(const std::string& class_name,
                               bool declaration_only,
                               IndentedText* text);

  // Generates SetPropertyChanged() method and callback.
  void AddSetPropertyChanged(const std::string& class_name,
                             bool declaration_only,
                             IndentedText* text);

  // Generates GetProperties() methods.
  void AddGetProperties(IndentedText* text);

  // Generates OnPropertyChanged() method.
  void AddOnPropertyChanged(IndentedText* text);

  // Generates logic permitting users to register handlers for signals.
  void AddSignalHandlerRegistration(const Interface::Signal& signal,
                                    const std::string& interface_name,
                                    bool declaration_only,
                                    IndentedText* text);

  // Generates the property set class to contain interface properties.
  void AddPropertySet(const ServiceConfig& config,
                      const Interface& interface,
                      IndentedText* text);

  // Generates the property accessors.
  void AddProperties(const Interface& interface,
                     bool declaration_only,
                     IndentedText* text);

  // Generates a native C++ method which calls a D-Bus method on the proxy.
  void AddMethodProxy(const Interface::Method& interface,
                      const std::string& interface_name,
                      bool declaration_only,
                      IndentedText* text);

  // Generates a native C++ method which calls a D-Bus method asynchronously.
  void AddAsyncMethodProxy(const Interface::Method& interface,
                           const std::string& interface_name,
                           bool declaration_only,
                           IndentedText* text);

  // Generates a mock for blocking D-Bus method.
  void AddMethodMock(const Interface::Method& interface,
                     const std::string& interface_name,
                     IndentedText* text);

  // Generates a mock for asynchronous D-Bus method.
  void AddAsyncMethodMock(const Interface::Method& interface,
                          const std::string& interface_name,
                          IndentedText* text);

  // Generates the MOCK_METHOD entry for the given arguments handling methods
  // with more than 10 arguments.
  void AddMockMethodDeclaration(const std::string& method_name,
                                const std::string& return_type,
                                const std::vector<std::string>& arguments,
                                IndentedText* text);

  // Generates a mock for the signal handler registration method.
  void AddSignalHandlerRegistrationMock(const Interface::Signal& signal,
                                        IndentedText* text);

  // Generate the signal callback argument of a signal handler.
  void AddSignalCallbackArg(const Interface::Signal& signal,
                            bool comment_arg_name,
                            IndentedText* block);

  // Generates the Object Manager proxy class.
  struct ObjectManager {
    // Generates the top-level class for Object Manager proxy.
    static void GenerateProxy(const ServiceConfig& config,
                              const std::vector<Interface>& interfaces,
                              IndentedText* text);

    // Generates Object Manager constructor.
    static void AddConstructor(const ServiceConfig& config,
                               const std::string& class_name,
                               const std::vector<Interface>& interfaces,
                               IndentedText* text);

    // Generates Object Manager destructor.
    static void AddDestructor(const std::string& class_name,
                              const std::vector<Interface>& interfaces,
                              IndentedText* text);

    // Generates GetObjectManagerProxy() method.
    static void AddGetObjectManagerProxy(IndentedText* text);

    // Generates code for interface-specific accessor methods
    static void AddInterfaceAccessors(const Interface& interface,
                                      IndentedText* text);

    // Generates OnPropertyChanged() method.
    static void AddOnPropertyChanged(const std::vector<Interface>& interfaces,
                                     IndentedText* text);

    // Generates ObjectAdded() method.
    static void AddObjectAdded(const ServiceConfig& config,
                               const std::vector<Interface>& interfaces,
                               IndentedText* text);

    // Generates ObjectRemoved() method.
    static void AddObjectRemoved(const std::vector<Interface>& interfaces,
                                 IndentedText* text);

    // Generates CreateProperties() method.
    static void AddCreateProperties(const std::vector<Interface>& interfaces,
                                    const std::string& class_name,
                                    IndentedText* text);

    // Generates data members of the class.
    static void AddDataMembers(const ServiceConfig& config,
                               const std::vector<Interface>& interfaces,
                               const std::string& class_name,
                               IndentedText* text);
  };
  // Generates the signal handler name for a given signal name.
  std::string GetHandlerNameForSignal(const std::string& signal);
};

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_PROXY_GENERATOR_H_
