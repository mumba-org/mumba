// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_METHOD_NAME_GENERATOR_H_
#define CHROMEOS_DBUS_BINDINGS_METHOD_NAME_GENERATOR_H_

#include <string>
#include <vector>

#include <base/macros.h>

namespace base {

class FilePath;

}  // namespace base

namespace chromeos_dbus_bindings {

struct Interface;

class MethodNameGenerator {
 public:
  MethodNameGenerator(const MethodNameGenerator&) = delete;
  MethodNameGenerator& operator=(const MethodNameGenerator&) = delete;
  static bool GenerateMethodNames(const std::vector<Interface>& interfaces,
                                  const base::FilePath& output_file);

 private:
  friend class MethodNameGeneratorTest;
};

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_METHOD_NAME_GENERATOR_H_
