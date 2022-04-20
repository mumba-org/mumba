// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos-dbus-bindings/method_name_generator.h"

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>

#include "chromeos-dbus-bindings/header_generator.h"
#include "chromeos-dbus-bindings/indented_text.h"
#include "chromeos-dbus-bindings/interface.h"
#include "chromeos-dbus-bindings/name_parser.h"

namespace chromeos_dbus_bindings {

bool MethodNameGenerator::GenerateMethodNames(
    const std::vector<Interface>& interfaces,
    const base::FilePath& output_file) {
  std::string contents;
  IndentedText text;
  for (const auto& interface : interfaces) {
    text.AddBlankLine();
    NameParser parser{interface.name};
    parser.AddOpenNamespaces(&text, true);
    for (const auto& method : interface.methods) {
      text.AddLine(base::StringPrintf("const char k%sMethod[] = \"%s\";",
                                      method.name.c_str(),
                                      method.name.c_str()));
    }
    parser.AddCloseNamespaces(&text, true);
  }
  return WriteTextToFile(output_file, text);
}

}  // namespace chromeos_dbus_bindings
