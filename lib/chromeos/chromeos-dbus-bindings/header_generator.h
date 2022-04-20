// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_HEADER_GENERATOR_H_
#define CHROMEOS_DBUS_BINDINGS_HEADER_GENERATOR_H_

#include <string>

#include <base/macros.h>

namespace base {

class FilePath;

};

namespace chromeos_dbus_bindings {

constexpr int kScopeOffset = 1;
constexpr int kBlockOffset = 2;
constexpr int kLineContinuationOffset = 4;

class IndentedText;

// Create a unique header guard string to protect multiple includes of header.
std::string GenerateHeaderGuard(const base::FilePath& output_file);

// Writes indented text to a file.
bool WriteTextToFile(const base::FilePath& output_file,
                     const IndentedText& text);

// Generate a name of a method/signal argument based on the name provided in
// the XML file. If |arg_name| is empty, it generates a name using
// the |arg_index| counter.
std::string GetArgName(const char* prefix,
                       const std::string& arg_name,
                       int arg_index);

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_HEADER_GENERATOR_H_
