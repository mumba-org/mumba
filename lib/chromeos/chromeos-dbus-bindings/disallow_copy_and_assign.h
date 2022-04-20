// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_DISALLOW_COPY_AND_ASSIGN_H_
#define CHROMEOS_DBUS_BINDINGS_DISALLOW_COPY_AND_ASSIGN_H_

#include "chromeos-dbus-bindings/indented_text.h"

#include <string>

namespace chromeos_dbus_bindings {
// Add 2 lines of code to delete the copy-constructor and assign-constructor
// into text.
void AddDisallowCopyAndAssign(const std::string& class_name,
                              IndentedText* text);
}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_DISALLOW_COPY_AND_ASSIGN_H_
