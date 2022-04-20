// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos-dbus-bindings/disallow_copy_and_assign.h"

#include <base/strings/stringprintf.h>

namespace chromeos_dbus_bindings {

void AddDisallowCopyAndAssign(const std::string& class_name,
                              IndentedText* text) {
  text->AddLine(base::StringPrintf("%s(const %s&) = delete;",
                                   class_name.c_str(), class_name.c_str()));
  text->AddLine(base::StringPrintf("%s& operator=(const %s&) = delete;",
                                   class_name.c_str(), class_name.c_str()));
}

}  // namespace chromeos_dbus_bindings
