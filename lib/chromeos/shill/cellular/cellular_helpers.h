// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_HELPERS_H_
#define SHILL_CELLULAR_CELLULAR_HELPERS_H_

#include <string>

#include "shill/data_types.h"

namespace shill {

// Gets a printable value from a Stringmap without adding a value when it
// doesn't exist. Return an empty string as the default value.
std::string GetStringmapValue(const Stringmap& string_map,
                              const std::string& key,
                              const std::string& default_value = "");

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_HELPERS_H_
