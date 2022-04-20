// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_helpers.h"

#include <base/containers/contains.h>

namespace shill {

std::string GetStringmapValue(const Stringmap& string_map,
                              const std::string& key,
                              const std::string& default_value) {
  if (!base::Contains(string_map, key))
    return default_value;

  return string_map.at(key);
}

}  // namespace shill
