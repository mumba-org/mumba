// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/resource_type.h"

namespace common {

bool IsResourceTypeFrame(ResourceType type) {
  return type == RESOURCE_TYPE_MAIN_FRAME || type == RESOURCE_TYPE_SUB_FRAME;
}

}  // namespace common
