// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_SHARED_COMMON_CONTENT_CONSTANTS_INTERNAL_H_
#define CONTENT_SHARED_COMMON_CONTENT_CONSTANTS_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>

#include "core/shared/common/content_export.h"

namespace common {

// How long to wait before we consider a renderer hung.
CONTENT_EXPORT extern const int64_t kHungRendererDelayMs;

} // namespace content

#endif  // CONTENT_COMMON_CONTENT_CONSTANTS_INTERNAL_H_
