// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/content_constants_internal.h"

#include "build/build_config.h"

namespace common {

#if defined(OS_ANDROID)
const int64_t kHungRendererDelayMs = 5000;
#else
// TODO(jdduke): Consider shortening this delay on desktop. It was originally
// set to 5 seconds but was extended to accomodate less responsive plugins.
const int64_t kHungRendererDelayMs = 30000;
#endif

}