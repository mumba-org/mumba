// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_TASK_SCHEDULER_
#define CONTENT_COMMON_TASK_SCHEDULER_

#include "core/shared/common/content_export.h"

namespace common {

// Returns the minimum number of threads that the TaskScheduler foreground pool
// must have in a process that runs a renderer.
int GetMinThreadsInRendererTaskSchedulerForegroundPool();

}  // namespace common

#endif  // CONTENT_COMMON_TASK_SCHEDULER_
