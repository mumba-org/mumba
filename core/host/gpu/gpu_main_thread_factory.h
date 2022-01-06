// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GPU_GPU_MAIN_THREAD_FACTORY_H_
#define CONTENT_BROWSER_GPU_GPU_MAIN_THREAD_FACTORY_H_

#include "core/shared/common/content_export.h"

namespace base {
class Thread;
}

namespace gpu {
struct GpuPreferences;
}

namespace common {
class InProcessChildThreadParams;
}

namespace host {

typedef base::Thread* (*GpuMainThreadFactoryFunction)(
    const common::InProcessChildThreadParams&,
    const gpu::GpuPreferences&);

CONTENT_EXPORT void RegisterGpuMainThreadFactory(
    GpuMainThreadFactoryFunction create);

GpuMainThreadFactoryFunction GetGpuMainThreadFactory();

}  // namespace host

#endif  // CONTENT_BROWSER_GPU_GPU_MAIN_THREAD_FACTORY_H_
