// Copyright 2014 The Chromium Authors. All rights reserved.
// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_SHARED_COMMON_COMPOSITOR_DEPENDENCIES_H_
#define MUMBA_CORE_SHARED_COMMON_COMPOSITOR_DEPENDENCIES_H_

#include <memory>
#include <vector>

#include "base/memory/ref_counted.h"
#include "components/viz/common/display/renderer_settings.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace cc {
class TaskGraphRunner;
class UkmRecorderFactory;
}

namespace blink {
namespace scheduler {
class WebMainThreadScheduler;
}
}

namespace gpu {
class GpuMemoryBufferManager;
class ImageFactory;
}

namespace viz {
class SharedBitmapManager;   
}

namespace common {
class CompositorHelper;

class CompositorDependencies {
 public:
  virtual bool IsGpuRasterizationForced() = 0;
  virtual int GetGpuRasterizationMSAASampleCount() = 0;
  virtual bool IsLcdTextEnabled() = 0;
  virtual bool IsZeroCopyEnabled() = 0;
  virtual bool IsPartialRasterEnabled() = 0;
  virtual bool IsGpuMemoryBufferCompositorResourcesEnabled() = 0;
  virtual bool IsElasticOverscrollEnabled() = 0;
  virtual scoped_refptr<base::SingleThreadTaskRunner> GetCompositorMainThreadTaskRunner() = 0;
  // Returns null if the compositor is in single-threaded mode (ie. there is no
  // compositor thread).
  virtual scoped_refptr<base::SingleThreadTaskRunner> GetCompositorImplThreadTaskRunner() = 0;
  virtual blink::scheduler::WebMainThreadScheduler* GetWebMainThreadScheduler() = 0;
  virtual cc::TaskGraphRunner* GetTaskGraphRunner() = 0;
  virtual gpu::GpuMemoryBufferManager* GetGpuMemoryBufferManager() = 0;
  virtual bool IsThreadedAnimationEnabled() = 0;
  virtual bool IsScrollAnimatorEnabled() = 0;
  virtual std::unique_ptr<cc::UkmRecorderFactory> CreateUkmRecorderFactory() = 0;
  virtual viz::SharedBitmapManager* GetSharedBitmapManager() = 0;
  virtual gpu::ImageFactory* GetImageFactory() = 0;
  virtual CompositorHelper* compositor_helper() = 0;
  virtual ~CompositorDependencies() {}
};

}  // namespace common

#endif
