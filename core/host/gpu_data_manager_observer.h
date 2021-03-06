// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_GPU_DATA_MANAGER_OBSERVER_H_
#define CONTENT_PUBLIC_BROWSER_GPU_DATA_MANAGER_OBSERVER_H_

#include "base/process/kill.h"
#include "core/shared/common/content_export.h"

namespace host {

// Observers can register themselves via GpuDataManager::AddObserver, and
// can un-register with GpuDataManager::RemoveObserver.
class CONTENT_EXPORT GpuDataManagerObserver {
 public:
  // Called for any observers whenever there is a GPU info update.
  virtual void OnGpuInfoUpdate() {}

  // Called for any observer when the GPU process crashed.
  virtual void OnGpuProcessCrashed(base::TerminationStatus exit_code) {}

 protected:
  virtual ~GpuDataManagerObserver() {}
};

};  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_GPU_DATA_MANAGER_OBSERVER_H_
