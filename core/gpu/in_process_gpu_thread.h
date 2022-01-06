// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_GPU_IN_PROCESS_GPU_THREAD_H_
#define CONTENT_GPU_IN_PROCESS_GPU_THREAD_H_

#include <memory>

#include "base/macros.h"
#include "base/threading/thread.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/in_process_child_thread_params.h"
#include "gpu/command_buffer/service/gpu_preferences.h"

namespace gpu {

class GpuProcess;

// This class creates a GPU thread (instead of a GPU process), when running
// with --in-process-gpu or --single-process.
class InProcessGpuThread : public base::Thread {
 public:
  explicit InProcessGpuThread(const common::InProcessChildThreadParams& params,
                              const gpu::GpuPreferences& gpu_preferences);
  ~InProcessGpuThread() override;

 protected:
  void Init() override;
  void CleanUp() override;

 private:
  common::InProcessChildThreadParams params_;

  // Deleted in CleanUp() on the gpu thread, so don't use smart pointers.
  GpuProcess* gpu_process_;

  gpu::GpuPreferences gpu_preferences_;

  DISALLOW_COPY_AND_ASSIGN(InProcessGpuThread);
};

CONTENT_EXPORT base::Thread* CreateInProcessGpuThread(
    const common::InProcessChildThreadParams& params,
    const gpu::GpuPreferences& gpu_preferences);

}  // namespace gpu

#endif  // CONTENT_GPU_IN_PROCESS_GPU_THREAD_H_
