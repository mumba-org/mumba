// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_GPU_GPU_PROCESS_H_
#define CONTENT_GPU_GPU_PROCESS_H_

#include "base/macros.h"
#include "core/shared/common/child_process.h"

namespace gpu {

class GpuProcess : public common::ChildProcess {
 public:
  explicit GpuProcess(base::ThreadPriority io_thread_priority);
  ~GpuProcess() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(GpuProcess);
};

}

#endif  // CONTENT_GPU_GPU_PROCESS_H_
