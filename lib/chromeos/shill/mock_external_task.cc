// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_external_task.h"

namespace shill {

MockExternalTask::MockExternalTask(
    ControlInterface* control,
    ProcessManager* process_manager,
    const base::WeakPtr<RpcTaskDelegate>& task_delegate,
    const base::Callback<void(pid_t, int)>& death_callback)
    : ExternalTask(control, process_manager, task_delegate, death_callback) {}

MockExternalTask::~MockExternalTask() {
  OnDelete();
}

}  // namespace shill
