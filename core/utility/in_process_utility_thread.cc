// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/utility/in_process_utility_thread.h"

#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/shared/common/child_process.h"
#include "core/utility/utility_thread_impl.h"

namespace utility {

// We want to ensure there's only one utility thread running at a time, as there
// are many globals used in the utility process.
static base::LazyInstance<base::Lock>::DestructorAtExit
    g_one_utility_thread_lock;

InProcessUtilityThread::InProcessUtilityThread(
    const common::InProcessChildThreadParams& params)
    : Thread("Chrome_InProcUtilityThread"), params_(params) {
}

InProcessUtilityThread::~InProcessUtilityThread() {
  // Wait till in-process utility thread finishes clean up.
  bool previous_value = base::ThreadRestrictions::SetIOAllowed(true);
  Stop();
  base::ThreadRestrictions::SetIOAllowed(previous_value);
}

void InProcessUtilityThread::Init() {
  // We need to return right away or else the main thread that started us will
  // hang.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&InProcessUtilityThread::InitInternal,
                                base::Unretained(this)));
}

void InProcessUtilityThread::CleanUp() {
  child_process_.reset();

  // See comment in RendererMainThread.
  SetThreadWasQuitProperly(true);
  g_one_utility_thread_lock.Get().Release();
}

void InProcessUtilityThread::InitInternal() {
  g_one_utility_thread_lock.Get().Acquire();
  child_process_.reset(new common::ChildProcess());
  child_process_->set_main_thread(new UtilityThreadImpl(params_));
}

base::Thread* CreateInProcessUtilityThread(
    const common::InProcessChildThreadParams& params) {
  return new InProcessUtilityThread(params);
}

}  // namespace content
