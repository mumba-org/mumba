// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_process.h"

#include "base/run_loop.h"
#include "base/lazy_instance.h"
#include "base/deferred_sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/synchronization/waitable_event.h"
#include "base/system_monitor/system_monitor.h"
#include "base/task_scheduler/initialization_util.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/thread.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/timer/hi_res_timer_manager.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/bind.h"
#include "base/callback.h"
#include "core/shared/common/paths.h"
#include "base/uuid.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

namespace {

std::unique_ptr<base::TaskScheduler::InitParams> GetDefaultTaskSchedulerInitParams() {
#if defined(OS_ANDROID)
  // Mobile config, for iOS see ios/web/app/web_main_loop.cc.
  return std::make_unique<base::TaskScheduler::InitParams>(
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(4, 8, 0.1, 0),
          base::TimeDelta::FromSeconds(30)),
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(4, 8, 0.1, 0),
          base::TimeDelta::FromSeconds(30)),
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(4, 8, 0.3, 0),
          base::TimeDelta::FromSeconds(30)),
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(4, 8, 0.3, 0),
          base::TimeDelta::FromSeconds(60)));
#else
  // Desktop config.
  return std::make_unique<base::TaskScheduler::InitParams>(
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(6, 8, 0.1, 0),
          base::TimeDelta::FromSeconds(30)),
      base::SchedulerWorkerPoolParams(

          base::RecommendedMaxNumberOfThreadsInPool(6, 8, 0.1, 0),
          base::TimeDelta::FromSeconds(40)),
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(8, 32, 0.3, 0),
          base::TimeDelta::FromSeconds(30)),
      base::SchedulerWorkerPoolParams(
          base::RecommendedMaxNumberOfThreadsInPool(8, 32, 0.3, 0),
          base::TimeDelta::FromSeconds(60))
#if defined(OS_WIN)
          ,
      base::TaskScheduler::InitParams::SharedWorkerPoolEnvironment::COM_MTA
#endif  // defined(OS_WIN)
      );
#endif
}

}

std::unique_ptr<DomainProcess> DomainProcess::Create() {
  auto task_scheduler_init_params = GetDefaultTaskSchedulerInitParams();
  return base::WrapUnique(
      new DomainProcess("shell", std::move(task_scheduler_init_params)));
}

DomainProcess::DomainProcess(
  const std::string& task_scheduler_name,
  std::unique_ptr<base::TaskScheduler::InitParams> task_scheduler_init_params):
  common::ChildProcess(
    base::ThreadPriority::NORMAL,
    task_scheduler_name,
    std::move(task_scheduler_init_params)) {
 // disable disk io and wait on main thread
 base::ThreadRestrictions::SetIOAllowed(false);
 base::ThreadRestrictions::DisallowWaiting();
}

DomainProcess::~DomainProcess() {
  DomainMainThread* thread = DomainMainThread::current();
  if (thread && thread->domain_context()) {
    thread->domain_context()->Shutdown();
  }
}

}