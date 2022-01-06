// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_APPLICATION_PROCESS_H_
#define MUMBA_APPLICATION_APPLICATION_PROCESS_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "base/at_exit.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "core/shared/common/content_export.h"

namespace application {
class ApplicationThread;

class CONTENT_EXPORT ApplicationProcess {
 public:

  ApplicationProcess(
      // we are meant to use them at stack scope.. but being
      // a wrapper, we have no option
      std::unique_ptr<base::AtExitManager> at_exit,
      base::ThreadPriority io_thread_priority = base::ThreadPriority::NORMAL,
      const std::string& task_scheduler_name = "ContentChild",
      std::unique_ptr<base::TaskScheduler::InitParams>
          task_scheduler_init_params = nullptr);
  virtual ~ApplicationProcess();

  ApplicationThread* main_thread();

  void Exit();

  void set_main_thread(ApplicationThread* thread);

  bool is_running() const {
    return is_running_;
  }

  base::MessageLoop* io_message_loop() { return io_thread_.message_loop(); }
  base::SingleThreadTaskRunner* io_task_runner() {
    return io_thread_.task_runner().get();
  }
  base::PlatformThreadId io_thread_id() { return io_thread_.GetThreadId(); }

  base::WaitableEvent* GetShutDownEvent();

  void AddRefProcess();
  void ReleaseProcess();

  static ApplicationProcess* current();

  std::unique_ptr<base::AtExitManager> ReleaseAtExitManager();

  void BindQuitClosure(base::Closure quit_closure) {
    quit_closure_ = std::move(quit_closure);
    is_running_ = true;
  }

 private:
  int ref_count_;

  base::WaitableEvent shutdown_event_;

  base::Thread io_thread_;

  std::unique_ptr<ApplicationThread> main_thread_;

  std::unique_ptr<base::AtExitManager> at_exit_;

  base::Closure quit_closure_;

  bool is_running_;

  bool initialized_task_scheduler_ = false;

  DISALLOW_COPY_AND_ASSIGN(ApplicationProcess);
};

extern ApplicationProcess* g_application_process;

}

#endif