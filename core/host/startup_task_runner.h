// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STARTUP_TASK_RUNNER_H_
#define MUMBA_HOST_STARTUP_TASK_RUNNER_H_

#include <list>

#include "base/callback.h"
#include "base/single_thread_task_runner.h"

#include "build/build_config.h"

namespace host {

// A startup task is a void function returning the status on completion.
// a status of > 0 indicates a failure, and that no further startup tasks should
// be run.
typedef base::Callback<int(void)> StartupTask;

class StartupTaskRunner {
public:
 StartupTaskRunner(base::Callback<void(int)> startup_complete_callback,
                    scoped_refptr<base::SingleThreadTaskRunner> proxy);

 ~StartupTaskRunner();

 // Add a task to the queue of startup tasks to be run.
 void AddTask(StartupTask& callback);

 // Start running the tasks asynchronously.
 void StartRunningTasksAsync();

 // Run all tasks, or all remaining tasks, synchronously
 void RunAllTasksNow();

private:
 friend class base::RefCounted<StartupTaskRunner>;

 std::list<StartupTask> task_list_;
 void WrappedTask();

 base::Callback<void(int)> startup_complete_callback_;
 scoped_refptr<base::SingleThreadTaskRunner> proxy_;

 DISALLOW_COPY_AND_ASSIGN(StartupTaskRunner);
};

}

#endif // MUMBA_HOST_STARTUP_TASK_RUNNER_H_
