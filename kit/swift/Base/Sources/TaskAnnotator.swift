// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public final class TaskAnnotator {

  static let threadSpecificPendingTask = ThreadSpecificVariable<PendingTask>()

  public init() {}

  public func didQueueTask(_ task: PendingTask) {
    // if !task.taskBacktrace[0] {
    //   if let parentTask = threadSpecificPendingTask.currentValue {
    //     task.taskBacktrace[0] =
    //         parentTask.postedFrom.programCounter
        
    //     // TODO: not the same thing as bellow
    //     for tb in parentTask.taskBacktrace {
    //       task.append(tb)
    //     }
    //     // std::copy(parent_task->task_backtrace.begin(),
    //     //           parent_task->task_backtrace.end() - 1,
    //     //           pending_task.task_backtrace.begin() + 1)
    //   }
    // }
  }

  public func runTask(_ task: PendingTask) throws {
    guard let taskToRun = task.task else {
      print("TaskAnnotator.runTask: severe error: pending task to run has no task")
      return
    }

    let previousPendingTask = TaskAnnotator.threadSpecificPendingTask.currentValue
    TaskAnnotator.threadSpecificPendingTask.currentValue = task
    
    // run
    try taskToRun.call()

    TaskAnnotator.threadSpecificPendingTask.currentValue = previousPendingTask
  }
  
}