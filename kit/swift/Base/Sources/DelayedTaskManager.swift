// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public final class DelayedTaskManager {

  public typealias PostTaskNowCallback = (_:Task) -> Void

  let tickClock: TickClock

  var started: AtomicFlag = AtomicFlag()

  let lock: Lock = Lock()

  var serviceThreadTaskRunner: TaskRunner?
  
  var tasksAddedBeforeStart: Array<(Task, PostTaskNowCallback)> = []

  public init(tickClock: TickClock) {
    self.tickClock = tickClock
  }

  public func start(taskRunner serviceThreadTaskRunner: TaskRunner) {
    
    var tasksAddedBeforeStartCopy: Array<(Task, PostTaskNowCallback)> = []

    lock.withLockVoid {
      self.serviceThreadTaskRunner = serviceThreadTaskRunner
      tasksAddedBeforeStartCopy = self.tasksAddedBeforeStart
      started.set()
    }

    let now: TimeTicks = tickClock.nowTicks
   
    for taskAndCallback in tasksAddedBeforeStartCopy {
      let delay: TimeDelta = max(TimeDelta(), taskAndCallback.0.delayedRunTime - now)
      addDelayedTaskNow(task: taskAndCallback.0, delay: delay, callback: taskAndCallback.1)
    }
  }

  public func addDelayedTask(_ task: Task, callback: @escaping PostTaskNowCallback) {
    let delay: TimeDelta = task.delay
    if started.isSet {
      addDelayedTaskNow(task: task, delay: delay, callback: callback)
    } else {
      lock.withLockVoid {
        if started.isSet {
          addDelayedTaskNow(task: task, delay: delay, callback: callback)
        } else {
          tasksAddedBeforeStart.append((task, callback))
        }
      }
    }
  }

  func addDelayedTaskNow(task: Task,
                         delay: TimeDelta,
                         callback: @escaping PostTaskNowCallback) {
     guard let taskRunner = serviceThreadTaskRunner else {
       assert(false)
     }

     taskRunner.postDelayedTask(
      { callback(task) },
      delay: delay)
  }

}