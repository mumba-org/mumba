// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class IncomingTaskQueue {

  public var hasPendingHighResolutionTasks: Bool {
    return pendingHighResTasks > 0
  }

  internal var triageTasks: TriageQueue
  internal var delayedTasks: DelayedQueue
  internal var deferredTasks: DeferredQueue

  let taskAnnotator: TaskAnnotator = TaskAnnotator()
  let alwaysScheduleWork: Bool = true
  var pendingHighResTasks: Int = 0
  let messageLoopLock: Lock = Lock()
  weak var messageLoop: MessageLoop?
  let incomingQueueLock: Lock = Lock()
  var highResTaskCount: Int = 0
  var incomingQueue: TaskQueue = TaskQueue()
  var acceptNewTasks: Bool = true
  var nextSequenceNum: Int = 0
  var messageLoopScheduled: Bool = false
  var isReadyForScheduling: Bool = false

  public init(messageLoop: MessageLoop?) {
    self.messageLoop = messageLoop
    triageTasks = TriageQueue()
    delayedTasks = DelayedQueue()
    deferredTasks = DeferredQueue()

    triageTasks.outer = self
    delayedTasks.outer = self
    deferredTasks.outer = self
  }

  public func addToIncomingQueue(task: Closure,
                                 delay: TimeDelta,
                                 nestable: Nestable) -> Bool {
    var pendingTask = PendingTask(task: task, delayedRunTime: calculateDelayedRuntime(delay), nestable: nestable)
    #if os(Windows)
    // We consider the task needs a high resolution timer if the delay is
    // more than 0 and less than 32ms. This caps the relative error to
    // less than 50% : a 33ms wait can wake at 48ms since the default
    // resolution on Windows is between 10 and 15ms.
    if delay > TimeDelta() && delay.milliseconds < (2 * Time.MinLowResolutionThresholdMs) {
      pendingTask.isHighRes = true
    }
    #endif
    return postPendingTask(&pendingTask)
  }

  public func willDestroyCurrentMessageLoop() {
    incomingQueueLock.withLockVoid {
      self.acceptNewTasks = false
    }
    messageLoopLock.withLockVoid {
      messageLoop = nil
    }
  }

  public func startScheduling() {
    var scheduleWork: Bool = false
    incomingQueueLock.withLockVoid {
      isReadyForScheduling = true
      scheduleWork = !incomingQueue.isEmpty
      if scheduleWork {
        messageLoopScheduled = true
      }
    }
    if scheduleWork {
      messageLoopLock.withLockVoid {
        messageLoop!.scheduleWork()
      }
    }
  }

  public func runTask(_ pendingTask: PendingTask) throws {
    try taskAnnotator.runTask(pendingTask)
  }

  // private
  func postPendingTask(_ pendingTask: inout PendingTask) -> Bool {
    var acceptTasks: Bool = true
    var scheduleWork: Bool = false
    incomingQueueLock.withLockVoid {
      acceptTasks = self.acceptNewTasks
      if acceptTasks {
        scheduleWork = postPendingTaskLockRequired(pendingTask)
      }
    }

    if !acceptTasks {
      pendingTask.task = nil
      return false
    }

    if scheduleWork {
      messageLoopLock.withLockVoid {
        if let loop = messageLoop {
          loop.scheduleWork()
        }
      }
    }

    return true
  }

  func postPendingTaskLockRequired(_ pendingTask: PendingTask) -> Bool {
    incomingQueueLock.assertAcquired()

  #if os(Windows)
    if pendingTask.isHighRes {
      highResTaskCount += 1
    }
  #endif

    pendingTask.sequenceNum = nextSequenceNum
    nextSequenceNum += 1

    taskAnnotator.didQueueTask(pendingTask)

    let wasEmpty = incomingQueue.isEmpty
    incomingQueue.push(pendingTask)
     
    if isReadyForScheduling &&
        (alwaysScheduleWork || (!messageLoopScheduled && wasEmpty)) {
      messageLoopScheduled = true
      return true
    }
    return false
  }

  func reloadWorkQueue(_ workQueue: inout TaskQueue) -> Int {
    return incomingQueueLock.withLock {
      if incomingQueue.isEmpty {
        messageLoopScheduled = false
      } else {
        incomingQueue.swap(&workQueue)
      }
      // Reset the count of high resolution tasks since our queue is now empty.
      let highResTasks = highResTaskCount
      highResTaskCount = 0
      return highResTasks
    }
  }

}

internal protocol InternalReadAndRemoveOnlyQueue : class {
  var count: Int { get }
  func peek() -> PendingTask?
  func pop() -> PendingTask?
  func clear()
  func hasTasks() -> Bool
}

internal protocol InternalTaskQueue : InternalReadAndRemoveOnlyQueue {
  func push(_ task: PendingTask)
}

internal class TriageQueue : InternalReadAndRemoveOnlyQueue {

  var count: Int { return queue.count }
  weak var outer: IncomingTaskQueue?
  var queue: TaskQueue = TaskQueue()

  internal init() {}

  internal init(outer: IncomingTaskQueue) {
    self.outer = outer
  }
  
  internal func peek() -> PendingTask? {
    reloadFromIncomingQueueIfEmpty()
    return queue.peek()
  }

  internal func hasTasks() -> Bool {
    reloadFromIncomingQueueIfEmpty()
    return !queue.isEmpty
  }

  internal func pop() -> PendingTask? {
    reloadFromIncomingQueueIfEmpty()
    let pendingTask: PendingTask? = queue.pop()

    if let task = pendingTask, task.isHighRes {
      outer!.pendingHighResTasks -= 1
    }

    return pendingTask
  }

  internal func clear() {
    while !queue.isEmpty {
      let pendingTask: PendingTask? = queue.pop()!

      if let task = pendingTask, task.isHighRes {
        outer!.pendingHighResTasks -= 1
      }

      if let task = pendingTask, task.delayedRunTime.isNull {
        outer!.delayedTasks.push(task)
      }
    }
  }

  private func reloadFromIncomingQueueIfEmpty() {
    if queue.isEmpty {
      outer!.pendingHighResTasks += outer!.reloadWorkQueue(&queue)
    }
  }

}

internal class DelayedQueue : InternalTaskQueue {

  var count: Int { return queue.count }
  weak var outer: IncomingTaskQueue?
  var queue: DelayedTaskQueue = DelayedTaskQueue()

  internal init() {}

  internal init(outer: IncomingTaskQueue) {
    self.outer = outer
  }

  internal func peek() -> PendingTask? {
    return queue.peek()
  }

  internal func pop() -> PendingTask? {
    let delayedTask: PendingTask? = queue.pop()

    if let task = delayedTask, task.isHighRes {
      outer!.pendingHighResTasks -= 1
    }

    return delayedTask
  }

  internal func clear() {
    while !queue.isEmpty { 
      let _ = pop()
    }
  }
  
  internal func push(_ pendingTask: PendingTask) {
    if pendingTask.isHighRes {
      outer!.pendingHighResTasks += 1
    }
    queue.push(pendingTask)
  }

  internal func hasTasks() -> Bool {
    //while !queue.isEmpty && queue.peek()?.task?.isCancelled {
    while let task = queue.peek()?.task, task.isCancelled {
      let delayedTask = queue.pop()!
      if delayedTask.isHighRes {
        outer!.pendingHighResTasks -= 1
      }
    }

    return !queue.isEmpty
  }

}

internal class DeferredQueue : InternalTaskQueue {
  
  var count: Int { return queue.count }
  weak var outer: IncomingTaskQueue?
  var queue: TaskQueue = TaskQueue()

  internal init() {}

  internal init(outer: IncomingTaskQueue) {
    self.outer = outer
  }
  
  internal func peek() -> PendingTask? {
    return queue.peek()
  }

  internal func pop() -> PendingTask? {
    let deferredTask: PendingTask? = queue.pop()

    if let task = deferredTask, task.isHighRes {
      outer!.pendingHighResTasks -= 1
    }

    return deferredTask
  }

  internal func clear() {
    while !queue.isEmpty {
      let _ = pop()
    }
  }
  
  internal func push(_ pendingTask: PendingTask) {
    if pendingTask.isHighRes {
      outer!.pendingHighResTasks += 1
    }
    queue.push(pendingTask)
  }

  internal func hasTasks() -> Bool {
    return !queue.isEmpty
  }

}

fileprivate func calculateDelayedRuntime(_ delay: TimeDelta) -> TimeTicks {
  var delayedRunTime = TimeTicks()
  if delay > TimeDelta() {
    delayedRunTime = TimeTicks.now + delay
  } else {
    precondition(delay.milliseconds == 0, "delay should not be negative")
  }
  return delayedRunTime
}
