// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum MessageLoopType {
  case IO
  case UI
  case custom
}

public class MessageLoop : MessageLoopCurrent,
                           MessagePumpDelegate,
                           RunLoopDelegate {
                             
  public static var current: MessageLoopCurrent { 
    return MessageLoopCurrent.instance
  }

  public static var isCurrent: Bool {
    return MessageLoopCurrent.isSet
  }

  public var type: MessageLoopType
  public var activeRunLoops: Queue<RunLoop> = Queue<RunLoop>()
  public var nestingObservers: [RunLoopNestingObserver] = []
  // RunLoopDelegate
  public var shouldQuitWhenIdle: Bool {
    do { 
      return try shouldQuitWhenIdleCallback(self) 
    } catch RuntimeError.IOMessagePumpInitError(let err) {
      print(err.message)
    } catch {
      print("unknown error \(error)")
    }
    return false
  }
  // RunLoopDelegate
  public var bound: Bool = false
  public var taskRunner: SingleThreadTaskRunner? {
    get {
      return _taskRunner
    }
    set {
      threadTaskRunnerHandle = nil
      _taskRunner = newValue
      if let runner = _taskRunner {
        threadTaskRunnerHandle = ThreadTaskRunnerHandle(taskRunner: runner)
      } else {
        // reset to null so we dont keep the old task runner
        threadTaskRunnerHandle = ThreadTaskRunnerHandle(taskRunner: nil)
      }
    }
  }

  // public var timerSlack: TimerSlack {
  //   get {
  //     return pump.timerSlack
  //   }
  //   set {
  //     pump.timerSlack = newValue
  //   }
  // }

  public var threadName: String {
    return ThreadIdNameManager.instance.getName(id: threadId)
  }

  internal var pump: MessagePump {
    //get {
      return pumpLock.withLock {
        return _pump!
      }
    //}
    //set {
    //  pumpLock.withLockVoid {
    //    _pump = newValue
    //  }
    //}
  }

  internal var taskObservers: [TaskObserver] = []
  internal var destructionObservers: [DestructionObserver] = []
  internal var taskExecutionAllowed: Bool = true
  
  private var recentTime: TimeTicks = TimeTicks()
  private var threadTaskRunnerHandle: ThreadTaskRunnerHandle?
  private var sequenceLocalStorageMap: SequenceLocalStorageMap = SequenceLocalStorageMap()
  private var threadId: PlatformThreadId = PlatformThread.invalidThreadId
  private var shouldQuitWhenIdleCallback: (_: RunLoopDelegate) throws -> Bool 
  private var _pump: MessagePump?
  private var pumpLock: Lock = Lock()
  private var incomingTaskQueue: IncomingTaskQueue
  private var unboundTaskRunner: MessageLoopTaskRunner?
  private var _taskRunner: SingleThreadTaskRunner?
 
  // Enables the SequenceLocalStorageSlot API within its scope.
  // Instantiated in BindToCurrentThread().
  var scopedSetSequenceLocalStorageMapForCurrentThread: ScopedSetSequenceLocalStorageMapForCurrentThread?    

#if os(Windows)
  var inHighResMode: Bool = false
#endif

  public override convenience init() throws {
    try self.init(type: .IO, unbound: false)
  }
 
  public convenience init(type: MessageLoopType) throws {
    try self.init(type: type, unbound: false)
  }

  internal init(type: MessageLoopType, unbound: Bool) throws {
    self.type = type
    
    shouldQuitWhenIdleCallback = {
      (_ delegate: RunLoopDelegate) throws -> Bool in
        guard let runloop = delegate.activeRunLoops.peek() else {
          throw RuntimeError.IOMessagePumpInitError(code: 0, message: "fatal: no active runloop found on activeRunLoops queue")
        }
        return runloop.quitWhenIdleReceived
    }

    incomingTaskQueue = IncomingTaskQueue(messageLoop: nil)
    
    // MessageLoopCurrent
    try super.init()
    super.current = self

    incomingTaskQueue.messageLoop = self

    unboundTaskRunner = MessageLoopTaskRunner(incomingQueue: incomingTaskQueue)
    _taskRunner = unboundTaskRunner

    if !unbound {
      try bindToCurrentThread()
    }
  }

  deinit {
    #if os(Windows)
    if inHighResMode {
      Time.activateHighResolutionTimer(false)
    }
    #endif

    var tasksRemain: Bool
    for _ in 0..<100 {
      deletePendingTasks()
      tasksRemain = incomingTaskQueue.triageTasks.hasTasks()
      if !tasksRemain {
        break
      }
    }

    // Let interested parties have one last shot at accessing this.
    for observer in destructionObservers {
      observer.willDestroyCurrentMessageLoop()
    }
    //threadTaskRunnerHandle = nil

    // Tell the incoming queue that we are dying.
    incomingTaskQueue.willDestroyCurrentMessageLoop()
    //incomingTaskQueue = nil
    unboundTaskRunner = nil
    taskRunner = nil

    // OK, now make it so that no one can find us.
    if MessageLoopCurrent.isBoundToCurrentThreadInternal(messageLoop: self) {
      MessageLoopCurrent.unbindFromCurrentThreadInternal(current: self)
    }
    // RunLoopDelegate
    if bound {
      RunLoop.threadSpecificDelegate.currentValue = nil
    }

    scopedSetSequenceLocalStorageMapForCurrentThread = nil
  }

  // RunLoopDelegate
  //@inline(never)
  public func run(applicationTasksAllowed: Bool) throws {
    if applicationTasksAllowed && !taskExecutionAllowed {
      // Allow nested task execution as explicitly requested.
      taskExecutionAllowed = true
      try pump.run(delegate: self)
      taskExecutionAllowed = false
    } else {
      try pump.run(delegate: self)
    }
  }

  //@inline(never)
  public func quit() {
    pump.quit()
  }
  
  //@inline(never)
  public func ensureWorkScheduled() {
    if incomingTaskQueue.triageTasks.hasTasks() {
      pump.scheduleWork()
    }
  }

  // MessagePumpDelegate
  //@inline(never)
  public func doWork() throws -> Bool {
    
    if !taskExecutionAllowed {
      return false
    }

    // Execute oldest task.
    while let pendingTask = incomingTaskQueue.triageTasks.pop() {
      
      if let task = pendingTask.task, task.isCancelled {
        continue
      }

      if !pendingTask.delayedRunTime.isNull {
      
        let sequenceNum = pendingTask.sequenceNum
        let delayedRunTime: TimeTicks = pendingTask.delayedRunTime
        incomingTaskQueue.delayedTasks.push(pendingTask)
        
        // If we changed the topmost task, then it is time to reschedule.
        if let task = incomingTaskQueue.delayedTasks.peek(), task.sequenceNum == sequenceNum {
          pump.scheduleDelayedWork(delayedWorkTime: delayedRunTime)
        }
      } else if try deferOrRunPendingTask(pendingTask) {
        return true
      }
    }

    // Nothing happened.
    return false
  }
  
  //@inline(never)
  public func doDelayedWork(nextDelayedWorkTime: inout TimeTicks) throws -> Bool {
    
    if !taskExecutionAllowed ||
        !incomingTaskQueue.delayedTasks.hasTasks() {
      recentTime = TimeTicks()
      nextDelayedWorkTime = TimeTicks()
      return false
    }

    // When we "fall behind", there will be a lot of tasks in the delayed work
    // queue that are ready to run.  To increase efficiency when we fall behind,
    // we will only call Time::Now() intermittently, and then process all tasks
    // that are ready to run before calling it again.  As a result, the more we
    // fall behind (and have a lot of ready-to-run delayed tasks), the more
    // efficient we'll be at handling the tasks.

    if let delayedTask = incomingTaskQueue.delayedTasks.peek() {
      let nextRunTime = delayedTask.delayedRunTime
      if nextRunTime > recentTime {
        recentTime = TimeTicks.now  // Get a better view of now()
        if nextRunTime > recentTime {
          nextDelayedWorkTime = nextRunTime
          return false
        }
      }
    }

    if let pendingTask = incomingTaskQueue.delayedTasks.pop() {
      if incomingTaskQueue.delayedTasks.hasTasks() {
        nextDelayedWorkTime = incomingTaskQueue.delayedTasks.peek()!.delayedRunTime
      }
      return try deferOrRunPendingTask(pendingTask)
    }

    return false
  }
  
  //@inline(never)
  public func doIdleWork() throws -> Bool {
     if try processNextDelayedNonNestableTask() {
      return true
     }

    if shouldQuitWhenIdle {
      pump.quit()
    }

    // When we return we will do a kernel wait for more tasks.
  #if os(Windows)
    let highRes = incomingTaskQueue.hasPendingHighResolutionTasks
    if highRes != inHighResMode {
      inHighResMode = highRes
      Time.activateHighResolutionTimer(inHighResMode)
    }
  #endif
    return false
  }

  //@inline(never)
  //public func runTask(_ pendingTask: inout PendingTask) {
  public func runTask(_ pendingTask: PendingTask) throws {
    taskExecutionAllowed = false

    for observer in taskObservers {
      observer.willProcessTask(pendingTask: pendingTask)
    }
  
    try incomingTaskQueue.runTask(pendingTask)
    
    for observer in taskObservers {
      observer.didProcessTask(pendingTask: pendingTask)
    }

    taskExecutionAllowed = true
  }

  //@inline(never)
  public func bindToCurrentThread() throws {

    switch type {
      case .UI:
        _pump = try UIMessagePump()
      case .IO:
        _pump = try IOMessagePump()
      case .custom: // not implemented
        _pump = try IOMessagePump()
    }

    try MessageLoopCurrent.bindToCurrentThreadInternal(current: self)

    incomingTaskQueue.startScheduling()
    unboundTaskRunner!.bindToCurrentThread()
    unboundTaskRunner = nil

    threadTaskRunnerHandle = nil
    threadTaskRunnerHandle = ThreadTaskRunnerHandle(taskRunner: _taskRunner!)

    threadId = PlatformThread.currentId

    scopedSetSequenceLocalStorageMapForCurrentThread = 
      ScopedSetSequenceLocalStorageMapForCurrentThread(sequenceLocalStorageMap)

    RunLoop.registerDelegateForCurrentThread(delegate: self)
  }

  //@inline(never)
  func processNextDelayedNonNestableTask() throws -> Bool {
    if RunLoop.isNestedOnCurrentThread {
      return false
    }

    while incomingTaskQueue.deferredTasks.hasTasks() {
      let pendingTask = incomingTaskQueue.deferredTasks.pop()!
      if !pendingTask.task!.isCancelled {
        try runTask(pendingTask)
        return true
      }
    } 

    return false
  }

  //@inline(never)
  func deferOrRunPendingTask(_ pendingTask: PendingTask) throws -> Bool {
    if pendingTask.nestable == Nestable.nestable || !RunLoop.isNestedOnCurrentThread {
      //var mutablePendingTask = pendingTask
      //runTask(&mutablePendingTask)
      try runTask(pendingTask)
      // Show that we ran a task (Note: a new one might arrive as a
      // consequence!).
      return true
    }
    incomingTaskQueue.deferredTasks.push(pendingTask)
    return false
  }

  func deletePendingTasks() {
    incomingTaskQueue.triageTasks.clear()
    incomingTaskQueue.deferredTasks.clear()
    incomingTaskQueue.delayedTasks.clear()
  }

  //@inline(never)
  func scheduleWork() {
    pump.scheduleWork()
  }

}

internal class MessageLoopTaskRunner : SingleThreadTaskRunner {
  
  var runTasksInCurrentSequence: Bool {
    return validThreadId == PlatformThread.currentId
  }

  let incomingQueue: IncomingTaskQueue
  var validThreadId: PlatformThreadId
  let validThreadIdLock: Lock = Lock()

  init(incomingQueue: IncomingTaskQueue) {
    self.incomingQueue = incomingQueue
    validThreadId = PlatformThread.invalidThreadId
  }

  func postDelayedTask(_ task: @escaping () -> Void, delay: TimeDelta) -> Bool {
    return incomingQueue.addToIncomingQueue(task: Closure(task), delay: delay, nestable: Nestable.nestable)
  }

  func postNonNestableDelayedTask(_ task: @escaping () -> Void,
                                  delay: TimeDelta) -> Bool {
    return incomingQueue.addToIncomingQueue(task: Closure(task), delay: delay, nestable: Nestable.nonNestable)
  }

  func bindToCurrentThread() {
    validThreadIdLock.withLockVoid {
      validThreadId = PlatformThread.currentId
    }
  }

}