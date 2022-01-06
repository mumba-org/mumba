// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fileprivate var gActivePoolsCount: Int = 0
fileprivate let maxNumberOfWorkers: Int = 256

internal class SchedulerParallelTaskRunner : TaskRunner {

  let traits: TaskTraits
  let workerPool: SchedulerWorkerPool

  public var runTasksInCurrentSequence: Bool {
    return SchedulerWorkerPool.current === workerPool
  }
  
  init(traits: TaskTraits,
       workerPool: SchedulerWorkerPool) {
    self.traits = traits
    self.workerPool = workerPool
  }

  public func postDelayedTask(
    _ task: @escaping () -> Void,
    delay: TimeDelta) -> Bool {
    if gActivePoolsCount == 0 {
      return false
    }

    return workerPool.postTaskWithSequence(
        task: Task(task: Closure(task), traits: traits, delay: delay),
        sequence: TaskSequence())
  }

}

internal class SchedulerSequencedTaskRunner : SequencedTaskRunner {

  public var runTasksInCurrentSequence: Bool {
    return sequence.token == TaskSequenceToken.getForCurrentThread()
  }

  let sequence: TaskSequence = TaskSequence()
  let traits: TaskTraits
  let workerPool: SchedulerWorkerPool

  init(traits: TaskTraits, workerPool: SchedulerWorkerPool) {
    self.traits = traits
    self.workerPool = workerPool
  }

  public func postDelayedTask(
     _ task: @escaping () -> Void,
     delay: TimeDelta) -> Bool {
    if gActivePoolsCount  == 0 {
      return false
    }

    let workerTask = Task(task: Closure(task), traits: traits, delay: delay)
    workerTask.sequencedTaskRunner = self

    return workerPool.postTaskWithSequence(task: workerTask, sequence: sequence)
  }

  public func postNonNestableDelayedTask(_ task: @escaping () -> Void,
                                         delay: TimeDelta) -> Bool {
    return postDelayedTask(task, delay: delay)
  }

}

public enum WorkerEnvironment {
    // No special worker environment required.
    case none
#if os(Windows)
    // Initialize a COM MTA on the worker.
    case COM_MTA
#endif  // defined(OS_WIN)
}

internal class SchedulerWorkerDelegateImpl : SchedulerWorkerDelegate,
                                             BlockingObserver {
 
  // SchedulerWorkerDelegate
  public var sleepTimeout: TimeDelta {
    return outer.suggestedReclaimTime
  }

  public var mustIncrementWorkerCapacityLockRequired: Bool {
    outer.lock.assertAcquired()

    if !incrementedWorkerCapacitySinceBlocked &&
        !mayBlockStartTime.isNull &&
        TimeTicks.now - mayBlockStartTime >= outer.mayBlockThreshold {
      incrementedWorkerCapacitySinceBlocked = true

      mayBlockStartTime = TimeTicks()
      outer.numPendingMayBlockWorkers -= 1
      return true
    }

    return false
  }

  weak var outer: SchedulerWorkerPool!
  
  var lastDetachTime: TimeTicks = TimeTicks()

  var numTasksSinceLastWait: Int = 0

  var numTasksSinceLastDetach: Int = 0

  var isOnIdleWorkersStack: Bool = true

  var incrementedWorkerCapacitySinceBlocked: Bool = false

  var mayBlockStartTime: TimeTicks = TimeTicks()

  var isRunningTask: Bool = false

#if os(Windows)
  let winThreadEnvironment: ScopedWindowsThreadEnvironment
#endif

  init(outer: SchedulerWorkerPool) {
    self.outer = outer
  }

  // SchedulerWorkerDelegate

  public func onCanScheduleSequence(sequence: TaskSequence) {
    outer.onCanScheduleSequence(sequence: sequence)
  }

  public func onMainEntry(worker: SchedulerWorker) {
    #if os(Windows)
    if outer.workerEnvironment == WorkerEnvironment.COM_MTA {
      if win.version >= VERSION_WIN8 {
        winThreadEnvironment_ = ScopedWinrtInitializer()
      } else {
        winThreadEnvironment = ScopedCOMInitializer(ScopedCOMInitializer.MTA)
      }
     assert(winThreadEnvironment.succeeded)
    }
    #endif

    assert(numTasksSinceLastWait == 0)

    PlatformThread.currentName = "TaskScheduler\(outer.poolLabel)Worker"

    outer.bindToCurrentThread()
    setBlockingObserverForCurrentThread(observer: self)
  }
  
  public func getWork(worker: SchedulerWorker) -> TaskSequence? {
    let shouldReturnNull = outer.lock.withLock { () -> Bool in
      if isOnIdleWorkersStack {
        if canCleanupLockRequired(worker: worker) {
          cleanupLockRequired(worker: worker)
        }
        return true
      }

      // Excess workers should not get work, until they are no longer excess (i.e.
      // worker capacity increases or another worker cleans up). This ensures that
      // if we have excess workers in the pool, they get a chance to no longer be
      // excess before being cleaned up.
      //if outer.numberOfExcessWorkersLockRequired > outer.idleWorkersStack.count {
      if outer.numberOfExcessWorkersLockRequired > outer.idleWorkersStack.count {
        onWorkerBecomesIdleLockRequired(worker: worker)
        return true
      }

      return false
    }

    if shouldReturnNull {
      return nil
    }
      
    let sharedTransaction = outer.sharedPriorityQueue.beginTransaction()

    if sharedTransaction.isEmpty {
      // |shared_transaction| is kept alive while |worker| is added to
      // |idle_workers_stack_| to avoid this race:
      // 1. This thread creates a Transaction, finds |shared_priority_queue_|
      //    empty and ends the Transaction.
      // 2. Other thread creates a Transaction, inserts a TaskSequence into
      //    |shared_priority_queue_| and ends the Transaction. This can't happen
      //    if the Transaction of step 1 is still active because because there
      //    can only be one active Transaction per PriorityQueue at a time.
      // 3. Other thread calls WakeUpOneWorker(). No thread is woken up because
      //    |idle_workers_stack_| is empty.
      // 4. This thread adds itself to |idle_workers_stack_| and goes to sleep.
      //    No thread runs the TaskSequence inserted in step 2.
      outer.lock.withLockVoid {
        onWorkerBecomesIdleLockRequired(worker: worker)
      }
      return nil
    }

    let sequence = sharedTransaction.popSequence()
    isRunningTask = true
    return sequence
  }
  
  public func didRunTask() {
    isRunningTask = false
    numTasksSinceLastWait += 1
    numTasksSinceLastDetach += 1
  }
  
  public func reEnqueueSequence(sequence: TaskSequence) {
    let sequenceSortKey = sequence.sortKey
    outer.sharedPriorityQueue.beginTransaction().push(sequence: sequence,
                                                      sortKey: sequenceSortKey)
  }
  
  public func onMainExit(worker: SchedulerWorker) {
    #if os(Windows)
    winThreadEnvironment = nil
    #endif  // defined(OS_WIN)
  }

  // BlockingObserver
  public func blockingStarted(type: BlockingType) {
    if !isRunningTask {
      return
    }

    switch type {
      case .mayBlock:
        mayBlockEntered()
        break
      case .willBlock:
        willBlockEntered()
        break
    }
  }
  
  public func blockingTypeUpgraded() {
    outer.lock.withLockVoid {

      if incrementedWorkerCapacitySinceBlocked {
        return
      }

      if !mayBlockStartTime.isNull {
        mayBlockStartTime = TimeTicks()
        outer.numPendingMayBlockWorkers -= 1
      }
    }

    willBlockEntered()
  }
  
  public func blockingEnded() {
    if !isRunningTask {
      return
    }

    outer.lock.withLockVoid {
      if incrementedWorkerCapacitySinceBlocked {
        outer.decrementWorkerCapacityLockRequired()
      } else {
        outer.numPendingMayBlockWorkers -= 1
      }
      incrementedWorkerCapacitySinceBlocked = false
      mayBlockStartTime = TimeTicks()
    }
  }

  public func mayBlockEntered() {
    outer.lock.withLockVoid {
      mayBlockStartTime = TimeTicks.now
      outer.numPendingMayBlockWorkers += 1
    }
    outer.postAdjustWorkerCapacityTaskIfNeeded()
  }
  
  public func willBlockEntered() {
    var wakeUpAllowed: Bool = false
    outer.lock.withLockVoid {
      let sharedTransaction = outer.sharedPriorityQueue.beginTransaction()
      incrementedWorkerCapacitySinceBlocked = true
      outer.incrementWorkerCapacityLockRequired()

      // If the number of workers was less than the old worker capacity, PostTask
      // would've handled creating extra workers during WakeUpOneWorker.
      // Therefore, we don't need to do anything here.
      if outer.workers.count < outer.workerCapacity - 1 {
        return
      }

      if sharedTransaction.isEmpty {
        outer.maintainAtLeastOneIdleWorkerLockRequired()
      } else {
        // TODO(crbug.com/757897): We may create extra workers in this case:
        // |workers.size()| was equal to the old |worker_capacity_|, we had
        // multiple ScopedBlockingCalls in parallel and we had work on the PQ.
        wakeUpAllowed = outer.wakeUpOneWorkerLockRequired()
      }
    }
    // TODO(crbug.com/813857): This can be better handled in the PostTask()
    // codepath. We really only should do this if there are tasks pending.
    if wakeUpAllowed {
      outer.postAdjustWorkerCapacityTaskIfNeeded()
    }
  }

  public func setIsOnIdleWorkersStackLockRequired(worker: SchedulerWorker) {
    outer.lock.assertAcquired()
    isOnIdleWorkersStack = true
  }

  public func unsetIsOnIdleWorkersStackLockRequired(worker: SchedulerWorker) {
    outer.lock.assertAcquired()
    isOnIdleWorkersStack = false
  }

  public func assertIsOnIdleWorkersStackLockRequired(worker: SchedulerWorker) {}

  func canCleanupLockRequired(worker: SchedulerWorker) -> Bool {
    return worker !== outer.peekAtIdleWorkersStackLockRequired()
  }

  func cleanupLockRequired(worker: SchedulerWorker) {
    outer.lock.assertAcquired()
    //outer.numTasksBeforeDetachHistogram.add(numTasksSinceLastDetach)
    outer.cleanupTimestamps.push(TimeTicks.now)
    worker.cleanup()
    outer.removeFromIdleWorkersStackLockRequired(worker: worker)

    // Remove the worker from |workers|.
    if let index = outer.workers.firstIndex(of: worker) {
      outer.workers.remove(at: index)
    }
  }

  func onWorkerBecomesIdleLockRequired(worker: SchedulerWorker) {
    outer.lock.assertAcquired()
    //outer.numTasksbetweenWaitsHistogram.add(numTasksSinceLastWait)
    numTasksSinceLastWait = 0
    outer.addToIdleWorkersStackLockRequired(worker: worker)
    setIsOnIdleWorkersStackLockRequired(worker: worker)
  }

}

public class SchedulerWorkerPool : CanScheduleSequenceObserver {

  static let blockedWorkersPollPeriod: TimeDelta = TimeDelta.from(milliseconds: 50)
  static let threadSpecificWorkerPool = ThreadSpecificVariable<SchedulerWorkerPool>()

  static var current: SchedulerWorkerPool? {
    get {
      return threadSpecificWorkerPool.currentValue
    }
    set {
      threadSpecificWorkerPool.currentValue = newValue
    }
  }

  var shouldPeriodicallyAdjustWorkerCapacityLockRequired: Bool {
    lock.assertAcquired()
    // AdjustWorkerCapacity() must be periodically called when (1) there are no
    // idle workers that can do work (2) there are workers that are within the
    // scope of a MAY_BLOCK ScopedBlockingCall but haven't cause a capacity
    // increment yet.
    //
    // - When (1) is false: A newly posted task will run on one of the idle
    //   workers that are allowed to do work. There is no hurry to increase
    //   capacity.
    // - When (2) is false: AdjustWorkerCapacity() would be a no-op.
    let idleWorkersThatCanDoWork = idleWorkersStack.count - numberOfExcessWorkersLockRequired
    return idleWorkersThatCanDoWork <= 0 && numPendingMayBlockWorkers > 0
  }

  var mayBlockThreshold: TimeDelta {
    // This value was set unscientifically based on intuition and may be adjusted
    // in the future. This value is smaller than |kBlockedWorkersPollPeriod|
    // because we hope than when multiple workers block around the same time, a
    // single AdjustWorkerCapacity() call will perform all the necessary capacity
    // adjustments.
    return TimeDelta.from(milliseconds: 10)
  }

  var numberOfExcessWorkersLockRequired: Int {
    lock.assertAcquired()
    return max(0, workers.count - workerCapacity)
  }
  
  let taskTracker: TaskTracker
  let delayedTaskManager: DelayedTaskManager
  let poolLabel: String
  let priorityHint: ThreadPriority = ThreadPriority.background
  var sharedPriorityQueue: SchedulerPriorityQueue = SchedulerPriorityQueue()
  var suggestedReclaimTime: TimeDelta = TimeDelta()
  let lock: Lock = Lock()
  var workers: [SchedulerWorker] = []
  var workerCapacity: Int = 0
  var initialWorkerCapacity: Int = 0
  var numPendingMayBlockWorkers: Int = 0
  var workerEnvironment: WorkerEnvironment = WorkerEnvironment.none
  var idleWorkersStack: SchedulerWorkerStack = SchedulerWorkerStack()
  var numWakeUpsBeforeStart: Int = 0
  var cleanupTimestamps: Stack<TimeTicks> = Stack<TimeTicks>()
  var pollingWorkerCapacity: Bool = false
  var serviceThreadTaskRunner: TaskRunner!

  public init(poolLabel: String,
              priorityHint: ThreadPriority,
              taskTracker: TaskTracker,
              delayedTaskManager: DelayedTaskManager) {
    
    self.taskTracker = taskTracker
    self.delayedTaskManager = delayedTaskManager
    self.poolLabel = poolLabel
    
    gActivePoolsCount += 1
  }

  deinit {
    gActivePoolsCount -= 1
    assert(workers.isEmpty)
  }

  public func start(params: SchedulerWorkerPoolParams,
                    serviceThreadTaskRunner: TaskRunner,
                    workerEnvironment: WorkerEnvironment) {
    lock.withLockVoid {
      self.workerCapacity = params.maxThreads
      self.initialWorkerCapacity = workerCapacity
      self.suggestedReclaimTime = params.suggestedReclaimTime
      self.workerEnvironment = workerEnvironment

      self.serviceThreadTaskRunner = serviceThreadTaskRunner

      // The initial number of workers is |num_wake_ups_before_start_| + 1 to try to
      // keep one at least one standby thread at all times (capacity permitting).
      let numInitialWorkers = min(self.numWakeUpsBeforeStart + 1, self.workerCapacity)
      self.workers.reserveCapacity(numInitialWorkers)

      for index in 0..<numInitialWorkers {
        if let worker = createRegisterAndStartSchedulerWorkerLockRequired() {
          let delegate = worker.delegate as! SchedulerWorkerDelegateImpl
          if index < self.numWakeUpsBeforeStart {
            delegate.unsetIsOnIdleWorkersStackLockRequired(worker: worker)
            worker.wakeUp()
          } else {
            self.idleWorkersStack.push(worker)
            delegate.assertIsOnIdleWorkersStackLockRequired(worker: worker)
          }
        }
      }
    }
  }

  public func createTaskRunnerWithTraits(traits: TaskTraits) -> TaskRunner {
    return SchedulerParallelTaskRunner(traits: traits, workerPool: self)
  }

  public func createSequencedTaskRunnerWithTraits(traits: TaskTraits) -> SequencedTaskRunner {
    return SchedulerSequencedTaskRunner(traits: traits, workerPool: self)
  }

  public func postTaskWithSequence(task: Task, sequence: TaskSequence) -> Bool {
    if !taskTracker.willPostTask(task) {
      return false
    }

    if task.delayedRunTime.isNull {
      postTaskWithSequenceNow(task: task, sequence: sequence)
    } else {
      delayedTaskManager.addDelayedTask(
        task, 
        callback: { t in
            self.postTaskWithSequenceNow(task: t, sequence: sequence)
        }
      )
    }

    return true
  }

  public func bindToCurrentThread() {
    SchedulerWorkerPool.threadSpecificWorkerPool.currentValue = self
  }

  public func unbindFromCurrentThread() {
    SchedulerWorkerPool.threadSpecificWorkerPool.currentValue = nil
  }

  func postTaskWithSequenceNow(task: Task, sequence: TaskSequence) {
    let sequenceWasEmpty = sequence.pushTask(task)
    if sequenceWasEmpty {
      // Try to schedule |sequence| if it was empty before |task| was inserted
      // into it. Otherwise, one of these must be true:
      // - |sequence| is already scheduled, or,
      // - The pool is running a Task from |sequence|. The pool is expected to
      //   reschedule |sequence| once it's done running the Task.
      if let sequence = taskTracker.willScheduleSequence(sequence, observer: self) {
        onCanScheduleSequence(sequence: sequence) 
      }
    }
  }

  // CanScheduleSequenceObserver
  public func onCanScheduleSequence(sequence: TaskSequence) {
    let sequenceSortKey = sequence.sortKey
    sharedPriorityQueue.beginTransaction().push(sequence: sequence,
                                                sortKey: sequenceSortKey)
    wakeUpOneWorker()
  }

  func wakeUpOneWorker() {
    var wakeUpAllowed: Bool = false
    lock.withLockVoid {
      wakeUpAllowed = wakeUpOneWorkerLockRequired()      
    }
    if wakeUpAllowed {
      postAdjustWorkerCapacityTaskIfNeeded()
    }
  }

  func wakeUpOneWorkerLockRequired() -> Bool {
    lock.assertAcquired()

    if workers.isEmpty {
      numWakeUpsBeforeStart += 1
      return false
    }

    // Ensure that there is one worker that can run tasks on top of the idle
    // stack, capacity permitting.
    maintainAtLeastOneIdleWorkerLockRequired()

    // If the worker on top of the idle stack can run tasks, wake it up.
    if numberOfExcessWorkersLockRequired < idleWorkersStack.count {
      if let worker = idleWorkersStack.pop() {
        let delegate = worker.delegate as! SchedulerWorkerDelegateImpl
        delegate.unsetIsOnIdleWorkersStackLockRequired(worker: worker)
        worker.wakeUp()
      }
    }

    // Ensure that there is one worker that can run tasks on top of the idle
    // stack, capacity permitting.
    maintainAtLeastOneIdleWorkerLockRequired()
    return true
  }

  // Adds a worker, if needed, to maintain one idle worker, |worker_capacity_|
  // permitting.
  func maintainAtLeastOneIdleWorkerLockRequired() {
    lock.assertAcquired()

    if workers.count == maxNumberOfWorkers { 
      return
    }
     
    if idleWorkersStack.isEmpty && workers.count < workerCapacity {
      if let newWorker = createRegisterAndStartSchedulerWorkerLockRequired() {
        idleWorkersStack.push(newWorker)
      }
    }
  }

  func addToIdleWorkersStackLockRequired(worker: SchedulerWorker) {
    lock.assertAcquired()
    idleWorkersStack.push(worker)
  }

  // Peeks from |idle_workers_stack_|.
  func peekAtIdleWorkersStackLockRequired() -> SchedulerWorker? {
    lock.assertAcquired()
    return idleWorkersStack.peek()
  }

  func removeFromIdleWorkersStackLockRequired(worker: SchedulerWorker) {
    lock.assertAcquired()
    idleWorkersStack.remove(worker)
  }

  func createRegisterAndStartSchedulerWorkerLockRequired() -> SchedulerWorker? {
    lock.assertAcquired()

    let worker = 
      SchedulerWorker(
        priorityHint: priorityHint,
        delegate: SchedulerWorkerDelegateImpl(outer: self),
        taskTracker: taskTracker)

    if !worker.start() {
      return nil
    }

    workers.append(worker)
   
    if !cleanupTimestamps.isEmpty {
      //detachDurationHistogram.addTime(TimeTicks.now -
      //                                cleanupTimestamps.top())
      cleanupTimestamps.pop()
    }
    return worker
  }

  func adjustWorkerCapacity() {
    let sharedTransaction = sharedPriorityQueue.beginTransaction()
    lock.withLockVoid {
      let originalWorkerCapacity = workerCapacity
      // Increment worker capacity for each worker that has been within a MAY_BLOCK
      // ScopedBlockingCall for more than MayBlockThreshold().
      for worker in workers {
        // The delegates of workers inside a SchedulerWorkerPoolImpl should be
        // SchedulerWorkerDelegateImpls.
        let delegate = worker.delegate as! SchedulerWorkerDelegateImpl
        if delegate.mustIncrementWorkerCapacityLockRequired {
          incrementWorkerCapacityLockRequired()
        }
      }

      // Wake up a worker per pending sequence, capacity permitting.
      let numPendingSequences = sharedTransaction.count
      let numWakeUpsNeeded = min(workerCapacity - originalWorkerCapacity, numPendingSequences)

      for _ in 0..<numWakeUpsNeeded {
        // No need to call PostAdjustWorkerCapacityTaskIfNeeded() as the caller will
        // take care of that for us.
        let _ = wakeUpOneWorkerLockRequired()
      }

      maintainAtLeastOneIdleWorkerLockRequired()
    }
  }

  func postAdjustWorkerCapacityTaskIfNeeded() {
    lock.withLockVoid {
      if pollingWorkerCapacity || 
        !shouldPeriodicallyAdjustWorkerCapacityLockRequired {
        return
      }
      pollingWorkerCapacity = true
    }
    serviceThreadTaskRunner.postDelayedTask(
        { self.adjustWorkerCapacityTaskFunction() },
        delay: SchedulerWorkerPool.blockedWorkersPollPeriod);
  }

  func adjustWorkerCapacityTaskFunction() {
    adjustWorkerCapacity()
    lock.withLockVoid {
      if !shouldPeriodicallyAdjustWorkerCapacityLockRequired {
        pollingWorkerCapacity = false
        return
      }
    }
    
    serviceThreadTaskRunner.postDelayedTask(
        { self.adjustWorkerCapacityTaskFunction() },
        delay: SchedulerWorkerPool.blockedWorkersPollPeriod)
  }

  func decrementWorkerCapacityLockRequired() {
    lock.assertAcquired()
    workerCapacity -= 1
  }

  func incrementWorkerCapacityLockRequired() {
    lock.assertAcquired()
    workerCapacity += 1
  }

}