// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

internal var gManagerIsAlive: Bool = false

internal class AtomicThreadRefChecker {
 
  public var isCurrentThreadSameAsSetThread: Bool {
    return isSet.isSet && threadRef === PlatformThread.current
  }

  let isSet: AtomicFlag = AtomicFlag()
  var threadRef: PlatformThread?

  init () {}

  public func set() {
    threadRef = PlatformThread.current
    isSet.set()
  }

}


fileprivate class SchedulerSingleThreadWorkerDelegate : SchedulerWorkerDelegate {
 
  public var sleepTimeout: TimeDelta { 
    return TimeDelta.max 
  }

  var worker: SchedulerWorker?

  var runTasksInCurrentSequence: Bool {
    return threadRefChecker.isCurrentThreadSameAsSetThread
  }

  var sequence: TaskSequence? {
    return sequenceLock.withLock {
      return _sequence
    }
  }

  let threadName: String

  let sequenceLock: Lock = Lock()
  
  var hasWork: Bool = false

  let threadRefChecker: AtomicThreadRefChecker = AtomicThreadRefChecker()
  
  var _sequence: TaskSequence?

  init(threadName: String) {
    self.threadName = threadName
    _sequence = TaskSequence()
  }

  // SchedulerWorkerDelegate:
  public func onCanScheduleSequence(sequence: TaskSequence) {
    guard let w = worker else {
      assert(false)
    }
    reEnqueueSequence(sequence: sequence)
    w.wakeUp()
  }

  public func onMainEntry(worker: SchedulerWorker) {
    threadRefChecker.set()
    PlatformThread.currentName = threadName
  }

  public func getWork(worker: SchedulerWorker) -> TaskSequence? {
    return sequenceLock.withLock {
      let hasWork = self.hasWork
      self.hasWork = false
      return hasWork ? _sequence : nil
    }
  }

  public func didRunTask() {}

  public func reEnqueueSequence(sequence: TaskSequence) {
    sequenceLock.withLockVoid {
      if _sequence == nil {
        return
      }
      hasWork = true
    }
  }

  public func onMainExit(worker: SchedulerWorker) {
    var localSequence: TaskSequence?
    // Move |sequence_| to |local_sequence| so that if we have the last
    // reference to the sequence we don't destroy it (and its tasks) within
    // |sequence_lock_|.
    sequenceLock.withLockVoid {
      localSequence = self._sequence
    }
  }

}

internal final class SchedulerSingleThreadTaskRunner : SingleThreadTaskRunner {
  
  public var runTasksInCurrentSequence: Bool {
    if !gManagerIsAlive {
      return false
    }
    return (delegate as! SchedulerSingleThreadWorkerDelegate).runTasksInCurrentSequence
  }

  var delegate: SchedulerWorkerDelegate {
    return worker.delegate
  }

  let outer: SchedulerSingleThreadTaskRunnerManager
  let traits: TaskTraits
  let worker: SchedulerWorker
  let threadMode: SingleThreadTaskRunnerThreadMode

  init(outer: SchedulerSingleThreadTaskRunnerManager,
       traits: TaskTraits,
       worker: SchedulerWorker,
       threadMode: SingleThreadTaskRunnerThreadMode) {
    self.outer = outer
    self.traits = traits
    self.worker = worker
    self.threadMode = threadMode
  }

  deinit {
    if gManagerIsAlive && threadMode == .dedicated {
      outer.unregisterSchedulerWorker(worker: worker)
    }
  }

  public func postDelayedTask(_ closure: @escaping () -> Void, delay: TimeDelta) -> Bool {
    if !gManagerIsAlive {
      return false
    }

    let task = Task(task: Closure(closure), traits: self.traits, delay: delay)
    task.singleThreadTaskRunner = self

    if !outer.taskTracker.willPostTask(task) {
      return false
    }

    if task.delayedRunTime.isNull {
      postTaskNow(task)
    } else {
      outer.delayedTaskManager.addDelayedTask(
        task, 
        callback: { t in
            self.postTaskNow(t) 
        })
    }
    return true
  }

  public func postNonNestableDelayedTask(_ closure: @escaping () -> Void, delay: TimeDelta) -> Bool {
    // Tasks are never nested within the task scheduler. 
    return postDelayedTask(closure, delay: delay)
  }

  func postTaskNow(_ task: Task) { 
    
    guard let sequence = (delegate as! SchedulerSingleThreadWorkerDelegate).sequence else {
      return
    }
    
    let sequenceWasEmpty = sequence.pushTask(task)

    if sequenceWasEmpty {
      if let sequence = outer.taskTracker.willScheduleSequence(sequence, observer: delegate) {
        delegate.reEnqueueSequence(sequence: sequence)
        worker.wakeUp()
      }
    }
  }

}

internal enum ContinueOnShutdown : Int {
    case isContinueOnShutdown = 0
    case isNotContinueOnShutdown = 1
}

extension ContinueOnShutdown: CaseIterable {}

public final class SchedulerSingleThreadTaskRunnerManager {

  let taskTracker: TaskTracker
  let delayedTaskManager: DelayedTaskManager
  let lock: Lock = Lock()
  var workers: [SchedulerWorker] = []
  var nextWorkerId: Int = 0
  var sharedSchedulerWorkers: [[SchedulerWorker?]] = [[]]
  var started: Bool = false

  static func traitsToContinueOnShutdown(_ traits: TaskTraits) -> ContinueOnShutdown {
    if traits.shutdownBehavior == .continueOnShutdown {
      return .isContinueOnShutdown
    }
    return .isNotContinueOnShutdown
  }

  public init(taskTracker: TaskTracker,
              delayedTaskManager: DelayedTaskManager) {
   self.taskTracker = taskTracker
   self.delayedTaskManager = delayedTaskManager

   sharedSchedulerWorkers = 
    Array(repeating: Array(repeating: nil, count: ContinueOnShutdown.allCases.count), 
      count: EnvironmentType.allCases.count)
   
   gManagerIsAlive = true
  }

  deinit {
    gManagerIsAlive = false
  }

  public func start() {
    
    var workersToStart: [SchedulerWorker]?

    lock.withLockVoid {
      self.started = true
      workersToStart = self.workers
    }

    // Start workers that were created before this method was called. Other
    // workers are started as they are created.
    for worker in workersToStart! {
      let _ = worker.start()
      worker.wakeUp()
    }
  }

  public func createSingleThreadTaskRunnerWithTraits(
      traits: TaskTraits,
      threadMode: SingleThreadTaskRunnerThreadMode) -> SingleThreadTaskRunner {
    //return createTaskRunnerWithTraitsImpl<SchedulerWorkerDelegate>(traits: traits, threadMode: threadMode)
    return createTaskRunnerWithTraitsImpl(traits: traits, threadMode: threadMode)
  }

  //func createTaskRunnerWithTraitsImpl<DelegateType>(
  func createTaskRunnerWithTraitsImpl(
      traits: TaskTraits,
      threadMode: SingleThreadTaskRunnerThreadMode) -> SchedulerSingleThreadTaskRunner {
    //var dedicatedWorker: SchedulerWorker?
    
    var worker: SchedulerWorker? =
        threadMode == .dedicated
            ? nil//dedicatedWorker
            : getSharedSchedulerWorkerForTraits(traits: traits)
            //: getSharedSchedulerWorkerForTraits<DelegateType>(traits: traits)
    var newWorker = false
    var started = false

    lock.withLockVoid {
      if worker == nil {
        let envParams = environmentParams[EnvironmentType.getEnvironmentIndexForTraits(traits)]
        var workerName = String()
        if threadMode == .shared {
          workerName += "Shared"
        }
        workerName += envParams.nameSuffix
        //worker = createAndRegisterSchedulerWorker<DelegateType>(workerName, envParams.priorityHint)
      
        worker = createAndRegisterSchedulerWorker(name: workerName, priorityHint: envParams.priorityHint)
        newWorker = true
      }
      started = self.started
    }

    if newWorker && started {
      let _ = worker!.start()
    }
       
    return SchedulerSingleThreadTaskRunner(
      outer: self, 
      traits: traits, 
      worker: worker!, 
      threadMode: threadMode)
  }

  //func createSchedulerWorkerDelegate<DelegateType>(
  func createSchedulerWorkerDelegate(
      name: String,
      id: Int) -> SchedulerWorkerDelegate {
    // return SchedulerWorkerDelegateImpl(threadName: "TaskSchedulerSingleThread\(name)\(id)")
    return SchedulerSingleThreadWorkerDelegate(threadName: "TaskSchedulerSingleThread\(name)\(id)")
  }

  // func createAndRegisterSchedulerWorker<DelegateType>(
  func createAndRegisterSchedulerWorker(
      name: String,
      priorityHint: ThreadPriority) -> SchedulerWorker {
    lock.assertAcquired()
    nextWorkerId += 1
    let id = nextWorkerId
    //let delegate = createSchedulerWorkerDelegate<DelegateType>(name: name, id: id)
    let delegate = createSchedulerWorkerDelegate(name: name, id: id)
    let delegateRaw = delegate as! SchedulerSingleThreadWorkerDelegate
    let worker = SchedulerWorker(
      priorityHint: priorityHint,
      delegate: delegate, 
      taskTracker: taskTracker)
    delegateRaw.worker = worker
    workers.append(worker)
    return worker
  }

  //func getSharedSchedulerWorkerForTraits<DelegateType>(traits: TaskTraits) -> SchedulerWorker {
  //  return sharedSchedulerWorkers[EnvironmentType.getEnvironmentIndexForTraits(traits)][SchedulerSingleThreadTaskRunnerManager.traitsToContinueOnShutdown(traits).rawValue]
  //}

  func getSharedSchedulerWorkerForTraits(traits: TaskTraits) -> SchedulerWorker? {
    return sharedSchedulerWorkers[EnvironmentType.getEnvironmentIndexForTraits(traits)][SchedulerSingleThreadTaskRunnerManager.traitsToContinueOnShutdown(traits).rawValue]
  }

  func unregisterSchedulerWorker(worker: SchedulerWorker) {
    var workerToDestroy: SchedulerWorker?
    lock.withLockVoid {
      // Skip when joining (the join logic takes care of the rest).
      if workers.isEmpty {
        return
      }

      guard let index = workers.firstIndex(of: worker) else {
        return
      }

      workerToDestroy = workers[index]
      workers.remove(at: index)
    }

    workerToDestroy!.cleanup()
  }

  func releaseSharedSchedulerWorkers() {
    var localSharedSchedulerWorkers = sharedSchedulerWorkers
  
    lock.withLockVoid {
      for i in 0..<sharedSchedulerWorkers.count {
        for j in 0..<sharedSchedulerWorkers[i].count {
          localSharedSchedulerWorkers[i][j] = sharedSchedulerWorkers[i][j]
          sharedSchedulerWorkers[i][j] = nil
        }
      }
    }

    for i in 0..<localSharedSchedulerWorkers.count {
      for j in 0..<localSharedSchedulerWorkers[i].count {
        if let worker = localSharedSchedulerWorkers[i][j] {
          unregisterSchedulerWorker(worker: worker)
        }
      }
    }
  }
  
}