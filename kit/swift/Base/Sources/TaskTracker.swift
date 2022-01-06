// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public final class PreemptedBackgroundSequence {

  var observer: CanScheduleSequenceObserver?
  var sequence: TaskSequence?
  var nextTaskSequencedTime: TimeTicks = TimeTicks()

  public init() {}
  
  public init(
    sequence: TaskSequence?,
    nextTaskSequencedTime: TimeTicks,
    observer: CanScheduleSequenceObserver?) {

    self.sequence = sequence
    self.nextTaskSequencedTime = nextTaskSequencedTime
    self.observer = observer
  }

}

extension PreemptedBackgroundSequence: Comparable {
    
    public static func < (lhs: PreemptedBackgroundSequence, rhs: PreemptedBackgroundSequence) -> Bool {
        return lhs.nextTaskSequencedTime < rhs.nextTaskSequencedTime
    }

    public static func == (lhs: PreemptedBackgroundSequence, rhs: PreemptedBackgroundSequence) -> Bool {
        return lhs === rhs
    }

}

internal class TaskTrackerState {
 
  public var hasShutdownStarted: Bool {
    return bits.load() & TaskTrackerState.shutdownHasStartedMask.load() != 0
  }

  public var areTasksBlockingShutdown: Bool {
    let numTasksBlockingShutdown = bits.load() >> TaskTrackerState.numTasksBlockingShutdownBitOffset.load()
    return numTasksBlockingShutdown != 0
  }

  static let shutdownHasStartedMask: Atomic<Int> = Atomic<Int>(value: 1)
  static let numTasksBlockingShutdownBitOffset: Atomic<Int> = Atomic<Int>(value: 1)
  static let numTasksBlockingShutdownIncrement: Atomic<Int> =
      Atomic<Int>(value: 1 << TaskTrackerState.numTasksBlockingShutdownBitOffset.load())

  var bits: Atomic<Int> = Atomic<Int>(value: 0)

  public init() {}

  public func startShutdown() -> Bool {
    let newValue = bits.add(TaskTrackerState.shutdownHasStartedMask.load())

    let numTasksBlockingShutdown =
        newValue >> TaskTrackerState.numTasksBlockingShutdownBitOffset.load()
    return numTasksBlockingShutdown != 0
  }

  public func incrementNumTasksBlockingShutdown() -> Bool {
    let newBits = bits.add(TaskTrackerState.numTasksBlockingShutdownIncrement.load())
    return newBits & TaskTrackerState.shutdownHasStartedMask.load() != 0
  }

  public func decrementNumTasksBlockingShutdown() -> Bool {
    //let newBits = bits.add(-TaskTrackerState.numTasksBlockingShutdownIncrement)
    let newBits = bits.sub(TaskTrackerState.numTasksBlockingShutdownIncrement.load())
    let shutdownHasStarted = newBits & TaskTrackerState.shutdownHasStartedMask.load()
    let numTasksBlockingShutdown =
        newBits >> TaskTrackerState.numTasksBlockingShutdownBitOffset.load()
    return shutdownHasStarted > 0 && numTasksBlockingShutdown == 0
  }

}

public class TaskTracker {

  public var hasShutdownStarted: Bool {
    return state.hasShutdownStarted
  }

  public var isShutdownComplete: Bool {
    return shutdownLock.withLock {
      return shutdownEvent != nil && shutdownEvent!.isSignaled
    }
  }

  public var preemptedBackgroundSequenceToScheduleLockRequired: PreemptedBackgroundSequence {
    backgroundLock.assertAcquired()

    numScheduledBackgroundSequences += 1
    
    let poppedSequence: PreemptedBackgroundSequence = preemptedBackgroundSequences.peek()!
    preemptedBackgroundSequences.pop()
    return poppedSequence
  }

  let state: TaskTrackerState

  var numIncompleteUndelayedTasks: Atomic<Int> = Atomic<Int>(value: 0)

  internal var watchFileDescriptorMessageLoop: MessageLoop?

  let flushLock: Lock = Lock()

  let flushcv: ConditionVariable

  let shutdownLock: Lock = Lock()

  var shutdownEvent: WaitableEvent?

  let backgroundLock: Lock = Lock()

  var preemptedBackgroundSequences: PriorityQueue<PreemptedBackgroundSequence> = PriorityQueue<PreemptedBackgroundSequence>()

  var maxNumScheduledBackgroundSequences: Int

  var numScheduledBackgroundSequences: Int = 0

  let taskAnnotator: TaskAnnotator = TaskAnnotator()

  public init(maxNumScheduledBackgroundSequences: Int = Int.max) {
    state = TaskTrackerState()
    flushcv = ConditionVariable(lock: flushLock)
    //shutdownLock = Lock(flushLock)
    self.maxNumScheduledBackgroundSequences = maxNumScheduledBackgroundSequences
  }

  public func shutdown() {
    performShutdown()
    flushLock.withLockVoid {
      flushcv.signal()
    }
  }

  public func willPostTask(_ task: Task) -> Bool {

    if !beforePostTask(behavior: task.traits.shutdownBehavior) {
      return false
    }

    if task.delayedRunTime.isNull {
      let _ = numIncompleteUndelayedTasks.add(1)
    }
  
    taskAnnotator.didQueueTask(task)

    return true
  }

  public func willScheduleSequence(
      _ sequence: TaskSequence,
      observer: CanScheduleSequenceObserver) -> TaskSequence? {
    
    let sortkey = sequence.sortKey

    if sortkey.priority != TaskPriority.background {
      return sequence
    }

    return backgroundLock.withLock {
      if numScheduledBackgroundSequences < maxNumScheduledBackgroundSequences {
        numScheduledBackgroundSequences += 1
        return sequence
      }

      preemptedBackgroundSequences.push(
          PreemptedBackgroundSequence(
            sequence: sequence, 
            nextTaskSequencedTime: sortkey.nextTaskSequencedTime, 
            observer: observer))

      return nil
    }
  }
  
  public func runAndPopNextTask(
      sequence: TaskSequence,
      observer: CanScheduleSequenceObserver) throws -> TaskSequence? {
    var sequenceRef: TaskSequence? = sequence

    if let task = sequence.takeTask() {
      let shutdownBehavior = task.traits.shutdownBehavior
      let taskPriority = task.traits.priority
      let canRunTask = beforeRunTask(behavior: shutdownBehavior)
      let isDelayed = !task.delayedRunTime.isNull

      try runOrSkipTask(task, sequence: sequence, canRunTask: canRunTask)
      
      if canRunTask {
        afterRunTask(behavior: shutdownBehavior)
      }

      if !isDelayed {
        decrementNumIncompleteUndelayedTasks()
      }

      let sequenceIsEmptyAfterPop = sequence.pop()

      // Never reschedule a TaskSequence emptied by Pop(). The contract is such that
      // next poster to make it non-empty is responsible to schedule it.
        
      if sequenceIsEmptyAfterPop {
        sequenceRef = nil
      }

      if taskPriority == TaskPriority.background {
        return manageBackgroundSequencesAfterRunningTask(sequence: sequenceRef, observer: observer)
      }
      return sequenceRef
    }

    return sequenceRef
  }

  func runOrSkipTask(_ task: Task, sequence: TaskSequence, canRunTask: Bool) throws {

  #if os(Linux) || os(macOS)
    guard let watchFileMessageLoop = watchFileDescriptorMessageLoop else {
      print("TaskTracker: File descriptor watcher message loop was not set up\nCancelling runOrSkipTask()")
      return
    }
    let fileDescriptorWatcher = FileDescriptorWatcher(messageLoop: watchFileMessageLoop)
  #endif

    //let previousSingletonAllowed: Bool =
    //  ThreadRestrictions.setSingletonAllowed(
    //      task.traits.shutdownBehavior != TaskShutdownBehavior.continueOnShutdown)
    //let previousIOAllowed: Bool = ThreadRestrictions.setIOAllowed(task.traits.mayBlock)
    //let previousWaitAllowed: Bool = ThreadRestrictions.setWaitAllowed(task.traits.withBaseSyncPrimitives)

    do {
      let sequenceToken = sequence.token
      //let scopedSetSequenceTokenForCurrentThread = ScopedSetSequenceTokenForCurrentThread(sequenceToken)
      TaskSequenceToken.setForCurrentThread(sequenceToken)
      TaskPriority.setForCurrentThread(task.traits.priority)
      SequenceLocalStorageMap.setForCurrentThread(sequence.sequenceLocalStorage)

      defer {
        TaskSequenceToken.setForCurrentThread(nil)
        TaskPriority.setForCurrentThread(nil)
        SequenceLocalStorageMap.setForCurrentThread(nil)
      }

      //let scopedSetTaskPriorityForCurrentThread = ScopedSetTaskPriorityForCurrentThread(task.traits.priority)
      //let scopedSetSequenceLocalStorageMapForCurrentThread = ScopedSetSequenceLocalStorageMapForCurrentThread(sequence.sequenceLocalStorage)

      var sequencedTaskRunnerHandle: SequencedTaskRunnerHandle?
      var singleThreadTaskRunnerHandle: ThreadTaskRunnerHandle?
      
      if task.sequencedTaskRunner != nil {
        sequencedTaskRunnerHandle = SequencedTaskRunnerHandle(taskRunner: task.sequencedTaskRunner!)
      } else if task.singleThreadTaskRunner != nil {
        singleThreadTaskRunnerHandle = ThreadTaskRunnerHandle(taskRunner: task.singleThreadTaskRunner!)
      }

      if canRunTask {
        //let executionMode =
        //    task.singleThreadTaskRunner != nil
        //        ? singleThreadExecutionMode
        //        : (task.sequencedTaskRunner != nil ? sequencedExecutionMode : parallelExecutionMode)
        try taskAnnotator.runTask(task)
      }

      task.task = Closure({})//OnceClosure()
    } // do

    //ThreadRestrictions.setWaitAllowed(previousWaitAllowed)
    //ThreadRestrictions.setIOAllowed(previousIoAllowed)
    //ThreadRestrictions.setSingletonAllowed(previousSingletonAllowed)
  }

  func performShutdown() {
    shutdownLock.withLockVoid {
      shutdownEvent = WaitableEvent(resetPolicy: WaitableEvent.ResetPolicy.manual, initialState: WaitableEvent.InitialState.notSignaled)
      let tasksAreBlockingShutdown = state.startShutdown()
      if !tasksAreBlockingShutdown {
        shutdownEvent!.signal()
        return
      }
    }

    setMaxNumScheduledBackgroundSequences(Int.max)

    //{
      //let allowWait = ThreadRestrictions.ScopedAllowWait()
    shutdownEvent!.wait()
    //}

    // shutdownLock.withLockVoid {
    //   if numBlockShutdownTasksPostedDuringShutdown <
    //       maxBlockShutdownTasksPostedDuringShutdown {
    //     recordNumBlockShutdownTasksPostedDuringShutdown(
    //         numBlockShutdownTasksPostedDuringShutdown)
    //   }
    // }
  }

  func setMaxNumScheduledBackgroundSequences(
      _ maxNumScheduledBackgroundSequences: Int) {

    var sequencesToSchedule = Array<PreemptedBackgroundSequence>()

    backgroundLock.withLockVoid {
      self.maxNumScheduledBackgroundSequences = maxNumScheduledBackgroundSequences

      while self.numScheduledBackgroundSequences <
                maxNumScheduledBackgroundSequences &&
            !preemptedBackgroundSequences.isEmpty {
        sequencesToSchedule.append(
            preemptedBackgroundSequenceToScheduleLockRequired)
      }
    }

    for sequenceToSchedule in sequencesToSchedule {
      schedulePreemptedBackgroundSequence(sequenceToSchedule)
    }
  }

  func schedulePreemptedBackgroundSequence(
      _ sequenceToSchedule: PreemptedBackgroundSequence) {
    sequenceToSchedule.observer?.onCanScheduleSequence(sequence: sequenceToSchedule.sequence!)
  }

  func beforePostTask(behavior shutdownBehavior: TaskShutdownBehavior) -> Bool {
    if shutdownBehavior == .blockShutdown {
      let shutdownStarted = state.incrementNumTasksBlockingShutdown()
      if shutdownStarted {
        let r = shutdownLock.withLock { () -> Bool in
          if shutdownEvent!.isSignaled {
            let _ = state.decrementNumTasksBlockingShutdown()
            return false
          }

          //numBlockShutdownTasksPostedDuringShutdown += 1
          //if numBlockShutdownTasksPostedDuringShutdown ==
          //    maxBlockShutdownTasksPostedDuringShutdown {
            // Record the TaskScheduler.BlockShutdownTasksPostedDuringShutdown
            // histogram as soon as its upper bound is hit. That way, a value will
            // be recorded even if an infinite number of BLOCK_SHUTDOWN tasks are
            // posted, preventing shutdown to complete.
            //recordNumBlockShutdownTasksPostedDuringShutdown(
            //    numBlockShutdownTasksPostedDuringShutdown)
          //}
          return true
        }
        if !r {
          return r
        }
      }
      return true
    }

    return !state.hasShutdownStarted
  }

  func beforeRunTask(behavior shutdownBehavior: TaskShutdownBehavior) -> Bool {
    switch shutdownBehavior {
      case .blockShutdown:
        return true
      case .skipOnShutdown:
        let shutdownStarted = state.incrementNumTasksBlockingShutdown()
        if shutdownStarted {
          let shutdownStartedAndNoTasksBlockShutdown =
              state.decrementNumTasksBlockingShutdown()
          if shutdownStartedAndNoTasksBlockShutdown {
            onBlockingShutdownTasksComplete()
          }
          return false
        }
        return true
      case .continueOnShutdown:
        return !state.hasShutdownStarted
    }
  }

  func afterRunTask(behavior shutdownBehavior: TaskShutdownBehavior) {
    if shutdownBehavior == .blockShutdown ||
        shutdownBehavior == .skipOnShutdown {
      let shutdownStartedAndNoTasksBlockShutdown =
          state.decrementNumTasksBlockingShutdown()
      if shutdownStartedAndNoTasksBlockShutdown {
        onBlockingShutdownTasksComplete()
      }
    }
  }

  func onBlockingShutdownTasksComplete() {
    shutdownLock.withLockVoid {
      shutdownEvent!.signal()
    }
  }

  func decrementNumIncompleteUndelayedTasks() {
    let newNumIncompleteUndelayedTasks = numIncompleteUndelayedTasks.sub(1)
    if newNumIncompleteUndelayedTasks == 0 {
      flushLock.withLockVoid {
        flushcv.signal()
      }
      //callFlushCallbackForTesting()
    }
  }

  func manageBackgroundSequencesAfterRunningTask(
      sequence justRanSequence: TaskSequence?,
      observer: CanScheduleSequenceObserver) -> TaskSequence? {

    let nextTaskSequencedTime: TimeTicks =
        justRanSequence != nil
            ? justRanSequence!.sortKey.nextTaskSequencedTime
            : TimeTicks()

    var sequenceToSchedule = PreemptedBackgroundSequence()

    let retval = backgroundLock.withLock { () -> TaskSequence? in
      numScheduledBackgroundSequences -= 1
      if let seq = justRanSequence {
        //print("preemptedBackgroundSequences.isEmpty ? \(preemptedBackgroundSequences.isEmpty)\npreemptedBackgroundSequences.peek()!.nextTaskSequencedTime > nextTaskSequencedTime ? \(preemptedBackgroundSequences.peek()!.nextTaskSequencedTime > nextTaskSequencedTime)")
        if preemptedBackgroundSequences.isEmpty ||
          preemptedBackgroundSequences.peek()!.nextTaskSequencedTime > 
            nextTaskSequencedTime {
          numScheduledBackgroundSequences += 1
          return seq
        }
               
        preemptedBackgroundSequences.push(
            PreemptedBackgroundSequence(sequence: seq, nextTaskSequencedTime: nextTaskSequencedTime, observer: observer))
      }

      if !preemptedBackgroundSequences.isEmpty {
        sequenceToSchedule = preemptedBackgroundSequenceToScheduleLockRequired
      }
      return nil
    }

    if retval != nil {
      return retval
    }

    //print("sequenceToSchedule.sequence == nil ? \(sequenceToSchedule.sequence == nil)")
    if sequenceToSchedule.sequence != nil {
      schedulePreemptedBackgroundSequence(sequenceToSchedule)
    }
    
    return nil
  }

}