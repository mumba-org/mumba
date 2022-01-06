// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol CanScheduleSequenceObserver : class {
  func onCanScheduleSequence(sequence: TaskSequence)
}

public protocol SchedulerWorkerDelegate : CanScheduleSequenceObserver {
    var sleepTimeout: TimeDelta { get }
    //var runTasksInCurrentSequence: Bool { get }
    //var sequence: TaskSequence? { get }
    func onMainEntry(worker: SchedulerWorker)
    func getWork(worker: SchedulerWorker) -> TaskSequence?
    func didRunTask()
    func reEnqueueSequence(sequence: TaskSequence)
    func waitForWork(wakeupEvent: WaitableEvent)
    func onMainExit(worker: SchedulerWorker)
}

extension SchedulerWorkerDelegate {
  
  public func onMainExit(worker: SchedulerWorker) {

  }

  public func waitForWork(wakeupEvent: WaitableEvent) {
    let sleepTime = sleepTimeout
    if sleepTime.isMax {
      wakeupEvent.wait()
    } else {
      let _ = wakeupEvent.timedWait(waitDelta: sleepTime)
    }
  }

}

public class SchedulerWorker : PlatformThreadDelegate {

  public private(set) var delegate: SchedulerWorkerDelegate

  var shouldExit: Bool {
    return shouldExitFlag.isSet || taskTracker.isShutdownComplete
  }

  var desiredThreadPriority: ThreadPriority {

    if !Lock.handlesMultipleThreadPriorities {
      return ThreadPriority.normal
    }

    if (priorityHint < ThreadPriority.normal) && taskTracker.hasShutdownStarted ||
       !PlatformThread.canIncreaseCurrentThreadPriority {
      return ThreadPriority.normal
    }

    return priorityHint
  }

  let threadLock: Lock = Lock()

  var threadHandle: PlatformThreadHandle = PlatformThreadHandle()

  let wakeupEvent: WaitableEvent = WaitableEvent(
                               resetPolicy: WaitableEvent.ResetPolicy.automatic,
                               initialState: WaitableEvent.InitialState.notSignaled)

  var shouldExitFlag: AtomicFlag = AtomicFlag()

  let taskTracker: TaskTracker

  let priorityHint: ThreadPriority

  var currentThreadPriority: ThreadPriority

  public init(priorityHint: ThreadPriority,
              delegate: SchedulerWorkerDelegate,
              taskTracker: TaskTracker) {
    
    self.delegate = delegate
    self.taskTracker = taskTracker
    self.priorityHint = priorityHint
    self.currentThreadPriority = priorityHint//self.desiredThreadPriority
  }

  deinit {
    threadLock.withLockVoid {
      if !threadHandle.isNull {
        PlatformThread.detach(handle: threadHandle)
      }
    }
  }

  public func start() -> Bool {
    return threadLock.withLock {
      currentThreadPriority = desiredThreadPriority
      if shouldExitFlag.isSet {
        return true
      }

      let defaultStackSize = 0
      guard let handle = PlatformThread.createWithPriority(
        stackSize: defaultStackSize, 
        delegate: self, 
        priority: currentThreadPriority) else {
        return false
      }

      threadHandle = handle

      return true
    }
  }

  public func wakeUp() {
    wakeupEvent.signal()
  }

  public func cleanup() {
    shouldExitFlag.set()
    wakeupEvent.signal()
  }

  public func threadMain() {
    do {
      delegate.onMainEntry(worker: self)
      delegate.waitForWork(wakeupEvent: wakeupEvent)

      #if os(Windows) //&& !defined(COM_INIT_HECK_HOOK_ENABLED)
      let comInitializer = ScopedCOMInitializer()
      #endif

      while !shouldExit {
        #if os(macOS)
        let autoreleasePool = ScopedNSAutoreleasePool()
        #endif

        updateThreadPriority(desiredThreadPriority)
        guard let sequence = delegate.getWork(worker: self) else {
          if shouldExit {
            break
          }
          delegate.waitForWork(wakeupEvent: wakeupEvent)
          continue
        }

        let nextSequence = try taskTracker.runAndPopNextTask(sequence: sequence, observer: delegate)
        delegate.didRunTask()
        
        if let nextSeq = nextSequence {
          delegate.reEnqueueSequence(sequence: nextSeq)
        }

        wakeupEvent.reset()
      }
      delegate.onMainExit(worker: self)
    } catch {
      print("user exception while running task")
    }
  }

  func updateThreadPriority(_ desiredPriority: ThreadPriority) {
    guard desiredPriority != currentThreadPriority else {
      return
    }
    PlatformThread.currentThreadPriority = desiredPriority
    currentThreadPriority = desiredPriority
  }

}

extension SchedulerWorker : Equatable {
 
  public static func == (lhs: SchedulerWorker, rhs: SchedulerWorker) -> Bool {
    // we only care if they are the same instance
    return lhs === rhs
  }

}