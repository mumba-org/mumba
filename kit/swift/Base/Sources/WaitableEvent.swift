// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

internal struct WaitableEventKernel {

  let lock: Lock = Lock()
  let manualReset: Bool
  var signaled: Bool
  var waiters: [Waiter] = []

  init(resetPolicy: WaitableEvent.ResetPolicy, initialState: WaitableEvent.InitialState) {
    manualReset = resetPolicy == WaitableEvent.ResetPolicy.manual
    signaled = initialState == WaitableEvent.InitialState.signaled
  }
  
  mutating func dequeue(waiter: Waiter, tag: AnyObject) -> Bool {
    for (index, elem) in waiters.enumerated() {
      if elem === waiter && elem.compare(tag: tag) {
        waiters.remove(at: index)
        return true
      }
    }

    return false
  }

}

internal protocol Waiter : class {
  func fire(signalingEvent: WaitableEvent) -> Bool
  func compare(tag: AnyObject) -> Bool
}

internal class SyncWaiter : Waiter {
  
  internal private(set) var signalingEvent: WaitableEvent?
  internal private(set) var fired: Bool

  let lock: Lock
  let cv: ConditionVariable

  init() {
    fired = false
    lock = Lock()
    cv = ConditionVariable(lock: lock)
  }

 internal func fire(signalingEvent: WaitableEvent) -> Bool {
    return lock.withLock {
      if fired {
        return false
      }

      fired = true
      self.signalingEvent = signalingEvent
      cv.broadcast()

      return true
    }
  }

  internal func compare(tag: AnyObject) -> Bool { 
    return self === tag 
  }

  internal func disable() {
    fired = true
  }

}

public class WaitableEvent {
  
  public enum ResetPolicy { 
    case manual 
    case automatic 
  }
  
  public enum InitialState { 
    case signaled
    case notSignaled
  }

  public var isSignaled: Bool {
    return kernel.lock.withLock {
      let result = kernel.signaled
      if result && !kernel.manualReset {
        kernel.signaled = false
      }
      return result
    }
  }

  //let resetPolicy: ResetPolicy
  var kernel: WaitableEventKernel

  public init(resetPolicy: ResetPolicy, initialState: InitialState) {
    kernel = WaitableEventKernel(resetPolicy: resetPolicy, initialState: initialState)
  }

  deinit {

  }

  public func reset() {
    kernel.lock.withLockVoid {
      kernel.signaled = false
    }
  }

  public func signal() {
    kernel.lock.withLockVoid {
      if kernel.signaled {
        return
      }
      if kernel.manualReset {
        let _ = signalAll()
        kernel.signaled = true
      } else {
        if !signalOne() {
          kernel.signaled = true
        }
      }
    }
  }

  public func wait() {
    let result = timedWaitUntil(endTime: TimeTicks.max)
    assert(result)
  }

  public func timedWait(waitDelta: TimeDelta) -> Bool {
    return timedWaitUntil(endTime: TimeTicks.now + waitDelta)
  }

  public func timedWaitUntil(endTime: TimeTicks) -> Bool {
    // assertBaseSyncPrimitivesAllowed()
    let scopedBlockingCall = ScopedBlockingCall(type: BlockingType.mayBlock)
   
    let finiteTime = !endTime.isMax

    kernel.lock.lock()
    if kernel.signaled {
      if !kernel.manualReset {
        kernel.signaled = false
      }

      kernel.lock.unlock()
      return true
    }

    let sw = SyncWaiter()
    sw.lock.lock()

    enqueue(waiter: sw)
    kernel.lock.unlock()
  
    while true {
      let currentTime = TimeTicks.now

      if sw.fired || (finiteTime && currentTime >= endTime) {
        let returnValue = sw.fired

        sw.disable()
        sw.lock.unlock()

        kernel.lock.lock()
        kernel.dequeue(waiter: sw, tag: sw)
        kernel.lock.unlock()

        return returnValue
      }

      if finiteTime {
        let maxWait = TimeDelta(ticks: endTime - currentTime)
        sw.cv.timedWait(maxWait)
      } else {
        sw.cv.wait()
      }
    }
  }


  public static func waitMany(waitables rawWaitables: [WaitableEvent]) -> Int {
    //assertBaseSyncPrimitivesAllowed()
    let count = rawWaitables.count
    let scopedBlockingCall = ScopedBlockingCall(type: BlockingType.mayBlock)
    //let eventActivity = ScopedEventWaitActivity(waitables[0])

    var waitables: [(WaitableEvent, Int)] = []
    for (i, elem) in rawWaitables.enumerated() {
      waitables.append((elem, i))
    }

    waitables.sort { (left, right) -> Bool in
      return unsafeBitCast(left.0, to: Int.self) < unsafeBitCast(right.0, to: Int.self)
    }

    // The set of waitables must be distinct. Since we have just sorted by
    // address, we can check this cheaply by comparing pairs of consecutive
    // elements.
    //for i in 0..<(waitables.count - 1) {
    //  assert(waitables[i].0 !== waitables[i+1].0)
    //}

    let sw = SyncWaiter()

    let r = enqueueMany(waitables: &waitables, count: count, waiter: sw)
    if r < count {
      // One of the events is already signaled. The SyncWaiter has not been
      // enqueued anywhere.
      return waitables[r].1
    }

    // At this point, we hold the locks on all the WaitableEvents and we have
    // enqueued our waiter in them all.
    sw.lock.lock()
      // Release the WaitableEvent locks in the reverse order
    for i in 0..<count {
      waitables[count - (1 + i)].0.kernel.lock.unlock()
    }

    while true {
      if sw.fired {
        break
      }
      sw.cv.wait()
    }
    sw.lock.unlock()

    // The address of the WaitableEvent which fired is stored in the SyncWaiter.
    let signaledEvent = sw.signalingEvent
    // This will store the index of the raw_waitables which fired.
    var signaledIndex = 0

    // Take the locks of each WaitableEvent in turn (except the signaled one) and
    // remove our SyncWaiter from the wait-list
    for i in 0..<count {
      if rawWaitables[i] !== signaledEvent {
        rawWaitables[i].kernel.lock.lock()
        rawWaitables[i].kernel.dequeue(waiter: sw, tag: sw)
        rawWaitables[i].kernel.lock.unlock()
      } else {
        // By taking this lock here we ensure that |Signal| has completed by the
        // time we return, because |Signal| holds this lock. This matches the
        // behaviour of |Wait| and |TimedWait|.
        rawWaitables[i].kernel.lock.lock()
        rawWaitables[i].kernel.lock.unlock()
        signaledIndex = i
      }
    }

    return signaledIndex
  }

 
  static func enqueueMany(waitables: inout [(WaitableEvent, Int)],
                          count: Int, 
                          waiter: Waiter) -> Int {
    var winner = count
    var winnerIndex = count
    for i in 0..<count {
      let kernel = waitables[i].0.kernel
      kernel.lock.lock()
      if kernel.signaled && waitables[i].1 < winner {
        winner = waitables[i].1
        winnerIndex = i
      }
    }

    // No events signaled. All locks acquired. Enqueue the Waiter on all of them
    // and return.
    if winner == count {
      for i in 0..<count {
        waitables[i].0.enqueue(waiter: waiter)
      }
      return count
    }

    // Unlock in reverse order and possibly clear the chosen winner's signal
    // before returning its index.
    for w in waitables.reversed() {
      var kernel = w.0.kernel
      if w.1 == winner {
        if !kernel.manualReset {
          kernel.signaled = false
        }
      }
      kernel.lock.unlock()
    }

    return winnerIndex
  }

  func signalAll() -> Bool {
    var signaledAtLeastOne = false

    for waiter in kernel.waiters {
      if waiter.fire(signalingEvent: self) {
        signaledAtLeastOne = true
      }
    }

    kernel.waiters.removeAll()
    return signaledAtLeastOne
  }
  
  func signalOne() -> Bool {
    repeat {
      guard let waiter = kernel.waiters.first else {
        return false
      }
      let r = waiter.fire(signalingEvent: self)
      kernel.waiters.removeFirst()
      if r {
        return true
      }
    } while true
  }

  func enqueue(waiter: Waiter) {
    kernel.waiters.append(waiter)
  }

}