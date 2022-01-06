// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//import Foundation

public enum TimerSlack {
  case none
  case maximum
}

public protocol Timer {
  var isRunning: Bool { get }
  var currentDelay: TimeDelta { get }
  var task: ()? { get }
  var desiredRunTime: TimeTicks { get }
  func start(delay: TimeDelta, _ task: @escaping () throws -> Void)
  func stop()
  func abandonAndStop()
  func reset()
}

public class BaseTimer : Timer{

  public var currentDelay: TimeDelta {
    return TimeDelta()
  }
  public let desiredRunTime: TimeTicks
  public private(set) var isRunning: Bool
  public private(set) var task: ()?
  fileprivate var retainUserTask: Bool
  fileprivate var isRepeating: Bool
  fileprivate var tickClock: TickClock?

  public init(delay: TimeDelta,
              isRepeating: Bool,
              task: ()) {
    self.isRepeating = isRepeating            
    self.task = task
    desiredRunTime = TimeTicks()
    retainUserTask = true
    isRunning = false
  }

  public init(retainUserTask: Bool, isRepeating: Bool, tickClock: TickClock?) {
    self.isRepeating = isRepeating
    self.retainUserTask = retainUserTask
    self.tickClock = tickClock
    desiredRunTime = TimeTicks()
    isRunning = false
  }

  public func start(delay: TimeDelta, _ task: @escaping () throws -> Void) {
    assert(false)
  }
  
  public func stop() {
    assert(false)
  }

  public func abandonAndStop() {
    abandonScheduledTask()
    stop()
  }

  public func reset() { }

  fileprivate func abandonScheduledTask() {}
}

public class RepeatingTimer : BaseTimer {
  
  public init(tickClock: TickClock?) {
    super.init(retainUserTask: false, isRepeating: false, tickClock: tickClock)
  }

}

public class OneShotTimer : BaseTimer {
  
  public convenience init() {
    self.init(tickClock: nil)
  }

  public init(tickClock: TickClock?) {
    super.init(retainUserTask: false, isRepeating: false, tickClock: tickClock)
  }

}