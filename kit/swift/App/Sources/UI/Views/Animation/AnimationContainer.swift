// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public protocol AnimationContainerObserver {
  func animationContainerProgressed(container: AnimationContainer)
  func animationContainerEmpty(container: AnimationContainer)
}

public class AnimationContainer {

  public var observer: AnimationContainerObserver?
  
  public private(set) var lastTickTime: TimeTicks
  
  public var isRunning: Bool { 
    return !elements.isEmpty
  }
  
  // FIX: We probably can convert this to some functional dialect
  fileprivate var minIntervalAndCount: (_: TimeDelta, _: Int) {
    var min = TimeDelta()
    var count = 1
    var index = elements.startIndex
    min = elements[index].timerInterval
    index = elements.index(after: index) // move to next
    while index != elements.endIndex {
      let interval = elements[index].timerInterval
      if interval < min {
        min = interval
        count = 1
      } else if interval == min {
        count += 1
      }
      index = elements.index(after: index)
    }

    return (min, count)
  }

  fileprivate var minTimerInterval: TimeDelta
  fileprivate var minTimerIntervalCount: Int
  fileprivate var timer: RepeatingTimer
  fileprivate var elements: [AnimationContainerElement]

  public init() {
    minTimerInterval = TimeDelta()
    minTimerIntervalCount = 0
    lastTickTime = TimeTicks.now
    timer = RepeatingTimer(tickClock: nil)
    elements = []
  }

  public func start(animation: AnimationContainerElement) {
    if elements.isEmpty {
      lastTickTime = TimeTicks.now
      minTimerInterval = animation.timerInterval
      minTimerIntervalCount = 1
    } else if animation.timerInterval < minTimerInterval {
      minTimerInterval = animation.timerInterval
      minTimerIntervalCount = 1
    } else if animation.timerInterval == minTimerInterval {
      minTimerIntervalCount += 1
    }
    animation.startTime = lastTickTime
    elements.append(animation)
  }

  public func stop(animation: AnimationContainerElement) {
    let interval = animation.timerInterval
    
    for (i, elem) in elements.enumerated() {
      if elem === animation {
        elements.remove(at: i)
      }
    }

    if elements.isEmpty {
      timer.stop()
      minTimerIntervalCount = 0
      if let obs = observer {
        obs.animationContainerEmpty(container: self)
      }
    } else if interval == minTimerInterval {
      minTimerIntervalCount -= 1

      // If the last element at the current (minimum) timer interval has been
      // removed then go find the new minimum and the number of elements at that
      // same minimum.
      if minTimerIntervalCount == 0 {
        let intervalCount = minIntervalAndCount
        minTimerInterval = intervalCount.0
        minTimerIntervalCount = intervalCount.1
      }
    }
  }

  fileprivate func run() {
    let currentTime = TimeTicks.now
    lastTickTime = currentTime

    for elem in elements {
      elem.step(timeNow: currentTime)
    }

    if let obs = observer {
      obs.animationContainerProgressed(container: self)
    }

  }

  fileprivate func setMinTimerInterval(delta: TimeDelta) {
    timer.stop()
    minTimerInterval = delta
    assert(false)
     // implement:
    //timer.start(FROM_HERE, minTimerInterval, self, &AnimationContainer.run)
  }

}
