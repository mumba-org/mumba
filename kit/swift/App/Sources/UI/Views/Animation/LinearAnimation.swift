// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class LinearAnimation : Animation {
  
  public static let defaultFrameRate: Int = 60

  public override var currentValue: Double {
    get {
      return state
    }
    set {
       var value = newValue
       value = max(0.0, min(1.0, value))
       let timeDelta: TimeDelta = TimeDelta.from(
        microseconds: duration.microseconds * Int64((value - state)))
       startTime = startTime - timeDelta
       state = value
    }
  }

  public var duration: TimeDelta {
    get {
      return _duration
    }
    set {
      _duration = newValue
      if _duration < timerInterval {
        _duration = timerInterval
      }
      if isAnimating {
        startTime = container!.lastTickTime
      }
    }
  }

  var state: Double
  var inEnd: Bool
  var _duration: TimeDelta
  
  public init(duration: TimeDelta,
              frameRate: Int,
              delegate: AnimationDelegate?) {
    state = 0.0
    inEnd = false
    _duration = duration
    super.init(timerInterval: calculateInterval(frameRate: frameRate))
    self.delegate = delegate
  }

  public convenience init(delegate: AnimationDelegate?,
              frameRate: Int = LinearAnimation.defaultFrameRate) {
    self.init(duration: TimeDelta(), frameRate: frameRate, delegate: delegate)
  }

  public func end() {
    if !isAnimating {
      return
    }

    inEnd = true
    stop()
  }

  internal func animateToState(state: Double) {}

  public override func step(timeNow: TimeTicks) {
    let elapsedTime: TimeDelta = timeNow - startTime
    
    state = Double(elapsedTime.microseconds) / Double(duration.microseconds)
    
    if state >= 1.0 {
      state = 1.0
    }
    
    animateToState(state: state)

    if let d = delegate {
      d.animationProgressed(animation: self)
    }

    if state == 1.0 {
      stop()
    }
  }

  internal override func animationStarted() {
    state = 0.0
  }
  
  internal override func animationStopped() {
    if !inEnd {
      return
    }

    inEnd = false
    // Set state_ to ensure we send ended to delegate and not canceled.
    state = 1
    animateToState(state: 1.0)
  }
  
  internal override func shouldSendCanceledFromStop() -> Bool { 
    return state != 1
  }

}

internal func calculateInterval(frameRate: Int) -> TimeDelta {
  var timerInterval = 1000000 / frameRate
  
  if timerInterval < 10000 {
    timerInterval = 10000
  }

  return TimeDelta.from(microseconds: Int64(timerInterval))
}