// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
#if os(Linux)
import Glibc
#endif

fileprivate let defaultDurationMs: Int = 120

public class SlideAnimation : LinearAnimation {
  
  public override var currentValue: Double {
    get {
      return valueCurrent
    }
    set {
      valueCurrent = newValue
    }
  }
  public var slideDuration: Int
  public var tweenType: TweenType
  public var dampeningValue: Double
  public override var duration: TimeDelta {
    get {
      let currentProgress =
        isShowing ? valueCurrent : 1.0 - valueCurrent

      return TimeDelta.from(
        milliseconds: Int64(slideDuration) * Int64(1 - pow(currentProgress, dampeningValue)))
    }
    set {
      super.duration = newValue
    }
  }
  var isClosing: Bool { 
    return !isShowing && valueEnd < valueCurrent 
  }
  //var target: AnimationDelegate?
  var isShowing: Bool
  var valueStart: Double
  var valueEnd: Double
  var valueCurrent: Double

  public init(target: AnimationDelegate?) {
      //self.target = target
      tweenType = TweenType.EaseOut
      isShowing = false
      valueStart = 0
      valueEnd = 0
      valueCurrent = 0
      slideDuration = defaultDurationMs
      dampeningValue = 1.0
      super.init(duration: TimeDelta(), frameRate: LinearAnimation.defaultFrameRate, delegate: target)
  }

  // Set the animation back to the 0 state.
  public func reset() {
    reset(value: 0)
  }

  public func reset(value: Double) {
    stop()
    isShowing = value == 1
    valueCurrent = value
  }

  public func show() {
    if isShowing {
      return
    }

    isShowing = true
    valueStart = valueCurrent
    valueEnd = 1.0

    // Make sure we actually have something to do.
    if slideDuration == 0 {
      animateToState(state: 1.0)  // Skip to the end of the animation.
      return
    } else if valueCurrent == valueEnd {
      return
    }

    // This will also reset the currently-occurring animation.
    let dur = duration
    duration = dur
    start()
  }

  public func hide() {
    // If we're already hiding (or hidden), we have nothing to do.
    if !isShowing {
      return
    }

    isShowing = false
    valueStart = valueCurrent
    valueEnd = 0.0

    // Make sure we actually have something to do.
    if slideDuration == 0 {
      // TODO(bruthig): Investigate if this should really be animating to 0.0, I
      // think it should be animating to 1.0.
      animateToState(state: 0.0)  // Skip to the end of the animation.
      return
    } else if valueCurrent == valueEnd {
      return
    }

    // This will also reset the currently-occurring animation.
    let dur = duration
    duration = dur
    start()
  }

  // Overridden from Animation.
  override func animateToState(state: Double) {
    var newState = state
    if state > 1.0 {
      newState = 1.0
    } else if state < 0 {
      newState = 0
    }

    newState = Tween.calculateValue(type: tweenType, state: newState)

    valueCurrent = valueStart + (valueEnd - valueStart) * newState

    // Implement snapping.
    if tweenType == TweenType.EaseOutSnap &&
        abs(valueCurrent - valueEnd) <= 0.06 {
      valueCurrent = valueEnd
    }

    // Correct for any overshoot (while state may be capped at 1.0, let's not
    // take any rounding error chances.
    if (valueEnd >= valueStart && valueCurrent > valueEnd) ||
        (valueEnd < valueStart && valueCurrent < valueEnd) {
      valueCurrent = valueEnd
    }
  }
}