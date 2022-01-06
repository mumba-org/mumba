// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class ThrobAnimation : SlideAnimation {
  
  public var throbDuration: Int

  public override var slideDuration: Int {
    get {
      return super.slideDuration
    }
    set {
       _slideDuration = newValue
    }
  }

  public var cyclesRemaining: Int

  var throbbing: Bool
  var _slideDuration: Int

  public override init(target: AnimationDelegate?) {
    throbDuration = defaultThrobDurationMS
    cyclesRemaining = 0
    throbbing = false
    _slideDuration = 0
    super.init(target: target)
    _slideDuration = super.slideDuration
  }

  public func startThrobbing(cyclesTilStop: Int) {
    let cyclesTilStopChanged = cyclesTilStop >= 0 ? cyclesTilStop : Int.max
    cyclesRemaining = cyclesTilStopChanged
    throbbing = true
    super.slideDuration = throbDuration
    if isAnimating {
      return  // We're already running, we'll cycle when current loop finishes.
    }

    if isShowing {
      super.hide()
    } else {
      super.show()
    }
    cyclesRemaining = cyclesTilStopChanged
  }

  public override func reset() {
    reset(value: 0)
  }

  public override func reset(value: Double) {
    resetForSlide()
    super.reset(value: value)
  }

  public override func show() {
    resetForSlide()
    super.show()
  }
 
  public override func hide() {
    resetForSlide()
    super.hide()
  }

  public override func step(timeNow: TimeTicks) {
    super.step(timeNow: timeNow)

    if !isAnimating && throbbing {
      // Were throbbing a finished a cycle. Start the next cycle unless we're at
      // the end of the cycles, in which case we stop.
      cyclesRemaining -= 1
      if isShowing {
        // We want to stop hidden, hence this doesn't check cycles_remaining_.
        super.hide()
      } else if cyclesRemaining > 0 {
        super.show()
      } else {
        // We're done throbbing.
        throbbing = false
      }
    }
  }

  fileprivate func resetForSlide() {
    super.slideDuration = _slideDuration
    cyclesRemaining = 0
    throbbing = false
  }

}

fileprivate let defaultThrobDurationMS: Int = 400