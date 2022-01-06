// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class Animation : AnimationContainerElement {

  public class var shouldRenderRichAnimation: Bool { return true }

  public var hashValue: Int {
    return -1
  }

  public var startTime: TimeTicks
  
  public internal(set) var timerInterval: TimeDelta

  public var container: AnimationContainer? {
    get {
      return _container
    }
    set {
      guard newValue !== _container else {
        return
      }

      if isAnimating {
        _container!.stop(animation: self)
      }

      if newValue != nil {
        _container = newValue!
      } else {
        _container = AnimationContainer()
      }

      if isAnimating {
        _container!.start(animation: self)
      }
    }
  }

  public var delegate: AnimationDelegate?

  public var currentValue: Double {
    get {
      return Double()
    }
    set {

    }
  }

  private(set) public var isAnimating: Bool
  private var _container: AnimationContainer?

  public init(timerInterval: TimeDelta) {
    self.timerInterval = timerInterval
    startTime = TimeTicks()
    isAnimating = false
  }

  deinit {
    if _container != nil && isAnimating {
      _container!.stop(animation: self)
    }
  }

  public func start() {
    if isAnimating {
      return
    }

    if _container == nil {
      _container = AnimationContainer()
    }

    isAnimating = true

    _container!.start(animation: self)

    animationStarted()
  }

  public func stop() {
    if !isAnimating {
      return
    }

    isAnimating = false

    // Notify the container first as the delegate may delete us.
    _container!.stop(animation: self)

    animationStopped()

    if let d = delegate {
      if shouldSendCanceledFromStop() {
        d.animationCanceled(animation: self)
      } else {
        d.animationEnded(animation: self)
      }
    }
  }

  public func step(timeNow: TimeTicks) {}

  public func currentValueBetween(start: Double, target: Double) -> Double {
    return Tween.doubleValueBetween(value: currentValue, start: start, target: target)
  }

  public func currentValueBetween(start: Int, target: Int) -> Int {
    return Tween.intValueBetween(value: currentValue, start: start, target: target)
  }

  public func currentValueBetween(startBounds: IntRect, targetBounds: IntRect) -> IntRect {
     return Tween.rectValueBetween(value: currentValue, start: startBounds, target: targetBounds)
  }

  public static func ==(lhs: Animation, rhs: Animation) -> Bool {
    assert(false)
    return false
  }

  internal func animationStarted() {}
  internal func animationStopped() {}
  internal func shouldSendCanceledFromStop() -> Bool { return false }
}
