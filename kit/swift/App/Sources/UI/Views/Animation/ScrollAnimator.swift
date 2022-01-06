// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol ScrollDelegate : class {
  func onScroll(dx: Float, dy: Float) -> Bool
}

public class ScrollAnimator {

  public var isScrolling: Bool {
    return animation != nil
  }
  public var acceleration: Float

  weak var delegate: ScrollDelegate?
  var velocityX: Float
  var velocityY: Float
  var lastT: Float
  var duration: Float

  var animation: SlideAnimation?
  
  public init(delegate: ScrollDelegate) {
    self.delegate = delegate
    velocityX = 0.0
    velocityY = 0.0
    lastT = 0.0
    duration = 0.0
    acceleration = defaultAcceleration
  }

  deinit {
    stop()
  }

  public func start(velocityX: Float, velocityY: Float) {
    if acceleration >= 0.0 {
      acceleration = defaultAcceleration
    }

    let v: Float = max(abs(velocityX), abs(velocityY))
    lastT = 0.0
    self.velocityX = velocityX
    self.velocityY = velocityY
    duration = -v / acceleration // in seconds
    animation = SlideAnimation(target: self)
    animation!.slideDuration = Int(duration * 1000)
    animation!.show()
  }
  
  public func stop() {
    velocityX = 0.0 
    velocityY = 0.0 
    lastT = 0.0
    duration = 0.0
    animation = nil
  }

}

extension ScrollAnimator : AnimationDelegate {
  
  public func animationEnded(animation: Animation) {
    stop()
  }
  
  public func animationProgressed(animation: Animation) {
    let t = Float(animation.currentValue) * duration
    let ax = velocityX > 0 ? acceleration : -acceleration
    let ay = velocityY > 0 ? acceleration : -acceleration
    let dx = getDelta(velocityX, ax, lastT, t)
    let dy = getDelta(velocityY, ay, lastT, t)
    lastT = t
    if let d = delegate {
      let _ = d.onScroll(dx: dx, dy: dy)
    }
  }
  
  public func animationCanceled(animation: Animation) {
    stop()
  }
}

fileprivate let defaultAcceleration: Float = -1500.0 // in pixels per second^2

// Assumes that d0 == 0.0f
fileprivate func getPosition(_ v0: Float, _ a: Float, _ t: Float) -> Float {
  let maxT = -v0 / a
  var t0 = t
  if t0 > maxT {
    t0 = maxT
  }
  return t0 * (v0 + 0.5 * a * t0)
}

fileprivate func getDelta(_ v0: Float, _ a: Float, _ t1: Float, _ t2: Float) -> Float {
  return getPosition(v0, a, t2) - getPosition(v0, a, t1)
}