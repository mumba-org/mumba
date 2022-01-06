// Copyright (c) 2015-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//import Foundation
import Graphics
import Base

public class LayerAnimatorCollection : UICompositorAnimationObserver {

  public weak var compositor: UICompositor?

  public var hasActiveAnimators: Bool {
    return !animators.isEmpty
  }

  public private (set) var lastTickTime: TimeTicks
  //private var animators: Set<LayerAnimator> = Set<LayerAnimator>()
  private var animators: Array<LayerAnimator>

  public init(compositor: UICompositor) {
    self.compositor = compositor
    lastTickTime = TimeTicks.now
    animators = Array<LayerAnimator>()
  }

  deinit {
    if let c = compositor {
      c.removeAnimationObserver(observer: self)
    }
  }

  public func startAnimator(animator: LayerAnimator) {
    if animators.isEmpty {
      lastTickTime = TimeTicks.now
    }
    animators.append(animator)
    if animators.count == 1 {
      compositor!.addAnimationObserver(observer: self)
    }
  }

  public func stopAnimator(animator: LayerAnimator) {
    if let index = animators.firstIndex(where: { $0 === animator }) {
      animators.remove(at: index)
    }
    if animators.isEmpty {
      compositor!.removeAnimationObserver(observer: self)
    }
  }

  public func onAnimationStep(timestamp now: TimeTicks) {
    lastTickTime = now
    let animatorsCollection = animators
    for animator in animatorsCollection {
      animator.step(now: now)
    }
    if !hasActiveAnimators {
      compositor!.removeAnimationObserver(observer: self)
    }
  }

  public func onCompositingShuttingDown(compositor: UICompositor) {
    compositor.removeAnimationObserver(observer: self)
    self.compositor = nil
  }

}
