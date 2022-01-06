// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class VisibilityController : VisibilityClient {
  public init() {}

  public func updateLayerVisibility(window: Window, visible: Bool) {
    var animated = window.type != .Control &&
                    window.type != .Unknown &&
                    shouldAnimateWindow(window: window)
    animated = animated &&
        callAnimateOnChildWindowVisibilityChanged(window, visible)

    // If we're already in the process of hiding don't do anything. Otherwise we
    // may end up prematurely canceling the animation.
    // This does not check opacity as when fading out a visibility change should
    // also be scheduled (to do otherwise would mean the window can not be seen,
    // opacity is 0, yet the window is marked as visible) (see CL 132903003).
    // TODO(vollick): remove this.
    if !visible &&
        window.layer!.animator.isAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Visibility) &&
        !window.layer!.targetVisibility {
      return
    }

    // When a window is made visible, we always make its layer visible
    // immediately. When a window is hidden, the layer must be left visible and
    // only made not visible once the animation is complete.
    if !animated || visible {
      window.layer!.isVisible = visible
    }
  }

  private func callAnimateOnChildWindowVisibilityChanged(_ window: Window, _ visible: Bool) -> Bool {
    return animateOnChildWindowVisibilityChanged(window, visible)
  }

}

fileprivate func shouldAnimateWindow(window: Window) -> Bool {
  guard let parent = window.parent else {
    return false
  }
  return parent.property[UI.childWindowVisibilityChangesAnimatedKey] as! Bool || window.property[UI.windowVisibilityChangesAnimatedKey] as! Bool
}