// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class ViewTargeter : EventTargeter {

  var delegate: ViewTargeterDelegate

  public init(delegate: ViewTargeterDelegate) {
    self.delegate = delegate
  }

  public func findTargetForEvent(root: EventTarget, event: Event) -> EventTarget? {
    let view = root as! View

    if event.isKeyEvent {
      return findTargetForKeyEvent(root: view,  key: event as! KeyEvent)
    }

    if event.isScrollEvent {
      return findTargetForScrollEvent(root: view, scroll: event as! ScrollEvent)
    }

    if event.isGestureEvent {
      let gesture = event as! GestureEvent
      let gestureTarget = findTargetForGestureEvent(root: view, gesture: gesture)
      root.convertEventToTarget(target: gestureTarget!, event: gesture)
      return gestureTarget
    }

    return nil
  }

  public func findNextBestTarget(previousTarget: EventTarget, event: Event) -> EventTarget? {

    //guard previousTarget != nil else {
    //  return nil
    //}

    if event.isGestureEvent {
      let gesture = event as! GestureEvent
      let nextTarget = findNextBestTargetForGestureEvent(previousTarget: previousTarget, gesture: gesture)
      previousTarget.convertEventToTarget(target: nextTarget!, event: gesture)
      return nextTarget
    }

    return previousTarget.parentTarget
  }

  public func targetForRect(root: View, rect: IntRect) -> View? {
    return delegate.targetForRect(root: root, rect: rect)
  }

  public func doesIntersectRect(target: View, rect: IntRect) -> Bool {
    return delegate.doesIntersectRect(target: target, rect: rect)
  }

  func findTargetForKeyEvent(root: View, key: KeyEvent) -> View? {
    if let focusManager = root.focusManager {
      return focusManager.focusedView
    }
    return nil
  }

  func findTargetForScrollEvent(root: View, scroll: ScrollEvent) -> View? {
    let rect = IntRect(origin: scroll.location, size: IntSize(width: 1, height: 1))
    return root.effectiveViewTargeter!.targetForRect(root: root, rect: rect)
  }

  func findTargetForGestureEvent(root: View, gesture: GestureEvent) -> View? {
    return nil
  }

  func findNextBestTargetForGestureEvent(previousTarget: EventTarget, gesture: GestureEvent) -> EventTarget? {
    return nil
  }

}
