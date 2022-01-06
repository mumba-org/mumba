// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class FocusController {
  public var isFocused: Bool = true
  public var active: Bool = true

  public init() {}

  public init(rules: FocusRules) {

  }

}

extension FocusController : ActivationClient {
  public var activeWindow: Window? { return nil }
  public func addObserver(observer: ActivationChangeObserver) {}
  public func removeObserver(observer: ActivationChangeObserver) {}
  public func activateWindow(window: Window) {}
  public func deactivateWindow(window: Window) {}
  public func getActivatableWindow(window: Window) -> Window? { return nil }
  public func getToplevelWindow(window: Window) -> Window? { return nil }
  public func canActivateWindow(window: Window) -> Bool { return false }
}

extension FocusController : FocusClient {
  public var focusedWindow: Window? { return nil }
  public func addObserver(observer: FocusChangeObserver) {}
  public func removeObserver(observer: FocusChangeObserver) {}
  public func focusWindow(window: Window) {}
  public func resetFocusWithinActiveWindow(window: Window) {}
}

extension FocusController : EventHandler {
  public func onEvent(event: inout Event) {}
  public func onKeyEvent(event: inout KeyEvent) {}
  public func onMouseEvent(event: inout MouseEvent) {}
  public func onScrollEvent(event: inout ScrollEvent) {}
  public func onTouchEvent(event: inout TouchEvent) {}
  public func onGestureEvent(event: inout GestureEvent) {}
  public func onCancelMode(event: inout CancelModeEvent) {}
}

extension FocusController : WindowObserver {
  public func onWindowDestroying(window: Window) {}
  public func onWindowDestroyed(window: Window) {}
  public func onWindowAddedToRootWindow(window: Window) {}
  public func onWindowRemovingFromRootWindow(window: Window, newRoot: Window) {}
  public func onWindowVisibilityChanging(window: Window, visible: Bool) {}
  public func onWindowVisibilityChanged(window: Window, visible: Bool) {}
  public func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect) {}
  public func onWindowTransforming(window: Window) {}
  public func onWindowTransformed(window: Window) {}
  public func onWindowTitleChanged(window: Window) {}
  public func onAncestorWindowTransformed(source: Window, window: Window) {}
  public func onWindowStackingChanged(window: Window) {}
  public func onWindowParentChanged(window: Window, parent: Window) {}
  public func onWillRemoveWindow(window: Window) {}
  public func onDelegatedFrameDamage(window: Window, damaged: IntRect) {}
  public func onObservingWindow(window: Window) {}
  public func onUnobservingWindow(window: Window) {}
  public func onWindowHierarchyChanging(params: WindowObserverHierarchyChangeParams) {}
  public func onWindowHierarchyChanged(params: WindowObserverHierarchyChangeParams) {}
  public func onWindowAdded(window: Window) {}
}
