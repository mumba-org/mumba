// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WindowObserverHierarchyChangePhase {
  case HierarchyNone
  case HierarchyChanging
  case HierarchyChanged
}

public struct WindowObserverHierarchyChangeParams {
  public var phase: WindowObserverHierarchyChangePhase
  public var target: Window?
  public var newParent: Window?
  public var oldParent: Window?
  public var receiver: Window?

  public init() {
    phase = .HierarchyNone
  }
}

public protocol WindowObserver: class {
  func onWindowDestroying(window: Window)
  func onWindowDestroyed(window: Window)
  func onWindowAddedToRootWindow(window: Window)
  func onWindowRemovingFromRootWindow(window: Window, newRoot: Window)
  func onWindowVisibilityChanging(window: Window, visible: Bool)
  func onWindowVisibilityChanged(window: Window, visible: Bool)
  func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect)
  func onWindowTransforming(window: Window)
  func onWindowTransformed(window: Window)
  func onWindowOpacitySet(window: Window, reason: PropertyChangeReason)
  func onWindowTitleChanged(window: Window)
  func onAncestorWindowTransformed(source: Window, window: Window)
  func onWindowStackingChanged(window: Window)
  func onWindowParentChanged(window: Window, parent: Window)
  func onWillRemoveWindow(window: Window)
  func onDelegatedFrameDamage(window: Window, damaged: IntRect)
  func onObservingWindow(window: Window)
  func onUnobservingWindow(window: Window)
  func onWindowHierarchyChanging(params: WindowObserverHierarchyChangeParams)
  func onWindowHierarchyChanged(params: WindowObserverHierarchyChangeParams)
  func onWindowAdded(window: Window)
}

extension WindowObserver {
  public func onWindowDestroying(window: Window) {}
  public func onWindowDestroyed(window: Window) {}
  public func onWindowAddedToRootWindow(window: Window) {}
  public func onWindowRemovingFromRootWindow(window: Window, newRoot: Window) {}
  public func onWindowVisibilityChanging(window: Window, visible: Bool) {}
  public func onWindowVisibilityChanged(window: Window, visible: Bool) {}
  public func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect) {}
  public func onWindowTransforming(window: Window) {}
  public func onWindowTransformed(window: Window) {}
  public func onWindowOpacitySet(window: Window, reason: PropertyChangeReason) {}
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
