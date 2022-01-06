// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class TransientWindowManager {

  private(set) public var transientParent: Window?

  private(set) public var transientChildren: [Window]

  public var parentControlsVisibility: Bool

  private var stackingTarget: Window?

  public static func get(window: Window) -> TransientWindowManager? {
    var manager = window.windowManager
    if manager == nil {
      manager = TransientWindowManager()
      window.windowManager = manager
    }
    return manager
  }

  public init() {
    parentControlsVisibility = false
    transientChildren = [Window]()
  }

  func addObserver(observer: TransientWindowObserver) {

  }

  func removeObserver(observer: TransientWindowObserver) {

  }

  func addTransientChild(child: Window) {

  }

  func removeTransientChild(child: Window) {

  }

  func isStackingTransient(target: Window) -> Bool {
    return target === stackingTarget
  }

}

extension TransientWindowManager : WindowObserver {
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
