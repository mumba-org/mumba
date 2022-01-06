// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims
import Foundation

public class DesktopDragDropClientX11 {

  public init(rootWindow: Window,
              cursorManager: DesktopNativeCursorManager,
              xdisplay: XDisplayHandle,
              xwindow: CUnsignedLong) {}

  public func initialize() {

  }


  // These methods reference the various X11 client messages from the platform.
  func onXdndEnter(event: XClientMessageEvent) {

  }

  func onXdndLeave(event: XClientMessageEvent) {

  }

  func onXdndPosition(event: XClientMessageEvent) {

  }

  func onXdndStatus(event: XClientMessageEvent) {

  }

  func onXdndFinished(event: XClientMessageEvent) {

  }

  func onXdndDrop(event: XClientMessageEvent) {

  }

  func onSelectionNotify(xselection: XSelectionEvent) {

  }


}

extension DesktopDragDropClientX11 : DragDropClient {

  public func startDragAndDrop(data: OSExchangeData,
                               rootWindow: Window,
                               sourceWindow: Window,
                               screenLocation: IntPoint,
                               operation: Int,
                               source: DragEventSource) -> DragOperation {

    return .DragNone
  }

  public func dragUpdate(target: Window, event: LocatedEvent) {

  }

  public func drop(target: Window, event: LocatedEvent) {

  }

  public func dragCancel() {

  }

  public func isDragDropInProgress() -> Bool {
    return false
  }

}

extension DesktopDragDropClientX11 : WindowObserver {
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

extension DesktopDragDropClientX11 : MoveLoopX11Delegate {

  public func onMouseMovement(screenPoint: IntPoint,
                              flags: Int,
                              eventTime: TimeTicks) {

  }

  public func onMouseReleased() {

  }

  public func onMoveLoopEnded() {

  }
}
