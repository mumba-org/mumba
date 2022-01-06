// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public class WindowEventFilterX11 {

  var host: DesktopWindowTreeHost?

  public init(host: DesktopWindowTreeHost) {
    self.host = host
  }

  func onClickedCaption(event: MouseEvent,
                        previousClickComponent: Int) {

  }

  // Called when the user clicked the maximize button.
  func onClickedMaximizeButton(event: MouseEvent) {

  }

  func toggleMaximizedState() {

  }

  func dispatchHostWindowDragMovement(hittest: Int,
                                      screenLocation: IntPoint) -> Bool {
    return false
  }

}

extension WindowEventFilterX11 : EventHandler {

  public func onEvent(event: inout Event) {

  }

  public func onKeyEvent(event: inout KeyEvent) {
    
  }

  public func onMouseEvent(event: inout MouseEvent) {

  }

  public func onScrollEvent(event: inout ScrollEvent) {

  }

  public func onTouchEvent(event: inout TouchEvent) {

  }

  public func onGestureEvent(event: inout GestureEvent) {

  }

  public func onCancelMode(event: inout CancelModeEvent) {

  }

}
