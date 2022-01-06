// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class WindowModalityController {
  public init(target: EventTarget) {}
}

extension WindowModalityController : EventHandler {

}

extension WindowModalityController : WindowObserver {
  public func onEvent(event: inout Event) {}
  public func onKeyEvent(event: inout KeyEvent) {}
  public func onMouseEvent(event: inout MouseEvent) {}
  public func onScrollEvent(event: inout ScrollEvent) {}
  public func onTouchEvent(event: inout TouchEvent) {}
  public func onGestureEvent(event: inout GestureEvent) {}
  public func onCancelMode(event: inout CancelModeEvent) {}
}

// TODO: figure it out EnvObserver
