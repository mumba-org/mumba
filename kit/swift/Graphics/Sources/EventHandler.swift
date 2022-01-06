// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol KeyEventHandler : class {
  func onKeyEvent(event: inout KeyEvent)
}

public protocol MouseEventHandler : class {
  func onMouseEvent(event: inout MouseEvent)
}

public protocol ScrollEventHandler : class {
  func onScrollEvent(event: inout ScrollEvent)
}

public protocol TouchEventHandler : class {
  func onTouchEvent(event: inout TouchEvent)
}

public protocol GestureEventHandler : class {
  func onGestureEvent(event: inout GestureEvent)
}

public protocol CancelEventHandler : class {
  func onCancelMode(event: inout CancelModeEvent)
}

public protocol EventHandler : KeyEventHandler,
                               MouseEventHandler,
                               ScrollEventHandler,
                               TouchEventHandler,
                               GestureEventHandler,
                               CancelEventHandler {
  func onEvent(event: inout Event)
}

extension EventHandler {
  public func onEvent(event: inout Event) {}
  public func onKeyEvent(event: inout KeyEvent) {}
  public func onMouseEvent(event: inout MouseEvent) {}
  public func onScrollEvent(event: inout ScrollEvent) {}
  public func onTouchEvent(event: inout TouchEvent) {}
  public func onGestureEvent(event: inout GestureEvent) {}
  public func onCancelMode(event: inout CancelModeEvent) {}
}