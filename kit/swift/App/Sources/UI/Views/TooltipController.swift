// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class TooltipController {

  private var tooltip: Tooltip

  public init(tooltip: Tooltip) {
    self.tooltip = tooltip
  }

}

extension TooltipController : TooltipClient {

  public func getMaxWidth(point: IntPoint, context: Window) -> Int {
    return 0
  }

  public func updateTooltip(target: Window) {

  }

  public func setTooltipShownTimeout(target: Window, timeoutInMs: Int) {

  }

  public func setTooltipsEnabled(enable: Bool) {

  }

}

extension TooltipController : EventHandler {

  public func onEvent(event: inout Event) {}
  public func onKeyEvent(event: inout KeyEvent) {}
  public func onMouseEvent(event: inout MouseEvent) {}
  public func onScrollEvent(event: inout ScrollEvent) {}
  public func onTouchEvent(event: inout TouchEvent) {}
  public func onGestureEvent(event: inout GestureEvent) {}
  public func onCancelMode(event: inout CancelModeEvent) {}

}

extension TooltipController : WindowObserver {

  public func onWindowDestroyed(window: Window) {

  }

}
