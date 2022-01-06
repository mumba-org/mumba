// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics


// TODO: make it a protocol now
public class UIWidgetDeletionObserver {

    var widget: UIWidget?

    public var widgetAlive: Bool {
      return widget != nil
    }

    public init(widget: UIWidget) {
      self.widget = widget
    }

    public func cleanupWindow() {
      widget = nil
    }
}

extension UIWidgetDeletionObserver: UIWidgetObserver {

  public func onWidgetDestroying(widget: UIWidget) {

  }

  public func onWidgetClosing(widget: UIWidget) {}
  public func onWidgetCreated(widget: UIWidget) {}
  public func onWidgetDestroyed(widget: UIWidget) {}
  public func onWidgetVisibilityChanging(widget: UIWidget, visible: Bool) {}
  public func onWidgetVisibilityChanged(widget: UIWidget, visible: Bool) {}
  public func onWidgetActivationChanged(widget: UIWidget, active: Bool) {}
  public func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect) {}

}
