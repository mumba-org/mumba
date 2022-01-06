// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base

public class ViewsDelegate {

  public enum ProcessMenuAcceleratorResult {
    case LeaveMenuOpen
    case CloseMenu
  }

  public var textfieldPasswordRevealDuration: TimeDelta {
    return TimeDelta()
  }

  public var shouldMirrorArrowsInRTL: Bool {
    return true
  }

  static var _instance: ViewsDelegate?

  public static var instance: ViewsDelegate {
    if _instance == nil {
      _instance = ViewsDelegate()
    }
    return _instance!
  }

  public func saveWindowPlacement(widget: UIWidget,
                                  windowName: String,
                                  bounds: IntRect,
                                  showState: WindowShowState) {}

  public func getSavedWindowPlacement(widget: UIWidget,
                                      windowName: String,
                                      bounds: inout IntRect,
                                      showState: inout WindowShowState) -> Bool {
    return false
  }

  public func notifyAccessibilityEvent(view: View, eventType: AXEvent) {

  }

  public func notifyMenuItemFocused(menuName: String,
                                    menuItemName: String,
                                    itemIndex: Int,
                                    itemCount: Int,
                                    hasSubmenu: Bool) {

  }

  // Gives the platform a chance to modify the properties of a UIWidget.
  public func onBeforeWidgetInit(params: inout UIWidget.InitParams,
                                 widget: UIWidget) {

  }

  public func getDefaultWindowIcon() -> Image? {
    return nil
  }

  public func createDefaultNonClientFrameView(widget: UIWidget) -> NonClientFrameView? {
    return nil
  }

  public func processAcceleratorWhileMenuShowing(_ accelerator: Accelerator) -> ViewsDelegate.ProcessMenuAcceleratorResult {
    return ProcessMenuAcceleratorResult.LeaveMenuOpen
  }

  public func windowManagerProvidesTitleBar(maximized: Bool) -> Bool {
    return false
  }


}
