// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol NativeWidgetDelegate : class {
  
  var isModal: Bool { get }
  var isDialogBox: Bool { get }
  var canActivate: Bool { get }
  var isAlwaysRenderAsActive: Bool { get set }
  var minimumSize: IntSize { get }
  var maximumSize: IntSize { get }
  var hasFocusManager: Bool { get } 
  var hasHitTestMask: Bool { get }
  var hitTestMask: Path? { get }

  func asWidget() -> UIWidget
  func onNativeWidgetActivationChanged(active: Bool) -> Bool
  func onNativeFocus()
  func onNativeBlur()
  func onNativeWidgetVisibilityChanging(visible: Bool)
  func onNativeWidgetVisibilityChanged(visible: Bool)
  func onNativeWidgetCreated(visible: Bool)
  func onNativeWidgetDestroying()
  func onNativeWidgetDestroyed()
  func onNativeWidgetMove()
  func onNativeWidgetSizeChanged(newSize: IntSize)
  func onNativeWidgetWorkspaceChanged()
  func onNativeWidgetWindowShowStateChanged()
  func onNativeWidgetBeginUserBoundsChange()
  func onNativeWidgetEndUserBoundsChange()
  func onNativeWidgetPaint(context: PaintContext)
  func getNonClientComponent(point: IntPoint) -> Int
  func onKeyEvent(event: inout KeyEvent)
  func onMouseEvent(event: inout MouseEvent)
  func onMouseCaptureLost()
  func onScrollEvent(event: inout ScrollEvent)
  func onGestureEvent(event: inout GestureEvent)
  func executeCommand(commandId: Int) -> Bool
  func setInitialFocus(showState: WindowShowState) -> Bool
  func shouldDescendIntoChildForEventHandling(
      rootLayer: Layer,
      child: Window,//NativeView,
      childLayer: Layer,
      location: IntPoint) -> Bool
}