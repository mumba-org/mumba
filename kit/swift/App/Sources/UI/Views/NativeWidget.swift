// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

// This protocol is meant to be a base for concrete implementations
// its equivalent to internal::NativeWidgetPrivate in Chrome
public protocol NativeWidget : class {

  static var isMouseButtonDown: Bool { get }
  static var windowTitleFontList: FontList { get }

  var shouldUseNativeFrame: Bool { get }
  var shouldWindowContentsBeTransparent: Bool { get }
  var widget: UIWidget { get }
  var window: Window { get }
  var topLevelWidget: UIWidget { get }
  var compositor: UICompositor? { get }
  var layer: Layer? { get }
  var tooltipManager: TooltipManager? { get }
  var inputMethod: InputMethod? { get }
  var windowBoundsInScreen: IntRect { get }
  var bounds: IntRect { get set }
  var size: IntSize { get set }
  var clientAreaBoundsInScreen: IntRect { get }
  var restoredBounds: IntRect { get }
  var workAreaBoundsInScreen: IntRect { get }
  var workspace: String { get }
  var name: String { get }
  var isVisible: Bool { get }
  var isActive: Bool { get }
  var isMouseEventsEnabled: Bool { get }
  var isFullscreen: Bool { get set }
  var isAlwaysOnTop: Bool { get set }
  var isVisibleOnAllWorkspaces: Bool { get set }
  var isMaximized: Bool { get }
  var isMinimized: Bool { get }
  var isTranslucentWindowOpacitySupported: Bool { get }
  var hasCapture: Bool { get }

  static func createNativeWidget(delegate: NativeWidgetDelegate) -> NativeWidget
  static func getNativeWidgetForWindow(window: Window) -> NativeWidget
  static func getTopLevelNativeWidget(window: Window) -> NativeWidget
  static func getAllChildWidgets(window: Window, children: inout Widgets)
  static func getAllOwnedWidgets(window: Window, owned: inout Widgets)
  // was reparentNativeView
  static func reparentWindow(window: Window, parent: Window?)

  static func constrainBoundsToDisplayWorkArea(bounds: IntRect) -> IntRect
 
  //func initNativeWidget(params: UIWidget.InitParams)
  func initNativeWidget(compositor: UIWebWindowCompositor, params: UIWidget.InitParams)
  func onWidgetInitDone()
  func createNonClientFrameView() -> NonClientFrameView?
  func frameTypeChanged()
  func reorderNativeViews()
  func viewRemoved(view: View)
  func setNativeWindowProperty(name: String, value: UnsafeMutableRawPointer)
  func getNativeWindowProperty(name: String) -> UnsafeMutableRawPointer?
  func setCapture()
  func releaseCapture()
  func centerWindow(size: IntSize)
  func getWindowPlacement(bounds: inout IntRect, showState: inout WindowShowState)
  func setWindowTitle(title: String) -> Bool
  func setWindowIcons(windowIcon: ImageSkia?,
                      appIcon: ImageSkia?)
  func initModalType(modalType: ModalType)
  func setBoundsConstrained(bounds: IntRect)
  func stackAbove(window: Window)
  func stackAtTop()
  func setShape(shape: UIWidget.ShapeRects)
  func close()
  func closeNow()
  func show()
  func hide()
  func showMaximizedWithBounds(restoredBounds: IntRect)
  func showWithWindowState(showState: WindowShowState)
  func activate()
  func deactivate()
  func maximize()
  func minimize()
  func restore()
  func setOpacity(opacity: Float)
  func flashFrame(flash: Bool)
  func runShellDrag(view: View,
                    data: OSExchangeData,
                    location: IntPoint,
                    operation: Int,
                    source: DragEventSource)
  func schedulePaintInRect(rect: IntRect)
  func setCursor(cursor: PlatformCursor)
  func clearNativeFocus()
  func runMoveLoop(
      dragOffset: IntVec2,
      source: UIWidget.MoveLoopSource,
      escapeBehavior: UIWidget.MoveLoopEscapeBehavior) -> UIWidget.MoveLoopResult
  func endMoveLoop()
  func setVisibilityChangedAnimationsEnabled(value: Bool)
  func setVisibilityAnimationDuration(duration: TimeDelta)
  func setVisibilityAnimationTransition(transition: UIWidget.VisibilityTransition)
  func onSizeConstraintsChanged()
  func repostNativeEvent(nativeEvent: inout PlatformEvent)
}

extension NativeWidget {
  
  public static func constrainBoundsToDisplayWorkArea(bounds: IntRect) -> IntRect {
    var newBounds = bounds
    let workArea = Screen.instance.getDisplayMatching(bounds: bounds)!.workArea
    if !workArea.isEmpty {
      newBounds.adjustToFit(rect: workArea)
    }
    return newBounds
  }

}