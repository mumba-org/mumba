// Copyright (c) 2016-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol DesktopWindowTreeHost : class {
  var isVisible: Bool { get }
  var size: IntSize { get set }
  var windowBoundsInScreen: IntRect { get }
  var clientAreaBoundsInScreen: IntRect { get }
  var restoredBounds: IntRect { get }
  var workspace: String { get }
  var workAreaBoundsInScreen: IntRect { get }
  var isActive: Bool { get }
  var isMaximized: Bool { get }
  var isMinimized: Bool { get }
  var hasCapture: Bool { get }
  var isAlwaysOnTop: Bool { get set }
  var isVisibleOnAllWorkspaces: Bool { get set }
  var shouldUseNativeFrame: Bool { get }
  var shouldWindowContentsBeTransparent: Bool { get }
  var isFullscreen: Bool { get set }
  var isAnimatingClosed: Bool { get }
  var translucentWindowOpacitySupported: Bool { get }
  var shouldUpdateWindowTransparency: Bool { get }
  var shouldUseDesktopNativeCursorManager: Bool { get }
  var shouldCreateVisibilityController: Bool { get }

  //func initialize(params: UIWidget.InitParams) throws
  func initialize(compositor: UIWebWindowCompositor, params: UIWidget.InitParams) throws
  func onNativeWidgetCreated(params: UIWidget.InitParams)
  func onWidgetInitDone()
  func onActiveWindowChanged(active: Bool) 
  func createTooltip() -> Tooltip
  func createDragDropClient(cursorManager: DesktopNativeCursorManager) -> DragDropClient?
  func close()
  func closeNow()
  func asWindowTreeHost() -> WindowTreeHost
  func showWindowWithState(showState: WindowShowState)
  func showMaximizedWithBounds(restoredBounds: IntRect)
  func stackAbove(window: Window)
  func stackAtTop()
  func centerWindow(size: IntSize)
  func getWindowPlacement(bounds: inout IntRect,
                          showState: inout WindowShowState)
  func setShape(nativeShape: UIWidget.ShapeRects?)
  func activate()
  func deactivate()
  func maximize()
  func minimize()
  func restore()
  func setWindowTitle(title: String) -> Bool
  func clearNativeFocus()
  func runMoveLoop(
      dragOffset: IntVec2,
      source: UIWidget.MoveLoopSource,
      escapeBehavior: UIWidget.MoveLoopEscapeBehavior) -> UIWidget.MoveLoopResult
  func endMoveLoop()
  func setVisibilityChangedAnimationsEnabled(value: Bool)
  func createNonClientFrameView() -> NonClientFrameView?
  func frameTypeChanged()
  func setOpacity(opacity: Float)
  func setWindowIcons(windowIcon: ImageSkia?,
                      appIcon: ImageSkia?)
  func initModalType(modalType: ModalType)
  func flashFrame(_ flashFrame: Bool)
  func sizeConstraintsChanged()
}