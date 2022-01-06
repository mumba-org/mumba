// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol DesktopWindowTreeHost {

  var shouldUseNativeFrame: Bool { get }
  var visible: Bool { get }
  var windowBoundsInScreen: IntRect { get }
  var clientAreaBoundsInScreen: IntRect { get }
  var restoredBounds: IntRect { get }
  var workAreaBoundsInScreen: IntRect { get }
  var size: IntSize { get set }
  var active: Bool { get }
  var maximized: Bool { get }
  var minimized: Bool { get }
  var hasCapture: Bool { get }
  var alwaysOnTop: Bool { get set }
  var shouldWindowContentsBeTransparent: Bool { get }
  var fullscreen: Bool { get set }
  var translucentWindowOpacitySupported: Bool { get }
  var tree: WindowTreeHost { get }
  var isAnimatingClosed: Bool { get }

  func initialize(window w: Window, params: UIWidget.InitParams) throws
  func onWindowCreated(params: UIWidget.InitParams)
  func createTooltip() -> Tooltip
  func createDragDropClient(cursorManager: DesktopCursorManager) -> DragDropClient?
  func close()
  func closeNow()
  func showWindowWithState(showState: WindowShowState)
  func showMaximizedWithBounds(restoredBounds: IntRect)
  func stackAbove(window: Window)
  func stackAtTop()
  func centerWindow(size: IntSize)
  func getWindowPlacement(bounds: inout IntRect,
                          showState: inout WindowShowState)
  func setShape(nativeRegion: Region?)
  func activate()
  func deactivate()
  func maximize()
  func minimize()
  func restore()
  func setVisibleOnAllWorkspaces(alwaysVisible: Bool)
  func setWindowTitle(title: String) -> Bool
  func clearNativeFocus()
  func runMoveLoop(
      dragOffset: IntVec2,
      source: UIWidget.MoveLoopSource,
      escapeBehavior: UIWidget.MoveLoopEscapeBehavior) -> UIWidget.MoveLoopResult
  func endMoveLoop()
  func frameTypeChanged()
  func setOpacity(opacity: UInt8)
  func setWindowIcons(windowIcon: Image?,
                      appIcon: Image?)
  func initModalType(modalType: ModalType)
  func flashFrame(flashFrame: Bool)
  func onRootViewLayout()
  func onWindowFocus()
  func onWindowBlur()
  func setVisibilityChangedAnimationsEnabled(value: Bool)
  func sizeConstraintsChanged()
}

public class DesktopWindowTreeHostFactory {

  static var _instance: DesktopWindowTreeHostFactory?

  public static var instance: DesktopWindowTreeHostFactory {
    if _instance == nil {
#if os(Linux)
      _instance = DesktopWindowTreeHostFactoryX11()
#endif
    }
    return _instance!
  }

  public func make(widget: UIWidget) -> DesktopWindowTreeHost? {
    return nil
  }

  init() {}
}
