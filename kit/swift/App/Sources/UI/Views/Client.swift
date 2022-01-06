// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform

public protocol CursorClientObserver {

}

public typealias CursorSetType = Int

public protocol CursorClient {
  var cursor: PlatformCursor { get set }
  var cursorSet: CursorSetType { get set }
  var cursorVisible: Bool { get }
  var cursorLocked: Bool { get }
  var mouseEventsEnabled: Bool { get }

  func showCursor()
  func hideCursor()
  func enableMouseEvents()
  func disableMouseEvents()
  func setDisplay(display: Display)
  func lockCursor()
  func unlockCursor()
  func addObserver(observer: CursorClientObserver)
  func removeObserver(observer: CursorClientObserver)
  func shouldHideCursorOnKeyEvent(event: KeyEvent) -> Bool
}

public protocol CaptureClient {
  var captureWindow: Window? { get }
  var globalCaptureWindow: Window? { get }
  func setCapture(window: Window)
  func releaseCapture(window: Window)
}

public protocol EventClient {
  var toplevelEventTarget: EventTarget? { get }
  func canProcessEventsWithinSubtree(window: Window) -> Bool
}

public protocol CaptureDelegate {
  func updateCapture(oldCapture: Window, newCapture: Window)
  func onOtherRootGotCapture()
  func setNativeCapture()
  func releaseNativeCapture()
}

public protocol FocusChangeObserver {
  func onWindowFocused(gainedFocus: Window, lostFocus: Window)
}

public protocol FocusClient {
  var focusedWindow: Window? { get }

  func addObserver(observer: FocusChangeObserver)
  func removeObserver(observer: FocusChangeObserver)
  func focusWindow(window: Window)
  func resetFocusWithinActiveWindow(window: Window)
}

public protocol WindowTreeClient {
  func getDefaultParent(
     context: Window,
     window: Window,
     bounds: IntRect) throws -> Window?
}

public protocol WindowStackingClient {
  func adjustStacking(child: inout Window,
                      target: inout Window,
                      direction: inout Window.StackDirection) -> Bool
}

public enum WindowMoveResult {
  case MoveSuccessful
  case MoveCanceled
}

public enum WindowMoveSource {
  case Mouse
  case Touch
}

public protocol WindowMoveClient {

  func runMoveLoop(window: Window,
                   dragOffset: IntVec2,
                   source: WindowMoveSource) -> WindowMoveResult

  func endMoveLoop()
}

public protocol VisibilityClient {
  func updateLayerVisibility(window: Window, visible: Bool)
}
