// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import Web

public protocol UIWindowInputHandlerDelegate : class {
  func focusChangeComplete()
  func observeGestureEventAndResult(
      gestureEvent: Web.GestureEvent,
      unusedDelta: FloatVec2,
      overscrollBehavior: OverscrollBehavior,
      eventProcessed: Bool)
  func onDidHandleKeyEvent()
  func onDidOverscroll(params: DidOverscrollParams)
  func setInputHandler(inputHandler: UIWindowInputHandler)
  func clearTextInputState()
  func updateTextInputState()
  func willHandleGestureEvent(event: WebGestureEvent) -> Bool
  func willHandleMouseEvent(event: WebMouseEvent) -> Bool
  func willHandleKeyEvent(event: WebKeyboardEvent) -> Bool
}

public class UIWindowInputHandler {
  
  public var handlingInputEvent: Bool = false

  private weak var delegate: UIWindowInputHandlerDelegate?
  
  public init(delegate: UIWindowInputHandlerDelegate) {
    self.delegate = delegate
  }

  public func processTouchAction(_ action: TouchAction) -> Bool {
    return false
  }

}
