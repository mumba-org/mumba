// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class Accelerator {

  public var keycode: KeyboardCode

  public var shortcutText: String

  var type: EventType

  var modifiers: Int

  var isRepeat: Bool

  public init() {
    self.keycode = KeyboardCode.KeyUnknown
    self.modifiers = 0
    type = EventType.Unknown
    isRepeat = false
    shortcutText = String()
  }

  public init(keycode: KeyboardCode, modifiers: Int) {
    self.keycode = keycode
    self.modifiers = modifiers
    type = EventType.Unknown
    isRepeat = false
    shortcutText = String()
  }

  public func toKeyEvent() -> KeyEvent {
    // return KeyEvent(keyState == Accelerator.KeyState.Pressed
    //                   ? .KeyPressed
    //                   : .KeyReleased,
    //               keycode, modifiers)//, timestamp)
    let event = Graphics.KeyEvent()
    event.keyCode = keycode
    return event
  }

}

public protocol AcceleratorTarget {}

public protocol AcceleratorProvider {
 
  func getAcceleratorForCommandId(commandId: Int) -> Accelerator?

}