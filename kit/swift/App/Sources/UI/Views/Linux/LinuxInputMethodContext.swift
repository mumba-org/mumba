// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol LinuxInputMethodContext {
  func dispatchKeyEvent(keyEvent: KeyEvent) -> Bool
  func setCursorLocation(rect: IntRect)
  func reset()
  func focus()
  func blur()
}

public protocol LinuxInputMethodContextDelegate {
  func onCommit(text: String)
  func onPreeditChanged(compositionText: CompositionText)
  func onPreeditEnd()
  func onPreeditStart()
}
