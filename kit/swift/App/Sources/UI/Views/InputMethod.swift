// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform

public typealias PlatformEventResult = Int32

public protocol InputMethodDelegate {
  func dispatchKeyEventPostIME(event: KeyEvent) -> EventDispatchDetails
}

public protocol InputMethodObserver {
  func onTextInputTypeChanged(client: TextInputClient)
  func onFocus()
  func onBlur()
  func onCaretBoundsChanged(client: TextInputClient)
  func onTextInputStateChanged(client: TextInputClient)
  func onInputMethodDestroyed(inputMethod: InputMethod)
  func onShowImeIfNeeded()
}

public protocol InputMethod {

  var delegate: InputMethodDelegate? { get set }
  var inputLocale: String { get }
  var textInputType: TextInputType { get }
  var textInputMode: TextInputMode { get }
  var textInputClient: TextInputClient? { get }
  var textInputFlags: Int { get }
  var canComposeInline: Bool { get }
  var isCandidatePopupOpen: Bool { get }

  func onFocus()
  func onBlur()
  func onUntranslatedIMEMessage(event: PlatformEvent,
                                result: inout PlatformEventResult) -> Bool
  func setFocusedTextInputClient(client: TextInputClient)
  func detachTextInputClient(client: TextInputClient)
  func dispatchKeyEvent(event: KeyEvent)
  func onTextInputTypeChanged(client: TextInputClient)
  func onCaretBoundsChanged(client: TextInputClient)
  func cancelComposition(client: TextInputClient)
  func onInputLocaleChanged()
  func showImeIfNeeded()
  func addObserver(observer: InputMethodObserver)
  func removeObserver(observer: InputMethodObserver)

}
