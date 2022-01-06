// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class InputMethodLinux {

  var _delegate: InputMethodDelegate?

  public init(delegate: InputMethodDelegate) {
    _delegate = delegate
  }

}

extension InputMethodLinux : InputMethod {

  public var delegate: InputMethodDelegate? {
    get {
      return _delegate
    }
    set {
      _delegate = newValue
    }
  }

  public var inputLocale: String { return "" }
  public var textInputType: TextInputType { return TextInputType.None }
  public var textInputMode: TextInputMode { return TextInputMode.Default }
  public var textInputClient: TextInputClient? { return  nil }
  public var textInputFlags: Int { return 0 }
  public var canComposeInline: Bool { return false }
  public var isCandidatePopupOpen: Bool { return false }

  public func onFocus() {}
  public func onBlur() {}
  public func onUntranslatedIMEMessage(event: PlatformEvent,
    result: inout PlatformEventResult) -> Bool {
    return false
  }
  public func setFocusedTextInputClient(client: TextInputClient) {}
  public func detachTextInputClient(client: TextInputClient) {}
  public func dispatchKeyEvent(event: KeyEvent) {}
  public func onTextInputTypeChanged(client: TextInputClient) {}
  public func onCaretBoundsChanged(client: TextInputClient) {}
  public func cancelComposition(client: TextInputClient) {}
  public func onInputLocaleChanged() {}
  public func showImeIfNeeded() {}
  public func addObserver(observer: InputMethodObserver) {}
  public func removeObserver(observer: InputMethodObserver) {}
}
