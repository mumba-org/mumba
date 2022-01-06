// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

// TODO: Implement!
public class PrefixSelector : TextInputClient {

  public var textInputType: TextInputType {
    return .None
  }

  public var textInputMode: TextInputMode {
    return .Default
  }

  public var textInputFlags: Int {
    return 0
  }

  public var textDirection: TextDirection {
    return .LeftToRight
  }

  public var canComposeInline: Bool {
    return false
  }

  public var caretBounds: IntRect {
    return IntRect()
  }

  public var hasCompositionText: Bool {
    return false
  }

  public var clientSourceInfo: String {
    return String()
  }

  public var textRange: TextRange? {
    return nil
  }

  public var selectionRange: TextRange? {
    get {
      return nil
    }
    set {

    }
  }

  public var compositionTextRange: TextRange? { 
    return nil 
  }

  weak var prefixDelegate: PrefixDelegate?

  var hostView: View

  // Time OnTextInput() was last invoked.
  var timeOfLastKey: TimeTicks = TimeTicks()

  var currentText: String = String()

  public init(delegate: PrefixDelegate, hostView: View) {
    self.prefixDelegate = delegate
    self.hostView = hostView
  }

  public func setCompositionText(_ composition: CompositionText) {

  }
  
  public func confirmCompositionText() {

  }
  
  public func clearCompositionText() {

  }
  
  public func insertText(_ text: String) {

  }
  
  public func insertChar(event: KeyEvent) {

  }
  
  public func getCompositionCharacterBounds(index: Int) -> IntRect? {
    return nil
  }
  
  public func deleteRange(_ range: TextRange) -> Bool {
    return false
  }
  
  public func getTextFromRange(_ range: TextRange) -> String? {
    return nil
  }
  
  public func onInputMethodChanged() {

  }
  
  public func changeTextDirectionAndLayoutAlignment(direction: TextDirection) -> Bool {
    return false
  }
  
  public func extendSelectionAndDelete(before: Int, after: Int) {

  }
  
  public func ensureCaretNotInRect(rect: IntRect) {

  }
  
  public func isTextEditCommandEnabled(command: TextEditCommand) -> Bool {
    return false
  }
  
  public func setTextEditCommandForNextKeyEvent(command: TextEditCommand) {

  }

}