// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Text

public enum TextEditCommand {
  case deleteBackward
  case deleteForward
  case deleteToBeginningOfLine
  case deleteToBeginningOfParagraph
  case deleteToEndOfLine
  case deleteToEndOfParagraph
  case deleteWordBackward
  case deleteWordForward
  case moveBackward
  case moveBackwardAndModifySelection
  case moveDown
  case moveDownAndModifySelection
  case moveForward
  case moveForwardAndModifySelection
  case moveLeft
  case moveLeftAndModifySelection
  case movePageDown
  case movePageDownAndModifySelection
  case movePageUp
  case movePageUpAndModifySelection
  case moveRight
  case moveRightAndModifySelection
  case moveToBeginningOfDocument
  case moveToBeginningOfDocumentAndModifySelection
  case moveToBeginningOfLine
  case moveToBeginningOfLineAndModifySelection
  case moveToBeginningOfParagraph
  case moveToBeginningOfParagraphAndModifySelection
  case moveToEndOfDocument
  case moveToEndOfDocumentAndModifySelection
  case moveToEndOfLine
  case moveToEndOfLineAndModifySelection
  case moveToEndOfParagraph
  case moveToEndOfParagraphAndModifySelection
  case moveParagraphBackwardAndModifySelection
  case moveParagraphForwardAndModifySelection
  case moveUp
  case moveUpAndModifySelection
  case moveWordBackward
  case moveWordBackwardAndModifySelection
  case moveWordForward
  case moveWordForwardAndModifySelection
  case moveWordLeft
  case moveWordLeftAndModifySelection
  case moveWordRight
  case moveWordRightAndModifySelection
  case undo
  case redo
  case cut
  case copy
  case paste
  case selectAll
  case transpose
  case yank
  case insertText
  case setMark
  case unselect
  case invalidCommand
}

public protocol TextInputClient {

  var textInputType: TextInputType { get }
  var textInputMode: TextInputMode { get }
  var textInputFlags: Int { get }
  var textRange: TextRange? { get }
  var compositionTextRange: TextRange? { get }
  var selectionRange: TextRange? { get set }
  var textDirection: TextDirection { get }
  var canComposeInline: Bool { get }
  var caretBounds: IntRect { get }
  var hasCompositionText: Bool { get }
  var clientSourceInfo: String { get }

  func setCompositionText(_ composition: CompositionText)
  func confirmCompositionText()
  func clearCompositionText()
  func insertText(_ text: String)
  func insertChar(event: KeyEvent)
  func getCompositionCharacterBounds(index: Int) -> IntRect?
  func deleteRange(_ range: TextRange) -> Bool
  func getTextFromRange(_ range: TextRange) -> String?
  func onInputMethodChanged()
  func changeTextDirectionAndLayoutAlignment(direction: TextDirection) -> Bool
  func extendSelectionAndDelete(before: Int, after: Int)
  func ensureCaretNotInRect(rect: IntRect)
  func isTextEditCommandEnabled(command: TextEditCommand) -> Bool
  func setTextEditCommandForNextKeyEvent(command: TextEditCommand)
}
