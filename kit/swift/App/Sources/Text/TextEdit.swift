// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum TextEditCommand {
  case DeleteBackward
  case DeleteForward
  case DeleteToBeginningOfLine
  case DeleteToBeginningOfParagraph
  case DeleteToEndOfLine
  case DeleteToEndOfParagraph
  case DeleteWordBackward
  case DeleteWordForward
  case MoveBackward
  case MoveBackwardAndModifySelection
  case MoveDown
  case MoveDownAndModifySelection
  case MoveForward
  case MoveForwardAndModifySelection
  case MoveLeft
  case MoveLeftAndModifySelection
  case MovePageDown
  case MovePageDownAndModifySelection
  case MovePageUp
  case MovePageUpAndModifySelection
  case MoveRight
  case MoveRightAndModifySelection
  case MoveToBeginningOfDocument
  case MoveToBeginningOfDocumentAndModifySelection
  case MoveToBeginningOfLine
  case MoveToBeginningOfLineAndModifySelection
  case MoveToBeginningOfParagraph
  case MoveToBeginningOfParagraphAndModifySelection
  case MoveToEndOfDocument
  case MoveToEndOfDocumentAndModifySelection
  case MoveToEndOfLine
  case MoveToEndOfLineAndModifySelection
  case MoveToEndOfParagraph
  case MoveToEndOfParagraphAndModifySelection
  case MoveParagraphBackwardAndModifySelection
  case MoveParagraphForwardAndModifySelection
  case MoveUp
  case MoveUpAndModifySelection
  case MoveWordBackward
  case MoveWordBackwardAndModifySelection
  case MoveWordForward
  case MoveWordForwardAndModifySelection
  case MoveWordLeft
  case MoveWordLeftAndModifySelection
  case MoveWordRight
  case MoveWordRightAndModifySelection
  case Undo
  case Redo
  case Cut
  case Copy
  case Paste
  case SelectAll
  case Transpose
  case Yank
  case InsertText
  case SetMark
  case Unselect
  case InvalidCommand
}