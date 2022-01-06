// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Text

// TODO: fix it with the real thing

fileprivate let IDS_APP_UNDO: Int = 100
fileprivate let IDS_APP_UT: Int = 101
fileprivate let IDS_APP_OPY: Int = 102
fileprivate let IDS_APP_PASTE: Int = 103
fileprivate let IDS_APP_DELETE: Int = 104
fileprivate let IDS_APP_SELECT_ALL: Int = 105

public protocol TextfieldController : class {
  func contentsChanged(sender: Textfield, contents: String)
  func handleKeyEvent(sender: Textfield, event: KeyEvent) -> Bool
  func handleMouseEvent(sender: Textfield, event: MouseEvent) -> Bool
  func handleGestureEvent(sender: Textfield, event: GestureEvent) -> Bool
  func onBeforeUserAction(sender: Textfield)
  func onAfterUserAction(sender: Textfield)
  func onAfterCutOrCopy(type: ClipboardType)
  func onAfterPaste()
  func onWriteDragData(data: OSExchangeData)
  func onGetDragOperationsForTextfield(dragops: inout DragOperation)
  func appendDropFormats(formats: inout Int, types: inout [ClipboardFormatType])
  func onDrop(data: OSExchangeData) -> Int
  func updateContextMenu(menuContents: SimpleMenuModel)
}

public protocol TextfieldModelDelegate : class {
  func onCompositionTextConfirmedOrCleared()
}

public protocol ViewsTextServicesContextMenu {
  
  static func create(menu: SimpleMenuModel,
                     textfield: Textfield) -> ViewsTextServicesContextMenu?

  func supportsCommand(commandId: Int) -> Bool
  func isCommandIdChecked(commandId: Int) -> Bool
  func isCommandIdEnabled(commandId: Int) -> Bool
  func executeCommand(commandId: Int)
}

extension ViewsTextServicesContextMenu {
  
  public static func create(menu: SimpleMenuModel,
                            textfield: Textfield) -> ViewsTextServicesContextMenu? {                   
    return nil
  }

}

public enum MergeType {
  case doNotMerge
  case mergeable
  case forceMerge
}


/*           
 * TextfieldModel
 */

public class TextfieldModel {

  public static var killbuffer: String = String()
  
  public var text: String {
    
    get {
      return rendertext.text
    }

    set {
      var changed = false
      
      if hasCompositionText {
        confirmCompositionText()
        changed = true
      }

      if text != newValue {
        if changed {
          let _ = undo()
        }
        let oldCursor = cursorPosition
        let newCursor = newValue.count
        selectAll(reversed: false)
        executeAndRecordReplace(mergeType: changed ? .doNotMerge : .forceMerge,
          oldCursorPos: oldCursor, 
          newCursorPos: newCursor, 
          newText: newValue, 
          newTextStart: 0)
        rendertext.cursorPosition = newCursor
      }

      clearSelection()
    }
  }

  public var selectedText: String {
    get {
      let start = text.index(text.startIndex, offsetBy: rendertext.selection.minimum)
      let end = text.index(text.startIndex, offsetBy: rendertext.selection.length)
      return String(text[start..<end])
    }
  }

  public var cursorPosition: Int {
    get {
      return rendertext.cursorPosition
    }
  }

  public var hasCompositionText: Bool {
    get {
      return !compositionRange.isEmpty
    }
  }

  public var canUndo: Bool {
    get {
      return !editHistory.isEmpty && currentEdit != editHistory.endIndex
    }
  }

  public var canRedo: Bool {
    if editHistory.isEmpty {
      return false
    }
    // There is no redo if the current edit is the last element in the history.
    return currentEdit == editHistory.endIndex || (currentEdit + 1) != editHistory.endIndex
  }

  public var hasSelection: Bool {
    return !rendertext.selection.isEmpty
  }

  public var textRange: TextRange {
    get {
      return TextRange(start: 0, end: text.length)
    }
  }

  public var compositionTextRange: TextRange? {
    return compositionRange
  }

  public weak var delegate: TextfieldModelDelegate?
  internal let rendertext: RenderText
  private var compositionRange: TextRange
  private var editHistory: ContiguousArray<Edit>
  private var currentEdit: Int

  public init(delegate: TextfieldModelDelegate?) {
    self.delegate = delegate
    rendertext = RenderText()
    compositionRange = TextRange()
    editHistory = ContiguousArray<Edit>()
    currentEdit = -1
  }

  public func insertText(_ text: String) {
    insertTextInternal(text: text, mergeable: false)
  }

  public func insertChar(_ c: Character) {
    insertTextInternal(text: String(c), mergeable: true)
  }

  public func replaceText(newtext: String) {
    replaceTextInternal(text: newtext, mergeable: false)
  }

  public func replaceChar(char c: Character) {
    replaceTextInternal(text: String(c), mergeable: true)
  }

  public func append(text: String) {
    if hasCompositionText {
      confirmCompositionText()
    }
    let save = cursorPosition
    moveCursor(breaktype: .Line, direction: rendertext.visualDirectionOfLogicalEnd, behavior: .SelectionNone)
    insertText(text)
    rendertext.cursorPosition = save
    clearSelection()
  }

  public func delete(addToKillBuffer: Bool) -> Bool {
    if hasCompositionText {
      cancelCompositionText()
      return true
    }
    
    if hasSelection {
      if addToKillBuffer {
        TextfieldModel.killbuffer = selectedText
      }
      deleteSelection()
      return true
    }
  
    if text.length > cursorPosition {
      let nextGraphemeIndex = rendertext.indexOfAdjacentGrapheme(index: cursorPosition, direction: .Forward)
      let rangeToDelete = TextRange(start: cursorPosition, end: nextGraphemeIndex)
      if addToKillBuffer {
        TextfieldModel.killbuffer = getTextFromRange(rangeToDelete) ?? String()
      }
      executeAndRecordDelete(range: rangeToDelete, mergeable: true)
      return true
    }

    return false
  }

  public func backspace(addToKillBuffer: Bool) -> Bool {
    if hasCompositionText {
      cancelCompositionText()
      return true
    }

    if hasSelection {
      if addToKillBuffer {
        TextfieldModel.killbuffer = selectedText
      }
      deleteSelection()
      return true
    }

    if cursorPosition > 0 {
      // Delete one code point, which may be two UTF-16 words.
      var offset = -1
      let previousChar = UTF16OffsetToIndex(s: text, base: cursorPosition, offset: &offset)
      let rangeToDelete = TextRange(start: cursorPosition, end: previousChar)
      if addToKillBuffer {
        TextfieldModel.killbuffer = getTextFromRange(rangeToDelete) ?? String()
      }
      executeAndRecordDelete(range: rangeToDelete, mergeable: true)
      
      return true
    }

    return false
  }

  public func moveCursor(breaktype: BreakType, direction: VisualCursorDirection, behavior: SelectionBehavior) {
    
    if hasCompositionText {
      confirmCompositionText()
    }
   
    rendertext.moveCursor(breakType: breaktype, direction: direction, behavior: behavior)
  }
  
  @discardableResult
  public func moveCursorTo(cursor: SelectionModel) -> Bool {
    if hasCompositionText {
      confirmCompositionText()
      // ConfirmCompositionText() updates cursor position. Need to reflect it in
      // the SelectionModel parameter of MoveCursorTo().
      let range = TextRange(start: rendertext.selection.start, end: cursor.caretPos)
      
      if !range.isEmpty {
        return rendertext.selectRange(range: range)
      }

      return rendertext.moveCursorTo(model: SelectionModel(pos: cursor.caretPos, affinity: cursor.caretAffinity))
    }
    return rendertext.moveCursorTo(model: cursor)
  }

  public func moveCursorTo(point: IntPoint, select: Bool) -> Bool {
    if hasCompositionText {
      confirmCompositionText()
    }

    let cursor: SelectionModel = rendertext.findCursorPosition(point: FloatPoint(point))
    if select {
      cursor.selection.start = rendertext.selection.start
    }
    return rendertext.moveCursorTo(model: cursor)
  }

  public func selectRange(_ range: TextRange) {
    if hasCompositionText {
      confirmCompositionText()
    }
    let _ = rendertext.selectRange(range: range)
  }

  public func selectSelectionModel(model sel: SelectionModel) {
    if hasCompositionText {
      confirmCompositionText()
    }
    let _ = rendertext.moveCursorTo(model: sel)
  }

  public func selectAll(reversed: Bool) {
    if hasCompositionText {
      confirmCompositionText()
    }
    rendertext.selectAll(reversed: reversed)
  }

  public func selectWord() {
    if hasCompositionText {
      confirmCompositionText()
    }
    rendertext.selectWord()
  }

  public func clearSelection() {
    if hasCompositionText {
      confirmCompositionText()
    }
    rendertext.clearSelection()
  }

  public func undo() -> Bool {
    if !canUndo {
      return false
    }
    // assert(!hasCompositionText)
    if hasCompositionText {
      cancelCompositionText()
    }

    let old = text
    let oldCursor = cursorPosition
    
    editHistory[currentEdit].commit()
    editHistory[currentEdit].undo(model: self)

    if currentEdit == editHistory.startIndex {
      currentEdit = editHistory.endIndex
    } else {
      currentEdit -= 1
    }
    
    return old != text || oldCursor != cursorPosition
  }

  public func redo() -> Bool {
    
    if !canRedo {
      return false
    }
    // assert(!hasCompositionText)
    if hasCompositionText {
      cancelCompositionText()
    }

    if currentEdit == editHistory.endIndex {
      currentEdit = editHistory.startIndex
    } else {
      currentEdit += 1
    }
    
    let old = text
    
    let oldCursor = cursorPosition
    editHistory[currentEdit].redo(model: self)
    return old != text || oldCursor != cursorPosition
  }
  
  public func cut() -> Bool {
    if !hasCompositionText && hasSelection && !rendertext.obscured {
      // func from uI.
      ScopedClipboardWriter(.CopyPaste).writeText(selectedText)
      // A trick to let undo/redo handle cursor correctly.
      // Undoing CUT moves the cursor to the end of the change rather
      // than beginning, unlike Delete/Backspace.
      // TODO(oshima): Change Delete/Backspace to use DeleteSelection,
      // update DeleteEdit and remove this trick.
      let selection: TextRange = rendertext.selection
      let _ = rendertext.selectRange(range: TextRange(start: selection.end, end: selection.start))
      deleteSelection()
      return true
    }
    return false
  }

  public func copy() -> Bool {
    if !hasCompositionText && hasSelection && !rendertext.obscured {
      ScopedClipboardWriter(.CopyPaste).writeText(selectedText)
      return true
    }
    return false
  }

  public func paste() -> Bool {
    var text: String

    text = Clipboard.forCurrentThread.readText(from: .CopyPaste) ?? String()
    if text.isEmpty {
      return false
    }
    // as in Base.CollapseWhitespace
    //var actualText = collapseWhitespace(text, false)
    // If the clipboard contains all whitespaces then paste a single space.
    //if actualText.isEmpty {
      //  base::ASCIIToUTF16(" ")
    //  actualText = " "
    //}

    //insertTextInternal(text: actualText, mergeable: false)
    insertTextInternal(text: text, mergeable: false)
    return true
  }

  public func deleteSelection() {
    //assert(!hasCompositionText)
    //assert(hasSelection)
    executeAndRecordDelete(range: rendertext.selection, mergeable: false)
  }

  public func deleteSelectionAndInsertTextAt(text: String, position: Int) {

    if hasCompositionText {
      cancelCompositionText()
    }

    executeAndRecordReplace(
      mergeType: .doNotMerge,
      oldCursorPos: cursorPosition,
      newCursorPos: position + text.count,
      newText: text,
      newTextStart: position)
  }

  public func getTextFromRange(_ range: TextRange) -> String? {
    if range.isValid && range.minimum < text.count {
      let start = text.index(text.startIndex, offsetBy: range.minimum)
      let end = text.index(text.startIndex, offsetBy: range.length)
      return String(text[start..<end])
    }
    return nil
  }

  public func setCompositionText(_ composition: CompositionText) {
    
    if hasCompositionText {
      cancelCompositionText()
    } else if hasSelection {
      deleteSelection()
    }

    if composition.text.isEmpty {
      return
    }

    let cursor = cursorPosition
    var newtext = text
    
    newtext.insert(
      contentsOf: composition.text, 
      at: newtext.index(newtext.startIndex, offsetBy: cursor))

    rendertext.text = newtext
    compositionRange = TextRange(start: cursor, end: cursor + composition.text.count)
    // Don't render transparent composition underlines.
    if composition.underlines.count > 0 && composition.underlines[0].color.value != 0 {
      rendertext.compositionRange = compositionRange
    } else {
      rendertext.compositionRange = TextRange.InvalidRange
    }

    let emphasizedRange = getFirstEmphasizedRange(composition)
    if emphasizedRange.isValid {
      // This is a workaround due to the lack of support in RenderText to draw
      // a thick underline. In a composition returned from an IME, the segment
      // emphasized by a thick underline usually represents the target clause.
      // Because the target clause is more important than the actual selection
      // range (or caret position) in the composition here we use a selection-like
      // marker instead to show this range.
      // TODO(yukawa, msw): Support thick underlines and remove this workaround.
      let _ = rendertext.selectRange(range: TextRange(
        start: cursor + emphasizedRange.minimum,
        end: cursor + emphasizedRange.maximum))
    } else if !composition.selection.isEmpty {
      let _ = rendertext.selectRange(range: TextRange(
        start: cursor + composition.selection.minimum,
        end: cursor + composition.selection.maximum))
    } else {
      rendertext.cursorPosition = cursor + composition.selection.end
    }
  }

  public func confirmCompositionText() {
   // assert(hasCompositionText)
    let start = text.index(text.startIndex, offsetBy: compositionRange.start)
    let end = text.index(text.startIndex, offsetBy: compositionRange.length)
    let composition = String(text[start..<end])
    // TODO(oshima): current behavior on ChromeOS is a bit weird and not
    // sure exactly how this should work. Find out and fix if necessary.
    let _ = addOrMergeEditHistory(edit: InsertEdit(false, composition, compositionRange.start))
    rendertext.cursorPosition = compositionRange.end
    clearComposition()
    if let d = delegate {
      d.onCompositionTextConfirmedOrCleared()
    }
  }

  public func cancelCompositionText() {
    //assert(hasCompositionText())
    let range = compositionRange
    clearComposition()
    var newtext = text
    let start = newtext.index(newtext.startIndex, offsetBy: range.start)
    let end = newtext.index(newtext.startIndex, offsetBy: range.length)
    newtext.removeSubrange(start..<end)
    rendertext.text = newtext 
    rendertext.cursorPosition = range.start
    
    if let d = delegate {
      d.onCompositionTextConfirmedOrCleared()
    }
  }

  public func clearComposition() {
    compositionRange = TextRange.InvalidRange
    rendertext.compositionRange = compositionRange
  }

  public func clearEditHistory() {
    editHistory.removeAll(keepingCapacity: true)
    currentEdit = editHistory.endIndex
  }

  public func yank() -> Bool {
    let killbuf = TextfieldModel.killbuffer
    if !killbuf.isEmpty || hasSelection {
      insertTextInternal(text: killbuf, mergeable: false)
      return true
    }
    return false
  }

  public func transpose() -> Bool {
    
    if hasCompositionText || hasSelection {
      return false
    }

    var cur = cursorPosition
    var next = rendertext.indexOfAdjacentGrapheme(index: cur, direction: .Forward)
    var prev = rendertext.indexOfAdjacentGrapheme(index: cur, direction: .Backward)

    // At the end of the line, the last two characters should be transposed.
    if cur == self.text.count {
      cur = prev
      prev = rendertext.indexOfAdjacentGrapheme(index: prev, direction: .Backward)
    }

    // This happens at the beginning of the line or when the line has less than
    // two graphemes.
    if UTF16IndexToOffset(s: self.text, base: &prev, pos: &next) != 2 {
      return false
    }

    selectRange(TextRange(start: prev, end: next))
    
    let slicePos = selectedText.index(selectedText.startIndex, offsetBy: cur - prev)
    let transposedText = String(selectedText[slicePos..<selectedText.endIndex] + selectedText[selectedText.startIndex..<slicePos])

    insertTextInternal(text: transposedText, mergeable: false)

    return true
  }

  fileprivate func insertTextInternal(text t: String, mergeable: Bool) {
    if hasCompositionText {
      cancelCompositionText()
      executeAndRecordInsert(newText: t, mergeable: mergeable)
    } else if hasSelection {
      executeAndRecordReplaceSelection(mergeType: mergeable ? .mergeable : .doNotMerge, text: t)
    } else {
      executeAndRecordInsert(newText: t, mergeable: mergeable)
    }
  }

  fileprivate func replaceTextInternal(text t: String, mergeable: Bool) {
    
    if hasCompositionText {
      cancelCompositionText()
    } else if !hasSelection {
      let cursor = cursorPosition
      let model = rendertext.selectionModel
      // When there is no selection, the default is to replace the next grapheme
      // with |new_text|. So, need to find the index of next grapheme first.
      let next = rendertext.indexOfAdjacentGrapheme(index: cursor, direction: .Forward)
      if next == model.caretPos {
        let _ = rendertext.moveCursorTo(model: model)
      } else {
        let _ = rendertext.selectRange(range: TextRange(start: next, end: model.caretPos))
      }
    }
    // Edit history is recorded in InsertText.
    insertTextInternal(text: text, mergeable: mergeable)
  }

  fileprivate func clearRedoHistory() {
    if editHistory.isEmpty {
      return 
    }

    if currentEdit == editHistory.endIndex {
      clearEditHistory()
      return
    }

    var deleteStart = currentEdit
    deleteStart += 1

    editHistory.removeSubrange(deleteStart..<editHistory.endIndex)
  }

  fileprivate func executeAndRecordDelete(range: TextRange, mergeable: Bool) {
    let oldTextStart = range.minimum
    let startIndex = text.index(text.startIndex, offsetBy: oldTextStart)
    let endIndex = text.index(text.startIndex, offsetBy: oldTextStart)
    let oldText = String(text[startIndex..<endIndex])
    let backward: Bool = range.isReversed
    let edit = DeleteEdit(mergeable, oldText, oldTextStart, backward)
    let _ = addOrMergeEditHistory(edit: edit)
    edit.redo(model: self)
  }

  fileprivate func executeAndRecordReplaceSelection(mergeType: MergeType, text newText: String) {
    let newTextStart = rendertext.selection.minimum
    let newCursorPos = newTextStart + newText.count
    executeAndRecordReplace(mergeType: mergeType,
                            oldCursorPos: cursorPosition,
                            newCursorPos: newCursorPos,
                            newText: newText,
                            newTextStart: newTextStart)
  }

  fileprivate func executeAndRecordReplace(mergeType: MergeType,
                                           oldCursorPos: Int,
                                           newCursorPos: Int,
                                           newText: String,
                                           newTextStart: Int) {
    let oldTextStart = rendertext.selection.minimum
    let backward = rendertext.selection.isReversed
    let edit = ReplaceEdit(mergeType,
                           selectedText,
                           oldCursorPos,
                           oldTextStart,
                           backward,
                           newCursorPos,
                           newText,
                           newTextStart)
    
    let _ = addOrMergeEditHistory(edit: edit)
    edit.redo(model: self)
  }

  fileprivate func executeAndRecordInsert(newText: String, mergeable: Bool) {
    let edit = InsertEdit(mergeable, newText, cursorPosition)
    let _ = addOrMergeEditHistory(edit: edit)
    edit.redo(model: self)
  }

  fileprivate func addOrMergeEditHistory(edit: Edit) -> Bool {
    clearRedoHistory()

    if currentEdit != editHistory.endIndex && editHistory[currentEdit].merge(edit: edit) {
      // If a current edit exists and has been merged with a new edit, don't add
      // to the history, and return true to delete |edit| after redo.
      return true
    }

    editHistory.append(edit)

    if currentEdit == editHistory.endIndex {
      // If there is no redoable edit, this is the 1st edit because RedoHistory
      // has been already deleted.
      //assert(editHistory.count == 1)
      currentEdit = editHistory.startIndex
    } else {
      currentEdit += 1
    }
    return false
  }

  internal func modifyText(from deleteFrom: Int,
                           to deleteTo: Int,
                           text newtext: String,
                           at newTextInsertAt: Int,
                           cursorTo newCursorPos: Int) {
    //DCHECK_LE(delete_from, delete_to)
    var oldtext = text
    clearComposition()
    if deleteFrom != deleteTo {
      let start = oldtext.index(oldtext.startIndex, offsetBy: deleteFrom)
      let end = oldtext.index(oldtext.startIndex, offsetBy: deleteTo - deleteFrom)
      oldtext.removeSubrange(start..<end)
      rendertext.text = oldtext
    }
    if !newtext.isEmpty {
      let insertIndex = oldtext.index(oldtext.startIndex, offsetBy: newTextInsertAt)
      oldtext.insert(contentsOf: newtext, at: insertIndex)
      rendertext.text = oldtext
    }
    rendertext.cursorPosition = newCursorPos
    // TODO(oshima): Select text that was just undone, like Mac (but not GTK).
  }

}

#if os(macOS)
let platformModifier: Graphics.EventFlags = .CommandDown
#else
let platformModifier: Graphics.EventFlags = .ControlDown
#endif  // OS_MACOSX
let lineSelectionBehavior: SelectionBehavior = .SelectionRetain
let wordSelectionBehavior: SelectionBehavior = .SelectionRetain
let moveParagraphSelectionBehavior: SelectionBehavior = .SelectionRetain
let defaultPlaceholderTextColor: Color = Color.LightGray

func getCommandForKeyEvent(event: KeyEvent) -> TextEditCommand {
  
  if event.type != .KeyPressed || event.isUnicodeKeyCode {
    return .invalidCommand
  }

  let shift = event.isShiftDown
  let control = event.isControlDown || event.isCommandDown
  let alt = event.isAltDown || event.isAltGrDown

  switch event.keyCode {
    case .KeyZ:
      if control && !shift && !alt {
        return .undo
      }
      return (control && shift && !alt) ? .redo
                                        : .invalidCommand
    case .KeyY:
      return (control && !alt) ? .redo
                               : .invalidCommand
    case .KeyA:
      return (control && !alt) ? .selectAll
                               : .invalidCommand
    case .KeyX:
      return (control && !alt) ? .cut
                               : .invalidCommand
    case .KeyC:
      return (control && !alt) ? .copy
                               : .invalidCommand
    case .KeyV:
      return (control && !alt) ? .paste
                               : .invalidCommand
    case .KeyRight:
      // Ignore alt+right, which may be a browser navigation shortcut.
      if alt {
        return .invalidCommand
      }
      if !shift {
        return control ? .moveWordRight
                       : .moveRight
      }
      return control ? .moveWordRightAndModifySelection
                     : .moveRightAndModifySelection
    case .KeyLeft:
      // Ignore alt+left, which may be a browser navigation shortcut.
      if alt {
        return .invalidCommand
      }
      if !shift {
        return control ? .moveWordLeft
                       : .moveLeft
      }
      return control ? .moveWordLeftAndModifySelection
                     : .moveLeftAndModifySelection
    case .KeyHome:
      return shift ? .moveToBeginningOfLineAndModifySelection
                   : .moveToBeginningOfLine
    case .KeyEnd:
      return shift
                 ? .moveToEndOfLineAndModifySelection
                 : .moveToEndOfLine
    case .KeyBack:
      if !control {
        return .deleteBackward
      }
      // Only erase by line break on Linux and ChromeOS.
      if shift {
        return .deleteToBeginningOfLine
      }
      return .deleteWordBackward
    case .KeyDelete:
      // Only erase by line break on Linux and ChromeOS.
      if shift && control {
        return .deleteToEndOfLine
      }
      if control {
        return .deleteWordForward
      }
      return shift ? .cut
                   : .deleteForward
    case .KeyInsert:
      if control && !shift {
        return .copy
      }
      return (shift && !control) ? .paste
                                 : .invalidCommand
    default:
      return .invalidCommand
  }
}

// Returns the ui::TextEditCommand corresponding to the |command_id| menu
// action. |has_selection| is true if the textfield has an active selection.
// Keep in sync with UpdateContextMenu.
func getTextEditCommandFromMenuCommand(commandId: Int, hasSelection: Bool) -> TextEditCommand {
  switch commandId {
    case IDS_APP_UNDO:
      return .undo
    case IDS_APP_UT:
      return .cut
    case IDS_APP_OPY:
      return .copy
    case IDS_APP_PASTE:
      return .paste
    case IDS_APP_DELETE:
      // The DELETE menu action only works in case of an active selection.
      if hasSelection {
        return .deleteForward
      }
    case IDS_APP_SELECT_ALL:
      return .selectAll
    default:
      return .invalidCommand     
  }
  return .invalidCommand
}    

/*           
 * Textfield
 */          

public class Textfield : View,
                         TextfieldModelDelegate,
                         ContextMenuController,
                         // WordLookupClient
                         SelectionControllerDelegate,
                         DragController,
                         TouchEditable,
                         TextInputClient {
  
  public static var caretBlinkInterval: TimeDelta {
    let defaultValue = TimeDelta.from(milliseconds: 500)
  #if os(Windows)
    let systemValue = GetCaretBlinkTime()
    if systemValue != 0 {
      return (systemValue == INFINITE)
                ? TimeDelta()
                : TimeDelta.from(milliseconds: systemValue)
    }
  #endif
    return defaultValue
  }

  public var controller: TextfieldController?

  public var isReadonly: Bool {
    didSet {
      if let ime = inputMethod {
        ime.onTextInputTypeChanged(client: self)
        color = textColor
        updateBackgroundColor()
      }
    }
  }

  public var glyphSpacing: Int {
    get {
      return rendertext.glyphSpacing
    }
    set {
      rendertext.glyphSpacing = newValue
    }
  }

  public var text: String {
    get {
      return model!.text
    }
    set {
      model!.text = newValue
      onCaretBoundsChanged()
      updateCursorViewPosition()
      updateCursorVisibility()
      schedulePaint()
      //notifyAccessibilityEvent(AXEvent.ValueChanged, true)
    }
  }

  // Returns the text direction.
  public var textDirection: TextDirection {
    return rendertext.displayTextDirection
  }

  // Returns the text that is currently selected.
  public var selectedText : String {
    return model!.selectedText
  }

  public var hasSelection: Bool {
    return !selectedRange.isEmpty
  }

  public var textColor: Color {
    get {
      if !useDefaultTextColor {
        return _textColor
      }

      return TextStyles.getColor(view: self, context: .textfield, style: textStyle)
    }
    set {
      _textColor = newValue
      useDefaultTextColor = false
      color = newValue
    }
  }

  public var backgroundColor: Color {
    get {
      if !useDefaultBackgroundColor {
        return _backgroundColor
      }

      return theme.getSystemColor(id: 
        isReadonly || !isEnabled
          ? Theme.ColorId.TextfieldReadOnlyBackground
          : Theme.ColorId.TextfieldDefaultBackground)
    }
    set {
      _backgroundColor = newValue
      useDefaultBackgroundColor = false
      updateBackgroundColor()
    }
  }

  public var selectionTextColor: Color {
    get {
      return useDefaultSelectionTextColor
           ? theme.getSystemColor(id: Theme.ColorId.TextfieldSelectionColor)
           : _selectionTextColor
    }
    set {
      _selectionTextColor = newValue
      useDefaultSelectionTextColor = false
      rendertext.selectionColor = _selectionTextColor
      schedulePaint()
    }
  }

  public var selectionBackgroundColor: Color {
    get {
      return useDefaultSelectionBackgroundColor
             ? theme.getSystemColor(id: 
                   Theme.ColorId.TextfieldSelectionBackgroundFocused)
             : _selectionBackgroundColor
    }
    set {
      _selectionBackgroundColor = newValue
      useDefaultSelectionBackgroundColor = false
      rendertext.selectionBackgroundFocusedColor = _selectionBackgroundColor
      schedulePaint()
    }
  }

  public var cursorEnabled: Bool {
    get {
      return rendertext.cursorEnabled
    }
    set {
      if rendertext.cursorEnabled == newValue {
        return
      }

      rendertext.cursorEnabled = newValue
      updateCursorViewPosition()
      updateCursorVisibility()
    }
  }

  public var defaultWidthInChars: Int

  public var placeholderText: String = String()

     // Set the accessible name of the text field.
  public var accessibleName: String = String()

  // Returns the current cursor position.
  public var cursorPosition: Int {
    return model!.cursorPosition
  }

  public var color: Color {
    didSet {
      rendertext.setColor(color: self.color)
      cursorView.layer!.setColor(color: self.color)
      schedulePaint()
    }
  }
  
  // Gets the text selection model!.
  public var selectionModel: SelectionModel {
    get {
      return rendertext.selectionModel
    }
    set {
      model!.selectSelectionModel(model: newValue)
      updateAfterChange(textChanged: false, cursorChanged: true)
    }
  }
  
  public var placeholderTextColor: Color?

  public var horizontalAlignment: HorizontalAlignment {
    get {
      return rendertext.horizontalAlignment
    }
    set {
      rendertext.horizontalAlignment = newValue
    }
  }
    // Gets the selected logical text range.
  public var selectedRange: TextRange {
    return rendertext.selection
  }

  public var isIMEComposing: Bool {
     return model!.hasCompositionText
  }

  // public var focusPainter: Painter {
  //   didSet {
      
  //   }
  // }

  // public var shadows: ShadowValues {
  //   didSet {
      
  //   }
  // }

  public var fontList: FontList? {
    get {
      return rendertext.fontList
    }
    set {
      if let list = newValue {
        rendertext.fontList = list
        onCaretBoundsChanged()
        preferredSizeChanged()
      }
    }
  }

  public var textInputType: TextInputType {
    get {
      if isReadonly || !isEnabled {
        return .None
      }
      
      return _textInputType
    }
    
    set {
      rendertext.obscured = (newValue == .Password)
      _textInputType = newValue
      onCaretBoundsChanged()
      if let im = inputMethod {
        im.onTextInputTypeChanged(client: self)
      }
      schedulePaint()
    }
  }

  public var textInputFlags: Int = 0

  // View
  public override var baseline: Int {
    return insets.top + rendertext.baseline
  }

  public override var preferredSize: IntSize {
    get {
      return IntSize(
        width: fontList!.getExpectedTextWidth(defaultWidthInChars) + insets.width,
        height: LayoutProvider.getControlHeightForFont(context: TextContext.textfield, 
          style: textStyle, 
          font: fontList!))
    }
    set {
      super.preferredSize = newValue
    }
  }

  public override var minimumSize: IntSize {
    var minimumSize = super.minimumSize
    if minimumWidthInChars >= 0 {
      minimumSize.width = 
        fontList!.getExpectedTextWidth(minimumWidthInChars) +
        insets.width
    }
    return minimumSize
  }

  public override var className: String {
    return "Textfield"
  }

  public override var border: Border? {
    get {
      return super.border
    }
    set {
      //if useFocusRing && hasFocus {
      //  FocusRing.uninstall(self)
     // }
      //useFocusRing = false
      super.border = newValue
    }
  }

  public override var keyboardContextMenuLocation: IntPoint {
    return caretBounds.bottomRight
  }

  public override var canHandleAccelerators: Bool {
    return rendertext.focused && super.canHandleAccelerators
  }
  
  public var textInputMode: TextInputMode {
    return .Default
  }

  public var canComposeInline: Bool {
    return true
  }
  
  public var caretBounds: IntRect {
    var rect = IntRect(rendertext.updatedCursorBounds)
    View.convertRectToScreen(src: self, rect: &rect)
    return rect
  }
  
  public var hasCompositionText: Bool {
    return model!.hasCompositionText
  }

  public var clientSourceInfo: String { 
    return String()
  }

  public var renderTextForSelectionController: RenderText? {
    return rendertext
  }

  public var supportsDrag: Bool {
    return true
  }

  public var hasTextBeingDragged: Bool {
    get {
      return initiatingDrag
    }
    set {
      initiatingDrag = newValue
    }
  }

  public var viewHeight: Int {
    return height
  }

  public var viewWidth: Int {
    return width
  }

  public var dragSelectionDelay: Int {
    // switch ScopedAnimationDurationScaleMode.durationScaleMode {
    //   case ScopedAnimationDurationScaleMode.NormalDuration:
    //     return 100
    //   case ScopedAnimationDurationScaleMode.FastDuration:
    //     return 25
    //   case ScopedAnimationDurationScaleMode.SlowDuration:
    //     return 400
    //   case ScopedAnimationDurationScaleMode.NonZeroDuration:
    //     return 1
    //   case ScopedAnimationDurationScaleMode.ZeroDuration:
    //     return 0
    // }
    return 100
  }

  public override var bounds: IntRect {
    get {
      return localBounds
    }
    set {
      super.bounds = newValue
    }
    //set {
    //  localBounds = newValue
    //}
  }

  public var useDefaultTextColor: Bool {
    didSet {
      if useDefaultTextColor {
        color = textColor
      }
    }
  }

  public var useDefaultBackgroundColor: Bool {
    didSet {
       if useDefaultBackgroundColor {
         updateBackgroundColor()
       }
    }
  }

  public var useDefaultSelectionTextColor: Bool {
    didSet {
      if useDefaultSelectionTextColor {
       rendertext.selectionColor = selectionTextColor
       schedulePaint()
      }
    }
  }

  public var useDefaultSelectionBackgroundColor: Bool {
    didSet {
      if useDefaultSelectionBackgroundColor {
        rendertext.selectionBackgroundFocusedColor = selectionBackgroundColor
        schedulePaint()
      }
    }
  }

  public var textRange: TextRange? {
    if !imeEditingAllowed {
      return nil
    }

    return model!.textRange
  }
  
  public var compositionTextRange: TextRange? {
    if !imeEditingAllowed {
      return nil
    }

    return model!.compositionTextRange
  }
  
  public var selectionRange: TextRange? {
    get {
      if !imeEditingAllowed {
        return nil
      }
    
      return rendertext.selection
    }

    set {
      guard let range = newValue else {
        return
      }

      if !imeEditingAllowed || !range.isValid {
        return
      }
      onBeforeUserAction()
      selectRange(range)
      onAfterUserAction()
    }
  }

  public var selectionClipboardText: String {
    //let selectionClipboardText = String()
    //return selectionClipboardText
    return Clipboard.forCurrentThread.readText(from: .Selection) ?? String()
  }

  private var lastClickLocation: IntPoint {
    return selectionController!.lastClickLocation
  }

  private var rendertext: RenderText {
    return model!.rendertext
  }

  // Returns true if an insertion cursor should be visible (a vertical bar,
  // placed at the point new text will be inserted).
  fileprivate var shouldShowCursor: Bool {
     return hasFocus && !hasSelection && isEnabled && !isReadonly &&
         !dropCursorVisible && rendertext.cursorEnabled
  }

  // Returns true if an insertion cursor should be visible and blinking.
  fileprivate var shouldBlinkCursor: Bool {
    return shouldShowCursor && !Textfield.caretBlinkInterval.isZero
  }

   // Gets the TextStyle that should be used.
  fileprivate var textStyle: TextStyle {
    return (isReadonly || !isEnabled) ? TextStyle.disabled
                                      : TextStyle.primary
  }

  // Returns true if the current text input type allows access by the IME.
  fileprivate var imeEditingAllowed: Bool {
    return (textInputType != .None && textInputType != .Password)
  }

  fileprivate let cursorView: View
  fileprivate var model: TextfieldModel?
  fileprivate var selectionController: SelectionController?
  fileprivate var scheduledTextEditCommand: TextEditCommand
  fileprivate var minimumWidthInChars: Int
  fileprivate var _selectionTextColor: Color
  fileprivate var _selectionBackgroundColor: Color
  fileprivate var placeholderTextDrawFlags: Int
  fileprivate var placeholderFontList: FontList?
  fileprivate var invalid: Bool
  fileprivate var labelAxId: Int32
  fileprivate var passwordRevealTimer: OneShotTimer
  fileprivate var performingUserAction: Bool
  fileprivate var skipInputMethodCancelComposition: Bool
  fileprivate var cursorBlinkTimer: RepeatingTimer
  fileprivate var dropCursorVisible: Bool
  fileprivate var dropCursorPosition: SelectionModel
  fileprivate var initiatingDrag: Bool
  fileprivate var dragStartLocation: IntPoint
  fileprivate var dragStartDisplayOffset: Int
  fileprivate var touchHandlesHiddenDueToScroll: Bool
  fileprivate var contextMenuContents: SimpleMenuModel?
  fileprivate var textServicesContextMenu: ViewsTextServicesContextMenu?
  fileprivate var contextMenuRunner: MenuRunner?
  fileprivate var _textColor: Color
  fileprivate var _backgroundColor: Color
  fileprivate var _textInputType: TextInputType
  private var useFocusRing: Bool = false

  public override init() {
    scheduledTextEditCommand = .invalidCommand
    isReadonly = false
    defaultWidthInChars = 0
    minimumWidthInChars = -1
    useDefaultTextColor = true
    useDefaultBackgroundColor = true
    useDefaultSelectionTextColor = true
    useDefaultSelectionBackgroundColor = true
    _textColor = Color.Black
    _backgroundColor = Color.White
    _selectionTextColor = Color.White
    _selectionBackgroundColor = Color.Blue
    placeholderTextDrawFlags = Canvas.defaultCanvasTextAlignment.rawValue
    invalid = false
    labelAxId = 0
    _textInputType = .Text
    textInputFlags = 0
    performingUserAction = false
    skipInputMethodCancelComposition = false
    dropCursorVisible = false
    initiatingDrag = false
    dragStartLocation = IntPoint()
    dragStartDisplayOffset = 0
    touchHandlesHiddenDueToScroll = false
    passwordRevealTimer = OneShotTimer()
    cursorBlinkTimer = RepeatingTimer(tickClock: nil)
    dropCursorPosition = SelectionModel()
    cursorView = View()
    cursorView.setPaintToLayer(type: .SolidColorLayer)
    cursorView.layer!.setColor(color: _textColor)
    color = _backgroundColor
    super.init()
    selectionController = SelectionController(delegate: self)
    model = TextfieldModel(delegate: self)
    //cursorView.ownedByClient = true
    addChild(view: cursorView)
    //rendertext.fontList = FontList()//FontList.default()
    updateBorder()
    contextMenuController = self
    dragController = self
    focusBehavior = FocusBehavior.always
  }

  public func appendText(_ text: String) {
    if text.isEmpty {
      return
    }
    model!.append(text: text)
    onCaretBoundsChanged()
    schedulePaint()
    //notifyAccessibilityEvent(AccessibilityEvent.TextChanged, true)
  }
  // Inserts |new_text| at the cursor position, replacing any selected text.
  public func insertOrReplaceText(_ text: String) {
    if text.isEmpty {
      return
    }
    model!.insertText(text)
    updateAfterChange(textChanged: true, cursorChanged: true)
  }

  public func selectAll(reversed: Bool) {
    model!.selectAll(reversed: reversed)
    if hasSelection && performingUserAction {
      updateSelectionClipboard()
    }
    updateAfterChange(textChanged: false, cursorChanged: true)
  }

  public func selectWordAt(point: IntPoint) {
    let _ = model!.moveCursorTo(point: point, select: false)
    model!.selectWord()
    updateAfterChange(textChanged: false, cursorChanged: true)
  }

  public func clearSelection() {
    model!.clearSelection()
    updateAfterChange(textChanged: false, cursorChanged: true)
  }

  // Displays a virtual keyboard or alternate input view if isEnabled.
  public func showImeIfNeeded() {
    if isEnabled && !isReadonly {
      inputMethod!.showImeIfNeeded()
    }
  }

  // Selects the specified logical text range.
  public func selectRange(_ range: TextRange) {
    model!.selectRange(range)
    updateAfterChange(textChanged: false, cursorChanged: true)
  }
  
  public func applyColor(value: Color, range: TextRange) {
    rendertext.applyColor(color: value,  range: range)
    schedulePaint()
  }

  public func setStyle(style: FontStyle, value: Bool) {
    rendertext.setStyle(style: style, value: value)
    schedulePaint()
  }
  
  public func applyStyle(style: FontStyle, value: Bool, range: TextRange) {
    rendertext.applyStyle(style: style, value: value, range: range)
    schedulePaint()
  }
  
  // Clears Edit history.
  public func clearEditHistory() {
    model!.clearEditHistory()
  }

  public func executeCommand(commandId: Int) {
    if textServicesContextMenu!.supportsCommand(commandId: commandId) {
      textServicesContextMenu!.executeCommand(commandId: commandId)
      return
    }

    var cmd = getTextEditCommandFromMenuCommand(commandId: commandId, hasSelection: hasSelection)
    executeTextEditCommand(command: &cmd)
  }

  public func executeTextEditCommand(command: inout TextEditCommand) {
    destroyTouchSelection()

    var addToKillBuffer = false

    // Some codepaths may bypass GetCommandForKeyEvent, so any selection-dependent
    // modifications of the command should happen here.
    switch command {
      case .deleteToBeginningOfLine:
        fallthrough
      case .deleteToBeginningOfParagraph:
        fallthrough
      case .deleteToEndOfLine:
        fallthrough
      case .deleteToEndOfParagraph:
        addToKillBuffer = textInputType != .Password
        fallthrough
      case .deleteWordBackward:
        fallthrough
      case .deleteWordForward:
        if hasSelection {
          command = .deleteForward
        }
      default:
        break
    }

    // We only execute the commands isEnabled in Textfield::IsTextEditCommandEnabled
    // below. Hence don't do a virtual IsTextEditCommandEnabled call.
    if !isTextEditCommandEnabled(command: command) {
      return
    }

    var textChanged = false
    var cursorChanged = false
    let rtl = textDirection == .RightToLeft
    let begin: VisualCursorDirection = rtl ? .Right : .Left
    let end: VisualCursorDirection = rtl ? .Left : .Right
    let lastSelectionModel = selectionModel

    onBeforeUserAction()
    
    switch command {
      case .deleteBackward:
        textChanged = model!.backspace(addToKillBuffer: addToKillBuffer)
        cursorChanged = textChanged 
      case .deleteForward:
        textChanged = model!.delete(addToKillBuffer: addToKillBuffer)
        cursorChanged = textChanged 
      case .deleteToBeginningOfLine:
       fallthrough
      case .deleteToBeginningOfParagraph:
        model!.moveCursor(breaktype: .Line, direction: begin, behavior: .SelectionRetain)
        textChanged = model!.backspace(addToKillBuffer: addToKillBuffer) 
        cursorChanged = textChanged
      case .deleteToEndOfLine:
        fallthrough
      case .deleteToEndOfParagraph:
        model!.moveCursor(breaktype: .Line, direction: end, behavior: .SelectionRetain)
        textChanged = model!.delete(addToKillBuffer: addToKillBuffer)
        cursorChanged = textChanged 
      case .deleteWordBackward:
        model!.moveCursor(breaktype: .Word, direction: begin, behavior: .SelectionRetain)
        textChanged = model!.backspace(addToKillBuffer: addToKillBuffer)
        cursorChanged = textChanged
      case .deleteWordForward:
        model!.moveCursor(breaktype: .Word, direction: end, behavior: .SelectionRetain)
        textChanged = model!.delete(addToKillBuffer: addToKillBuffer)
        cursorChanged = textChanged 
      case .moveBackward:
        model!.moveCursor(breaktype: .Char, direction: begin, behavior: .SelectionNone)
      case .moveBackwardAndModifySelection:
        model!.moveCursor(breaktype: .Char, direction: begin, behavior: .SelectionRetain)
      case .moveForward:
        model!.moveCursor(breaktype: .Char, direction: end, behavior: .SelectionNone)
      case .moveForwardAndModifySelection:
        model!.moveCursor(breaktype: .Char, direction: end, behavior: .SelectionRetain)
      case .moveLeft:
        model!.moveCursor(breaktype: .Char, direction: .Left,
                         behavior: .SelectionNone)
      case .moveLeftAndModifySelection:
        model!.moveCursor(breaktype: .Char, direction: .Left,
                         behavior: .SelectionRetain)
      case .moveRight:
        model!.moveCursor(breaktype: .Char, direction: .Right,
                         behavior: .SelectionNone)
      case .moveRightAndModifySelection:
        model!.moveCursor(breaktype: .Char, direction: .Right,
                         behavior: .SelectionRetain)
      case .moveToBeginningOfDocument:
        fallthrough
      case .moveToBeginningOfLine:
        fallthrough
      case .moveToBeginningOfParagraph:
        fallthrough
      case .moveUp:
        fallthrough
      case .movePageUp:
        model!.moveCursor(breaktype: .Line, direction: begin, behavior: .SelectionNone)
      case .moveToBeginningOfDocumentAndModifySelection:
        fallthrough
      case .moveToBeginningOfLineAndModifySelection:
        fallthrough
      case .moveToBeginningOfParagraphAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: begin, behavior: lineSelectionBehavior)
      case .movePageUpAndModifySelection:
        fallthrough
      case .moveUpAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: begin, behavior: .SelectionRetain)
      case .moveToEndOfDocument:
        fallthrough
      case .moveToEndOfLine:
        fallthrough
      case .moveToEndOfParagraph:
        fallthrough
      case .moveDown:
        fallthrough
      case .movePageDown:
        model!.moveCursor(breaktype: .Line, direction: end, behavior: .SelectionNone)
      case .moveToEndOfDocumentAndModifySelection:
        fallthrough
      case .moveToEndOfLineAndModifySelection:
        fallthrough
      case .moveToEndOfParagraphAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: end, behavior: lineSelectionBehavior)
      case .movePageDownAndModifySelection:
        fallthrough
      case .moveDownAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: end, behavior: .SelectionRetain)
      case .moveParagraphBackwardAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: begin,
                          behavior: moveParagraphSelectionBehavior)
      case .moveParagraphForwardAndModifySelection:
        model!.moveCursor(breaktype: .Line, direction: end, behavior: moveParagraphSelectionBehavior)
      case .moveWordBackward:
        model!.moveCursor(breaktype: .Word, direction: begin, behavior: .SelectionNone)
      case .moveWordBackwardAndModifySelection:
        model!.moveCursor(breaktype: .Word, direction: begin, behavior: wordSelectionBehavior)
      case .moveWordForward:
        model!.moveCursor(breaktype: .Word, direction: end, behavior: .SelectionNone)
      case .moveWordForwardAndModifySelection:
        model!.moveCursor(breaktype: .Word, direction: end, behavior: wordSelectionBehavior)
      case .moveWordLeft:
        model!.moveCursor(breaktype: .Word, direction: .Left, behavior: .SelectionNone)
      case .moveWordLeftAndModifySelection:
        model!.moveCursor(breaktype: .Word, direction: .Left, behavior: wordSelectionBehavior)
      case .moveWordRight:
        model!.moveCursor(breaktype: .Word, direction: .Right, behavior: .SelectionNone)
      case .moveWordRightAndModifySelection:
        model!.moveCursor(breaktype: .Word, direction: .Right, behavior: wordSelectionBehavior)
      case .undo:
        let r = model!.undo()
        textChanged = r
        cursorChanged = r
      case .redo:
        let r = model!.redo()
        textChanged = r
        cursorChanged = r
      case .cut:
        let r = cut()
        textChanged = r
        cursorChanged = r
      case .copy:
        let _ = copy()
      case .paste:
        let r = paste()
        textChanged = r
        cursorChanged = r
      case .selectAll:
        selectAll(reversed: false)
      case .transpose:
        let r = model!.transpose()
        textChanged = r
        cursorChanged = r
      case .yank:
        let r = model!.yank()
        textChanged = r
        cursorChanged = r
      case .insertText:
        fallthrough
      case .setMark:
        fallthrough
      case .unselect:
        fallthrough
      case .invalidCommand: // TODO: use exception/throw
        assert(false)
    }

    cursorChanged = cursorChanged || (self.selectionModel != lastSelectionModel)
    if cursorChanged && hasSelection {
      updateSelectionClipboard()
    }
    updateAfterChange(textChanged: textChanged, cursorChanged: cursorChanged)
    onAfterUserAction()
  }

  public func onCompositionTextConfirmedOrCleared() {
    if !skipInputMethodCancelComposition {
      inputMethod!.cancelComposition(client: self)
    }
  }

  // View overrides
  open override func getCursor(event: MouseEvent) -> PlatformCursor {
    let platformArrow = PlatformStyle.textfieldUsesDragCursorWhenDraggable
    let inSelection = rendertext.isPointInSelection(point: FloatPoint(event.location))
    let dragEvent = event.type == .MouseDragged
    let textCursor =
      !initiatingDrag && (dragEvent || !inSelection || !platformArrow)
    return textCursor ? PlatformCursor(CursorType.CursorIBeam.rawValue) : PlatformCursorNil
  }
  
   // ???
  // WordLookupClient* wordLookupClient:  override
  open override func onGestureEvent(event: inout GestureEvent) {
    // switch event.type {
    //   case .GestureTapDown:
    //     requestFocus()
    //     showImeIfNeeded()
    //     event.handled = true
    //   case .GestureTap:
    //     if let c = controller {
    //       if c.handleGestureEvent(sender: self, event: event) {
    //         event.handled = true
    //         return
    //       }
    //     }
    //     if event.details.tapCount == 1 {
    //       // If tap is on the selection and touch handles are not present, handles
    //       // should be shown without changing selection. Otherwise, cursor should
    //       // be moved to the tap location.
          
    //       //if touchSelectionController != nil ||
    //       if !rendertext.isPointInSelection(point: FloatPoint(event.location)) {
    //         onBeforeUserAction()
    //         moveCursor(to: event.location, select: false)
    //         onAfterUserAction()
    //       }
    //     } else if event.details.tapCount == 2 {
    //       onBeforeUserAction()
    //       selectWordAt(point: event.location)
    //       onAfterUserAction()
    //     } else {
    //       onBeforeUserAction()
    //       selectAll(reversed: false)
    //       onAfterUserAction()
    //     }
    //     createTouchSelectionControllerAndNotifyIt()
    //     event.handled = true
    //   case .GestureLongPress:
    //     if !rendertext.isPointInSelection(point: FloatPoint(event.location)) {
    //       // If long-press happens outside selection, select word and try to
    //       // activate touch selection.
    //       onBeforeUserAction()
    //       selectWordAt(point: event.location)
    //       onAfterUserAction()
    //       createTouchSelectionControllerAndNotifyIt()
    //       // If touch selection activated successfully, mark event as handled so
    //       // that the regular context menu is not shown.
        
    //       //if touchSelectionController != nil{
    //       //  event.handled = true
    //       //}
    //     } else {
    //       // If long-press happens on the selection, deactivate touch selection
    //       // and try to initiate drag-drop. If drag-drop is not isEnabled, context
    //       // menu will be shown. Event is not marked as handled to let Views
    //       // handle drag-drop or context menu.
    //       destroyTouchSelection()
    //       initiatingDrag = false//switches.isTouchDragDropEnabled
    //     }
    //   case .GestureLongTap:
    //     // If touch selection is isEnabled, the context menu on long tap will be
    //     // shown by the |touch_selection_controller_|, hence we mark the event
    //     // handled so Views does not try to show context menu on it.
        
    //     //if touchSelectionController != nil {
    //     //  event.handled = true
    //     //}
    //     break
    //   case .GestureScrollBegin:
    //     touchHandlesHiddenDueToScroll = false//touchSelectionController != nil
    //     destroyTouchSelection()
    //     dragStartLocation = event.location
    //     dragStartDisplayOffset =
    //         Int(rendertext.updatedDisplayOffset.x)
    //     event.handled = true
    //   case .GestureScrollUpdate:
    //     let newOffset = Float(dragStartDisplayOffset + event.location.x -
    //                      dragStartLocation.x)
    //     rendertext.setDisplayOffset(horizontalOffset: newOffset)
    //     schedulePaint()
    //     event.handled = false
    //   case .GestureScrollEnd:
    //     fallthrough
    //   case .ScrollFlingStart:
    //     if touchHandlesHiddenDueToScroll {
    //       createTouchSelectionControllerAndNotifyIt()
    //       touchHandlesHiddenDueToScroll = false
    //     }
    //     event.handled = false
    //   default:
    //     return
    // }
 
  }

  open override func onMousePressed(event: MouseEvent) -> Bool {
    let hadFocus = hasFocus
    var handled = false
    
    if let handler = controller {
      handled = handler.handleMouseEvent(sender: self, event: event)
    }

    if !handled &&
      (event.onlyLeftMouseButton || event.onlyRightMouseButton) {
      if !hadFocus {
        requestFocus()
      }
      showImeIfNeeded()
    }

//#if os(Linux)
//    if !handled && !hadFocus && event.isOnlyMiddleMouseButton {
//      requestFocus()
//    }
//#endif

    return selectionController!.onMousePressed(
      event: event, 
      handled: handled,
      initialFocusState: hadFocus ? 
        SelectionController.InitialFocusStateOnMousePress.Focused : 
        SelectionController.InitialFocusStateOnMousePress.Unfocused)
  }

  open override func onMouseDragged(event: MouseEvent) -> Bool {
    return selectionController!.onMouseDragged(event: event)
  }

  open override func onMouseReleased(event: MouseEvent) {
    selectionController!.onMouseReleased(event: event)
  }

  open override func onMouseCaptureLost() {
    selectionController!.onMouseCaptureLost()
  }

  open override func onMouseWheel(event: MouseWheelEvent) -> Bool {
    guard let handler = controller else {
      return false
    }
    return handler.handleMouseEvent(sender: self, event: event)
  }

  open override func acceleratorPressed(accelerator: Accelerator) -> Bool {
    // let event = KeyEvent(
    //   accelerator.keystate == Accelerator.KeyState.Pressed
    //       ? .KeyPressed
    //       : .KeyReleased,
    //   accelerator.keyCode, accelerator.modifiers)
    // var cmd = getCommandForKeyEvent(event)
    // executeTextEditCommand(command: &cmd)
    return true
  }
  
  open override func aboutToRequestFocusFromTabTraversal(reverse: Bool) {
    selectAll(reversed: PlatformStyle.textfieldScrollsToStartOnFocusChange)
  }

  open override func skipDefaultKeyEventProcessing(event: KeyEvent) -> Bool {
    let isBackspace = event.keyCode == .KeyBack
    return (isBackspace && !isReadonly) || event.isUnicodeKeyCode
  }

  open override func getDropFormats(formats: inout Int, formatTypes: inout [ClipboardFormatType]) -> Bool {
    // if !isEnabled || isReadonly {
    //   return false
    // }
    
    // formats = OSExchangeData.String
    
    // if let c = controller {
    //   c.appendDropFormats(formats: &formats, types: &formatTypes)
    // }
    
    // return true
    return false
  }
  
  open override func canDrop(data: OSExchangeData) -> Bool {
    //var formats: Int = -1
    //var formatTypes = [ClipboardFormatType]()
    //getDropFormats(formats: &formats, formatTypes: &formatTypes)
    //return isEnabled && !isReadonly && data.hasAnyFormat(formats, formatTypes)
    return false
  }

  public override func onDragUpdated(event: DropTargetEvent) -> DragOperation {
    let selection = rendertext.selection
    dropCursorPosition = rendertext.findCursorPosition(point: FloatPoint(event.location))
    let inSelection = !selection.isEmpty && selection.contains(range: TextRange(pos: dropCursorPosition.caretPos))
    dropCursorVisible = !inSelection
    // TODO(msw): Pan over text when the user drags to the visible text edge.
    onCaretBoundsChanged()
    schedulePaint()

    stopBlinkingCursor()

    if initiatingDrag {
      if inSelection {
        return DragOperation.DragNone
      }
      
      return event.isControlDown ? DragOperation.DragCopy
                                  : DragOperation.DragMove
    }
    return DragOperation(rawValue: DragOperation.DragCopy.rawValue | DragOperation.DragMove.rawValue)!
  }

  public override func onDragExited() {
    dropCursorVisible = false
    
    if shouldBlinkCursor {
      startBlinkingCursor()
    }

    schedulePaint()
  }

  public override func onPerformDrop(event: DropTargetEvent) -> DragOperation {
    // dropCursorVisible = false

    // if let c = controller {
    //   let dragOperation = c.onDrop(data: event.data)
    //   if dragOperation != DragOperation.DragNone.rawValue {
    //     return DragOperation(rawValue: dragOperation)!
    //   }
    // }

    // //assert(!initiatingDrag ||
    // //      !rendertext.isPointInSelection(event.location))
    
    // onBeforeUserAction()
    // skipInputMethodCancelComposition = true

    // let dropDestinationModel: SelectionModel =
    //     rendertext.findCursorPosition(point: FloatPoint(event.location))

    // var newtext: String
    // event.data.getString(&newtext)

    // // Delete the current selection for a drag and drop within this view.
    // let move = initiatingDrag && !event.isControlDown &&
    //                   ((event.sourceOperations & DragOperation.DragMove.rawValue) != 0)
    // if move {
    //   // Adjust the drop destination if it is on or after the current selection.
    //   var pos = dropDestinationModel.caretPos
    //   pos -= rendertext.selection.intersect(range: TextRange(start: 0, end: pos)).length
    //   model!.deleteSelectionAndInsertTextAt(text: newtext, position: pos)
    // } else {
    //   model!.moveCursorTo(cursor: dropDestinationModel)
    //   // Drop always inserts text even if the textfield is not in insert mode.
    //   model!.insertText(newtext)
    // }
    // skipInputMethodCancelComposition = false
    // updateAfterChange(textChanged: true, cursorChanged: true)
    // onAfterUserAction()
    // return move ? DragOperation.DragMove : DragOperation.DragCopy
    return DragOperation.DragNone
  }
  
  open override func onDragDone() {
    initiatingDrag = false
    dropCursorVisible = false
  }

  //var accessibleNodeData: AXNodeData?
  //func handleAccessibleAction(actionData: AXActionData) -> Bool
  
  open override func onBoundsChanged(previousBounds: IntRect) {
    var bounds = localBounds
    // The text will draw with the correct verticial alignment if we don't apply
    // the vertical insets.
    bounds.inset(left: insets.left, top: 0, right: insets.right, bottom: 0)
    rendertext.displayRect = FloatRect(bounds)
    onCaretBoundsChanged()
    updateCursorViewPosition()
    updateCursorVisibility()
  }
  
  open override func getNeedsNotificationWhenVisibleBoundsChange() -> Bool {
    return true
  }

  open override func onVisibleBoundsChanged() {}

  open override func onEnabledChanged() {
    super.onEnabledChanged()
    
    if let ime = inputMethod {
      ime.onTextInputTypeChanged(client: self)
    }
    schedulePaint()
  }

  open override func onPaint(canvas: Canvas) {
    onPaintBackground(canvas: canvas)
    paintTextAndCursor(canvas: canvas)
    onPaintBorder(canvas: canvas)
  }

  open override func onFocus() {
    rendertext.focused = true
    
    if shouldShowCursor {
      updateCursorViewPosition()
      cursorView.isVisible = true
    }
    
    if let ime = inputMethod {
      ime.setFocusedTextInputClient(client: self)
    }

    onCaretBoundsChanged()
    
    if shouldBlinkCursor {
      startBlinkingCursor()
    }

    // if useFocusRing {
    //   FocusRing.install(self, invalid
    //                               ? NativeTheme.ColorIdAlertSeverityHigh
    //                               : NativeTheme.ColorIdNumColors)
    // }

    schedulePaint()
    super.onFocus()
  }

  open override func onBlur() {
    rendertext.focused = false

    // If necessary, yank the cursor to the logical start of the textfield.
    if PlatformStyle.textfieldScrollsToStartOnFocusChange {
      model!.moveCursorTo(cursor: SelectionModel(pos: 0, affinity: .Forward))
    }

    if let ime = inputMethod {
      ime.detachTextInputClient(client: self)
    }
 
    stopBlinkingCursor()
    cursorView.isVisible = false

    destroyTouchSelection()

    // if useFocusRing {
    //   FocusRing.uninstall(self)
    // }

    schedulePaint()
    super.onBlur()
  }

  // open override func onThemeChanged(theme: Theme)

  public func showContextMenuForView(source: View,
                                     point: IntPoint,
                                     sourceType: MenuSourceType) {
    updateContextMenu()
    contextMenuRunner!.runMenuAt(parent: widget, 
                                button: nil,
                                bounds: IntRect(origin: point, size: IntSize()),
                                anchor: .TopLeft, 
                                sourceType: sourceType)
  }
  // DragController overrides
  public func writeDragDataForView(sender: View,
                                   pressPoint: IntPoint,
                                   data: OSExchangeData) {

  //   data.string = selectedText
  //   let label = Label(text: selectedText, fontlist: fontList!)
  //   label.backgroundColor = backgroundColor
  //   label.subpixelRenderingEnabled = false
  //   var size = label.preferredSize
  //   let display =
  //       Screen.getDisplayNearestWindow(windowId: widget!.window.id)
  //   size.setToMin(other: IntSize(width: display.size.width, height: height))
  //   label.bounds = IntRect(size: size)
  //   label.enabledColor = textColor

  //   var bitmap: Bitmap
  //   let rasterScale = scaleFactorForDragFromWidget(widget)
  //   let color = Color.Transparent
  // //#if defined(USE_X11)
  //   // Fallback on the background color if the system doesn't support compositing.
  // //  if (!ui::XVisualManager::GetInstance()->ArgbVisualAvailable())
  // //    color = GetBackgroundColor()
  // //#endif
  //   label.Paint(PaintInfo.createRootPaintInfo(
  //     CanvasPainter(&bitmap, label.size, rasterScale, color, widget.compositor.isPixelCanvas)
  //     .context,
  //     label.size))
  //   let offset = IntVec2(x: -15, y: 0)
  //   let image = ImageSkia(bitmap: bitmap, scale: rasterScale)
  //   data.provider.setDragImage(image, cursorOffset: offset)
  //   if let c = controller {
  //     c.onWriteDragData(data: data)
  //   }
  }

  public func getDragOperationsForView(sender: View,
                                       point: IntPoint) -> DragOperation {
    var dragOperations = DragOperation.DragCopy
    if !isEnabled || textInputType == .Password ||
        !rendertext.isPointInSelection(point: FloatPoint(point)) {
      dragOperations = DragOperation.DragNone
    } else if sender == self && !isReadonly {
      dragOperations =
          DragOperation(rawValue: DragOperation.DragMove.rawValue | DragOperation.DragCopy.rawValue)!
    }
    if let c = controller {
      c.onGetDragOperationsForTextfield(dragops: &dragOperations)
    }
    return dragOperations
  }

  public func canStartDragForView(sender: View,
                                  pressPoint: IntPoint,
                                  point: IntPoint) -> Bool {
    return initiatingDrag && rendertext.isPointInSelection(point: FloatPoint(pressPoint))
  }

  // WordLookupClient overrides:
  //bool GetWordLookupDataAtPoint(const gfx::IntPoint& point,
  //                              gfx::DecoratedText* decorated_word,
  //                              gfx::IntPoint* baseline_point) override;
  // bool GetWordLookupDataFromSelection(gfx::DecoratedText* decorated_text,
  //                                    gfx::IntPoint* baseline_point) override;

  // SelectionControllerDelegate overrides:
  //bool HasTextBeingDragged() const override;

  // ui::TouchEditable overrides:
  public func selectRect(start: IntPoint, end: IntPoint) {
    if textInputType == .None {
      return
    }

    let startCaret = rendertext.findCursorPosition(point: FloatPoint(start))
    let endCaret = rendertext.findCursorPosition(point: FloatPoint(end))
    let selection = SelectionModel(
      selection: TextRange(start: startCaret.caretPos, end: endCaret.caretPos),
      affinity: endCaret.caretAffinity)

    onBeforeUserAction()
    selectionModel = selection
    onAfterUserAction()
  }

  public func moveCaret(to: IntPoint) {
    selectRect(start: to, end: to)
  }

  public func getSelectionEndPoints(anchor: inout SelectionBound,
                                    focus: inout SelectionBound) {

    let sel = rendertext.selectionModel
    let startSel = rendertext.selectionModelForSelectionStart
    let r1 = rendertext.getCursorBounds(caret: startSel, insertMode: true)
    let r2 = rendertext.getCursorBounds(caret: sel, insertMode: true)

    anchor.setEdge(top: FloatPoint(r1.origin), bottom: FloatPoint(r1.bottomLeft))
    focus.setEdge(top: FloatPoint(r2.origin), bottom: FloatPoint(r2.bottomLeft))

    // Determine the SelectionBound's type for focus and anchor.
    // TODO(mfomitchev): Ideally we should have different logical directions for
    // start and end to support proper handle direction for mixed LTR/RTL text.
    let ltr = textDirection != .RightToLeft
    let anchorPositionIndex = sel.selection.start
    let focusPositionIndex = sel.selection.end

    if anchorPositionIndex == focusPositionIndex {
      anchor.type = SelectionBoundType.Center
      focus.type = SelectionBoundType.Center
    } else if (ltr && anchorPositionIndex < focusPositionIndex) ||
              (!ltr && anchorPositionIndex > focusPositionIndex) {
      anchor.type = SelectionBoundType.Left
      focus.type = SelectionBoundType.Right
    } else {
      anchor.type = SelectionBoundType.Right
      focus.type = SelectionBoundType.Left
    }
  }

  public func convertPointToScreen(point: inout IntPoint) {
    View.convertPointToScreen(src: self, point: &point)
  }
  
  public func convertPointFromScreen(point: inout IntPoint) {
    View.convertPointFromScreen(dst: self, point: &point)
  }

  public func drawsHandles() -> Bool {
    return false 
  }

  public func openContextMenu(anchor: IntPoint) {
    destroyTouchSelection()
    showContextMenu(point: anchor, sourceType: .TouchEditMenu)//MenuSourceTouchEditMenu)
  }

  public func destroyTouchSelection() {
    //touch_selection_controller_ = nil
  }
  
  //public var nativeView: NativeView? {}
  
  // SimpleMenuModelDelegate overrides:

  public func onIconChanged(index: Int) {

  }
  
  public func onMenuStructureChanged() {

  }

  public func isCommandIdChecked(commandId: Int) -> Bool {
    if let tsm = textServicesContextMenu {
      if tsm.supportsCommand(commandId: commandId) {
        return tsm.isCommandIdChecked(commandId: commandId)
      }
    }

    return true
  }
  
  public func isCommandIdEnabled(commandId: Int) -> Bool {
    if let tsm = textServicesContextMenu, 
        tsm.supportsCommand(commandId: commandId) {
      return tsm.isCommandIdEnabled(commandId: commandId)
    }

    return isTextEditCommandEnabled(
        command: getTextEditCommandFromMenuCommand(commandId: commandId, hasSelection: hasSelection))
  }

  public func getAcceleratorForCommandId(commandId: Int) -> Accelerator? {
    
    switch commandId {
      case IDS_APP_UNDO:
        return Accelerator(keycode: KeyboardCode.KeyZ, modifiers: platformModifier.rawValue)

      case IDS_APP_UT:
        return Accelerator(keycode: KeyboardCode.KeyX, modifiers: platformModifier.rawValue)

      case IDS_APP_OPY:
        return Accelerator(keycode: KeyboardCode.KeyC, modifiers: platformModifier.rawValue)

      case IDS_APP_PASTE:
        return Accelerator(keycode: KeyboardCode.KeyV, modifiers: platformModifier.rawValue)

      case IDS_APP_SELECT_ALL:
        return Accelerator(keycode: KeyboardCode.KeyA, modifiers: platformModifier.rawValue)

      default:
        return nil
    }
  }
  
  public func executeCommand(commandId: Int, eventFlags: Int) {
    //if let ts = textServicesContextMenu,
    //    ts.textServicesContextMenu.supportsCommand(commandId) {
    //  ts.executeCommand(commandId: commandId)
    //  return
    //}
    var cmd = getTextEditCommandFromMenuCommand(commandId: commandId, hasSelection: hasSelection)
    executeTextEditCommand(command: &cmd)
  }

  // TextInputClient override
  public func setCompositionText(_ composition: CompositionText) {
    if textInputType == .None {
      return
    }

    onBeforeUserAction()
    skipInputMethodCancelComposition = true
    model!.setCompositionText(composition)
    skipInputMethodCancelComposition = false
    updateAfterChange(textChanged: true, cursorChanged: true)
    onAfterUserAction()
  }

  public func confirmCompositionText() {
    if !model!.hasCompositionText {
      return
    }

    onBeforeUserAction()
    skipInputMethodCancelComposition = true
    model!.confirmCompositionText()
    skipInputMethodCancelComposition = false
    updateAfterChange(textChanged: true, cursorChanged: true)
    onAfterUserAction()
  }
  
  public func clearCompositionText() {
    if !model!.hasCompositionText {
      return
    }

    onBeforeUserAction()
    skipInputMethodCancelComposition = true
    model!.cancelCompositionText()
    skipInputMethodCancelComposition = false
    updateAfterChange(textChanged: true, cursorChanged: true)
    onAfterUserAction()
  }
  
  public func insertText(_ newtext: String) {
    if textInputType == .None || newtext.isEmpty {
      return
    }

    onBeforeUserAction()
    skipInputMethodCancelComposition = true
    model!.insertText(newtext)
    skipInputMethodCancelComposition = false
    updateAfterChange(textChanged: true, cursorChanged: true)
    onAfterUserAction()
  }
  
  public func insertChar(event: KeyEvent) {
    
    if isReadonly {
      onEditFailed()
      return
    }

    // Filter out all control characters, including tab and new line characters,
    // and all characters with Alt modifier (and Search on ChromeOS, Ctrl on
    // Linux). But allow characters with the AltGr modifier. On Windows AltGr is
    // represented by Alt+Ctrl or Right Alt, and on Linux it's a different flag
    // that we don't care about.
    let ch = event.character
    let shouldInsertChar = ((ch >= 0x20 && ch < 0x7F) || ch > 0x9F) &&
                                    !isSystemKeyModifier(event.flags.rawValue) &&
                                    !isControlKeyModifier(event.flags.rawValue)

    if textInputType == .None || !shouldInsertChar {
      return
    }

    doInsertChar(Character(UnicodeScalar(ch)!))

    if textInputType == .Password &&
        !passwordRevealDuration.isZero {
      let changeOffset = model!.cursorPosition
      //assert(change_offset, 0u)
      revealPasswordChar(index: changeOffset - 1)
    }
  }

  public func getCompositionCharacterBounds(index: Int) -> IntRect? {
    
    if !hasCompositionText {
      return nil
    }

    guard let compositionRange = compositionTextRange else {
      return nil
    }

    var textIndex = compositionRange.start + index

    if compositionRange.end <= textIndex {
      return nil
    }
    
    if !rendertext.isValidCursorIndex(index: textIndex) {
      textIndex =
          rendertext.indexOfAdjacentGrapheme(index: textIndex, direction: .Backward)
    }

    if textIndex < compositionRange.start {
      return nil
    }

    let caret = SelectionModel(pos: textIndex, affinity: .Backward)
    
    var rect = IntRect(rendertext.getCursorBounds(caret: caret, insertMode: false))
    View.convertRectToScreen(src: self, rect: &rect)
    
    return rect
  }

  // public func setSelectionRange(range: TextRange) -> Bool {
  //   if (!ImeEditingAllowed() || !range.IsValid())
  //     return false;
  //   OnBeforeUserAction()
  //   SelectRange(range)
  //   OnAfterUserAction()
  //   return true;
  // }
  
  public func deleteRange(_ range: TextRange) -> Bool {
    
    if !imeEditingAllowed || range.isEmpty {
      return false
    }

    onBeforeUserAction()
    model!.selectRange(range)
    
    if model!.hasSelection {
      model!.deleteSelection()
      updateAfterChange(textChanged: true, cursorChanged: true)
    }

    onAfterUserAction()
    return true
  }
  
  public func getTextFromRange(_ range: TextRange) -> String? {
    
    if !imeEditingAllowed || !range.isValid {
      return nil
    }
 
    if !model!.textRange.contains(range: range) {
      return nil
    }

    return model!.getTextFromRange(range)
  }
  
  public func onInputMethodChanged() {}
  
  public func changeTextDirectionAndLayoutAlignment(direction: TextDirection) -> Bool {
     let mode: DirectionalityMode = direction == .RightToLeft
                                           ? .DirectionalityForceRTL
                                           : .DirectionalityForceLTR
    if mode == rendertext.directionalityMode {
      rendertext.directionalityMode = .DirectionalityFromText
    } else {
      rendertext.directionalityMode = mode
    }
    schedulePaint()
    return true
  }
  
  public func extendSelectionAndDelete(before: Int, after: Int) {
    var range = rendertext.selection
    range.start = range.start - before
    range.end = range.end + after
    if let r = textRange {
      if r.contains(range: range) {
        let _ = deleteRange(range)
      }
    }
  }
  
  public func ensureCaretNotInRect(rect: IntRect) {}
  
  public func isTextEditCommandEnabled(command: TextEditCommand) -> Bool {
    var result: String
    let editable = !isReadonly
    let readable = textInputType != .Password
    switch command {
      case .deleteBackward:
        fallthrough
      case .deleteForward:
        fallthrough
      case .deleteToBeginningOfLine:
        fallthrough
      case .deleteToBeginningOfParagraph:
        fallthrough
      case .deleteToEndOfLine:
        fallthrough
      case .deleteToEndOfParagraph:
        fallthrough
      case .deleteWordBackward:
        fallthrough
      case .deleteWordForward:
        return editable
      case .moveBackward:
        fallthrough
      case .moveBackwardAndModifySelection:
        fallthrough
      case .moveForward:
        fallthrough
      case .moveForwardAndModifySelection:
        fallthrough
      case .moveLeft:
        fallthrough
      case .moveLeftAndModifySelection:
        fallthrough
      case .moveRight:
        fallthrough
      case .moveRightAndModifySelection:
        fallthrough
      case .moveToBeginningOfDocument:
        fallthrough
      case .moveToBeginningOfDocumentAndModifySelection:
        fallthrough
      case .moveToBeginningOfLine:
        fallthrough
      case .moveToBeginningOfLineAndModifySelection:
        fallthrough
      case .moveToBeginningOfParagraph:
        fallthrough
      case .moveToBeginningOfParagraphAndModifySelection:
        fallthrough
      case .moveToEndOfDocument:
        fallthrough
      case .moveToEndOfDocumentAndModifySelection:
        fallthrough
      case .moveToEndOfLine:
        fallthrough
      case .moveToEndOfLineAndModifySelection:
        fallthrough
      case .moveToEndOfParagraph:
        fallthrough
      case .moveToEndOfParagraphAndModifySelection:
        fallthrough
      case .moveParagraphForwardAndModifySelection:
        fallthrough
      case .moveParagraphBackwardAndModifySelection:
        fallthrough
      case .moveWordBackward:
        fallthrough
      case .moveWordBackwardAndModifySelection:
        fallthrough
      case .moveWordForward:
        fallthrough
      case .moveWordForwardAndModifySelection:
        fallthrough
      case .moveWordLeft:
        fallthrough
      case .moveWordLeftAndModifySelection:
        fallthrough
      case .moveWordRight:
        fallthrough
      case .moveWordRightAndModifySelection:
        return true
      case .undo:
        return editable && model!.canUndo
      case .redo:
        return editable && model!.canRedo
      case .cut:
        return editable && readable && model!.hasSelection
      case .copy:
        return readable && model!.hasSelection
      case .paste:
        result = Clipboard.forCurrentThread.readText(
            from: .CopyPaste) ?? String()
        return editable && !result.isEmpty
      case .selectAll:
        return !text.isEmpty && selectedRange.length != text.count
      case .transpose:
        return editable && !model!.hasSelection &&
              !model!.hasCompositionText
      case .yank:
        return editable
      case .moveDown:
        fallthrough
      case .moveDownAndModifySelection:
        fallthrough
      case .movePageDown:
        fallthrough
      case .movePageDownAndModifySelection:
        fallthrough
      case .movePageUp:
        fallthrough
      case .movePageUpAndModifySelection:
        fallthrough
      case .moveUp:
        fallthrough
      case .moveUpAndModifySelection:
        return false
      case .insertText:
        fallthrough
      case .setMark:
        fallthrough
      case .unselect:
        fallthrough
      case .invalidCommand:
        return false
    }
  }
  
  public func setTextEditCommandForNextKeyEvent(command: TextEditCommand) {
    scheduledTextEditCommand = command
  }
  // View overrides:
  // Declared final since overriding by subclasses would interfere with the
  // accounting related to the scheduled text edit command. Subclasses should
  // use TextfieldController::HandleKeyEvent, to intercept the key event.

  open override func onKeyPressed(event: KeyEvent) -> Bool {
    var editCommand = scheduledTextEditCommand
    scheduledTextEditCommand = .invalidCommand

    var handled = controller != nil && controller!.handleKeyEvent(sender: self, event: event)

    // if !textfield {
    //   return handled
    // }

  // #if defined(OS_LINUX) && !defined(OS_HROMEOS)
  //   ui::TextEditKeyBindingsDelegateAuraLinux* delegate =
  //       ui::GetTextEditKeyBindingsDelegate()
  //   std::vector<ui::TextEditCommandAuraLinux> commands;
  //   if (!handled && delegate && delegate->MatchEvent(event, &commands)) {
  //     for (size_t i = 0; i < commands.size() ++i) {
  //       if (IsTextEditCommandEnabled(commands[i].command())) {
  //         ExecuteTextEditCommand(commands[i].command())
  //         handled = true;
  //       }
  //     }
  //     return handled;
  //   }
  // #endif

    if editCommand == .invalidCommand {
      editCommand = getCommandForKeyEvent(event: event)
    }

    if !handled && isTextEditCommandEnabled(command: editCommand) {
      executeTextEditCommand(command: &editCommand)
      handled = true
    }
    return handled
  }

  open override func onKeyReleased(event: KeyEvent) -> Bool {
    guard let c = controller else {
      return false
    }
    return c.handleKeyEvent(sender: self, event: event)
  }

  // SelectionControllerDelegate overrides:
  public func onBeforePointerAction() {
    onBeforeUserAction()
    if model!.hasCompositionText {
      model!.confirmCompositionText()
    }
  }

  public func onAfterPointerAction(textChanged: Bool, selectionChanged: Bool) {
    onAfterUserAction()
    updateAfterChange(textChanged: textChanged, cursorChanged: selectionChanged)
  }
  
  public func pasteSelectionClipboard() -> Bool {
    if selectionClipboardText.isEmpty {
      return false
    }

    model!.insertText(selectionClipboardText)
    
    return true
  }

  //public func updateSelectionClipboard() {}
  
  public func updateSelectionClipboard() {
    if textInputType != .Password {
       ScopedClipboardWriter(.Selection).writeText(selectedText)
       if let c = controller {
         c.onAfterCutOrCopy(type: .Selection)
      }
    }
  }

  // Updates the painted background color.
  fileprivate func updateBackgroundColor() {
    //let color = backgroundColor
    // if MaterialDesignController.isSecondaryUiMaterial() {
    //   background = 
    //       createBackgroundFromPainter(Painter.createSolidRoundRectPainter(
    //           backgroundColor, FocusableBorder.CornerRadiusOp))
    // } else {
      background = SolidBackground(color: backgroundColor)
    //}
    // Disable subpixel rendering when the background color is not opaque because
    // it draws incorrect colors around the glyphs in that case.
    // See crbug.com/115198
    rendertext.subpixelRenderingSuppressed = backgroundColor.a != ColorAlpha.opaque.rawValue
    
    schedulePaint()
  }

  // Updates the border per the state of |invalid_|.
  fileprivate func updateBorder() {
    let border = FocusableBorder()
    
    let provider = LayoutProvider.instance()

    border.setInsets(
        vertical: provider.getDistanceMetric(.ControlVerticalTextPadding),
        horizontal: provider.getDistanceMetric(.TextfieldHorizontalTextPadding))
    
    if invalid {
      border.setColorId(Theme.ColorId.AlertSeverityHigh)
    }

    super.border = border
  }

  // Does necessary updates when the text and/or cursor position changes.
  fileprivate func updateAfterChange(textChanged: Bool, cursorChanged: Bool) {
    if textChanged {
      if let c = controller {
        c.contentsChanged(sender: self, contents: text)
      }
      //notifyAccessibilityEvent(AXEvent.ValueChanged, true)
    }

    if cursorChanged {
      updateCursorViewPosition()
      updateCursorVisibility()
    }

    if textChanged || cursorChanged {
      onCaretBoundsChanged()
      schedulePaint()
    }
  }

  func doInsertChar(_ ch: Character) {
    onBeforeUserAction()
    skipInputMethodCancelComposition = true
    model!.insertChar(ch)
    skipInputMethodCancelComposition = false
    updateAfterChange(textChanged: true, cursorChanged: true)
    onAfterUserAction()
  }

  // Updates cursor visibility and blinks the cursor if needed.
  // ERROR Textfield.cc does not implement that
  //fileprivate func showCursor() {}

  // A callback function to periodically update the cursor node_data.
  fileprivate func updateCursorVisibility() {
    cursorView.isVisible = shouldShowCursor
    if shouldBlinkCursor {
      startBlinkingCursor()
    } else {
      stopBlinkingCursor()
    }
  }

  // Update the cursor position in the text field.
  fileprivate func updateCursorViewPosition() {
    var location = IntRect(rendertext.updatedCursorBounds)
    location.x = getMirroredXForRect(rect: location)
    location.height = min(location.height, localBounds.height - location.y - location.y)
    
    cursorView.bounds = location
  }

  fileprivate func paintTextAndCursor(canvas: Canvas) {
    canvas.save()

    // Draw placeholder text if needed.
    if text.isEmpty && !placeholderText.isEmpty {
      // Disable subpixel rendering when the background color is not opaque
      // because it draws incorrect colors around the glyphs in that case.
      // See crbug.com/786343
      if backgroundColor.a != ColorAlpha.opaque.rawValue {
        placeholderTextDrawFlags |= TextOptions.NoSubpixelRendering.rawValue
      }

      canvas.drawStringRect(
          text: placeholderText,
          font: fontList!,//placeholderFontList!.value ?? fontList,
          color: placeholderTextColor ?? defaultPlaceholderTextColor,
              //MaterialDesignController.isSecondaryUiMaterial
              //    ? textColor.Alpha = 0x83
              //    : DefaultPlaceholderTextColor),
          rect: rendertext.displayRect, 
          flags: TextOptions(rawValue: placeholderTextDrawFlags))
    }

    rendertext.draw(canvas: canvas)

    // Draw the detached drop cursor that marks where the text will be dropped.
    if dropCursorVisible {
      canvas.fillRect(rect: rendertext.getCursorBounds(caret: dropCursorPosition, insertMode: true),
                      color: textColor)
    }

    canvas.restore()
  }

  // Helper function to call MoveCursorTo on the TextfieldModel.
  fileprivate func moveCursor(to point: IntPoint, select: Bool) {
    if model!.moveCursorTo(point: point, select: select) {
      updateAfterChange(textChanged: false, cursorChanged: true)
    }
  }

  // Convenience method to notify the InputMethod and TouchSelectionController.
  fileprivate func onCaretBoundsChanged() {
    
    if let ime = inputMethod {
      ime.onCaretBoundsChanged(client: self)
    }

    //if let touch = touchSelectionController {
    //  touch.selectionChanged()
    //}

  //#if os(macOS)
    // On Mac, the context menu contains a look up item which displays the
    // selected text. As such, the menu needs to be updated if the selection has
    // changed.
  //  contextMenuContents = nil
  //#endif

    // Screen reader users don't expect notifications about unfocused textfields.
   // if hasFocus {
   //   notifyAccessibilityEvent(AXEvent.TextSelectionChanged, true)
   // }

  }

  // Convenience method to call TextfieldController::OnBeforeUserAction()
  fileprivate func onBeforeUserAction() {
    performingUserAction = true
    if let c = controller {
      c.onBeforeUserAction(sender: self)
    }
  }

  // Convenience method to call TextfieldController::OnAfterUserAction()
  fileprivate func onAfterUserAction() {
    if let c = controller {
      c.onAfterUserAction(sender: self)
    }
    performingUserAction = false
  }

  // Calls |model_->Cut()| and notifies TextfieldController on success.
  fileprivate func cut() -> Bool {
    if !isReadonly && textInputType != .Password &&
        model!.cut() {
      if let c = controller {
        c.onAfterCutOrCopy(type: .CopyPaste)
      }
      return true
    }
    return false
  }

  // Calls |model_->Copy()| and notifies TextfieldController on success.
  fileprivate func copy() -> Bool {
    if textInputType != .Password && model!.copy() {
      if let c = controller {
        c.onAfterCutOrCopy(type: .CopyPaste)
      }
      return true
    }
    return false
  }

  // Calls |model_->Paste()| and calls TextfieldController::ContentsChanged()
  // explicitly if paste succeeded.
  fileprivate func paste() -> Bool {
    if !isReadonly && model!.paste() {
      if let c = controller {
        c.onAfterPaste()
      }
      return true
    }
    return false
  }

  // Utility function to prepare the context menu.
  fileprivate func updateContextMenu() {
    if contextMenuContents == nil {
      contextMenuContents = SimpleMenuModel(delegate: self)
      contextMenuContents!.addItem(IDS_APP_UNDO, stringId: IDS_APP_UNDO)
      contextMenuContents!.addSeparator(separatorType: .NormalSeparator)
      contextMenuContents!.addItem(IDS_APP_UT, stringId: IDS_APP_UT)
      contextMenuContents!.addItem(IDS_APP_OPY, stringId: IDS_APP_OPY)
      contextMenuContents!.addItem(IDS_APP_PASTE, stringId: IDS_APP_PASTE)
      contextMenuContents!.addItem(IDS_APP_DELETE, stringId: IDS_APP_DELETE)
      contextMenuContents!.addSeparator(separatorType: .NormalSeparator)
      contextMenuContents!.addItem(IDS_APP_SELECT_ALL,
                                   stringId: IDS_APP_SELECT_ALL)

      // If the controller adds menu commands, also override ExecuteCommand() and
      // IsCommandIdEnabled() as appropriate, for the commands added.
      if let c = controller {
        c.updateContextMenu(menuContents: contextMenuContents!)
      }

      //textServicesContextMenu = ViewsTextServicesContextMenu.create(contextMenuContents!, self)
    }

    contextMenuRunner = MenuRunner(
      menuModel: contextMenuContents!, 
      runTypes: Int32(MenuRunner.RunTypes.HasMnemonics.rawValue | MenuRunner.RunTypes.ContextMenu.rawValue))
  }

  // Reveals the password character at |index| for a set duration.
  // If |index| is -1, the existing revealed character will be reset.
  fileprivate func revealPasswordChar(index: Int) {
    rendertext.obscuredRevealIndex = index
    schedulePaint()

    if index != -1 {
      passwordRevealTimer.start(
          delay: passwordRevealDuration,
          { self.revealPasswordChar(index: -1) })
    }
  }

  fileprivate func createTouchSelectionControllerAndNotifyIt() {
    //if !hasFocus
    //  return

    // if !touchSelectionController = nil {
    //   touchSelectionController =
    //       TouchEditingControllerDeprecated.create(self))
    // }

    // if let c = touchSelectionController {
    //   c.selectionChanged()
    // }

  }

  // Called when editing a textfield fails because the textfield is readonly.
  fileprivate func onEditFailed() {
     PlatformStyle.onTextfieldEditFailed()
  }

  // Starts and stops blinking the cursor, respectively. These are both
  // idempotent if the cursor is already blinking/not blinking.
  fileprivate func startBlinkingCursor() {
     cursorBlinkTimer.start(delay: Textfield.caretBlinkInterval, { self.onCursorBlinkTimerFired() } )
  }
  
  fileprivate func stopBlinkingCursor() {
    cursorBlinkTimer.stop()
  }

  // Callback for the cursor blink timer. Called every
  // Textfield::GetCaretBlinkMs().
  fileprivate func onCursorBlinkTimerFired() {
    updateCursorViewPosition()
    cursorView.isVisible = !cursorView.isVisible
  }

}

internal protocol EditMerger {
  func doMerge(edit: Edit) -> Bool
}

extension EditMerger {
  func doMerge(edit: Edit) -> Bool {
    return false
  }
}

enum EditType {
  case insert
  case delete
  case replace
}

internal class Edit : EditMerger {

  var ismergeable: Bool { 
    return mergeType == .mergeable
  }

  var forceMerge: Bool { 
    return mergeType == .forceMerge
  }

  var oldTextEnd: Int { 
    return oldTextStart + oldText.count 
  }

  var newTextEnd: Int { 
    return newTextStart + newText.count 
  }

  var type: EditType
  var mergeType: MergeType
  var oldCursorPos: Int
  var oldText: String  
  var oldTextStart: Int
  var deleteBackward: Bool  
  var newCursorPos: Int
  var newText: String
  var newTextStart: Int

  init(type: EditType,
       mergeType: MergeType,
       oldCursorPos: Int,
       oldText: String,
       oldTextStart: Int,
       deleteBackward: Bool,
       newCursorPos: Int,
       newText: String,
       newTextStart: Int) {

    self.type = type
    self.mergeType = mergeType
    self.oldCursorPos = oldCursorPos
    self.oldText = oldText
    self.oldTextStart = oldTextStart
    self.deleteBackward = deleteBackward
    self.newCursorPos = newCursorPos
    self.newText = newText
    self.newTextStart = newTextStart
  }

  func undo(model: TextfieldModel) {
    model.modifyText(from: newTextStart, to: newTextEnd,
                     text: oldText, at: oldTextStart,
                     cursorTo: oldCursorPos)
  }

  func redo(model: TextfieldModel) {
    model.modifyText(from: oldTextStart, 
                     to: oldTextEnd,
                     text: newText, 
                     at: newTextStart,
                     cursorTo: newCursorPos)
  }

  func merge(edit: Edit) -> Bool {
    if type != .delete && edit.forceMerge {
      mergeReplace(edit: edit)
      return true
    }
    return ismergeable && edit.ismergeable && doMerge(edit: edit)
  }

  func commit() { 
    mergeType = .doNotMerge 
  }

  func mergeReplace(edit: Edit) {
    // TODO: see if this algo work as intended
    var old = edit.oldText
    let startIndex = newText.index(newText.startIndex, offsetBy: newTextStart)
    old.removeSubrange(startIndex..<newText.endIndex)
    let insertIndex = old.index(old.startIndex, offsetBy: oldTextStart)
    old.insert(contentsOf: oldText, at: insertIndex)
    oldText = old
    oldTextStart = edit.oldTextStart
    deleteBackward = false

    newText = edit.newText
    newTextStart = edit.newTextStart
    mergeType = .doNotMerge
  }

}

class InsertEdit : Edit {
  
  init(_ mergeable: Bool, _ newText: String, _ at: Int) {
    super.init(
       type: .insert,
       mergeType: mergeable ? .mergeable : .doNotMerge,
       oldCursorPos: at,
       oldText: String(),
       oldTextStart: at,
       deleteBackward: false,
       newCursorPos: at + newText.count,
       newText: newText,
       newTextStart: at)
  }

  func doMerge(edit: Edit) -> Bool {

    if edit.type != .insert || newTextEnd != edit.newTextStart {
      return false
    }

    newText += edit.newText
    newCursorPos = edit.newCursorPos
    return true
  }

}

class ReplaceEdit : Edit {
  
  init(_ mergeType: MergeType,
       _ oldText: String,
       _ oldCursorPos: Int,
       _ oldTextStart: Int,
       _ backward: Bool,
       _ newCursorPos: Int,
       _ newText: String,
       _ newTextStart: Int) {
      
      super.init(
            type: .replace, 
            mergeType: mergeType,
            oldCursorPos: oldCursorPos,
            oldText: oldText,
            oldTextStart: oldTextStart,
            deleteBackward: backward,
            newCursorPos: newCursorPos,
            newText: newText,
            newTextStart: newTextStart)
  }

  func doMerge(edit: Edit) -> Bool {
    if edit.type == .delete ||
        newTextEnd != edit.oldTextStart ||
        edit.oldTextStart != edit.newTextStart {
      return false
    }
    oldText += edit.oldText
    newText += edit.newText
    newCursorPos = edit.newCursorPos
    return true
  }
}

class DeleteEdit : Edit {
  
  init(_ mergeable: Bool,
       _ text: String,
       _ textStart: Int,
       _ backward: Bool) {

    super.init(
             type: .delete,
             mergeType: mergeable ? .mergeable : .doNotMerge,
             oldCursorPos: (backward ? textStart + text.count : textStart),
             oldText: text,
             oldTextStart: textStart,
             deleteBackward: backward,
             newCursorPos: textStart,
             newText: String(),
             newTextStart: textStart)
  }

  func doMerge(edit: Edit) -> Bool {
    if edit.type != .delete {
      return false
    }

    if deleteBackward {
      if !edit.deleteBackward || oldTextStart != edit.oldTextEnd {
        return false
      }
      oldTextStart = edit.oldTextStart
      oldText = edit.oldText + oldText
      newCursorPos = edit.newCursorPos
    } else {
      if edit.deleteBackward || oldTextStart != edit.oldTextStart {
        return false
      }
      oldText += edit.oldText
    }
    return true
  }

}

fileprivate var passwordRevealDuration: TimeDelta {
  return ViewsDelegate.instance.textfieldPasswordRevealDuration
}

fileprivate func getFirstEmphasizedRange(_ composition: CompositionText) -> TextRange {
  for underline in composition.underlines {
    if underline.thick {
      return TextRange(start: Int(underline.startOffset), end: Int(underline.endOffset))
    }
  }
  return TextRange.InvalidRange
}

fileprivate func isControlKeyModifier(_ flags: Int) -> Bool {
// XKB layout doesn't natively generate printable characters from a
// Control-modified key combination, but we cannot extend it to other platforms
// as Control has different meanings and behaviors.
// https://crrev.com/2580483002/#msg46
#if os(Linux)
  return (flags & EventFlags.ControlDown.rawValue) != 0
#else
  return false
#endif
}

#if os(macOS)
fileprivate let systemKeyModifierMask: Int = EventFlags.CommandDown.rawValue
#else
fileprivate let systemKeyModifierMask: Int = EventFlags.AltDown.rawValue
#endif

fileprivate func isSystemKeyModifier(_ flags: Int) -> Bool {
  return (systemKeyModifierMask & flags) != 0 &&
         (EventFlags.AltgrDown.rawValue & flags) == 0
}