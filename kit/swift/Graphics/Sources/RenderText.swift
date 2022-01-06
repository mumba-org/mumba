// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

import MumbaShims
import Base

//internal struct IndexedFontStyle {
  
//  var styles: [FontStyle : BreakList<Bool>]

//  subscript(style: FontStyle) -> Bool {
//    guard let breaklist = styles[style] else {
//      return false
//    }
//    return breaklist[0].value
//  }

//  public init() {
//    styles = [FontStyle : BreakList<Bool>]()
//  }
//}

fileprivate let maxScripts = 8
fileprivate let UTF16LineBreak: UInt16 = 10 // "\n"
fileprivate let UTF16EmailAt: UInt16 = 64 // "@"
fileprivate let UTF16PasswordChar: UInt16 = 42 // "*"
fileprivate let UTF16Brackets: [UInt16] = [40, 41, 123, 125, 60, 62] // "(",")","{","}","<",">"
// Internal helper class used to iterate colors, baselines, and styles.
internal struct StyleIterator {

  // Get the colors and styles at the current iterator position.
  public var color: Color {
    //return color_->second
    return Color.Black
  }

  public var baseline: BaselineStyle { 
    //return baseline_->second 
    return .NormalBaseline
  }

  public func style(_ style: FontStyle) -> Bool {//IndexedFontStyle
    let s = _style[style.position]
    if let first = s.first {
      return first.value
    }
    return false
  }
  // Get the intersecting range of the current iterator set.
  var range: TextRange {
    var value = TextRange()
    if let firstColor = _color.first {
      value = colors.range(at: firstColor.index)
    }
    if let firstBaseline = _baseline.first {
      value = value.intersect(range: baselines.range(at: firstBaseline.index))
    }  

    for breakList in styles {
      if let br = breakList.breaks.first {
        value = value.intersect(range: breakList.range(at: br.index))
      }
    }

    return value
  }

  var colors: BreakList<Color>
  var baselines: BreakList<BaselineStyle>
  var styles: [BreakList<Bool>]
  var _color: [BreakList<Color>.Break]
  var _baseline: [BreakList<BaselineStyle>.Break]
  var _style: [[BreakList<Bool>.Break]]
  //convenience init() {//colors: BreakList<Color>,
                //baselines: BreakList<BaselineStyle>,
                //styles: [BreakList<Bool>] ) {
    //color_ = colors_.breaks().begin()
    //baseline_ = baselines_.breaks().begin()
    //for (size_t i = 0 i < styles_.size() ++i)
    //  style_.push_back(styles_[i].breaks().begin())
    //styles = BreakList<Bool>()
  //}

  init(colors: BreakList<Color>,
       baselines: BreakList<BaselineStyle>,
       styles: [BreakList<Bool>]) {
    
    self.styles = styles
    self.colors = colors
    self.baselines = baselines
     // warning: this should be temporary
    //for (i, style) in FontStyle.All.enumerated() {
    //  let br = BreakList.Break(index: style.index, value: false)
    //  self.styles[style]?.breaks.insert(br, at: style.index)
    //}

    _style = []

    _color = colors[0]
    _baseline = baselines[0]
    //
    for (i, s) in self.styles.enumerated() {
      _style.insert(s[0], at: i)
    }

  }

  //func getStyle(_ s: FontStyle) -> Bool { 
  // return style_[s]->second 
  // return false
  //}

  // Update the iterator to point to colors and styles applicable at |position|.
  mutating func updatePosition(pos: Int) {
    _color = colors[pos]
    _baseline = baselines[pos]
    for (i, _) in FontStyle.All.enumerated() {
      _style.insert(styles[i][pos], at: i)
    }
  }

}

// Line segments are slices of the display text to be rendered on a single line.
public struct LineSegment {
  // X coordinates of this line segment in text space.
  var xRange: TextRangef

  // The character range this segment corresponds to.
  var charRange: TextRange

  // Index of the text run that generated this segment.
  var run: Int

  // Returns the width of this line segment in text space.
  var width: Float { 
    return xRange.length
  }

  public init () {
    xRange = TextRangef()
    charRange = TextRange()
    run = 0  
  }
}

// A line of display text, comprised of a line segment list and some metrics.
public struct Line {
  // Segments that make up this line in visual order.
  var segments: [LineSegment]

  // The sum of segment widths and the maximum of segment heights.
  var size: FloatSize

  // Sum of preceding lines' heights.
  var precedingHeights: Float

  // Maximum baseline of all segments on this line.
  var baseline: Int

  public init () {
    segments = []
    size = FloatSize()
    precedingHeights = 0.0
    baseline = 0
  }
}

func restoreBreakList<T>(renderText: RenderText, breakList: inout BreakList<T> ) {
  breakList.max = renderText.text.utf16.count
  var range = TextRange()

  while range.end < breakList.max {
    //let currentBreak = breakList[range.end][0]
    let currentBreak = breakList[range.end]

    range = breakList.range(from: currentBreak)
    if range.end < breakList.max && !renderText.isValidCursorIndex(index: range.end) {
      let firstbreak = currentBreak[currentBreak.startIndex]
      range.end = renderText.indexOfAdjacentGrapheme(index: range.end, direction: .Forward)
      breakList.apply(value: firstbreak.value, range: range)
    }
  }
}

public class RenderText {

  let PasswordReplacementChar: UInt16 = UTF16PasswordChar

  // Default color used for the text and cursor.
  let DefaultColor = Color.Black

  // Default color used for drawing selection background.
  let DefaultSelectionBackgroundColor = Color.Gray

  // Invalid value of baseline.  Assigning this value to |baseline_| causes
  // re-calculation of baseline.
  let InvalidBaseline = Int.max

#if os(macOS)
  internal static let selectionIsAlwaysDirected: Bool = false
#else
  internal static let selectionIsAlwaysDirected: Bool = true
#endif

  public var multilineSupported: Bool {
    return true
  }

  public var displayText: String {
    if multiline || elideBehavior == .NoElide || elideBehavior == .FadeTail {
      // Call UpdateDisplayText to clear |display_text_| and |text_elided_|
      // on the RenderText class.
      updateDisplayText(textWidth: 0)
      _updateDisplayText = false
      displayRunList = nil
      return layoutText
    }

    ensureLayoutRunList()
    //assert(!_updateDisplayText)
    return textElided ? _displayText : layoutText
  }

  public var runList : TextRunList {
    assert(!updateLayoutRunList)
    assert(!updateDisplayRunList)
    return textElided ? displayRunList! : layoutRunList
  }

  public var insertMode: Bool {
    didSet {
      cachedBoundsAndOffsetValid = false
    }
  }

  public var obscured: Bool {
    didSet {
      guard oldValue != obscured else {
        return
      }
      obscuredRevealIndex = -1
      // will trigger this from the top
      //cachedBoundsAndOffsetValid = false
      //onTextAttributeChanged()
    }
  }

  public var obscuredRevealIndex: Int {
    didSet {
      guard obscuredRevealIndex != oldValue else {
        return
      }
      cachedBoundsAndOffsetValid = false
      onTextAttributeChanged()
    }
  }

  public var multiline: Bool {
    didSet {
      guard multiline != oldValue else {
        return
      }
      cachedBoundsAndOffsetValid = false
      lines.removeAll()
      onTextAttributeChanged()
    }
  }

  public var glyphSpacing: Int

  public var wordWrapBehavior: WordWrapBehavior {
    didSet {
      guard wordWrapBehavior != oldValue else {
        return
      }
      if multiline {
        cachedBoundsAndOffsetValid = false
        lines.removeAll()
        onTextAttributeChanged()
      }
    }
  }

  public var minLineHeight: Int {
    didSet {
      guard minLineHeight != oldValue else {
        return
      }
      cachedBoundsAndOffsetValid = false
      lines.removeAll()
      onDisplayTextAttributeChanged()
    }
  }
  
  public var cursorEnabled: Bool {
    didSet {
      cachedBoundsAndOffsetValid = false
    }
  }
 
  public var fontList: FontList {
    didSet {
      let fontStyle = fontList.fontStyle
      setStyle(style: .Bold, value: fontStyle.contains(.Bold))
      setStyle(style: .Italic, value: fontStyle.contains(.Italic))
      setStyle(style: .Underline, value: fontStyle.contains(.Underline))
      _baseline = InvalidBaseline
      cachedBoundsAndOffsetValid = false
      onLayoutTextAttributeChanged(textChanged: false)
    }
  }

  public var horizontalAlignment: HorizontalAlignment {
    didSet {
      guard horizontalAlignment != oldValue else {
        return
      } 
      displayOffset = FloatVec2()
      cachedBoundsAndOffsetValid = false
    }
  }

  public var displayRect: FloatRect {
    didSet {
      guard oldValue != displayRect else {
        return
      } 
      _baseline = InvalidBaseline
      cachedBoundsAndOffsetValid = false
      lines.removeAll()
      if elideBehavior != .NoElide && elideBehavior != .FadeTail {
        onDisplayTextAttributeChanged()
      }
    }
  }

  public var compositionRange: TextRange {
    get {
      return _compositionRange
    }
    set {
     //assert(!composition_range.IsValid() || TextRange(0, text_.length()).Contains(composition_range))
      _compositionRange.end = newValue.end
      _compositionRange.start = newValue.start
      // TODO(oshima|msw): Altering composition underlines shouldn't
      // require layout changes. It's currently necessary because
      // RenderTextHarfBuzz paints text decorations by run, and
      // RenderTextMac applies all styles during layout.
      onLayoutTextAttributeChanged(textChanged: false)
    }
  }

  public var text: String {
    get {
      return _text
    }
    set {
      // assert(!compositionRange.isValid)
      guard _text != newValue else {
        return
      }

      _text = newValue

      updateStyleLengths()

      // Clear style ranges as they might break new text graphemes and apply
      // the first style to the whole text instead.
      if let (_, color) = colors.breaks.first {
        colors.set(value: color)
      }
      if let (_, baseline) = baselines.breaks.first { 
        baselines.set(value: baseline)
      }

      for style in FontStyle.All {
        var s = styles[style.position]
        if let (_, val) = s.breaks.first { 
          s.set(value: val)
        }
      }

      cachedBoundsAndOffsetValid = false

      // Reset selection model. SetText should always followed by SetSelectionModel
      // or SetCursorPosition in upper layer.
      //selectionModel = selectionModel

      // Invalidate the cached text direction if it depends on the text contents.
      if directionalityMode == .DirectionalityFromText {
        textDirection = .Unknown
      }

      obscuredRevealIndex = -1
      onTextAttributeChanged()
    }
  }

  public var elideBehavior: ElideBehavior {
    didSet {
      guard elideBehavior != oldValue else {
        return
      }
      onDisplayTextAttributeChanged()
    }
  }
  
  public var selection: TextRange {
    return selectionModel.selection
  }

  public var selectionModel: SelectionModel {
     didSet {
       guard selectionModel != oldValue else {
         return
       }
       cachedBoundsAndOffsetValid = false
       hasDirectedSelection = RenderText.selectionIsAlwaysDirected
     }
  }

  public var cursorPosition: Int {
    get {
      return selectionModel.caretPos
    }
    set {
      moveCursorTo(position: newValue, sel: false)
    }
  }
  
  public var directionalityMode: DirectionalityMode {
    didSet {
      guard oldValue != directionalityMode else {
        return
      }
      textDirection = .Unknown
      cachedBoundsAndOffsetValid = false
      onLayoutTextAttributeChanged(textChanged: false)
    }
  }
  
  public var shadows: ShadowValues

  public var visualDirectionOfLogicalEnd: VisualCursorDirection {
     return displayTextDirection == .LeftToRight ? .Right : .Left
  }
  
  public var replaceNewlineCharsWithSymbols: Bool {
    didSet {
      if oldValue != replaceNewlineCharsWithSymbols {
        cachedBoundsAndOffsetValid = false
        onTextAttributeChanged()
      }
    }
  }
  
  public var displayTextDirection: TextDirection {
    return getTextDirection(text: displayText)
  }

  public var displayTextBaseline: Int {
    ensureLayout()
    return lines[0].baseline
  }
  
  public var stringSize: IntSize {
    let sizef = stringSizef
    return IntSize(width: Int(ceilf(sizef.width)), height: Int(ceilf(sizef.height)))
  }

  public var stringSizef: FloatSize {
    ensureLayout()
    return totalSize
  }

  public var contentWidth: Int {
    return Int(ceilf(contentWidthf))
  }

  public var contentWidthf: Float {
    let stringSize = stringSizef.width
    // The cursor is drawn one pixel beyond the int-enclosed text bounds.
    return cursorEnabled ? ceilf(stringSize) + 1 : stringSize
  }

  public var baseline: Int {
    if _baseline == InvalidBaseline {
      _baseline = determineBaselineCenteringText(displayRect: displayRect, list: fontList)
    }
    //assert(InvalidBaseline != _baseline)
    return _baseline
  }

  public var updatedCursorBounds: FloatRect {
    updateCachedBoundsAndOffset()
    return cursorBounds
  }

  public var selectionModelForSelectionStart: SelectionModel {
    let sel = selection
    
    if sel.isEmpty {
      return selectionModel
    }

    return SelectionModel(pos: sel.start, affinity: sel.isReversed ? .Backward : .Forward)
  }

  public var updatedDisplayOffset: FloatVec2 {
    updateCachedBoundsAndOffset()
    return displayOffset
  }

  public var lineBreaks: BreakList<Int> {
    if _lineBreaks.max != 0 {
      return _lineBreaks
    }

    let layout = displayText
    let textLength = layout.utf16.count
    _lineBreaks.set(value: 0)
    _lineBreaks.max = textLength
    let iter = BreakIterator(str: layout, type: .Line)
    let success = iter.initialize()
    //assert(success)
    if success {
      repeat {
        _lineBreaks.apply(value: iter.pos, range: TextRange(start: iter.pos, end: textLength))
      } while iter.advance()
    }
    return _lineBreaks
  }

  public var currentHorizontalAlignment: HorizontalAlignment {
    
    if horizontalAlignment != .AlignToHead {
      return horizontalAlignment
    }
    
    return displayTextDirection == .RightToLeft ? .AlignRight : .AlignLeft
  }

  public var cursorVisible: Bool
  public var cursorColor: Color
  public var cursorBounds: FloatRect
  public var selectionColor: Color
  public var selectionBackgroundFocusedColor: Color
  public var focused: Bool
  public var clipToDisplayRect: Bool
  public var displayOffset: FloatVec2
  public var subpixelRenderingSuppressed: Bool
  public var layoutText: String
  public var textElided: Bool
  public var colors: BreakList<Color>
  public var baselines: BreakList<BaselineStyle>
  //public var styles: [FontStyle : BreakList<Bool>] ///IndexedFontStyle//[BreakList<Bool>]
  public var styles: [BreakList<Bool>]
  public var weights: BreakList<Font.Weight>
  public var lines: [Line]
  public var textDirection: TextDirection
  var cachedBoundsAndOffsetValid: Bool
  var truncateLength: Int
  var displayRunList: TextRunList?
  var layoutRunList: TextRunList
  var updateLayoutRunList: Bool
  var updateDisplayRunList: Bool
  var updateGraphemeIterator: Bool
  var updateDisplayText: Bool
  var hasDirectedSelection: Bool
  var savedColors: BreakList<Color>
  var savedUnderlines: BreakList<Bool>
  var compositionAndSelectionStylesApplied: Bool
  var _lineBreaks: BreakList<Int>
  var _compositionRange: TextRange
  var _updateDisplayText: Bool
  var _displayText: String
  var _text: String
  var _baseline: Int
  var graphemeIterator: BreakIterator?
  var totalSize: FloatSize

  public static func rangeContainsCaret(range: TextRange,
                                        caretPos: Int,
                                        caretAffinity: LogicalCursorDirection) -> Bool { 
    let adjacent = (caretAffinity == .Backward) ? caretPos - 1 : caretPos + 1
    return range.contains(range: TextRange(start: caretPos, end: adjacent))
  }
  
  public init() {
    horizontalAlignment = .AlignLeft
    fontList = FontList()
    cursorEnabled = false
    displayRect = FloatRect()
    elideBehavior = .NoElide
    minLineHeight = 0
    cursorVisible = false
    insertMode = false
    glyphSpacing = 0
    cursorColor = Color.Black
    selectionColor = Color.Black
    selectionBackgroundFocusedColor = Color.Black
    focused = false
    clipToDisplayRect = false
    obscured = false
    multiline = false
    wordWrapBehavior = .IgnoreLongWords
    subpixelRenderingSuppressed = false
    selectionModel = SelectionModel()
    directionalityMode = .DirectionalityFromText
    shadows = ShadowValues()
    replaceNewlineCharsWithSymbols = false
    cachedBoundsAndOffsetValid = false
    displayOffset = FloatVec2()
    truncateLength = 0
    displayRunList = TextRunList()
    layoutRunList = TextRunList()
    updateLayoutRunList = false
    updateDisplayRunList = false
    updateGraphemeIterator = false
    updateDisplayText = false
    totalSize = FloatSize() 
    graphemeIterator = BreakIterator()
    savedColors = BreakList<Color>()
    weights = BreakList<Font.Weight>()
    savedUnderlines = BreakList<Bool>()
    compositionAndSelectionStylesApplied = false
    obscuredRevealIndex = 0
    cursorBounds = FloatRect()
    layoutText = String()
    textElided = false
    hasDirectedSelection = RenderText.selectionIsAlwaysDirected
    lines = []
    textDirection = .Unknown
    _lineBreaks = BreakList<Int>()
    _compositionRange = TextRange()
    _updateDisplayText = false
    _displayText = String()
    _text = String()
    _baseline = 0

    //styles = [FontStyle : BreakList<Bool>]()
    styles = []
    // fill in styles
    // TODO: do it statically?
    for style in FontStyle.All {
      styles.insert(BreakList<Bool>(), at: style.position)  
    }

    colors = BreakList<Color>()
    baselines = BreakList<BaselineStyle>()
  }
  
  public func setDisplayOffset(horizontalOffset: Float) {
    let extraContent = contentWidthf - displayRect.width
    let cursorWidth: Float = cursorEnabled ? 1.0 : 0.0

    var offset = horizontalOffset

    var minOffset: Float = 0.0
    var maxOffset: Float = 0.0
    if extraContent > 0 {
      switch currentHorizontalAlignment {
        case .AlignLeft:
          minOffset = -extraContent
        case .AlignRight:
          maxOffset = extraContent
        case .AlignCenter:
          // The extra space reserved for cursor at the end of the text is ignored
          // when centering text. So, to calculate the valid range for offset, we
          // exclude that extra space, calculate the range, and add it back to the
          // range (if cursor is enabled).
          minOffset = -(extraContent - cursorWidth + 1) / 2 - cursorWidth
          maxOffset = (extraContent - cursorWidth) / 2
        default:
         break
      }
    }
    if offset < minOffset {
      offset = minOffset
    } else if offset > maxOffset {
      offset = maxOffset
    }

    cachedBoundsAndOffsetValid = true
    displayOffset.x = offset
    cursorBounds = getCursorBounds(caret: selectionModel, insertMode: insertMode)
  }

  public func getLineOffset(line: Int) -> FloatVec2 {
    var lineOffset = displayRect.offsetFromOrigin
    // TODO(ckocagil): Apply the display offset for multiline scrolling.
    if !multiline {
      lineOffset += updatedDisplayOffset
    } else {
      lineOffset += FloatVec2(x: 0.0, y: lines[line].precedingHeights)
    }
    lineOffset += getAlignmentOffset(line: line)

    return lineOffset
  }

  public func appendText(text: String) {
    _text += text
    updateStyleLengths()
    cachedBoundsAndOffsetValid = false
    obscuredRevealIndex = -1
    onTextAttributeChanged()
  }

  // TODO: deprecate this in favor of the method that follows
  //@deprecate
  public func moveCursor(breakType: BreakType,
                         direction: VisualCursorDirection,
                         select: Bool) {
    var cursor = SelectionModel(pos: cursorPosition, affinity: selectionModel.caretAffinity)
    // Cancelling a selection moves to the edge of the selection.
    if breakType != .Line && !selection.isEmpty && !select {
      let selectionStart = selectionModelForSelectionStart
      let startX = getCursorBounds(caret: selectionStart, insertMode: true).x
      let cursorX = getCursorBounds(caret: cursor, insertMode: true).x
      // Use the selection start if it is left (when |direction| is .CursorLeft)
      // or right (when |direction| is .CursorRight) of the selection end.
      if direction == .Right ? startX > cursorX : startX < cursorX {
        cursor = selectionStart
      }
      
      // Use the nearest word boundary in the proper |direction| for word breaks.
      if breakType == .Word {
        cursor = getAdjacentSelectionModel(current: cursor, breakType: breakType, direction: direction)
      }
      
      // Use an adjacent selection model if the cursor is not at a valid position.
      if !isValidCursorIndex(index: cursor.caretPos) {
        cursor = getAdjacentSelectionModel(current: cursor, breakType: .Char, direction: direction)
      }
    } else {
      cursor = getAdjacentSelectionModel(current: cursor, breakType: breakType, direction: direction)
    }

    if select {
      cursor.selection.start = selection.start
    }
    
    let _ = moveCursorTo(model: cursor)
  }

  public func moveCursor(breakType: BreakType,
                         direction: VisualCursorDirection,                     
                         behavior: SelectionBehavior) {
    var cursor = SelectionModel(pos: cursorPosition, affinity: selectionModel.caretAffinity)
    // Ensure |cursor| is at the "end" of the current selection, since this
    // determines which side should grow or shrink. If the prior change to the
    // selection wasn't from cursor movement, the selection may be undirected. Or,
    // the selection may be collapsing. In these cases, pick the "end" using
    // |direction| (e.g. the arrow key) rather than the current selection range.
    if (!self.hasDirectedSelection || behavior == .SelectionNone) && !selection.isEmpty {
      let selectionStart = selectionModelForSelectionStart
      let startX = getCursorBounds(caret: selectionStart, insertMode: true).x
      let endX = getCursorBounds(caret: cursor, insertMode: true).x      
      // Use the selection start if it is left (when |direction| is CURSOR_LEFT)
      // or right (when |direction| is CURSOR_RIGHT) of the selection end.
      if direction == .Right ? startX > endX : startX < endX {
        // In this case, a direction has been chosen that doesn't match
        // |selection_model|, so the range must be reversed to place the cursor at
        // the other end. Note the affinity won't matter: only the affinity of
        // |start| (which points "in" to the selection) determines the movement.
        let range = selectionModel.selection
        selectionModel = SelectionModel(selection: TextRange(start: range.end, end: range.start),
                                        affinity: selectionModel.caretAffinity)
        cursor = selectionStart
      }
    }
     
    if breakType != .Line && !selection.isEmpty && behavior == .SelectionNone {
      if breakType == .Word {
        cursor = getAdjacentSelectionModel(current: cursor, breakType: breakType, direction: direction)
      }
      // Use an adjacent selection model if the cursor is not at a valid position.
      if !isValidCursorIndex(index: cursor.caretPos) {
        cursor = getAdjacentSelectionModel(current: cursor, breakType: .Char, direction: direction)
      }
    } else {
      cursor = getAdjacentSelectionModel(current: cursor, breakType: breakType, direction: direction)  
    } 
    
    // |cursor| corresponds to the tentative end point of the new selection. The
    // selection direction is reversed iff the current selection is non-empty and
    // the old selection end point and |cursor| are at the opposite ends of the
    // old selection start point.
    let minEnd = min(selection.end, cursor.selection.end)
    let maxEnd = max(selection.end, cursor.selection.end)
    let currentStart = selection.start
    let selectionReversed = !selection.isEmpty &&
                            minEnd <= currentStart &&
                            currentStart <= maxEnd
    // Take |selection_behavior| into account.
    switch behavior {
      case .SelectionRetain:
        cursor.selection.start = currentStart
      case .SelectionExtend:
        cursor.selection.start = selectionReversed ? selection.end
                                                   : currentStart
      case .SelectionCaret:
        if selectionReversed {
          cursor = SelectionModel(pos: currentStart, affinity: selectionModel.caretAffinity)
        } else {
          cursor.selection.start = currentStart
        }
      case .SelectionNone:
        // Do nothing.
        break
    }

    selectionModel = cursor    
    hasDirectedSelection = true
  }

  public func moveCursorTo(model: SelectionModel) -> Bool {
    let textLength = _text.utf16.count

    let range = TextRange(start: min(model.selection.start, textLength), end: min(model.caretPos, textLength))
    // The current model only supports caret positions at valid cursor indices.
    if !isValidCursorIndex(index: range.start) || !isValidCursorIndex(index: range.end) {
      return false
    }

    let sel = SelectionModel(selection: range, affinity: model.caretAffinity)
    let changed = sel != selectionModel
    selectionModel = sel
    return changed
  }

  public func moveCursorTo(point: FloatPoint, select: Bool) -> Bool {
    let model = findCursorPosition(point: point)
    
    if select {
      model.selection.start = selection.start
    }

    return moveCursorTo(model: model)//setSelection(model: model)
  }

  public func moveCursorTo(position: Int, sel: Bool) {
    let cursor = min(position, _text.utf16.count)
   
    if isValidCursorIndex(index: cursor) {
      selectionModel = SelectionModel(
          selection: TextRange(start: (sel == true) ? selection.start : cursor, end: cursor),
          affinity: (cursor == 0) ? .Forward : .Backward)
    }
  }

  public func selectRange(range: TextRange) -> Bool {
    let sel = TextRange(start: min(range.start, _text.utf16.count), end: min(range.end, _text.utf16.count))
    // Allow selection bounds at valid indicies amid multi-character graphemes.
    if !isValidLogicalIndex(index: sel.start) || !isValidLogicalIndex(index: sel.end) {
      return false
    }
    
    let affinity: LogicalCursorDirection = (sel.isReversed || sel.isEmpty) ? .Forward : .Backward
    
    selectionModel = SelectionModel(selection: sel, affinity: affinity)
    return true
  }

  public func isPointInSelection(point: FloatPoint) -> Bool {
    if selection.isEmpty {
      return false
    }
    
    let cursor: SelectionModel = findCursorPosition(point: point)
    return rangeContainsCaret(range: selection, pos: cursor.caretPos, affinity: cursor.caretAffinity)
  }

  public func clearSelection() {
    selectionModel = SelectionModel(pos: cursorPosition, affinity: selectionModel.caretAffinity)
  }

  public func selectAll(reversed: Bool) {
    let length = _text.utf16.count
    let all = reversed ? TextRange(start: length, end: 0) : TextRange(start: 0, end: length)
    let _ = selectRange(range: all)
    //assert(success)
  }

  public func selectWord() {
    if obscured {
      selectAll(reversed: false)
      return
    }

    var selectionMax = selection.maximum

    let iter = BreakIterator(str: _text, type: .Word)
    let success = iter.initialize()
    //assert(success)
    if !success {
      return
    }

    var selectionMin = selection.minimum
    if selectionMin == _text.utf16.count && selectionMin != 0 {
      selectionMin = selectionMin - 1 
    }

    while selectionMin != 0 {
      if iter.isStartOfWord(pos: selectionMin) || iter.isEndOfWord(pos: selectionMin) {
        break
      }
     selectionMin = selectionMin - 1 
    }

    if selectionMin == selectionMax && selectionMax != _text.utf16.count {
      selectionMax = selectionMax + 1
    }

    for selectionMax in selectionMax..._text.utf16.count {
      if iter.isEndOfWord(pos: selectionMax) || iter.isStartOfWord(pos: selectionMax) {
        break
      }
    }

    let reversed = selection.isReversed
    moveCursorTo(position: reversed ? selectionMax : selectionMin, sel: false)
    moveCursorTo(position: reversed ? selectionMin : selectionMax, sel: true)
  }

  public func setColor(color: Color) {
    colors.set(value: color)
    onTextColorChanged()
  }

  public func applyColor(color: Color, range: TextRange) {
    colors.apply(value: color, range: range)
    onTextColorChanged()
  }

  public func setBaselineStyle(value: BaselineStyle) {
    baselines.set(value: value)
  }

  public func applyBaselineStyle(value: BaselineStyle, range: TextRange) {
    baselines.apply(value: value, range: range)
  }

  public func getStyle(style: FontStyle) -> Bool {
    return styles[style.position].breaks.count == 1 && styles[style.position].breaks.first!.value
  }

  public func setStyle(style: FontStyle, value: Bool) {
    styles[style.position].set(value: value)

    cachedBoundsAndOffsetValid = false
    // TODO(oshima|msw): Not all style change requires layout changes.
    // Consider optimizing based on the type of change.
    onLayoutTextAttributeChanged(textChanged: false)
  }

  public func applyStyle(style: FontStyle, value: Bool, range: TextRange) {
    let start = isValidCursorIndex(index: range.start) ? range.start : indexOfAdjacentGrapheme(index: range.start, direction: .Backward)
    let end = isValidCursorIndex(index: range.end) ? range.end : indexOfAdjacentGrapheme(index: range.end, direction: .Forward)
    
    styles[style.position].apply(value: value, range: TextRange(start: start, end: end))

    cachedBoundsAndOffsetValid = false
    // TODO(oshima|msw): Not all style change requires layout changes.
    // Consider optimizing based on the type of change.
    onLayoutTextAttributeChanged(textChanged: false)
  }

  public func getGlyphBounds(index: Int) -> TextRangef {
    ensureLayout()
    
    let runIndex = getRunContainingCaret(caret: SelectionModel(pos: index, affinity: .Forward))
  
    // Return edge bounds if the index is invalid or beyond the layout text size.
    if runIndex >= runList.runs.count {
      return TextRangef(pos: stringSizef.width)
    }
    
    let layoutIndex = textIndexToDisplayIndex(index: index)
    let run = runList.runs[runIndex]
    
    var bounds = run.getGraphemeBounds(iterator: graphemeIterator!, index: layoutIndex)
    // If cursor is enabled, extend the last glyph up to the rightmost cursor
    // position since clients expect them to be contiguous.
    
    if cursorEnabled && runIndex == runList.runs.count - 1 && index == Int(run.isRtl ? run.range.start : run.range.end - 1) {
      bounds.end = ceil(bounds.end)
    }
    
    return run.isRtl ? TextRangef(start: bounds.end, end: bounds.start) : bounds
  }
  
  public func draw(canvas: Canvas) {
    //print("RenderText.draw()")
    ensureLayout()

    if clipToDisplayRect {
      var clipRect = displayRect
      clipRect.inset(insets: ShadowValue.getMargin(shadows: shadows))

      let _ = canvas.save()
      canvas.clipRect(rect: clipRect)
    }

    if !_text.isEmpty && focused {
      drawSelection(canvas: canvas)
    }

    if cursorEnabled && cursorVisible && focused {
      drawCursor(canvas: canvas, position: selectionModel)
    }

    if !_text.isEmpty {
      let renderer = TextRenderer(canvas: canvas)
      drawVisualText(renderer: renderer)
    }

    if clipToDisplayRect {
      canvas.restore()
    }
  }

  public func setWeight(_ value: Font.Weight) {
    weights.set(value: value)
    cachedBoundsAndOffsetValid = false
    onLayoutTextAttributeChanged(textChanged: false)
  }

  public func drawCursor(canvas: Canvas, position: SelectionModel) {
    canvas.fillRect(rect: getCursorBounds(caret: position, insertMode: true), color: cursorColor)
  }

  public func findCursorPosition(point: FloatPoint) -> SelectionModel {
    ensureLayout()

    let x = toTextPoint(point: point).x
    var offset: Float = 0.0
    let runIndex = getRunContainingXCoord(x: x, offset: &offset)

    if runIndex >= runList.runs.count {
      return edgeSelectionModel(direction: (x < 0) ? .Left : .Right)
    }
  
    let run = runList.runs[runIndex]
    for i in 0..<run.glyphCount {
    //for i in 0...run.glyphCount {
      let end: Float = i + 1 == run.glyphCount ? run.width : Float(run.positions[i + 1].x)
      let pos = run.positions[i]
      let middle = (end + Float(pos.x)) / 2

      if offset < middle {
        let dir: LogicalCursorDirection = run.isRtl ? .Backward : .Forward
        let i = run.isRtl ? 1 : 0
        let char = Int(run.glyphToChar[i])
        return SelectionModel(
          pos: displayIndexToTextIndex(index: char + i),
          affinity: dir)
      }
      if offset < end {
        let dir: LogicalCursorDirection = run.isRtl ? .Forward : .Backward
        let i = run.isRtl ? 0 : 1
        let char = Int(run.glyphToChar[i])
        return SelectionModel(
            pos: displayIndexToTextIndex(index: char + i),
            affinity: dir)
      }
    }
    return edgeSelectionModel(direction: .Right)
  }

  public func isValidCursorIndex(index: Int) -> Bool {
    if index == 0 || index == _text.utf16.count {
      return true
    }
    
    if !isValidLogicalIndex(index: index) {
      return false
    }
    
    if let iterator = graphemeIterator {
      return iterator.isGraphemeBoundary(pos: index)
    }
    return false
  }

  public func isValidLogicalIndex(index: Int) -> Bool {
    return index == 0 || index == _text.utf16.count ||
      (index < _text.utf16.count &&
       (truncateLength == 0 || index < truncateLength) &&
       isValidCodePointIndex(s: _text, index: index))
  }

  public func getCursorBounds(caret: SelectionModel, insertMode: Bool) -> FloatRect {
    ensureLayout()
    let caretPos = caret.caretPos
    //assert(isValidLogicalIndex(caretPos))
    // In overtype mode, ignore the affinity and always indicate that we will
    // overtype the next character.
    let caretAffinity: LogicalCursorDirection = insertMode ? caret.caretAffinity : .Forward
    
    var x: Float = 0.0
    var width: Float = 1.0
    let size = stringSizef
    if caretPos == (caretAffinity == .Backward ? 0 : _text.utf16.count) {
      // The caret is attached to the boundary. Always return a 1-dip width caret,
      // since there is nothing to overtype.
      if (displayTextDirection == .RightToLeft) == (caretPos == 0) {
        x = size.width
      }
    } else {
      let graphemeStart = (caretAffinity == .Forward) ? caretPos : indexOfAdjacentGrapheme(index: caretPos, direction: .Backward)
      let xspan = getGlyphBounds(index: graphemeStart)
      if insertMode {
        x = (caretAffinity == .Backward) ? xspan.end : xspan.start
      } else {  // overtype mode
        x = xspan.minimum
        width = xspan.length
      }
    }
    return FloatRect(origin: toViewPoint(point: FloatPoint(x: x, y: 0)), size: FloatSize(width: width, height: size.height))
  }

  public func indexOfAdjacentGrapheme(index: Int, direction: LogicalCursorDirection) -> Int {
    var i = index
    if i > _text.utf16.count {
      return _text.utf16.count
    }

    ensureLayout()

    if direction == .Forward {
      while i < _text.utf16.count {
        i += i
        if isValidCursorIndex(index: i) {
          return i
        }
      }
      return _text.utf16.count
    }

    while i > 0 {
      i -= i
      if isValidCursorIndex(index: i) {
        return i
      }
    }
    return 0
  }

  func getAdjacentSelectionModel(current: SelectionModel,
                                 breakType: BreakType,
                                 direction: VisualCursorDirection) -> SelectionModel {
    ensureLayout()

    if breakType == .Line || _text.isEmpty {
      return edgeSelectionModel(direction: direction)
    }
    if breakType == .Char {
      return adjacentCharSelectionModel(selection: current, direction: direction)
    }
    //assert(breakType == .WordBreak)
    
    return adjacentWordSelectionModel(selection: current, direction: direction)
  }

  func adjacentCharSelectionModel(selection: SelectionModel, 
                                  direction: VisualCursorDirection) -> SelectionModel {
    //assert(!updateDisplayRunList)

    var run = TextRun()

    let runIndex = getRunContainingCaret(caret: selection)
    if runIndex >= runList.runs.count {
      // The cursor is not in any run: we're at the visual and logical edge.
      let edge = edgeSelectionModel(direction: direction)
      if edge.caretPos == selection.caretPos {
        return edge
      }
      let visualIndex = (direction == .Right) ? 0 : runList.runs.count - 1
      run = runList.runs[Int(runList.visualToLogical[visualIndex])]
    } else {
      // If the cursor is moving within the current run, just move it by one
      // grapheme in the appropriate direction.
      run = runList.runs[runIndex]
      var caret = selection.caretPos
      let forwardMotion = run.isRtl == (direction == .Left)
      if forwardMotion {
        if caret < displayIndexToTextIndex(index: run.range.end) {
          caret = indexOfAdjacentGrapheme(index: caret, direction: .Forward)
          return SelectionModel(pos: caret, affinity: .Backward)
        }
      } else {
        if caret > displayIndexToTextIndex(index: run.range.start) {
          caret = indexOfAdjacentGrapheme(index: caret, direction: .Backward)
          return SelectionModel(pos: caret, affinity: .Forward)
        }
      }
      // The cursor is at the edge of a run move to the visually adjacent run.
      var visualIndex = Int(runList.logicalToVisual[runIndex])
      visualIndex += (direction == .Left) ? -1 : 1
      if visualIndex < 0 || Int(visualIndex) >= runList.runs.count {
        return edgeSelectionModel(direction: direction)
      }
      run = runList.runs[Int(runList.visualToLogical[visualIndex])]
    }
    let forwardMotion = run.isRtl == (direction == .Left)
    return forwardMotion ? firstSelectionModelInsideRun(run) : lastSelectionModelInsideRun(run)
  }

  func adjacentWordSelectionModel(selection: SelectionModel, 
                                  direction: VisualCursorDirection) -> SelectionModel {
    if obscured {
      return edgeSelectionModel(direction: direction)
    }

    let iter = BreakIterator(str: _text, type: .Word)
    let success = iter.initialize()
    //assert(success)
    if !success {
      return selection
    }

    // Match OS specific word break behavior.
#if os(Windows)      
    let pos = 0
    if direction == .CursorRight {
      pos = min(selection.caretPos + 1, _text.utf16.count)
      while iter.advance() {
        pos = iter.pos
        if iter.isWord && pos > selection.caretPos {
          break
        }
      }
    } else {  // direction == .CursorLeft
      // Notes: We always iterate words from the beginning.
      // This is probably fast enough for our usage, but we may
      // want to modify WordIterator so that it can start from the
      // middle of string and advance backwards.
      pos = max(selection.caretPos - 1, 0)
      while iter.advance() {
        if iter.isWord {
          let begin = iter.pos - iter.string.utf16.count
          if begin == selection.caretPos {
            // The cursor is at the beginning of a word.
            // Move to previous word.
            break
          } else if iter.pos >= selection.caretPos {
            // The cursor is in the middle or at the end of a word.
            // Move to the top of current word.
            pos = begin
            break
          }
          pos = iter.pos - iter.string.utf16.count
        }
      }
    }
    return SelectionModel(pos, .Forward)
#else
    var cur = selection
    while true {
      cur = adjacentCharSelectionModel(selection: cur,  direction: direction)
      let run = getRunContainingCaret(caret: cur)
      if run == runList.runs.count {
        break
      }
      let isForward = runList.runs[run].isRtl == (direction == .Left)
      let cursor = cur.caretPos
      if isForward ? iter.isEndOfWord(pos: cursor) : iter.isStartOfWord(pos: cursor) {
        break
      }
    }
    return cur
#endif
  }

  func edgeSelectionModel(direction: VisualCursorDirection) -> SelectionModel {
    if direction == visualDirectionOfLogicalEnd {
      return SelectionModel(pos: _text.utf16.count, affinity: .Forward)
    }
    return SelectionModel(pos: 0, affinity: .Backward)
  }

  func getSubstringBounds(range: TextRange) -> [FloatRect] {
    //assert(!updateDisplayRunList)
    //assert(TextRange(0, text.utf16.count).contains(range))
    let layoutRange = TextRange(start: textIndexToDisplayIndex(index: range.start), end: textIndexToDisplayIndex(index: range.end))
    //assert(TextRange(0, displayText.utf16.count).contains(layoutRange))

    var rects: [FloatRect] = [] 
    if layoutRange.isEmpty {
      return rects
    }
    var bounds: [TextRange] = []

    // Add a TextRange for each run/selection intersection.
    //for i in 0...runList.runs.count {
    for i in 0..<runList.runs.count {
      let run = runList.runs[Int(runList.visualToLogical[i])]
      let intersection = run.range.intersect(range: layoutRange)
      if !intersection.isValid {
        continue
      }
      
      //assert(!intersection.isReversed)
      let leftIndex = run.isRtl ? intersection.end - 1 : intersection.start
      let leftmostCharacterX = run.getGraphemeBounds(iterator: graphemeIterator!, index: leftIndex).rounded
      let rightIndex = run.isRtl ? intersection.start : intersection.end - 1
      let rightmostCharacterX = run.getGraphemeBounds(iterator: graphemeIterator!, index: rightIndex).rounded
      var rangeX = TextRange(start: leftmostCharacterX.start, end: rightmostCharacterX.end)
      //assert(!rangeX.isReversed)
      
      if rangeX.isEmpty {
        continue
      }

      // Union this with the last range if they're adjacent.
      //assert(bounds.isEmpty || bounds.last.max <= rangeX.min)
      if !bounds.isEmpty && bounds.last!.maximum == rangeX.minimum {
        rangeX = TextRange(start: bounds.last!.minimum, end: rangeX.maximum)
        bounds.removeLast()
      }
      bounds.append(rangeX)
    }
    for bound in bounds {
      let currentRects: [FloatRect] = textBoundsToViewBounds(x: bound)
      rects.append(contentsOf: currentRects)
    }
    return rects
  }

  func textIndexToDisplayIndex(index: Int) -> Int {
    return textIndexToGivenTextIndex(givenText: _displayText, index: index)
  }
  
  func displayIndexToTextIndex(index: Int) -> Int {
    if !obscured {
      return index
    }
    
    var mutindex = index
    let textIndex = UTF16OffsetToIndex(s: _text, base: 0, offset: &mutindex)
    //assert(textIndex =< _text.utf16.count)
    return textIndex
  }

  func onLayoutTextAttributeChanged(textChanged: Bool) {
    updateLayoutRunList = true
    onDisplayTextAttributeChanged()
  }

  func onDisplayTextAttributeChanged() {
    _updateDisplayText = true
    updateGraphemeIterator = true
  }

  // not implemented
  func onTextColorChanged() {}

  func ensureLayout() {
    ensureLayoutRunList()

    if updateDisplayRunList {
      //assert(textElided)
      displayRunList = TextRunList()

      if !_displayText.isEmpty {
        //TRACE_EVENT0("ui", "RenderTextHarfBuzz:EnsureLayout1")

        itemizeTextToRuns(text: _displayText, list: &displayRunList!)

        // TODO(ckocagil): Remove ScopedTracker below once crbug.com/441028 is
        // fixed.
        //tracked_objects::ScopedTracker tracking_profile(
        //  FROM_HERE_WITH_EXPLICIT_FUNCTION("441028 ShapeRunList() 1"))
        shapeRunList(text: _displayText, list: &displayRunList!)
      }
      updateDisplayRunList = false

      lines = [Line]()
    }

    if lines.isEmpty {
      // TODO(ckocagil): Remove ScopedTracker below once crbug.com/441028 is
      // fixed.
      //scoped_ptr<tracked_objects::ScopedTracker> tracking_profile(
       // new tracked_objects::ScopedTracker(
      //      FROM_HERE_WITH_EXPLICIT_FUNCTION("441028 HarfBuzzLineBreaker")))

      let lineBreaker = TextLineBreaker(
        maxWidth: Float(displayRect.width),
        minBaseline: fontList.baseline, 
        minHeight: Float(max(fontList.height, minLineHeight)),
        behavior: wordWrapBehavior, 
        text: _displayText,
        words: multiline ? lineBreaks : nil, 
        list: runList)

      //tracking_profile.reset()

      if multiline {
        lineBreaker.constructMultiLines()
      } else {
        lineBreaker.constructSingleLine()
      }
      var newLines: [Line] = []
      lineBreaker.finalizeLines(&newLines, size: &totalSize)
      lines = newLines
    }
  }

  func drawVisualText(renderer: TextRenderer) {
    //assert(!update_layout_run_list_)
    //assert(!update_display_run_list_)
    //assert(!_updateDisplayText)
    
    if lines.isEmpty {
      return
    }

    applyFadeEffects(renderer: renderer)
    applyTextShadows(renderer: renderer)
    applyCompositionAndSelectionStyles()

    for (i, line) in lines.enumerated() {
      
      let origin: FloatVec2 = getLineOffset(line: i) + FloatVec2(x: 0.0, y: Float(line.baseline))
      var precedingSegmentWidths: Float = 0.0

      //print("line.segments: \(line.segments.count)")
      //print("runList.runs: \(runList.runs.count)")
      for segment in line.segments {
        let run = runList.runs[segment.run]
        renderer.typeface = run.typeface // originally was run.typeface
        renderer.textSize = run.fontSize
        renderer.setFontRenderParams(params: run.renderParams, subpixelRenderingSuppressed: subpixelRenderingSuppressed)
        let glyphsRange = run.charRangeToGlyphRange(range: segment.charRange)
        var positions: [FloatPoint] = []
        //print("\n\n** here this program will break **\n\nrun.positions[].count = \(run.positions.count) glyphsRange.minimum = \(glyphsRange.minimum) segment.charRange -> start:\(segment.charRange.start) end:\(segment.charRange.end)")
        let offsetX = precedingSegmentWidths - (glyphsRange.minimum != 0 ? run.positions[glyphsRange.minimum].x : 0)
        //print("ok.. we passed the error")
        for j in 0..<glyphsRange.length {
          let posOffset = (glyphsRange.isReversed) ? (glyphsRange.start - j) : (glyphsRange.start + j)
          
          var position = run.positions[posOffset] 
          ////print("position.x: \(position.x) position.y: \(position.y)")
          position.offset(x: origin.x + offsetX,
                          y: origin.y + Float(run.baselineOffset))
          
          positions.insert(position, at: j)                    
        }

        let colorRange = colors[segment.charRange.start]
        var current = colorRange.startIndex
        for (_, color) in colorRange {
          let intersection = colors.range(at: current).intersect(range: segment.charRange)
          let coloredGlyphs = run.charRangeToGlyphRange(range: intersection)
          // The range may be empty if a portion of a multi-character grapheme is
          // selected, yielding two colors for a single glyph. For now, this just
          // paints the glyph with a single style, but it should paint it twice,
          // clipped according to selection bounds. See http://crbug.com/366786
          if coloredGlyphs.isEmpty {
            continue
          }

          renderer.foreground = color
          
          // TODO fix: we need to check of the colored glyphs end also match
          let glyphs = coloredGlyphs.start == 0 ? run.glyphs : ContiguousArray<UInt16>(run.glyphs.prefix(coloredGlyphs.start))//Array<UInt16>(run.glyphs.prefix(coloredGlyphs.start))//String(describing: )          
          let glyphStart = coloredGlyphs.start - glyphsRange.start
          let glyphOffsets = glyphStart == 0 ? positions : Array<FloatPoint>(positions.prefix(positions.count - glyphStart)) 
          
          renderer.drawText(pos: glyphOffsets, glyphs: glyphs, len: coloredGlyphs.length)
          
          let startX = Int(positions[coloredGlyphs.start - glyphsRange.start].x)
          
          let endX = (coloredGlyphs.end == glyphsRange.end)
                ? Int(segment.width + precedingSegmentWidths + origin.x)
                : Int(positions[coloredGlyphs.end - glyphsRange.start].x)
          
          renderer.drawDecorations(x: startX, y: Int(origin.y), width: endX - startX,
                                   underline: run.underline, strike: run.strike,
                                   diagonalStrike: run.diagonalStrike)
          current += 1
        }
        precedingSegmentWidths += segment.width
      }
    }

    renderer.endDiagonalStrike()
    undoCompositionAndSelectionStyles()
  }

  func ensureLayoutRunList() {
  
    if updateLayoutRunList {
      layoutRunList.reset()

      if !layoutText.isEmpty {
        itemizeTextToRuns(text: layoutText, list: &layoutRunList)
        shapeRunList(text: layoutText, list: &layoutRunList)
      }

      let emptyLines: [Line] = []
      lines = emptyLines
      displayRunList = nil
      _updateDisplayText = true
      updateLayoutRunList = false
    }
    if _updateDisplayText {
      updateDisplayText(textWidth: multiline ? 0 : layoutRunList.width)
      _updateDisplayText = false
      updateDisplayRunList = textElided
    }
  
  }

  func updateDisplayText(textWidth: Float) {
    if multiline ||
        elideBehavior == .NoElide ||
        elideBehavior == .FadeTail ||
        textWidth < displayRect.width ||
        layoutText.isEmpty {
      textElided = false
      _displayText.removeAll()
      return
    }

    // This doesn't trim styles so ellipsis may get rendered as a different
    // style than the preceding text. See crbug.com/327850.
     _displayText = elide(text: layoutText,
                             width: textWidth,
                             availableWidth: Float(displayRect.width),
                             behavior: elideBehavior)

    textElided = _displayText != layoutText
    if !textElided {
      _displayText.removeAll()
    }
  }

  func applyCompositionAndSelectionStyles() {
    //assert(!compositionAndSelectionStylesApplied)
    savedColors = colors
    savedUnderlines = styles[FontStyle.Underline.position]

    // Apply an underline to the composition range in |underlines|.
    if compositionRange.isValid && !compositionRange.isEmpty {
      styles[FontStyle.Underline.position].apply(value: true, range: compositionRange)
    }

    // Apply the selected text color to the [un-reversed] selection range.
    if !selection.isEmpty && focused {
      let range = TextRange(start: selection.minimum, end: selection.maximum)
      colors.apply(value: selectionColor, range: range)
    }
    compositionAndSelectionStylesApplied = true
  }
  
  func undoCompositionAndSelectionStyles() {
    //assert(compositionAndSelectionStylesApplied)
    colors = savedColors
    styles.insert(savedUnderlines, at: FontStyle.Underline.position)
    compositionAndSelectionStylesApplied = false
  }

  func toTextPoint(point: FloatPoint) -> FloatPoint {
    return point - getLineOffset(line: 0)
  }
  
  func toViewPoint(point: FloatPoint) -> FloatPoint {
    
    if !multiline {
      return point + getLineOffset(line: 0)
    }

    // TODO(ckocagil): Traverse individual line segments for RTL support.
    //assert(!lines.isEmpty)
    var x = point.x
    var offset = 0
    for line in lines where x > line.size.width {
      x -= line.size.width
      offset += offset
    }
    return FloatPoint(x: x, y: point.y) + getLineOffset(line: offset)
  }

  func textBoundsToViewBounds(x: TextRange) -> [FloatRect] {
    var rects = [FloatRect]() 

    if !multiline {
      rects.append(
          FloatRect(origin: toViewPoint(point: FloatPoint(x: Float(x.minimum), y: 0)),
               size: FloatSize(width: Float(x.length), height: Float(stringSize.height))))
      return rects
    }

    ensureLayout()

    // Each line segment keeps its position in text coordinates. Traverse all line
    // segments and if the segment intersects with the given range, add the view
    // rect corresponding to the intersection to |rects|.
    for line in lines {
      var linex:Float = 0.0
      let offset = getLineOffset(line: Int(linex))
      for segment in line.segments {
        let intersection = segment.xRange.intersect(range: x)
        if !intersection.isEmpty {
          let rect = FloatRect(x: linex + intersection.start - segment.xRange.start,
                  y: 0, width: intersection.length, height: line.size.height)
          rects.append(rect + offset)
        }
        linex += segment.xRange.length
      }
    }

    return rects
  }

  func getAlignmentOffset(line: Int) -> FloatVec2 {
    if multilineSupported && multiline {
      assert(line < lines.count)
    }
  
    var offset = FloatVec2()

    let horizontalAlignment = currentHorizontalAlignment
    if horizontalAlignment != .AlignLeft {
      let width = multiline ? lines[line].size.width + (cursorEnabled ? 1 : 0) : contentWidthf
      offset.x = displayRect.width - width
      // Put any extra margin pixel on the left to match legacy behavior.
      if horizontalAlignment == .AlignCenter {
        offset.x = (offset.x + 1) / 2
      }
    }

    // Vertically center the text.
    if multiline {
      let textHeight = lines.last!.precedingHeights + lines.last!.size.height
      offset.y = (displayRect.height - textHeight) / 2
    } else {
      offset.y = Float(baseline - displayTextBaseline)
    }

    return offset
  }

  func applyFadeEffects(renderer: TextRenderer) {
    let width = displayRect.width
    
    if multiline || elideBehavior != .FadeTail || contentWidthf <= width {
      return
    }

    let gradientWidth = calculateFadeGradientWidth(list: fontList, width: width)
    
    if gradientWidth == 0 {
      return
    }

    let horizontalAlignment = currentHorizontalAlignment
    var solidPart = displayRect
    var leftPart = FloatRect()
    var rightPart = FloatRect()
    
    if horizontalAlignment != .AlignLeft {
      leftPart = solidPart
      leftPart.inset(left: 0, top: 0, right: solidPart.width - gradientWidth, bottom: 0)
      solidPart.inset(left: gradientWidth, top: 0, right: 0, bottom: 0)
    }

    if horizontalAlignment != .AlignRight {
      rightPart = solidPart
      rightPart.inset(left: solidPart.width - gradientWidth, top: 0, right: 0, bottom: 0)
      solidPart.inset(left: 0, top: 0, right: gradientWidth, bottom: 0)
    }

    var textRect = displayRect
    textRect.inset(left: getAlignmentOffset(line: 0).x, top: 0, right: 0,  bottom: 0)

    // TODO(msw): Use the actual text colors corresponding to each faded part.
    let shader = createFadeShader(list: fontList, textRect: textRect, leftPart: leftPart, rightPart: rightPart, color: colors.breaks.first!.value)
    renderer.shader = shader
  }

  func applyTextShadows(renderer: TextRenderer) {
    let looper = DefaultDrawLooperFactory.makeShadow(shadows: shadows)
    renderer.drawLooper = looper
  }

  func getTextDirection(text: String) -> TextDirection {
    if textDirection == .Unknown {
      switch directionalityMode {
        case .DirectionalityFromText:
          textDirection = i18n.getFirstStrongCharacterDirection(text: _text)
        case .DirectionalityFromUI:
          textDirection = i18n.isRTL() ? .RightToLeft : .LeftToRight
        case .DirectionalityForceLTR:
          textDirection = .LeftToRight
        case .DirectionalityForceRTL:
          textDirection = .RightToLeft
        //default:
        //  break
      }
    }
    return textDirection
  }

  func textIndexToGivenTextIndex(givenText: String,
                                 index: Int) -> Int {
    //assert(givenText == layoutText || givenText == _displayText)
    //assert(index <= _text.utf16.count)
    var base = 0
    var mutindex = index
    let i = obscured ? UTF16IndexToOffset(s: _text, base: &base, pos: &mutindex) : index
    //assert(i >= 0)
    // Clamp indices to the length of the given layout or display text.
    return min(givenText.count, i)
  }

  func updateStyleLengths() {
    let textLength = _text.utf16.count
    colors.max = textLength
    baselines.max = textLength
    for style in FontStyle.All {
      styles[style.position].max = textLength
    }
  }

  func onTextAttributeChanged() {
    layoutText.removeAll()
    _displayText.removeAll()
    textElided = false
    _lineBreaks.max = 0

    if obscured {
      let obscuredTextLength = _text.endIndex//UTF16IndexToOffset(_text, 0, _text.utf16.count)
      // TODO: como informar apenas o character?
      let passwdChar = String(describing: PasswordReplacementChar)
      let index = layoutText.index(before: layoutText.endIndex)
      layoutText.replaceSubrange(index..<obscuredTextLength, with: passwdChar)
      //layoutText.replaceSubrange(index...obscuredTextLength, with: passwdChar)

      if obscuredRevealIndex >= 0 && obscuredRevealIndex < _text.utf16.count {
        // Gets the index range in |text_| to be revealed.
        var start = obscuredRevealIndex
        let textUTF16Array = ContiguousArray(_text.utf16)
        textUTF16Array.withUnsafeBufferPointer {
          _ICUU16SetCPStart($0.baseAddress, Int32(0), Int32(start))
        }
        
        let end = start
        textUTF16Array.withUnsafeBufferPointer {
          let _ = _ICUU16Next($0.baseAddress, Int32(end), Int32(_text.utf16.count))
        }
        // Gets the index in |layout_text_| to be replaced.
        var base = 0
        let cpStart = UTF16IndexToOffset(s: _text, base: &base, pos: &start)
        
        if layoutText.utf16.count > cpStart {
          let toTextStart = _text.index(_text.startIndex, offsetBy: start) 
          let toText = _text.substring(with: toTextStart..<_text.index(_text.startIndex, offsetBy: end - start))
          let idx = layoutText.index(layoutText.startIndex, offsetBy: cpStart)
          let endIdx = layoutText.index(layoutText.startIndex, offsetBy: cpStart+1)
          layoutText.replaceSubrange(idx..<endIdx, with: toText)
        }
      }
    } else {
      layoutText = _text
    }

    let txt = layoutText
    if truncateLength > 0 && truncateLength < txt.utf16.count {
      // Truncate the text at a valid character break and append an ellipsis.
      let iter = ICUStringCharacterIterator(text: _text)
      // Respect .ElideHead and .ElideMiddle preferences during truncation.
      if elideBehavior == .ElideHead {
        iter.setIndex32(txt.utf16.count - truncateLength + 1)
        layoutText = String(describing: EllipsisUTF16) + txt.substring(from: txt.index(txt.startIndex, offsetBy: iter.currentIndex))
      } else if elideBehavior == .ElideMiddle {
        iter.setIndex32(truncateLength / 2)
        let ellipsisStart = iter.currentIndex
        iter.setIndex32(txt.utf16.count - (truncateLength / 2))
        let ellipsisEnd = iter.currentIndex
        //assert(ellipsisStart <= ellipsisEnd)
        layoutText = _text.substring(to: _text.index(_text.startIndex, offsetBy: ellipsisStart)) + String(describing: EllipsisUTF16) + _text.substring(from: _text.index(_text.startIndex, offsetBy: ellipsisEnd))
      } else {
        iter.setIndex32(truncateLength - 1)
        layoutText = _text.substring(to: _text.index(_text.startIndex, offsetBy: iter.currentIndex)) + String(describing: EllipsisUTF16)
      }
    }
    //let newlineSymbol: [UInt16] = [ 0x2424, 0 ]
    if !multiline && replaceNewlineCharsWithSymbols {
      // TODO: isso aqui pega apenas uma newline
      if let start = layoutText.index(of: "\n") {
        let end = layoutText.index(after: start)
        // layoutText.replaceSubrange(index, newlineSymbol)
        layoutText.replaceSubrange(start..<end, with: String(0x2424 as UInt16))
      }
      //base.replaceChars(layoutText, newline, newlineSymbol, &layoutText)
    }

    onLayoutTextAttributeChanged(textChanged: true)
  }

  func elide(text: String,
             width: Float,
             availableWidth: Float,
             behavior: ElideBehavior) -> String {
    
    var textWidth = width          

    if availableWidth <= 0 || _text.isEmpty {
      return String()
    }

    if behavior == .ElideEmail {
      return elideEmail(email: _text, width: availableWidth)
    }
    
    if textWidth > 0 && textWidth < availableWidth {
      return _text
    }

    // Create a RenderText copy with attributes that affect the rendering width.
    let renderText = RenderText()
    renderText.fontList = fontList
    renderText.directionalityMode = directionalityMode
    renderText.cursorEnabled = cursorEnabled
    renderText.truncateLength = truncateLength
    renderText.styles = styles
    renderText.baselines = baselines
    renderText.colors = colors
    
    if textWidth == 0 {
      renderText.text = _text
      textWidth = renderText.contentWidthf
    }

    if textWidth <= availableWidth {
      return _text
    }

    let ellipsis = EllipsisUTF16
    let insertEllipsis = (behavior != .Truncate)
    let elideInMiddle = (behavior == .ElideMiddle)
    let elideAtBeginning = (behavior == .ElideHead)

    if insertEllipsis {
      renderText.text = String(describing: ellipsis)
      let ellipsisWidth = renderText.contentWidthf
      if ellipsisWidth > availableWidth {
        return String()
      }
    }

    let slicer = StringSlicer( text: _text, ellipsis: String(describing: ellipsis), elideInMiddle: elideInMiddle, elideAtBeginning: elideAtBeginning)

    // Use binary search to compute the elided text.
    var lo = 0
    var hi = _text.utf16.count - 1
    var guess = (lo + hi) / 2
    
    while lo <= hi {
      // Restore colors. They will be truncated to size by SetText.
      renderText.colors = colors
      var newText = slicer.cutString(length: guess, insertEllipsis: insertEllipsis && behavior != .ElideTail)
      renderText.text = newText

      // This has to be an additional step so that the ellipsis is rendered with
      // same style as trailing part of the text.
      if insertEllipsis && behavior == .ElideTail {
        // When ellipsis follows text whose directionality is not the same as that
        // of the whole text, it will be rendered with the directionality of the
        // whole text. Since we want ellipsis to indicate continuation of the
        // preceding text, we force the directionality of ellipsis to be same as
        // the preceding text using LTR or RTL markers.
        let trailingTextDirection : TextDirection = i18n.getLastStrongCharacterDirection(text: newText)  
        newText.append(String(describing: ellipsis))

        if trailingTextDirection != textDirection {
          if trailingTextDirection == .LeftToRight {
            newText += String(describing: i18n.LeftToRightMark)
          } else {
            newText += String(describing: i18n.RightToLeftMark)
          }
        }
        renderText.text = newText
      }

      // Restore styles and baselines without breaking multi-character graphemes.
      renderText.styles = styles
      for var style in renderText.styles {
        restoreBreakList(renderText: renderText, breakList: &style)
      }
      
      restoreBreakList(renderText: renderText, breakList: &renderText.baselines)

      // We check the width of the whole desired string at once to ensure we
      // reference kerning/ligatures/etc. correctly.
      let guessWidth = renderText.contentWidthf
      if guessWidth == availableWidth {
        break
      }
      if guessWidth > availableWidth {
        hi = guess - 1
        // Move back on the loop terminating condition when the guess is too wide.
        if hi < lo {
          lo = hi
        }
      } else {
        lo = guess + 1
      }

      guess = (lo + hi) / 2
    }

    return renderText.text
  }

  func elideEmail(email: String, width: Float) -> String {
    // The returned string will have at least one character besides the ellipsis
    // on either side of '@' if that's impossible, a single ellipsis is returned.
    // If possible, only the username is elided. Otherwise, the domain is elided
    // in the middle, splitting available width equally with the elided username.
    // If the username is short enough that it doesn't need half the available
    // width, the elided domain will occupy that extra width.

    // Split the email into its local-part (username) and domain-part. The email
    // spec allows for @ symbols in the username under some special requirements,
    // but not in the domain part, so splitting at the last @ symbol is safe.
    let splitIndex = email.utf16.index(of: UTF16EmailAt)!
    //DCHECK_NE(split_index, base::string16::npos)
    var username = String(email.utf16.prefix(upTo: splitIndex))!
    var domain = String(email.utf16.suffix(splitIndex.encodedOffset + 1))!
    //assert(!username.isEmpty)
    //assert(!domain.isEmpty)

    // Subtract the @ symbol from the available width as it is mandatory.
    let atSignUTF16 = "@"
    var availableWidth = width
    availableWidth -= getStringWidth(text: atSignUTF16, list: fontList)

    // Check whether eliding the domain is necessary: if eliding the username
    // is sufficient, the domain will not be elided.
    let fullUsernameWidth = getStringWidth(text: username, list: fontList)
    let index = username.utf16.index(after: username.utf16.startIndex)
    let dom = username.utf16.prefix(upTo: index) + EllipsisUTF16
    let availableDomainWidth: Float = availableWidth -
      min(fullUsernameWidth, getStringWidth(text: String(describing: dom), list: fontList))
    
    if getStringWidth(text: domain, list: fontList) > availableDomainWidth {
      // Elide the domain so that it only takes half of the available width.
      // Should the username not need all the width available in its half, the
      // domain will occupy the leftover width.
      // If |desired_domain_width| is greater than |available_domain_width|: the
      // minimal username elision allowed by the specifications will not fit thus
      // |desired_domain_width| must be <= |available_domain_width| at all cost.
     let desiredDomainWidth: Float =
        min(availableDomainWidth,
            max(availableWidth - fullUsernameWidth, availableWidth / 2))
      domain = elide(text: domain, width: 0, availableWidth: desiredDomainWidth, behavior: .ElideMiddle)
      // Failing to elide the domain such that at least one character remains
      // (other than the ellipsis itself) remains: return a single ellipsis.
      if domain.utf16.count <= 1 {
        return String(describing: EllipsisUTF16)
      }
    }

    // Fit the username in the remaining width (at this point the elided username
    // is guaranteed to fit with at least one character remaining given all the
    // precautions taken earlier).
    availableWidth -= getStringWidth(text: domain, list: fontList)
    username = elide(text: username, width: 0, availableWidth: availableWidth, behavior: .ElideTail)
    return username + atSignUTF16 + domain
  }

  func updateCachedBoundsAndOffset() {
    if cachedBoundsAndOffsetValid {
      return
    }

    // TODO(ckocagil): Add support for scrolling multiline text.
    var deltaX: Float = 0.0

    if cursorEnabled {
      // When cursor is enabled, ensure it is visible. For this, set the valid
      // flag true and calculate the current cursor bounds using the stale
      // |display_offset_|. Then calculate the change in offset needed to move the
      // cursor into the visible area.
      cachedBoundsAndOffsetValid = true
      cursorBounds = getCursorBounds(caret: selectionModel, insertMode: insertMode)

      // TODO(bidi): Show RTL glyphs at the cursor position for ALIGN_LEFT, etc.
      if cursorBounds.right > displayRect.right {
        deltaX = displayRect.right - cursorBounds.right
      } else if cursorBounds.x < displayRect.x {
        deltaX = displayRect.x - cursorBounds.x
      }
    }

    setDisplayOffset(horizontalOffset: displayOffset.x + deltaX)
  }

  func drawSelection(canvas: Canvas) {
    for s in getSubstringBounds(range: selection) {
      canvas.fillRect(rect: s, color: selectionBackgroundFocusedColor)
    }
  }

  func getRunContainingCaret(caret: SelectionModel) -> Int {
    guard !updateDisplayRunList else {
      return 0
    }
    let layoutPosition = textIndexToDisplayIndex(index: caret.caretPos)
    let affinity = caret.caretAffinity
    for (i, run) in runList.runs.enumerated() {
      if rangeContainsCaret(range: run.range, pos: layoutPosition, affinity: affinity) {
        return i
      }
    }
    return runList.runs.count
  }

  func getRunContainingXCoord(x: Float, offset: inout Float) -> Int {
    
    guard !updateDisplayRunList else {
      return 0
    }
    
    if x < 0 {
      return runList.runs.count
    }
    // Find the text run containing the argument point (assumed already offset).
    var currentX: Float = 0
    //for i in 0...runList.runs.count {
    for i in 0..<runList.runs.count {
      let run = Int(runList.visualToLogical[i])
      currentX += runList.runs[run].width
      if x < currentX {
        offset = x - (currentX - runList.runs[run].width)
        return run
      }
    }
    return runList.runs.count
  }

  func rangeContainsCaret(range: TextRange,
                          pos: Int,
                          affinity: LogicalCursorDirection) -> Bool {
    let adjacent = (affinity == .Backward) ? pos - 1 : pos + 1
    return range.contains(range: TextRange(start: pos, end: adjacent))
  }

  func shapeRunList(text: String, list: inout TextRunList) {
    for run in list.runs {
      shapeRun(text: text, run: run)
    }
    list.computePrecedingRunWidths()
  }

  // Using MoveTo(model: ) instead

  // func setSelection(model: SelectionModel) -> Bool {
  //   let textLength = text.utf16.length
  //   let range = TextRange(
  //     min(model.selection.start, textLength),
  //     min(model.caretPos, textLength))
  
  //   // The current model only supports caret positions at valid cursor indices.
  //   if !isValidCursorIndex(range.start) || !isValidCursorIndex(range.end) {
  //     return false
  //   }

  //   let sel = SelectionModel(range, model.caretAffinity)
  //   let changed = sel != selectionModel
  //   selectionModel = sel
  //   return changed
  // }

  func shapeRun(text: String, run: TextRun) {
    
    let primaryFont = fontList.primaryFont
    //let primaryFamily = primaryFont.fontName
    run.fontSize = primaryFont.fontSize
    run.baselineOffset = 0
    
    if run.baselineType != .NormalBaseline {
      // Calculate a slightly smaller font. The ratio here is somewhat arbitrary.
      // Proportions from 5/9 to 5/7 all look pretty good.
      let ratio: Float = 5.0 / 9.0
      run.fontSize = (Float(primaryFont.fontSize) * ratio).roundedInt
      
      switch run.baselineType {
        case .Superscript:
          run.baselineOffset = primaryFont.capHeight - primaryFont.height
        case .Superior:
          run.baselineOffset = (Float(primaryFont.capHeight) * ratio).roundedInt - primaryFont.capHeight
        case .Subscript:
          run.baselineOffset =
              primaryFont.height - primaryFont.baseline
        //case .INFERIOR:  // Fall through.
        default:
          break
      }
    }

    var bestFont = String()
    var bestRenderParams = FontRenderParams()
    var bestMissingGlyphs = UInt.max

    for font in fontList.fonts {
      
      if compareFamily(
          text: text, 
          family: font.fontFamily, 
          renderParams: font.fontRenderParams, 
          run: run, 
          bestFamily: &bestFont, 
          bestRenderParams: &bestRenderParams, 
          bestMissingGlyphs: &bestMissingGlyphs) {
        
        return
      }

    }

#if os(Windows)
    let uniscribeFont = Font()
    var uniscribeFamily = String()
    var runText = text[run.range.start]
    // was: var runText = &text[run.range.start]

    if getUniscribeFallbackFont(primaryFont, runText, run.range.length, &uniscribeFont) {
    
      uniscribeFamily = uniscribeFont.fontName

      if compareFamily(text, uniscribeFont, 
                       uniscribeFont.fontRenderParams, run,
                       &bestFont, &bestRenderParams, &bestMissingGlyphs) {
        return
      }
    }
#endif

    let fallbackFontList: [String] = getFallbackFontFamilies(fontFamily: primaryFont.fontFamily)

#if os(Windows)
    // Append fonts in the fallback list of the Uniscribe font.
    if !uniscribeFamily.isEmpty {
      let uniscribeFallbacks: [String] = getFallbackFontFamilies(fontFamily: uniscribeFont.fontFamily)
      fallbackFontList.append(fallbackFontList.end,
          uniscribeFallbacks.begin, uniscribeFallbacks.end)
    }

    // Add Segoe UI and its associated linked fonts to the fallback font list to
    // ensure that the fallback list covers the basic cases.
    // http://crbug.com/467459. On some Windows configurations the default font
    // could be a raster font like System, which would not give us a reasonable
    // fallback font list.
    if primaryFont.fontName != "segoe ui" && uniscribeFamily != "segoe ui" {
    
      let defaultFallbackFamilies: [String] = getFallbackFontFamilies(fontFamily: "Segoe UI")
    
      fallbackFontList.append(defaultFallbackFamilies)
    }
#endif

    // Use a set to track the fallback fonts and avoid duplicate entries.
    var fallbackFonts: [String] = []

    // Try shaping with the fallback fonts.
    for font in fallbackFontList {

      let fontName = font

      if fontName == primaryFont.fontName {
        continue
      }
#if os(Windows)
      if fontName == uniscribeFamily {
        continue
      }
#endif
      //if fallbackFonts.find(font) != fallbackFonts.end() {
      if fallbackFonts.contains(font) {
        continue
      }

      fallbackFonts.append(font)

      var query = FontRenderParamsQuery()
      query.families.append(fontName)
      query.pixelSize = run.fontSize
      query.style = run.fontStyle

      let fallbackRenderParams: FontRenderParams = getFontRenderParams(query: query)
      
      if compareFamily(text: text, 
                       family: font, 
                       renderParams: fallbackRenderParams, 
                       run: run, 
                       bestFamily: &bestFont,
                       bestRenderParams: &bestRenderParams, 
                       bestMissingGlyphs: &bestMissingGlyphs) {
        return
      }

    }

    if bestMissingGlyphs != UInt.max &&
        (bestFont == run.fontFamily || shapeRunWithFont(text: text, fontFamily: bestFont, params: bestRenderParams, run: run)) {
      return
    }

    run.glyphCount = 0
    run.width = 0.0
  }

  func shapeRunWithFont(text: String,
                        fontFamily: String,
                        params: FontRenderParams,
                        run: TextRun) -> Bool {

    let typeface = Typeface(font: fontFamily, style: run.fontStyle)
    
    run.typeface = typeface
    run.fontFamily = fontFamily
    run.renderParams = params
        
    let font = HarfBuzzFont(
      typeface: run.typeface, 
      textSize: run.fontSize, 
      params: run.renderParams,
      subpixelRenderingSuppressed: subpixelRenderingSuppressed)

    // Create a HarfBuzz buffer and add the string to be shaped. The HarfBuzz
    // buffer holds our text, run information to be used by the shaping engine,
    // and the resulting glyph data.
    let buffer = HarfBuzzBuffer()
    buffer.addUTF16(text: text, start: run.range.start, length: run.range.length)
    let script = HarfBuzzScript.fromICUScript(run.script)
    buffer.setScript(script)
    buffer.setDirection(run.isRtl ? .RTL : .LTR)
    buffer.setDefaultLanguage()
 
    // Shape the text.
    font.shape(buffer: buffer)

    // Populate the run fields with the resulting glyph data in the buffer.
    let infos = buffer.glyphInfos
    run.glyphCount = infos.count
    let positions = buffer.glyphPositions
    run.glyphs.reserveCapacity(run.glyphCount)
    run.glyphToChar.reserveCapacity(run.glyphCount)
    run.positions.reserveCapacity(run.glyphCount)
    run.width = 0.0
    
    for i in 0..<run.glyphCount {
      //DCHECK_LE(infos[i].codepoint, std::numeric_limits<uint16>::max());
      run.glyphs.append(UInt16(infos[i].codepoint))
      run.glyphToChar.append(UInt32(infos[i].cluster))
      let xOffset = Float(positions[i].xOffset)
      let yOffset = Float(positions[i].yOffset)
      run.positions.append(FloatPoint(x: run.width + xOffset, y: -yOffset))
      run.width += fixedToFloat(positions[i].xAdvance)
      
      // Round run widths if subpixel positioning is off to match native behavior.
      if !run.renderParams.subpixelPositioning {
        run.width = floor(run.width + 0.5)
      }
    }

    return true
  }

  func itemizeTextToRuns(text: String, list: inout TextRunList) {
    let bidiIterator = BiDiLineIterator()
    
    if !bidiIterator.open(text: text, direction: getTextDirection(text: text)) {
      let run = TextRun()
      run.range = TextRange(start: 0, end: text.count)
      list.runs.append(run)
      list.initIndexMap()
      return
    }

    // Temporarily apply composition underlines and selection colors.
    applyCompositionAndSelectionStyles()

    // Build the run list from the script items and ranged styles and baselines.
    // Use an empty color BreakList to avoid breaking runs at color boundaries.
    var emptyColors = BreakList<Color>()
    emptyColors.max = text.count
    //DCHECK_LE(text.size(), baselines().max());
    //for (const BreakList<bool>& style : styles())
    //  DCHECK_LE(text.size(), style.max());
    var style = StyleIterator(colors: emptyColors, baselines: baselines, styles: styles)

    var runBreak = 0
    while runBreak < text.count {
      let run = TextRun()
      run.range.start = runBreak
      run.fontStyle = //FontStyle.Normal
        FontStyle(rawValue: (style.style(FontStyle.Bold) ? FontStyle.Bold.rawValue : FontStyle.None.rawValue) |
                    (style.style(FontStyle.Italic) ? FontStyle.Italic.rawValue : FontStyle.None.rawValue))
      run.baselineType = style.baseline
      run.strike = style.style(FontStyle.Strike) // false
      run.diagonalStrike = style.style(FontStyle.DiagonalStrike) // false
      run.underline = style.style(FontStyle.Underline) // false
      var scriptItemBreak = 0
      bidiIterator.getLogicalRun(start: runBreak, end: &scriptItemBreak, level: &run.level)
      // Odd BiDi embedding levels correspond to RTL runs.
      run.isRtl = (run.level % 2) == 1
      // Find the length and script of this script run.
      scriptItemBreak = scriptInterval(text: text, start: runBreak,
          length: scriptItemBreak - runBreak, script: &run.script) + runBreak
      // Find the next break and advance the iterators as needed.
      let newRunBreak = min(scriptItemBreak, textIndexToGivenTextIndex(givenText: text, index: style.range.end))
      
      runBreak = newRunBreak

      // Break runs at certain characters that need to be rendered separately to
      // prevent either an unusual character from forcing a fallback font on the
      // entire run, or brackets from being affected by a fallback font.
      // http://crbug.com/278913, http://crbug.com/396776
      if runBreak > run.range.start {
        runBreak = findRunBreakingCharacter(text: text, runStart: run.range.start, runBreak: runBreak)
      }

      style.updatePosition(pos: displayIndexToTextIndex(index: runBreak))
      run.range.end = runBreak

      list.runs.append(run)
    }

    // Undo the temporarily applied composition underlines and selection colors.
    undoCompositionAndSelectionStyles()

    list.initIndexMap()
  }

  func firstSelectionModelInsideRun(_ run: TextRun) -> SelectionModel {
    var position = displayIndexToTextIndex(index: Int(run.range.start))
    position = indexOfAdjacentGrapheme(index: position, direction: .Forward)
    return SelectionModel(pos: position, affinity: .Backward)
  }

  func lastSelectionModelInsideRun(_ run: TextRun) -> SelectionModel {
    var position = displayIndexToTextIndex(index: Int(run.range.end))
    position = indexOfAdjacentGrapheme(index: position, direction: .Backward)
    return SelectionModel(pos: position, affinity: .Forward)
  }

  func compareFamily(text: String,
                     family: String,
                     renderParams: FontRenderParams,
                     run: TextRun,
                     bestFamily: inout String,
                     bestRenderParams: inout FontRenderParams,
                     bestMissingGlyphs: inout UInt) -> Bool {
  
    if !shapeRunWithFont(text: text, fontFamily: family, params: renderParams, run: run) {
      return false
    }

    let missingGlyphs = UInt(run.countMissingGlyphs)
    
    if missingGlyphs < bestMissingGlyphs {
      bestFamily = family
      bestRenderParams = renderParams
      bestMissingGlyphs = missingGlyphs
    }

    return missingGlyphs == 0
  }

} // RenderText

func calculateFadeGradientWidth(list: FontList, width: Float) -> Float {
  // Fade in/out about 2.5 characters of the beginning/end of the string.
  // The .5 here is helpful if one of the characters is a space.
  // Use a quarter of the display width if the display width is very short.
  let averageCharacterWidth = Float(list.getExpectedTextWidth(1))
  let gradientWidth: Float = min(averageCharacterWidth * 2.5, width / 4.0)
  //DCHECK_GE(gradientWidth, 0.0)
  return floorf(gradientWidth + 0.5)
}

func addFadeEffect(textRect: FloatRect,
                   fadeRect: FloatRect,
                   c0: Color,
                   c1: Color,
                   positions: inout [Float],
                   colors: inout [Color]) {

  let left = fadeRect.x - textRect.x
  let width = fadeRect.width
  let p0 = left / textRect.width
  let p1 = (left + width) / textRect.width
  // Prepend 0.0 to |positions|, as required by Skia.
  if positions.isEmpty && p0 != 0 {
    positions.append(0.0)
    colors.append(c0)
  }
  positions.append(p0)
  colors.append(c0)
  positions.append(p1)
  colors.append(c1)
}

func createFadeShader(list: FontList,
                      textRect: FloatRect,
                      leftPart: FloatRect,
                      rightPart: FloatRect,
                      color: Color) -> PaintShader {
  let widthFraction =
      Float(textRect.width) / Float(list.getExpectedTextWidth(4))
  let alphaAtZeroWidth: Float = 51.0
  let alpha: UInt8 = (widthFraction < 1) ? UInt8(round((1.0 - widthFraction) * alphaAtZeroWidth)) : 0
  
  // Fade alpha of 51/255 corresponds to a fade of 0.2 of the original color.
  var fadeColor = color 
  fadeColor.a = alpha
  
  var positions: [Float] = []
  var colors: [Color] = []

  if !leftPart.isEmpty {
    addFadeEffect(textRect: textRect, fadeRect: leftPart, c0: fadeColor, c1: color,
                  positions: &positions, colors: &colors)
  }
  
  if !rightPart.isEmpty {
    addFadeEffect(textRect: textRect, fadeRect: rightPart, c0: color, c1: fadeColor,
                  positions: &positions, colors: &colors)
  }
  //DCHECK(!positions.isEmpty());

  // Terminate |positions| with 1.0, as required by Skia.
  if positions.last! != 1 {
    positions.append(1.0)
    colors.append(colors.last!)
  }

  let points = [textRect.origin, textRect.topRight]
  
  return PaintShaderFactory.makeLinearGradient(points: points, colors: colors, pos: positions,
                                               count: colors.count, mode: TileMode.Clamp)
}

// Returns the baseline, with which the text best appears vertically centered.
func determineBaselineCenteringText(displayRect: FloatRect,
                                    list: FontList) -> Int {
  let displayHeight = Int(displayRect.height)
  let fontHeight = list.height
  // Lower and upper bound of baseline shift as we try to show as much area of
  // text as possible.  In particular case of |display_height| == |font_height|,
  // we do not want to shift the baseline.
  let minShift = min(0, displayHeight - fontHeight)
  let maxShift = abs(displayHeight - fontHeight)
  let baseline = list.baseline
  let capHeight = list.capHeight
  let internalLeading = baseline - capHeight
  // Some platforms don't support getting the cap height, and simply return
  // the entire font ascent from GetCapHeight().  Centering the ascent makes
  // the font look too low, so if GetCapHeight() returns the ascent, center
  // the entire font height instead.
  let space = displayHeight - ((internalLeading != 0) ? capHeight : fontHeight)
  let baselineShift = space / 2 - internalLeading
  return baseline + max(minShift, min(maxShift, baselineShift))
}

func isValidCodePointIndex(s: String, index: Int) -> Bool {
  return index == 0 || index == s.count ||
    !(_ICUCBU16IsTrail(s.utf16[s.index(s.startIndex, offsetBy: index).samePosition(in: s.utf16)!]) != 0 
    && _ICUCBU16IsLead(s.utf16[s.index(s.startIndex, offsetBy: index - 1).samePosition(in: s.utf16)!]) != 0)
}

public func UTF16IndexToOffset(s: String, base: inout Int, pos: inout Int) -> Int {
  // The indices point between UTF-16 words (range 0 to s.length() inclusive).
  // In order to consistently reference indices that point to the middle of a
  // surrogate pair, we count the first word in that surrogate pair and not
  // the second. The test "s[i] is not the second half of a surrogate pair" is
  // "IsValidCodePointIndex(s, i)".
  //assert(base <= s.length)
  //assert(pos <= s.length)
  var delta = 0
  while base < pos {
    delta += isValidCodePointIndex(s: s, index: base) ? 1 : 0
    base += 1
  }
  while pos < base {
    delta -= isValidCodePointIndex(s: s, index: pos) ? 1 : 0
    pos += 1
  }
  return delta
}

public func UTF16OffsetToIndex(s: String, base: Int, offset: inout Int) -> Int {
  //DCHECK_LE(base, s.length());
  // As in UTF16IndexToOffset, we count the first half of a surrogate pair, not
  // the second. When stepping from pos to pos+1 we check s[pos:pos+1] == s[pos]
  // (Python syntax), hence pos++. When stepping from pos to pos-1 we check
  // s[pos-1], hence --pos.
  var pos = base

  while offset > 0 && pos < s.count {
    offset -= isValidCodePointIndex(s: s, index: pos) ? 1 : 0
    pos += 1
  }

  while offset < 0 && pos > 0 {
    pos -= 1
    offset += isValidCodePointIndex(s: s, index: pos) ? 1 : 0
  }
  // If offset != 0 then we ran off the edge of the string, which is a contract
  // violation but is handled anyway (by clamping) in release for safety.
  //DCHECK_EQ(offset, 0);
  // Since the second half of a surrogate pair has "length" zero, there is an
  // ambiguity in the returned position. Resolve it by always returning a valid
  // index.
  if !isValidCodePointIndex(s: s, index: pos) {
    pos += 1
  }

  return pos
}

func findRunBreakingCharacter(text: String,
                              runStart: Int,
                              runBreak: Int) -> Int {

  let runLength = runBreak - runStart
  let iter = UTF16CharIterator(string: text, start: runStart, length: runLength)
  let firstChar = iter.character
  // The newline character should form a single run so that the line breaker
  // can handle them easily.
  if firstChar == UTF16LineBreak {
    return runStart + 1
  }

  let firstBlock: UBlockCode = UBlockCode(Int(_ICUUBlockGetCode(firstChar)))
  let firstBlockUnusual: Bool = isUnusualBlockCode(firstBlock)
  let firstBracket: Bool = isBracket(firstChar)

  while iter.advance() && Int(iter.arrayPos) < runLength {
    let currentChar = iter.character
    let currentBlock: UBlockCode = UBlockCode(Int(_ICUUBlockGetCode(currentChar)))
    let blockBreak: Bool = currentBlock != firstBlock && (firstBlockUnusual || isUnusualBlockCode(currentBlock))
  
    if blockBreak || currentChar == UTF16LineBreak || 
      firstBracket != isBracket(currentChar) || asciiBreak(first: firstChar, current: currentChar) {
    
      return runStart + Int(iter.arrayPos)
    }
  }

  return runBreak
}

func isUnusualBlockCode(_ blockCode: UBlockCode) -> Bool {
  return blockCode == UBlockGeometricShapes || blockCode == UBlockMiscellaneousSymbols
}

func isBracket(_ character: UTF16.CodeUnit) -> Bool {
  let brackets: [UTF16.CodeUnit] = UTF16Brackets
  
  for bracket in brackets {
    if character == bracket {
      return true
    }
  }
  return false
}

func asciiBreak(first firstChar: UTF16.CodeUnit, current currentChar: UTF16.CodeUnit) -> Bool {
  
  if isascii(Int32(firstChar)) == isascii(Int32(currentChar)) {
    return false
  }

  var scriptsSize = 1
  var scripts: [UScriptCode] = [UScriptInvalidCode]
  
  scriptSetIntersect(codepoint: firstChar, result: &scripts, resultSize: &scriptsSize)
  
  if scriptsSize == 0 {
    return false
  }
  
  scriptSetIntersect(codepoint: currentChar, result: &scripts, resultSize: &scriptsSize)
  
  return scriptsSize != 0
}

func scriptSetIntersect(codepoint: UTF16.CodeUnit,
                        result: inout [UScriptCode],
                        resultSize: inout Int) {

  var scripts = [UScriptCode](repeating: UScriptInvalidCode, count: maxScripts)
  let count = getScriptExtensions(codepoint: codepoint, scripts: &scripts)

  var size = 0
  let resultCount = resultSize

  for i in 0..<resultCount {
    for j in 0..<count {
      ////print("i: \(i) j: \(j) resultSize: \(resultSize) count: \(count) result.count: \(result.count) scripts.count: \(scripts.count)")
      let intersection = scriptIntersect(first: result[i], second: scripts[j])
      ////print("intersection invalid? \(intersection == UScriptInvalidCode)")
      if intersection != UScriptInvalidCode {
        result.insert(intersection, at: size)
        size += 1
        break
      }
    }
  }

  resultSize = size
}

func scriptIntersect(first: UScriptCode, second: UScriptCode) -> UScriptCode {
  
  if first == second || second == UScriptInherited {
    return first
  }

  if first == UScriptInherited {
    return second
  }
  
  return UScriptInvalidCode
}

func getScriptExtensions(codepoint: UTF16.CodeUnit, scripts: inout [UScriptCode]) -> Int {
  var icuError: Int32 = 0
  // ICU documentation incorrectly states that the result of
  // |uscript_getScriptExtensions| will contain the regular script property.
  // Write the character's script property to the first element.
  
  //scripts[0] = UScriptCode(_ICUGetScript(codepoint, &icuError))
  
  //if icuError > 0 {
  //  return 0
  //}
  // Fill the rest of |scripts| with the extensions.
  let size = maxScripts
  let byteSize = size * MemoryLayout<Int32>.stride
  let alignSize = MemoryLayout<Int32>.alignment

  let rawBuffer = UnsafeMutableRawPointer.allocate(byteCount: byteSize,  alignment: alignSize)
  let typedBuffer = rawBuffer.bindMemory(to: Int32.self, capacity: size)
 
  var count = Int(_ICUGetScriptExtensions(codepoint, typedBuffer, Int32(size), &icuError))
  
  for i in 0..<count {
    scripts[i] = UScriptCode(typedBuffer[i])
  }
  
  if icuError > 0 {
    count = 0
  }

  rawBuffer.deallocate()
  
  return count
}

func scriptInterval(text: String,
                    start: Int,
                    length: Int,
                    script: inout UScriptCode) -> Int {
  //DCHECK_GT(length, 0U);

  var scripts = [UScriptCode](repeating: UScriptCommon, count: maxScripts)

  let charIterator = UTF16CharIterator(string: text, start: start, length: length)
  var scriptsSize = getScriptExtensions(codepoint: charIterator.character, scripts: &scripts)
  script = scripts[0]

  while charIterator.advance() {
    // Special handling to merge white space into the previous run.
    if _ICUIsWhiteSpace(charIterator.character) != 0 {
      continue
    }
    scriptSetIntersect(codepoint: charIterator.character, result: &scripts, resultSize: &scriptsSize)
    
    if scriptsSize == 0 {
      return Int(charIterator.arrayPos)
    }

    script = scripts[0]
  }

  return length
}