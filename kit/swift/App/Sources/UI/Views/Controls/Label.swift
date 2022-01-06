// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class Label : View {
  
  public var fontList: FontList {
    get {
      return rendertext.fontList
    }
    set {
      isFirstPaintText = true
      rendertext.fontList = newValue
      resetLayout()
    }
  }

  public var text: String {
    get {
      return rendertext.text
    }
    set {
      isFirstPaintText = true
      rendertext.text = newValue
      resetLayout()
    }
  }
  
  public var lineheight: Int { 
    get {
      return rendertext.minLineHeight
    }
    set {
      guard lineheight != newValue else {
        return
      }
      isFirstPaintText = true
      rendertext.minLineHeight = newValue
      resetLayout()
    }
  }
  
  public var enabledColor: Color {
    get {
      return actualEnabledColor
    }
    set {
      if enabledColorSet && requestedEnabledColor == newValue {
        return
      }
      isFirstPaintText = true
      requestedEnabledColor = newValue
      enabledColorSet = true
      recalculateColors()
    }
  }
  
  public var disabledColor: Color {
    get {
      return actualDisabledColor
    }
    set {
      if disabledColorSet && requestedDisabledColor == newValue {
        return
      }
      isFirstPaintText = true
      requestedDisabledColor = newValue
      disabledColorSet = true
      recalculateColors()
    }
  }
  
  public var backgroundColor: Color {
    didSet {
      if backgroundColorSet && backgroundColor == oldValue {
        return
      }
      isFirstPaintText = true
      backgroundColorSet = true
      recalculateColors()
    }
  }
  
  var autoColorReadability: Bool {
    didSet {
      if autoColorReadability == oldValue {
        return
      }
      isFirstPaintText = true
      recalculateColors()
    }
  }
  
  public var shadows: ShadowValues { 
    get {
      return rendertext.shadows
    }
    set {
      rendertext.shadows = newValue
    }
  }
  
  public var subpixelRenderingEnabled: Bool {
    didSet {
      if subpixelRenderingEnabled == oldValue {
        return
      }
      isFirstPaintText = true
      recalculateColors()
    }
  }
  
  public var horizontalAlignment: HorizontalAlignment {
    get {
      return rendertext.horizontalAlignment
    }
    set {
      var alignment = newValue
      if i18n.isRTL() && (alignment == .AlignLeft || alignment == .AlignRight) {
        alignment = (alignment == .AlignLeft) ? .AlignRight : .AlignLeft
      }
      if horizontalAlignment == alignment {
        return
      }
      isFirstPaintText = true
      rendertext.horizontalAlignment = alignment
      resetLayout()
    }
  }

  public var multiline: Bool {
    didSet {
      assert(!multiline || (elideBehavior == .ElideTail || elideBehavior == .NoElide))
      if multiline == oldValue {
        return
      }
      isFirstPaintText = true
      if rendertext.multilineSupported {
        rendertext.multiline = multiline
      }
      rendertext.replaceNewlineCharsWithSymbols = !multiline
      resetLayout()
    }
  }
  
  public var obscured: Bool { 
    get {
      return rendertext.obscured
    }
    set {
     if obscured == newValue {
      return
     }
     isFirstPaintText = true
     rendertext.obscured = newValue
     resetLayout()
    }
  }
  
  public var elideBehavior: ElideBehavior {
    didSet {
      assert(!multiline || (elideBehavior == .ElideTail || elideBehavior == .NoElide))
      if elideBehavior == oldValue {
        return
      }
      isFirstPaintText = true
      resetLayout()
    }
  }

  public var tooltipText: String
  
  public var handlesTooltips: Bool
  
  public var allowCharacterBreak: Bool {
    get {
      return rendertext.wordWrapBehavior == .WrapLongWords ? true : false
    }
    set {
      let behavior: WordWrapBehavior = newValue ? .WrapLongWords : .TruncateLongWords
      if rendertext.wordWrapBehavior == behavior {
        return
      }
      rendertext.wordWrapBehavior = behavior
      if multiline {
        isFirstPaintText = true
        resetLayout()
      }
    }
  }
  
  // Whether to collapse the label when it's not visible.
  public var collapseWhenHidden: Bool

  // View
  public override var insets: IntInsets {
    return IntInsets()
  }
  
  public override var baseline: Int {
    return 0
  }
  
  public override var minimumSize: IntSize {
    return IntSize()
  }
  
  public override var className: String {
    return "Label"
  }
  
  public override var canProcessEventsWithinSubtree: Bool {
    get {
      return false
    }
    set {
      
    }
  }

  public var textContext: TextContext
  
  var focusBounds: IntRect {
    maybeBuildRenderTextLines()
    var bounds = IntRect()
    if lines.isEmpty {
      bounds = IntRect(size: textSize)
    } else {
      for line in lines {
        var origin = IntPoint()
        origin = origin + IntPoint(line.getLineOffset(line: 0))
        bounds.union(other: IntRect(origin: origin, size: line.stringSize))
      }
    }
    bounds.inset(horizontal: -focusBorderPadding, vertical: -focusBorderPadding)
    bounds.intersect(rect: localBounds)
    //print("Label.focusBounds: \(bounds)")
    return bounds
  }
  
  // Get the text size for the current layout.
  var textSize: IntSize {
    var size = IntSize()
    if text.isEmpty {
      size = IntSize(width: 0, height: max(lineheight, fontList.height))
    } else if !multiline || rendertext.multilineSupported {
      rendertext.displayRect = FloatRect(x: 0, y: 0, width: Float(width), height: 0)
      size = rendertext.stringSize
    } else {
      let lines = getLinesFor(width: width)
      let rendertext = RenderText()
      rendertext.fontList = fontList
      for line in lines {
        rendertext.text = line
        let lineSize = rendertext.stringSize
        size.width = max(size.width, lineSize.width)
        size.height = max(lineheight, size.height + lineSize.height)
      }
    }
    let shadowmargin = -Graphics.ShadowValue.getMargin(shadows: shadows)
    size.enlarge(width: Int(shadowmargin.width), height: Int(shadowmargin.height))
    return size
  }
  
  var shouldShowDefaultTooltip: Bool {
    let size = contentsBounds.size
    return !obscured && (textSize.width > size.width ||
                         (multiline && textSize.height > size.height))
  }
    
  var rendertext: RenderText

  // The RenderText instances used to display elided and multi-line text.
  var lines: [RenderText]

  var requestedEnabledColor: Color
  var actualEnabledColor: Color
  var requestedDisabledColor: Color
  var actualDisabledColor: Color

  // Set to true once the corresponding setter is invoked.
  var enabledColorSet: Bool
  var disabledColorSet: Bool
  var backgroundColorSet: Bool
 
  var maxWidth: Int

  var isFirstPaintText: Bool
  
  let focusBorderPadding: Int = 1
  
  public override init() {
    rendertext = RenderText()
    elideBehavior = .ElideTail
    enabledColorSet = false
    disabledColorSet = false
    backgroundColorSet = false
    subpixelRenderingEnabled = true
    autoColorReadability = true
    multiline = false
    handlesTooltips = true
    collapseWhenHidden = false
    maxWidth = 0
    isFirstPaintText = true
    lines = []
    backgroundColor = Color()
    tooltipText = String()
    requestedEnabledColor = Color()
    actualEnabledColor = Color()
    requestedDisabledColor = Color()
    actualDisabledColor = Color()
    rendertext.horizontalAlignment = .AlignCenter
    rendertext.directionalityMode = .DirectionalityFromText
    rendertext.elideBehavior = .NoElide
    rendertext.fontList = FontList()
    rendertext.cursorEnabled = false 
    rendertext.wordWrapBehavior = .TruncateLongWords
    rendertext.text = String()
    textContext = TextContext.label
    super.init()
  }
  
  public init(text input: String) {
    rendertext = RenderText()
    elideBehavior = .ElideTail
    enabledColorSet = false
    disabledColorSet = false
    backgroundColorSet = false
    subpixelRenderingEnabled = true
    autoColorReadability = true
    multiline = false
    handlesTooltips = true
    collapseWhenHidden = false
    maxWidth = 0
    isFirstPaintText = true
    lines = []
    backgroundColor = Color()
    requestedEnabledColor = Color()
    actualEnabledColor = Color()
    requestedDisabledColor = Color()
    actualDisabledColor = Color()
    tooltipText = String()
    rendertext.horizontalAlignment = .AlignCenter
    rendertext.directionalityMode = .DirectionalityFromText
    rendertext.elideBehavior = .NoElide
    rendertext.fontList = FontList()
    rendertext.cursorEnabled = false 
    rendertext.wordWrapBehavior = .TruncateLongWords
    rendertext.text = input
    textContext = TextContext.label
    super.init()
  }
  
  public init(text input: String, fontlist: FontList) {
    rendertext = RenderText()
    elideBehavior = .ElideTail
    enabledColorSet = false
    disabledColorSet = false
    backgroundColorSet = false
    subpixelRenderingEnabled = true
    autoColorReadability = true
    multiline = false
    handlesTooltips = true
    collapseWhenHidden = false
    maxWidth = 0
    isFirstPaintText = true
    lines = []
    backgroundColor = Color()
    requestedEnabledColor = Color()
    actualEnabledColor = Color()
    requestedDisabledColor = Color()
    actualDisabledColor = Color()
    tooltipText = String()
    rendertext.horizontalAlignment = .AlignCenter
    rendertext.directionalityMode = .DirectionalityFromText
    rendertext.elideBehavior = .NoElide
    rendertext.fontList = fontlist
    rendertext.cursorEnabled = false 
    rendertext.wordWrapBehavior = .TruncateLongWords
    rendertext.text = input
    textContext = TextContext.label
    super.init()
  }

  public init(text input: String,
              context: TextContext,
              style: TextStyle = TextStyle.primary) {

    rendertext = RenderText()
    elideBehavior = .ElideTail
    enabledColorSet = false
    disabledColorSet = false
    backgroundColorSet = false
    subpixelRenderingEnabled = true
    autoColorReadability = true
    multiline = false
    handlesTooltips = true
    collapseWhenHidden = false
    maxWidth = 0
    isFirstPaintText = true
    lines = []
    backgroundColor = Color()
    requestedEnabledColor = Color()
    actualEnabledColor = Color()
    requestedDisabledColor = Color()
    actualDisabledColor = Color()
    tooltipText = String()
    rendertext.horizontalAlignment = .AlignCenter
    rendertext.directionalityMode = .DirectionalityFromText
    rendertext.elideBehavior = .NoElide
    rendertext.fontList = TextStyles.getFont(context: context, style: style)
    rendertext.cursorEnabled = false 
    rendertext.wordWrapBehavior = .TruncateLongWords
    rendertext.text = input
    textContext = context

    super.init()

    lineheight = TextStyles.getLineHeight(context: context, style: style)

    if style != .primary {
      enabledColor = TextStyles.getColor(view: self, context: context, style: style)
    }
    
  }
  
  public override func getHeightFor(width w: Int) -> Int {
    return 0
  }
  
  public override func getTooltipHandlerFor(point p: IntPoint) -> View? {
    return nil
  }
  
  public override func getAccessibleState(state: inout AXViewState) {
    
  }
  
  public override func getTooltipText(p: IntPoint) -> String? {
    if !handlesTooltips {
      return nil
    }

    if !tooltipText.isEmpty {
      return tooltipText
    }

    if shouldShowDefaultTooltip {
      // Note that |render_text_| is never elided (see the comment in Init() too).
      return rendertext.displayText
    }

    return nil
  }
  
  public override func layout() {
    //print("Label.layout")
  }
  
  public override func onPaint(canvas: Canvas) {
    //print("Label.onPaint")
    super.onPaint(canvas: canvas)
    if isFirstPaintText {
      isFirstPaintText = false
      paintText(canvas: canvas)
    } else {
      paintText(canvas: canvas)
    }
    if hasFocus {
      canvas.drawFocusRect(rect: FloatRect(focusBounds))
    }
  }
  
  public override func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {
    super.onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    resetLayout()
  }
  
  public override func onEnabledChanged() {
    recalculateColors()
  }
  
   // View
  public override func onBoundsChanged(previousBounds: IntRect) {
    
  }
  
  public override func visibilityChanged(startingFrom: View, isVisible: Bool) {
    if !isVisible {
      lines.removeAll()
    }
  }
  
  public func sizeToFit(maxWidth: Int) {
    
  }
  
  func initInternal(list: FontList) {
    rendertext.horizontalAlignment = .AlignCenter
    rendertext.directionalityMode = .DirectionalityFromText
    rendertext.elideBehavior = .NoElide
    rendertext.fontList = list
    rendertext.cursorEnabled = false 
    rendertext.wordWrapBehavior = .TruncateLongWords
  }
  
  func resetLayout() {
    invalidateLayout()
    preferredSizeChanged()
    schedulePaint()
    lines.removeAll()
  }
  
  func createRenderText(
      text: String,
      alignment: HorizontalAlignment,
      directionality: DirectionalityMode,
      elideBehavior: ElideBehavior) -> RenderText {
  
    let outtext = RenderText()
    
    outtext.horizontalAlignment = alignment
    outtext.directionalityMode = directionality
    outtext.elideBehavior = elideBehavior
    outtext.obscured = obscured
    outtext.minLineHeight = lineheight
    outtext.fontList = fontList
    outtext.shadows = shadows
    outtext.cursorEnabled = false
    outtext.text = text
    
    return outtext
  }
  
  func paintText(canvas: Canvas) {
    //print("Label.paintText")
    maybeBuildRenderTextLines()
    for line in lines {
      //print("Label.pantText: processing line")
      line.draw(canvas: canvas)
    }
  }
  
  func maybeBuildRenderTextLines() {
    
    if !lines.isEmpty {
      return
    }

    var rect = contentsBounds
    
    if focusable {
      rect.inset(horizontal: focusBorderPadding, vertical: focusBorderPadding)
    }
    
    if rect.isEmpty {
      return
    }

    var alignment = horizontalAlignment
    var directionality = rendertext.directionalityMode
    
    if multiline {
      // Force the directionality and alignment of the first line on other lines.
      let rtl = rendertext.displayTextDirection == .RightToLeft
      if alignment == .AlignToHead {
        alignment = rtl ? .AlignRight : .AlignLeft
      }
    
      directionality = rtl ? .DirectionalityForceRTL : .DirectionalityForceLTR
    }

    // Text eliding is not supported for multi-lined Labels.
    // TODO(mukai): Add multi-lined elided text support.
    let elide: ElideBehavior = multiline ? .NoElide : elideBehavior
    if !multiline || rendertext.multilineSupported {
      let rtext = createRenderText(text: text, alignment: alignment, directionality: directionality, elideBehavior: elide)
      rtext.displayRect = FloatRect(rect)
      rtext.multiline = multiline
      rtext.wordWrapBehavior = rendertext.wordWrapBehavior
      lines.append(rtext)
    } else {
      let strlines = getLinesFor(width: rect.width)
      if strlines.count > 1 {
        rect.height = max(lineheight, fontList.height)
      }

      let bottom = contentsBounds.bottom
      for line in strlines {
        if rect.y <= bottom {
          let newline = createRenderText(text: line, alignment: alignment, directionality: directionality, elideBehavior: elide)
          newline.displayRect = FloatRect(rect)
          lines.append(newline)
          rect.y = rect.y + rect.height
        }
      }
      // Append the remaining text to the last visible line.
      let last = lines.endIndex - 1
      var i = last
      while i < (strlines.endIndex - 1) {
        lines[last].text = lines[last].text + strlines[i]
        i = i + 1
      }
    }
    recalculateColors()
  }
  
  func getLinesFor(width: Int) -> [String] {
    var lines = [String]()
    // |width| can be 0 when getting the default text size, in that case
    // the ideal lines (i.e. broken at newline characters) are wanted.
    if width <= 0 {
      lines = rendertext.displayText.split(sep: "\n")
    } else {

      let _ = Graphics.elideRectangleText(text: rendertext.displayText, 
                                  list: fontList, 
                                  width: Float(width),
                                  height: Int.max,
                                  behavior: rendertext.wordWrapBehavior, 
                                  lines: &lines)
    }
    return lines
  }
  
  func recalculateColors() {
    
    actualEnabledColor = autoColorReadability ?
      ColorUtils.getReadableColor(foreground: requestedEnabledColor, background: backgroundColor) : requestedEnabledColor
    
    actualDisabledColor = autoColorReadability ?
      ColorUtils.getReadableColor(foreground: requestedDisabledColor, background: backgroundColor) : requestedDisabledColor

    let color = isEnabled ? actualEnabledColor : actualDisabledColor
    let subpixelRenderingSuppressed: Bool = Color.alpha(color: backgroundColor) != 0xff || !subpixelRenderingEnabled
    for line in lines {
      line.setColor(color: color)
      line.subpixelRenderingSuppressed = subpixelRenderingSuppressed
    }
    schedulePaint()
  }
  
}

extension String {
  
  public func split(sep: Character) -> [String]{
    var result = [String]()
    var buff = String()
    for ch in self {
      buff.append(ch)
      if ch == sep {
        result.append(buff)
        buff.removeAll()
      }      
    }
    result.append(buff)
    return result
  }
  
}