// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

// TODO: should be temporary of course

fileprivate let IDR_TEXTBUTTON_HOVER: Int = 0
fileprivate let IDR_TEXTBUTTON_PRESSED: Int = 1
fileprivate let IDR_BUTTON_NORMAL: Int = 2
fileprivate let IDR_BUTTON_HOVER: Int = 3
fileprivate let IDR_BUTTON_PRESSED: Int = 4
fileprivate let IDR_BUTTON_DISABLED: Int = 5
fileprivate let IDR_BUTTON_FOCUSED_NORMAL: Int = 6
fileprivate let IDR_BUTTON_FOCUSED_HOVER: Int = 7
fileprivate let IDR_BUTTON_FOCUSED_PRESSED: Int = 8

// IntInsets for the unified button images. This assumes that the images
// are of a 9 grid, of 5x5 size each.
fileprivate let ButtonInsets: Int = 5

// The text-button hot and pushed image IDs; normal is unadorned by default.
fileprivate let textHoveredImages: [Int] = []//IMAGE_GRID(IDR_TEXTBUTTON_HOVER)
fileprivate let textPressedImages: [Int] = []//IMAGE_GRID(IDR_TEXTBUTTON_PRESSED)


public class LabelButtonBorder: Border {
  
  public internal(set) var insets: IntInsets
 
  public var minimumSize: IntSize {
    return IntSize()
  }

  public init() {
    insets = IntInsets()
  }

  public func paintsButtonState(focused: Bool, state: Button.State) -> Bool {
    return false
  }

  public func paint(view: View, canvas: Canvas) {

  }

}

public class LabelButtonAssetBorder : LabelButtonBorder {
  
  class func getDefaultInsetsForStyle(style: Button.Style) -> IntInsets {
    var insets: IntInsets? 
    if style == .Button {
      insets = IntInsets(vertical: 8, horizontal: 13)
    } else if style == .TextButton {
      insets = LayoutProvider.instance().getInsetsMetric(InsetsMetric.LabelButton)
    } else {
      assert(false)
    }
    return insets!
  }

  public override var minimumSize: IntSize {
    var minimumSize = IntSize()
    for i in 0..<2 {
      for j in 0..<Button.State.count {
        let painter = painters[i][j]
        minimumSize.setToMax(other: painter.minimumSize)
      }
    }
    return minimumSize
  }

  fileprivate var painters: [[Painter]]// Painter[2][Button.State.count]

  public init(style: Button.Style) {

    painters = [[]]//Array<Array<Painter>>(repeating: Array<Painter>(repeating: Painter(), count: 2), count: Button.State.count)

    super.init()

    insets = LabelButtonAssetBorder.getDefaultInsetsForStyle(style: style)

    let ins = IntInsets(all: ButtonInsets)
    if style == .Button {
      setPainter(focused: false, state: .Normal,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_NORMAL)!, insets: ins))

      setPainter(focused: false, state: .Hovered,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_HOVER)!, insets: ins))

      setPainter(focused: false, state: .Pressed,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_PRESSED)!, insets: ins))

      setPainter(focused: false, state: .Disabled,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_DISABLED)!, insets: ins))

      setPainter(focused: true, state: .Normal,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_FOCUSED_NORMAL)!, insets: ins))

      setPainter(focused: true, state: .Hovered,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_FOCUSED_HOVER)!, insets: ins))

      setPainter(focused: true, state: .Pressed,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_FOCUSED_PRESSED)!, insets: ins))

      setPainter(focused: true, state: .Disabled,
                 painter: PainterFactory.makeImagePainter(
                    image: ResourceBundle.getImage(IDR_BUTTON_DISABLED)!, insets: ins))

    } else if style == .TextButton {
      setPainter(focused: false, state: .Hovered,
                 painter: PainterFactory.makeImageGridPainter(imageIds: textHoveredImages))
      setPainter(focused: false, state: .Pressed,
                 painter: PainterFactory.makeImageGridPainter(imageIds: textPressedImages))
    }
  }

  public override func paint(view: View, canvas: Canvas) {
    // view -> LabelButton
    let themeDelegate: ThemeDelegate = view as! LabelButton
    let rect = themeDelegate.themePaintRect
    var extra = Theme.ExtraParams()
    var state: Theme.State = themeDelegate.getThemeState(params: &extra)

    if let animation = themeDelegate.themeAnimation {
      if animation.isAnimating {
        // Linearly interpolate background and foreground painters during animation.
        let fgAlpha = UInt8(animation.currentValueBetween(start: 0, target: 255))

        //let autoRestore = PaintCanvasAutoRestore(canvas, false)
        let outerCount = canvas.paintCanvas.saveCount
        let _ = canvas.paintCanvas.saveLayer(bounds: FloatRect(rect), flags: nil)
      
        // { inner scope for PaintCanvasAutoRestore

        // First, modulate the background by 1 - alpha.
    //   let autoRestore = PaintCanvasAutoRestore(canvas, false)
        let innerCount = canvas.paintCanvas.saveCount
        let _ = canvas.paintCanvas.saveLayerAlpha(bounds: FloatRect(rect),  alpha: 255 - fgAlpha, preserveLcdTextRequests: false)
        state = themeDelegate.getBackgroundThemeState(params: &extra)
        paintHelper(border: self, canvas: canvas, state: state, rect: rect, extra: extra)
        canvas.paintCanvas.restoreToCount(saveCount: innerCount)
        // } 
        
        // Then modulate the foreground by alpha, and blend using kPlus_Mode.
        let flags = PaintFlags()
        flags.alpha = fgAlpha
        flags.blendMode = BlendMode.Plus
        let _ = canvas.paintCanvas.saveLayer(bounds: FloatRect(rect), flags: flags)
        state = themeDelegate.getForegroundThemeState(params: &extra)
        paintHelper(border: self, canvas: canvas, state: state, rect: rect, extra: extra)
      
        canvas.paintCanvas.restoreToCount(saveCount: outerCount)
      }
    } else {
      paintHelper(border: self, canvas: canvas, state: state, rect: rect, extra: extra)
    } 
  }

  public override func paintsButtonState(focused: Bool, state: Button.State) -> Bool {
    return getPainter(focused: focused, state: state) != nil || (focused && getPainter(focused: false, state: state) != nil)
  }

  public func getPainter(focused: Bool, state: Button.State) -> Painter? {
    return painters[focused ? 1 : 0][state.rawValue]
  }
  
  public func setPainter(focused: Bool, state: Button.State, painter: Painter) {
    painters[focused ? 1 : 0][state.rawValue] = painter
  }

}

public class LabelButton : Button {

  public static let hoverAnimationDurationMs: Int = 170

  public var text: String {
    get {
      return label.text
    }
    set {
      accessibleName = newValue
      label.text = newValue
    }
  }

  public var isDefault: Bool {
    didSet {
      let accel = Accelerator(keycode: .KeyReturn, modifiers: 0)
      isDefault ? addAccelerator(accelerator: accel) : removeAccelerator(accelerator: accel)
      updateStyleToIndicateDefaultStatus()
    }
  }

  // TODO: é apenas o set
  public override var border: Border? {

    get {
      return super.border
    }
    set {
      borderIsThemedBorder = false
      super.border = newValue
      resetCachedPreferredSize()
    }
  }

  public override var className: String {
    return "LabelButton"
  }

  public var textShadows: ShadowValues {
    get {
      return label.shadows
    }
    set {
      label.shadows = newValue
    }
  }

  public var textSubpixelRenderingEnabled: Bool {
    get {
      return label.subpixelRenderingEnabled
    }
    set {
      label.subpixelRenderingEnabled = newValue
    }
  }

  public var elideBehavior: ElideBehavior {
    get {
      return label.elideBehavior
    }
    set {
      label.elideBehavior = newValue
    }
  }

  public var horizontalAlignment: HorizontalAlignment {
    didSet {
      invalidateLayout()
    }
  }

  public var minSize: IntSize {
    didSet {
      resetCachedPreferredSize()
    }
  }

  public var maxSize: IntSize {
    didSet {
      resetCachedPreferredSize()
    }
  }

  public var imageLabelSpacing: Int {
    didSet {
      resetCachedPreferredSize()
      invalidateLayout()
    }
  }

  public var childAreaBounds: IntRect  {
    return localBounds
  }

  internal var unclampedSizeWithoutLabel: IntSize {
    let imageSize = image.preferredSize
    var size = imageSize
    
    size.enlarge(width: insets.width, height: insets.height)

    // Accommodate for spacing between image and text if both are present.
    if !text.isEmpty && imageSize.width > 0 {
      size.enlarge(width: imageLabelSpacing, height: 0)
    }

    // Make the size at least as large as the minimum size needed by the border.
    if let b = border {
      size.setToMax(other: b.minimumSize)
    }

    return size
  }

  public var style: Button.Style

  // public var fontList: FontList {

  // }

  //public override var focusPainter: Painter

  public private(set) var label: LabelButtonLabel
  public private(set) var image: ImageView
  internal var inkDropContainer: InkDropContainerView 

  // The cached font lists in the normal and default button style. The latter
  // may be bold.
  var cachedNormalFontList: FontList = FontList()
  var cachedDefaultButtonFontList: FontList = FontList()

  // The images and colors for each button state.
  var buttonStateImages: Array<ImageSkia> = Array<ImageSkia>(repeating: ImageSkia(), count: Button.State.count)
  var buttonStateColors: Array<Color> = Array<Color>(repeating: Color(), count: Button.State.count)
  var explicitlySetColors: Array<Bool> = Array<Bool>(repeating: false, count: Button.State.count)

  // Cache the last computed preferred size.
  var cachedPreferredSize: IntSize
  var cachedPreferredSizeValid: Bool

  // True if current border was set by UpdateThemedBorder. Defaults to true.
  var borderIsThemedBorder: Bool

 
  public init(listener: ButtonListener?, text: String, context buttonContext: TextContext = TextContext.button) {
   
    image = ImageView()

    minSize = IntSize()
    maxSize = IntSize()

    label = LabelButtonLabel(text: text, context: buttonContext)
   
    inkDropContainer = InkDropContainerView()
   
    cachedNormalFontList = TextStyles.getFont(context: buttonContext, style: .primary)
   
    cachedDefaultButtonFontList = TextStyles.getFont(context: buttonContext, style: .dialogButtonDefault)
   
    isDefault = false
    style = .TextButton
    borderIsThemedBorder = true
    imageLabelSpacing = LayoutProvider.instance().getDistanceMetric(DistanceMetric.RelatedLabelHorizontal)
    horizontalAlignment = .AlignLeft
    cachedPreferredSize = Size()
    cachedPreferredSizeValid = false

    super.init(listener: listener)

    self.text = text

    addChild(view: inkDropContainer)
    inkDropContainer.setPaintToLayer()
    inkDropContainer.layer!.fillsBoundsOpaquely = false
    inkDropContainer.isVisible = false

    addChild(view: image)
    image.canProcessEventsWithinSubtree = false

    addChild(view: label)
    label.autoColorReadability = false
    label.horizontalAlignment = .AlignToHead

    // Inset the button focus rect from the actual border; roughly match Windows.
    focusPainter = PainterFactory.makeDashedFocusPainterWithInsets(insets: IntInsets(all: 3))
    
    setAnimationDuration(duration: LabelButton.hoverAnimationDurationMs)
  }

  public func getImage(forState: Button.State) -> ImageSkia {
    if forState != .Normal && buttonStateImages[forState.rawValue].isNull {
      return buttonStateImages[Button.State.Normal.rawValue]
    }
    
    return buttonStateImages[forState.rawValue]
  }

  public func setImage(forState: Button.State, image: ImageSkia) {
    buttonStateImages[forState.rawValue] = image
    updateImage()
  }

  public func setTextColor(forState: Button.State, color: Color) {
    buttonStateColors[forState.rawValue] = color
    if forState == .Disabled {
      label.disabledColor = color
    } else if forState == state {
      label.enabledColor = color
    }
    explicitlySetColors[forState.rawValue] = true
  }

  public func createDefaultBorder() -> LabelButtonBorder {
    if style != .TextButton {
      return LabelButtonAssetBorder(style: style)
    }
    
    let border = LabelButtonBorder()
    border.insets = LabelButtonAssetBorder.getDefaultInsetsForStyle(style: style)
    
    return border
  }

  public func getHeightForWidth(w: Int) -> Int {
    let sizeWithoutLabel = unclampedSizeWithoutLabel
    // Get label height for the remaining width.
    let labelHeightWithInsets =
        label.getHeightFor(width: width - sizeWithoutLabel.width) + insets.height

    // Height is the larger of size without label and label height with insets.
    var height = max(sizeWithoutLabel.height, labelHeightWithInsets)

    // Make sure height respects min_size_.
    if height < minSize.height {
      height = minSize.height
    }

    // Clamp height to the maximum height (if valid).
    if maxSize.height > 0 {
      return min(maxSize.height, height)
    }

    return height
  }

  public override func layout() {
    inkDropContainer.bounds = localBounds

    // By default, GetChildAreaBounds() ignores the top and bottom border, but we
    // want the image to respect it.
    var childArea = childAreaBounds
    // The space that the label can use. Its actual bounds may be smaller if the
    // label is short.
    var labelArea = childArea
    childArea.inset(insets: insets)
    // Labels can paint over the vertical component of the border insets.
    labelArea.inset(left: insets.left, top: 0, right: insets.right, bottom: 0)

    var imageSize = image.preferredSize
    imageSize.setToMin(other: childArea.size)

    if !imageSize.isEmpty {
      let imageSpace = imageSize.width + imageLabelSpacing
      if horizontalAlignment == .AlignRight {
        labelArea.inset(left: 0, top: 0, right: imageSpace, bottom: 0) 
      } else {
        labelArea.inset(left: imageSpace, top: 0, right: 0, bottom: 0)
      }
    }

    let labelSize = IntSize(width: min(labelArea.width, label.preferredSize.width), height: labelArea.height)

    var imageOrigin = childArea.origin
    if label.multiline {
      // Right now this code currently only works for CheckBox and RadioButton
      // descendants that have multi-line enabled for their label.
      imageOrigin.offset(
          x: 0, y: max(0, (label.fontList.height - imageSize.height) / 2))
    } else {
      imageOrigin.offset(x: 0, y: (childArea.height - imageSize.height) / 2)
    }
    if horizontalAlignment == .AlignCenter {
      let spacing = (imageSize.width > 0 && labelSize.width > 0) ? imageLabelSpacing : 0
      let totalWidth = imageSize.width + labelSize.width + spacing
      imageOrigin.offset(x: (childArea.width - totalWidth) / 2, y: 0)
    } else if horizontalAlignment == .AlignRight {
      imageOrigin.offset(x: childArea.width - imageSize.width, y: 0)
    }
    //image.boundsRect = IntRect(imageOrigin, imageSize)
    image.bounds = IntRect(origin: imageOrigin, size: imageSize)

    var labelBounds = labelArea
    if labelArea.width == labelSize.width {
      // Label takes up the whole area.
    } else if horizontalAlignment == .AlignCenter {
      labelBounds.clampToCenteredSize(size: labelSize)
    } else {
      labelBounds.size = labelSize
      if horizontalAlignment == .AlignRight {
        labelBounds.offset(horizontal: labelArea.width - labelSize.width, vertical: 0)
      }
    }

    label.bounds = labelBounds
    super.layout()
  }

  public override func enableCanvasFlippingForRTLUI(enable flip: Bool) {
    super.enableCanvasFlippingForRTLUI(enable: flip)
    image.enableCanvasFlippingForRTLUI(enable: flip)
  }

  //public override func onPaint(canvas: Canvas) {}

  public override func onFocus() {
    super.onFocus()
    // Typically the border renders differently when focused.
    schedulePaint()
  }

  public override func onBlur() {
    super.onBlur()
    // Typically the border renders differently when focused.
    schedulePaint()
  }

  public override func onThemeChanged(theme: Theme) {
    resetColorsFromTheme()
    updateThemedBorder()
    resetLabelEnabledColor()
    // Invalidate the layout to pickup the new insets from the border.
    invalidateLayout()
    // The entire button has to be repainted here, since the native theme can
    // define the tint for the entire background/border/focus ring.
    schedulePaint()
  }

  open override func calculatePreferredSize() -> IntSize {
    if cachedPreferredSizeValid {
      return cachedPreferredSize
    }

    // Use a temporary label copy for sizing to avoid calculation side-effects.
    let labelCopy = Label(text: text, fontlist: (label.fontList))
    labelCopy.lineheight = label.lineheight
    labelCopy.shadows = label.shadows

    if style == .Button {
      // Some text appears wider when rendered normally than when rendered bold.
      // Accommodate the widest, as buttons may show bold and shouldn't resize.
      let currentWidth = label.preferredSize.width
      labelCopy.fontList = cachedDefaultButtonFontList
      if labelCopy.preferredSize.width < currentWidth {
        label.fontList = labelCopy.fontList
      }
    }

    // Calculate the required size.
    let preferredLabelSize = labelCopy.preferredSize
    var size = unclampedSizeWithoutLabel
    size.enlarge(width: preferredLabelSize.width, height: 0)

    // Increase the height of the label (with insets) if larger.
    size.height = max(preferredLabelSize.height + insets.height, size.height)

    size.setToMax(other: minSize)

    // Clamp size to max size (if valid).
    if maxSize.width > 0 {
      size.width = min(maxSize.width, size.width)
    }

    if maxSize.height > 0 {
      size.height = min(maxSize.height, size.height)
    }

    // Cache this computed size, as recomputing it is an expensive operation.
    cachedPreferredSizeValid = true
    cachedPreferredSize = size
    return cachedPreferredSize
  }

  public override func childPreferredSizeChanged(child: View) {
    resetCachedPreferredSize()
    preferredSizeChanged()
    layout()
  }

  internal override func stateChanged(oldState: State) {
    let previousImageSize = image.preferredSize
    updateImage()
    resetLabelEnabledColor()
    label.isEnabled = state != .Disabled
    if image.preferredSize != previousImageSize {
      layout()
    }
  }

  public func updateImage() {
    image.image = getImage(forState: state)
    resetCachedPreferredSize()
  }

  public func setEnabledTextColors(color: Color) {
    let states: [Button.State] = [Button.State.Normal, Button.State.Hovered, Button.State.Pressed]
    for state in states {
      setTextColor(forState: state, color: color)
    }
  }

  public func updateThemedBorder() {
    if !borderIsThemedBorder {
      return
    }

    border = PlatformStyle.createThemedLabelButtonBorder(button: self)
    borderIsThemedBorder = true
  }

  public func getThemePaintRect() -> IntRect {
    return IntRect()
  }

  internal func resetLabelEnabledColor() {
    let color = buttonStateColors[state.rawValue]
    if state != .Disabled && label.enabledColor != color {
      label.enabledColor = color
    }
  }

  internal func updateStyleToIndicateDefaultStatus() {
    label.fontList = isDefault ? cachedDefaultButtonFontList : cachedNormalFontList
    invalidateLayout()
    resetLabelEnabledColor()
  }

    internal func getThemeExtraParams(params: inout Theme.ExtraParams) {
    params.button.checked = false
    params.button.indeterminate = false
    params.button.isDefault = isDefault
    params.button.isFocused = hasFocus// && isAccessibilityFocusable
    params.button.hasBorder = false
    params.button.classicState = 0
    params.button.backgroundColor = label.backgroundColor
  }

  private func resetCachedPreferredSize() {
    cachedPreferredSizeValid = false
    cachedPreferredSize = IntSize()
  }

  func resetColorsFromTheme() {
    let buttonStyle: Bool = style == .Button
    // Button colors are used only for STYLE_BUTTON, otherwise we use label
    // colors. As it turns out, these are almost always the same color anyway in
    // pre-MD, although in the MD world labels and buttons get different colors.
    // TODO(estade): simplify this by removing STYLE_BUTTON.
    var colors: [Color] = [
        theme.getSystemColor(id: buttonStyle
                                  ? Theme.ColorId.ButtonEnabledColor
                                  : Theme.ColorId.LabelEnabledColor),
        theme.getSystemColor(id: buttonStyle
                                  ? Theme.ColorId.ButtonHoverColor
                                  : Theme.ColorId.LabelEnabledColor),
        theme.getSystemColor(id: buttonStyle
                                  ? Theme.ColorId.ButtonHoverColor
                                  : Theme.ColorId.LabelEnabledColor),
        theme.getSystemColor(id: buttonStyle
                                  ? Theme.ColorId.ButtonDisabledColor
                                  : Theme.ColorId.LabelDisabledColor)
    ]

    // Use hardcoded colors for inverted color scheme support and STYLE_BUTTON.
    if ColorUtils.isInvertedColorScheme {
      colors[State.Normal.rawValue] = Color.White
      colors[State.Hovered.rawValue] = Color.White
      colors[State.Pressed.rawValue] = Color.White
      label.backgroundColor = Color.Black
      label.background = BackgroundFactory.makeSolidBackground(color: Color.Black)
      label.autoColorReadability = true
      label.shadows = ShadowValues()
    } else {
      if style == .Button {
        var localLabel = label as Label
        PlatformStyle.applyLabelButtonTextStyle(label: &localLabel, colors: &colors)
      }
      label.background = nil
      label.autoColorReadability = false
    }

    for i in State.Normal.rawValue ..< State.count {
      if !explicitlySetColors[i] {
        setTextColor(forState: State(rawValue: i)!, color: colors[i])
        explicitlySetColors[i] = false
      }
    }
  }

}

extension LabelButton : ThemeDelegate {
  
  public var themePart: Theme.Part {
    return Theme.Part.PushButton
  }
  
  public var themePaintRect: IntRect {
    return localBounds
  }
  
  public var themeAnimation: Animation? {
    return hoverAnimation
  }

  public func getThemeState(params: inout Theme.ExtraParams) -> Theme.State {
    getThemeExtraParams(params: &params)
    switch state {
      case .Normal:
        return Theme.State.Normal
      case .Hovered:
        return Theme.State.Hovered
      case .Pressed:
        return Theme.State.Pressed
      case .Disabled:
        return Theme.State.Disabled
    }
  }
  
  public func getBackgroundThemeState(params: inout Theme.ExtraParams) -> Theme.State {
    getThemeExtraParams(params: &params)
    return Theme.State.Normal
  }

  public func getForegroundThemeState(params: inout Theme.ExtraParams) -> Theme.State {
    getThemeExtraParams(params: &params)
    return Theme.State.Hovered
  }

}

fileprivate func paintHelper(border: LabelButtonAssetBorder,
                             canvas: Canvas,
                             state: Theme.State,
                             rect: IntRect,
                             extra: Theme.ExtraParams) {
  var maybePainter: Painter? 
  
  maybePainter = border.getPainter(focused: extra.button.isFocused, state: Button.getButtonStateFrom(theme: state))
    
  if maybePainter == nil {
    maybePainter = border.getPainter(focused: false, state: Button.getButtonStateFrom(theme: state))
  }

  if let painter = maybePainter {
    PainterHelper.paintPainterAt(canvas: canvas, painter: painter, rect: rect)
  }
}