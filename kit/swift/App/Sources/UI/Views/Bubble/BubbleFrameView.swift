// Copyright (c) 2016-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let footnoteBackgroundColor = Color.fromRGB(250, 250, 250)
fileprivate let footnoteBorderColor = Color.fromRGB(235, 235, 235)

fileprivate func getOffScreenLength(
  _ availableBounds: IntRect, _ windowBounds: IntRect, _ vertical: Bool) -> Int {
  
  if availableBounds.isEmpty || availableBounds.contains(rect: windowBounds) {
    return 0
  }

  //  window_bounds
  //  +---------------------------------+
  //  |             top                 |
  //  |      +------------------+       |
  //  | left | available_bounds | right |
  //  |      +------------------+       |
  //  |            bottom               |
  //  +---------------------------------+
  if vertical {
    return max(0, availableBounds.y - windowBounds.y) +
           max(0, windowBounds.bottom - availableBounds.bottom)
  }

  return max(0, availableBounds.x - windowBounds.x) +
         max(0, windowBounds.right - availableBounds.right)
}

fileprivate class FootnoteContainerView : View {
  open override func childVisibilityChanged(child: View) {
    self.isVisible = child.isVisible
  }
}

public class BubbleFrameView : NonClientFrameView,
                               ButtonListener {

  public static let viewClassName: String = "BubbleFrameView"
  
  public static func createDefaultTitleLabel(text: String) -> Label {
    let title = Label(text: text, context: TextContext.dialogTitle)
    title.horizontalAlignment = .AlignLeft
    title.collapseWhenHidden = true
    title.multiline = true
    return title
  }

  public static func createCloseButton(listener: ButtonListener) -> LabelButton {
    return LabelButton(listener: listener, text: "close")
    // let rb = ResourceBundle.getSharedInstance()
    // let closeButton = ImageButton(listener: listener)
    // closeButton.setImage(Button.STATE_NORMAL,
    //                      rb.getImageNamed(IDR_LOSE_DIALOG).ToImageSkia())
    // closeButton.setImage(
    //     Button.STATE_HOVERED,
    //     rb.getImageNamed(IDR_LOSE_DIALOG_H).ToImageSkia())
    // closeButton.setImage(
    //     Button.STATE_PRESSED,
    //     rb.getImageNamed(IDR_LOSE_DIALOG_P).ToImageSkia())
    // closeButton.tooltipText = l10n.getStringUTF16(IDS_APP_LOSE)
    // closeButton.sizeToPreferredSize()
    // closeButton.focusBehavior = View.FocusBehavior.NEVER
    // return closeButton
  }

  // nonClientFrame
  public override var boundsForClientView: IntRect {
    var clientBounds = contentsBounds//localBounds
    clientBounds.inset(insets: getClientInsetsForFrameWidth(width: clientBounds.width))
    if let footnote = footnoteContainer, footnote.isVisible {
      clientBounds.height = clientBounds.height - footnote.height
    }
    return clientBounds
  }

  // View

  open override var className: String {
    return BubbleFrameView.viewClassName
  }

  open override var insets: IntInsets {
    return getClientInsetsForFrameWidth(width: contentsBounds.width)
  }

  open override var minimumSize: IntSize {
    let clientSize = widget!.clientView!.minimumSize
    return getWindowBoundsForClientBounds(clientBounds: IntRect(size: clientSize)).size
  }

  open override var maximumSize: IntSize {
#if os(Windows)
  // On Windows, this causes problems, so do not set a maximum size (it doesn't
  // take the drop shadow area into account, resulting in a too-small window;
  // see http://crbug.com/506206). This isn't necessary on Windows anyway, since
  // the OS doesn't give the user controls to resize a bubble.
  return IntSize()
#else
#if os(macOS)
  // Allow BubbleFrameView dialogs to be resizable on Mac.
  if widget!.widgetDelegate.canResize {
    let clientSize = widget!.clientView.maximumSize
    if clientSize.isEmpty {
      return clientSize
    }
    return getWindowBoundsForClientBounds(IntRect(clientSize)).size
  }
#endif  // OS_MACOSX
  // Non-dialog bubbles should be non-resizable, so its max size is its
  // preferred size.
  return preferredSize
#endif
  }

  public var titleView: View? {
    get {
      return customTitle ?? defaultTitle
    }
    set {
      if let view = newValue {
        defaultTitle = nil
        customTitle = view
        // Keep the title after the icon for focus order.
        addChildAt(view: view, index: 1)
      }
    }
  }

  public var bubbleBorder: BubbleBorder? {
    didSet {
      if let b = bubbleBorder {
        border = b
        background = BubbleBackground(border: b)
      }
    }
  }

  public var footnoteMargins: IntInsets
  
  public private(set) var contentMargins: IntInsets
  public private(set) var closeButtonClicked: Bool
  
  internal var isCloseButtonVisible: Bool {
    return close?.isVisible ?? false
  }

  internal var closeButtonMirroredBounds: IntRect {
    return close?.mirroredBounds ?? IntRect()
  }

  internal var extendClientIntoTitle: Bool {
    return false
  }

  private var hasTitle: Bool {
    return (customTitle != nil &&
          widget!.widgetDelegate!.shouldShowWindowTitle) ||
         (defaultTitle != nil &&
          defaultTitle!.preferredSize.height > 0) ||
         titleIcon!.preferredSize.height > 0
  }

  private var titleLabelInsetsFromFrame: IntInsets {
    var insetsRight = 0
    if widget!.widgetDelegate!.shouldShowCloseButton {
      let closeMargin =
          LayoutProvider.instance().getDistanceMetric(DistanceMetric.CloseButtonMargin)
      insetsRight = 2 * closeMargin + self.close!.width
    }
    if !hasTitle {
      return IntInsets(top: 0, left: 0, bottom: 0, right: insetsRight)
    }

    insetsRight = max(insetsRight, self.titleMargins.right)
    let titleIconPrefSize = titleIcon!.preferredSize
    let titleIconPadding =
        titleIconPrefSize.width > 0 ? titleMargins.left : 0
    let insetsLeft =
        titleMargins.left + titleIconPrefSize.width + titleIconPadding
    return IntInsets(top: titleMargins.top, left: insetsLeft, bottom: titleMargins.bottom, right: insetsRight)
  }

  private var titleMargins: IntInsets
  private var footnoteContainer: View?
  private var titleIcon: ImageView?
  private var defaultTitle: Label?
  private var customTitle: View?
  private var close: Button?
  
  public init(
    titleMargins: IntInsets,
    contentMargins: IntInsets) {
     
    closeButtonClicked = false
    self.titleMargins = titleMargins
    self.contentMargins = contentMargins
    footnoteMargins = contentMargins
    titleIcon = ImageView()
    defaultTitle = BubbleFrameView.createDefaultTitleLabel(text: String())
    super.init()

    addChild(view: titleIcon!)
    defaultTitle!.isVisible = false
    addChild(view: defaultTitle!)

    self.close = BubbleFrameView.createCloseButton(listener: self)
    self.close!.isVisible = false
#if os(Windows)
    // Windows will automatically create a tooltip for the close button based on
    // the HTCLOSE result from NonClientHitTest().
    self.close!.tooltipText = String()
#endif
    addChild(view: close!)
  }

  public override func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect { 
    let size = getFrameSizeForClientSize(size: clientBounds.size)
    return bubbleBorder!.getBounds(anchorRect: IntRect(), contentsSize: size)
  }

  public override func getClientMask(size: IntSize) -> Path? {
    let radius = bubbleBorder!.borderCornerRadius
    let contentInsets = self.insets
    // If the client bounds don't touch the edges, no need to mask.
    if min(contentInsets.top, contentInsets.left,
            contentInsets.bottom, contentInsets.right) > radius {
      return nil
    }
    let rect = FloatRect(IntRect(size: size))
    let path = Path()
    path.addRoundRect(rect, x: Float(radius), y: Float(radius))
    return path
  }

  public override func nonClientHitTest(point: IntPoint) -> HitTest {
    if !bounds.contains(point: point) {
      return .HTNOWHERE
    }
    
    if close!.isVisible && self.close!.mirroredBounds.contains(point: point) {
      return .HTCLOSE
    }

    // Allow dialogs to show the system menu and be dragged.
    if widget!.widgetDelegate!.asDialogDelegate() != nil &&
        widget!.widgetDelegate!.asBubbleDialogDelegate() != nil {
      var bounds = IntRect(contentsBounds)
      bounds.inset(insets: titleMargins)
      var sysRect = IntRect(x: 0, y: 0, width: bounds.x, height: bounds.y)
      sysRect.origin = IntPoint(x: getMirroredXForRect(rect: sysRect), y: 0)
      if sysRect.contains(point: point) {
        return .HTSYSMENU
      }
      if point.y < titleView!.bounds.bottom {
        return .HTCAPTION
      }
    }

    return widget!.clientView!.nonClientHitTest(point: point)
  }

  public override func getWindowMask(size: IntSize) -> Path? {
    
    let windowMask = Path()

    if bubbleBorder!.shadow != BubbleBorder.Shadow.SmallShadow &&
       bubbleBorder!.shadow != BubbleBorder.Shadow.NoShadowOpaqueBorder &&
       bubbleBorder!.shadow != BubbleBorder.Shadow.NoAssets {
      return nil
    }

    // We don't return a mask for windows with arrows unless they use
    // BubbleBorder::NO_ASSETS.
    if bubbleBorder!.shadow != BubbleBorder.Shadow.NoAssets &&
       bubbleBorder!.arrow != BubbleBorder.Arrow.None &&
       bubbleBorder!.arrow != BubbleBorder.Arrow.Float {
      return  nil
    }

    // Use a window mask roughly matching the border in the image assets.
    let borderStrokeSize =
        bubbleBorder!.shadow == BubbleBorder.Shadow.NoAssets ? 0 : 1
    let cornerRadius = bubbleBorder!.borderCornerRadius
    let borderInsets = bubbleBorder!.insets
    var rect = IntRect(
        x: borderInsets.left - borderStrokeSize,
        y: borderInsets.top - borderStrokeSize,
        width: size.width - borderInsets.right + borderStrokeSize,
        height: size.height - borderInsets.bottom + borderStrokeSize)

    if bubbleBorder!.shadow == BubbleBorder.Shadow.NoShadowOpaqueBorder ||
        bubbleBorder!.shadow == BubbleBorder.Shadow.NoAssets {
      windowMask.addRoundRect(FloatRect(rect), x: Float(cornerRadius), y: Float(cornerRadius))
    } else {
      let bottomBorderShadowSize = 2
      rect.bottom += bottomBorderShadowSize
      windowMask.addRect(FloatRect(rect))
    }
    if let path = bubbleBorder!.getArrowPath(bounds: IntRect(size: size)) {
      windowMask.addPath(path, x: 0, y: 0)
    }

    return windowMask
  }

  public override func resetWindowControls() {
    close!.isVisible = widget!.widgetDelegate!.shouldShowCloseButton
  }

  public override func updateWindowIcon() {
    var image = ImageSkia()
    if widget!.widgetDelegate!.shouldShowWindowIcon {
      image = widget!.widgetDelegate!.windowIcon!
    }
    titleIcon!.image = image
  }

  public override func updateWindowTitle() {
    if let title = defaultTitle, let delegate = widget?.widgetDelegate {
      title.isVisible = delegate.shouldShowWindowTitle
      title.text = delegate.windowTitle
    }  // custom_title_'s updates are handled by its creator.
  }

  public override func sizeConstraintsChanged() {}
  
  public func getUpdatedWindowBounds(
    anchorRect: IntRect,
    clientSize: IntSize,
    adjustIfOffscreen: Bool) -> IntRect {
    
    let size = getFrameSizeForClientSize(size: clientSize)
    let arrow = bubbleBorder!.arrow
    if adjustIfOffscreen && BubbleBorder.hasArrow(arrow) {
      // Try to mirror the anchoring if the bubble does not fit on the screen.
      if !BubbleBorder.isArrowAtCenter(arrow) {
        mirrorArrowIfOffScreen(vertical: true, anchorRect: anchorRect, clientSize: size)
        mirrorArrowIfOffScreen(vertical: false, anchorRect: anchorRect, clientSize: size)
      } else {
        let mirrorVertical = BubbleBorder.isArrowOnHorizontal(arrow)
        mirrorArrowIfOffScreen(vertical: mirrorVertical, anchorRect: anchorRect, clientSize: size)
        offsetArrowIfOffScreen(anchorRect: anchorRect, clientSize: size)
      }
    }

    // Calculate the bounds with the arrow in its updated location and offset.
    return bubbleBorder!.getBounds(anchorRect: anchorRect, contentsSize: size)
  }

  // View
  open override func calculatePreferredSize() -> IntSize {
    let clientSize = widget!.clientView!.preferredSize
    return getWindowBoundsForClientBounds(clientBounds: IntRect(size: clientSize)).size
  }

  open override func layout() {
    var bounds = contentsBounds

    bounds.inset(insets: titleMargins)
    
    if bounds.isEmpty {
      return
    }

    var titleLabelRight = bounds.right
    if close!.isVisible {
      // The close button is positioned somewhat closer to the edge of the bubble.
      let closeMargin =
          LayoutProvider.instance().getDistanceMetric(DistanceMetric.CloseButtonMargin)
      close!.position = 
          IntPoint(x: contentsBounds.right - closeMargin - close!.width,
                   y: contentsBounds.y + closeMargin)
      titleLabelRight = min(titleLabelRight, close!.x - closeMargin)
    }

    let titleIconPrefSize = IntSize(titleIcon!.preferredSize)
    let titleIconPadding =
        titleIconPrefSize.width > 0 ? titleMargins.left : 0
    let titleLabelX =
        bounds.x + titleIconPrefSize.width + titleIconPadding

    // TODO(tapted): Layout() should skip more surrounding code when !HasTitle().
    // Currently DCHECKs fail since title_insets is 0 when there is no title.
    //if (DCHECK_IS_ON() && HasTitle()) {
    //if hasTitle {
    //  var titleInsets = getTitleLabelInsetsFromFrame()
    //  if let b = border {
    //    titleInsets += border.insets
    //  }
      //DCHECK_EQ(title_insets.left(), title_label_x);
      //DCHECK_EQ(title_insets.right(), width() - title_label_right);
    //}

    let titleAvailableWidth =
        max(1, titleLabelRight - titleLabelX)
    let titlePreferredHeight = titleView!.getHeightFor(width: titleAvailableWidth)
    let titleHeight =
        max(titleIconPrefSize.height, titlePreferredHeight)
    titleView!.bounds = IntRect(
      x: titleLabelX,
      y: bounds.y + (titleHeight - titlePreferredHeight) / 2,
      width: titleAvailableWidth, 
      height: titlePreferredHeight)

    titleIcon!.bounds = IntRect(
      x: bounds.x, 
      y: bounds.y, 
      width: titleIconPrefSize.width, 
      height: titleHeight)

    // Only account for footnote_container_'s height if it's visible, because
    // content_margins_ adds extra padding even if all child views are invisible.
    if let footnote = footnoteContainer, footnote.isVisible {
      let width = contentsBounds.width
      let height = footnote.getHeightFor(width: width)
      footnote.bounds = 
          IntRect(x: contentsBounds.x, 
                  y: contentsBounds.bottom - height, 
                  width: width, 
                  height: height)
    }    
  }

  open override func onPaint(canvas: Canvas) {
    onPaintBackground(canvas: canvas)
  }

  open override func paintChildren(info paintInfo: PaintInfo) {
    super.paintChildren(info: paintInfo)
    //let paintCache = PaintCache()
    let recorder = PaintRecorder(
      context: paintInfo.context, 
      recordingSize: paintInfo.paintRecordingSize,
      scaleX: paintInfo.paintRecordingScaleX,
      scaleY: paintInfo.paintRecordingScaleY,
      cache: nil)//paintCache)
    onPaintBorder(canvas: recorder.canvas)
  }

  open override func onThemeChanged(theme: Theme) {
    updateWindowTitle()
    resetWindowControls()
    updateWindowIcon()

    if let border = bubbleBorder, border.useThemeBackgroundColor {
      border.backgroundColor = theme.getSystemColor(id: Theme.ColorId.DialogBackground)
      schedulePaint()
    }
  }

  open override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if !details.isAdd && details.parent === footnoteContainer &&
        footnoteContainer!.childCount == 1 &&
        details.child === footnoteContainer!.childAt(index: 0) {
      // Setting the footnote_container_ to be hidden and null it. This will
      // remove update the bubble to have no placeholder for the footnote and
      // enable the destructor to delete the footnote_container_ later.
      footnoteContainer!.isVisible = false
      footnoteContainer = nil
    }
  }

  public func buttonPressed(sender: Button, event: Event) {
    if sender === close {
      closeButtonClicked = true
      widget!.close()
    }
  }

  public func setFootnoteView(_ newView: View?) {
    guard let view = newView else {
      return
    }

    footnoteContainer = FootnoteContainerView()
    footnoteContainer!.layoutManager = BoxLayout(orientation: BoxOrientation.Vertical, insideBorderInsets: footnoteMargins, betweenChildSpacing: 0)
    footnoteContainer!.background = BackgroundFactory.makeSolidBackground(color: footnoteBackgroundColor)
    footnoteContainer!.border = createSolidSidedBorder(top: 1, left: 0, bottom: 0, right: 0, color: footnoteBorderColor)
    footnoteContainer!.addChild(view: view)
    footnoteContainer!.isVisible = view.isVisible
    addChild(view: footnoteContainer!)
  }

  internal func getAvailableScreenBounds(rect: IntRect) -> IntRect {
    if let display = Screen.getDisplayNearestPoint(point: rect.centerPoint) {
      return display.workArea
    }
    return IntRect()
  }

  private func mirrorArrowIfOffScreen(vertical: Bool,
                                      anchorRect: IntRect,
                                      clientSize: IntSize) {
    let availableBounds = getAvailableScreenBounds(rect: anchorRect)
    let windowBounds = bubbleBorder!.getBounds(anchorRect: anchorRect, contentsSize: clientSize)
    if getOffScreenLength(availableBounds, windowBounds, vertical) > 0 {
      let arrow = bubbleBorder!.arrow
      // Mirror the arrow and get the new bounds.
      bubbleBorder!.arrow = 
          vertical ? BubbleBorder.verticalMirror(arrow) :
                    BubbleBorder.horizontalMirror(arrow)
      let mirrorBounds =
          bubbleBorder!.getBounds(anchorRect: anchorRect, contentsSize: clientSize)
      // Restore the original arrow if mirroring doesn't show more of the bubble.
      // Otherwise it should invoke parent's Layout() to layout the content based
      // on the new bubble border.
      if getOffScreenLength(availableBounds, mirrorBounds, vertical) >=
          getOffScreenLength(availableBounds, windowBounds, vertical) {
        bubbleBorder!.arrow = arrow
      } else {
        if let p = parent {
          p.layout()
        }
        schedulePaint()
      }
    }
  }

  private func offsetArrowIfOffScreen(anchorRect: IntRect,
                                      clientSize: IntSize) {
    let arrow = bubbleBorder!.arrow
    
    // Get the desired bubble bounds without adjustment.
    bubbleBorder!.arrowOffset = 0
    let windowBounds = IntRect(bubbleBorder!.getBounds(anchorRect: anchorRect, contentsSize: clientSize))

    let availableBounds = getAvailableScreenBounds(rect: anchorRect)
    if availableBounds.isEmpty || availableBounds.contains(rect: windowBounds) {
      return
    }

    // Calculate off-screen adjustment.
    let isHorizontal = BubbleBorder.isArrowOnHorizontal(arrow)
    var offscreenAdjust = 0
    if isHorizontal {
      if windowBounds.x < availableBounds.x {
        offscreenAdjust = availableBounds.x - windowBounds.x
      }
      else if windowBounds.right > availableBounds.right {
        offscreenAdjust = availableBounds.right - windowBounds.right
      }
    } else {
      if windowBounds.y < availableBounds.y {
        offscreenAdjust = availableBounds.y - windowBounds.y
      }
      else if windowBounds.bottom > availableBounds.bottom {
        offscreenAdjust = availableBounds.bottom - windowBounds.bottom
      }
    }

    // For center arrows, arrows are moved in the opposite direction of
    // |offscreen_adjust|, e.g. positive |offscreen_adjust| means bubble
    // window needs to be moved to the right and that means we need to move arrow
    // to the left, and that means negative offset.
    bubbleBorder!.arrowOffset = 
        bubbleBorder!.getArrowOffset(borderSize: windowBounds.size) - offscreenAdjust
    if offscreenAdjust > 0 {
      schedulePaint()
    }
  }

  private func getFrameWidthForClientWidth(width clientWidth: Int) -> Int {
    let titleBarWidth = titleView!.minimumSize.width + titleLabelInsetsFromFrame.width
    let clientAreaWidth = clientWidth + contentMargins.width
    let frameWidth = max(titleBarWidth, clientAreaWidth)
    let dialogDelegate = widget!.widgetDelegate!.asDialogDelegate()
    return dialogDelegate != nil && dialogDelegate!.shouldSnapFrameWidth
              ? LayoutProvider.instance().getSnappedDialogWidth(minWidth: frameWidth)
              : frameWidth
  }

  private func getFrameSizeForClientSize(size clientSize: IntSize) -> IntSize {
    let frameWidth = getFrameWidthForClientWidth(width: clientSize.width)
    let clientInsets = getClientInsetsForFrameWidth(width: frameWidth)
    //DCHECK_GE(frameWidth, clientSize.width)
    var size = IntSize(width: frameWidth, height: clientSize.height + clientInsets.height)

    // Only account for footnote_container_'s height if it's visible, because
    // content_margins_ adds extra padding even if all child views are invisible.
    if let footnote = footnoteContainer, footnote.isVisible {
      size.enlarge(width: 0, height: footnote.getHeightFor(width: size.width))
    }

    return size
  }

  private func getClientInsetsForFrameWidth(width frameWidth: Int) -> IntInsets {
    var closeHeight = 0
    if !extendClientIntoTitle && widget!.widgetDelegate!.shouldShowCloseButton {
      let closeMargin =
          LayoutProvider.instance().getDistanceMetric(DistanceMetric.CloseButtonMargin)
      // Note: |close_margin| is not applied on the bottom of the icon.
      closeHeight = closeMargin + close!.height
    }
    if !hasTitle {
      return contentMargins + IntInsets(top: closeHeight, left: 0, bottom: 0, right: 0)
    }

    let iconHeight = titleIcon!.preferredSize.height
    let labelHeight = titleView!.getHeightFor(
      width: frameWidth - titleLabelInsetsFromFrame.width)
    let titleHeight = max(iconHeight, labelHeight) + titleMargins.height
    return contentMargins +
          IntInsets(top: max(titleHeight, closeHeight), left: 0, bottom: 0, right: 0)
  }

}
