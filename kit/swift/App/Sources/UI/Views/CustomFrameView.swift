// Copyright (c) 2015-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

/// A view that provides the non client frame for windows
/// rendering the non-standard window caption, border and controls

fileprivate let defaultFrameBorderThickness = 4
fileprivate let resizeAreaCornerSize = 16
fileprivate let captionButtonHeightWithPadding = 19
fileprivate let titlebarTopAndBottomEdgeThickness = 2
fileprivate let iconLeftSpacing = 2
fileprivate let titleIconOffsetX = 4
fileprivate let titleCaptionSpacing = 5

fileprivate let defaultColorFrame = Color.fromRGB(66, 116, 201)
fileprivate let defaultColorFrameInactive = Color.fromRGB(161, 182, 228)

// TODO: fix for the real thing

fileprivate let IDR_APP_TOP_LEFT: Int = 1
fileprivate let IDR_APP_TOP_ENTER: Int = 2
fileprivate let IDR_APP_TOP_RIGHT: Int = 3
fileprivate let IDR_ONTENT_RIGHT_SIDE: Int = 4
fileprivate let IDR_ONTENT_BOTTOM_LEFT_ORNER: Int = 5
fileprivate let IDR_ONTENT_BOTTOM_ENTER: Int = 6
fileprivate let IDR_ONTENT_BOTTOM_RIGHT_ORNER: Int = 7
fileprivate let IDR_ONTENT_LEFT_SIDE: Int = 8
fileprivate let IDR_WINDOW_TOP_ENTER: Int = 9
fileprivate let IDR_WINDOW_RIGHT_SIDE: Int = 10
fileprivate let IDR_WINDOW_LEFT_SIDE: Int = 11
fileprivate let IDR_WINDOW_BOTTOM_ENTER: Int = 12
fileprivate let IDR_WINDOW_TOP_LEFT_ORNER: Int = 13
fileprivate let IDR_WINDOW_TOP_RIGHT_ORNER: Int = 14
fileprivate let IDR_WINDOW_BOTTOM_LEFT_ORNER: Int = 15
fileprivate let IDR_WINDOW_BOTTOM_RIGHT_ORNER: Int = 16
fileprivate let IDS_APP_ACCNAME_LOSE: Int = 17
fileprivate let IDR_LOSE: Int = 18
fileprivate let IDR_LOSE_H: Int = 19
fileprivate let IDR_LOSE_P: Int = 20
fileprivate let IDS_APP_ACCNAME_MINIMIZE: Int = 21
fileprivate let IDR_MINIMIZE: Int = 22
fileprivate let IDR_MINIMIZE_H: Int = 23
fileprivate let IDR_MINIMIZE_P: Int = 24
fileprivate let IDS_APP_ACCNAME_MAXIMIZE: Int = 25
fileprivate let IDR_MAXIMIZE: Int = 26
fileprivate let IDR_MAXIMIZE_H: Int = 27
fileprivate let IDR_MAXIMIZE_P: Int = 28
fileprivate let IDS_APP_ACCNAME_RESTORE: Int = 29
fileprivate let IDR_RESTORE: Int = 30
fileprivate let IDR_RESTORE_H: Int = 31
fileprivate let IDR_RESTORE_P: Int = 32
fileprivate let IDR_FRAME: Int = 33
fileprivate let IDR_FRAME_ACTIVE: Int = 34
fileprivate let IDR_FRAME_INACTIVE: Int = 35

public class CustomFrameView: NonClientFrameView,
                              ButtonListener {

  public override var boundsForClientView: IntRect {
    return self.clientViewBounds
  }

  public override var minimumSize: IntSize {
    return frame!.nonClientView!.getWindowBoundsForClientBounds(
      clientBounds: IntRect(size: frame!.clientView!.minimumSize)).size
  }

  public override var maximumSize: IntSize {
    let maxSize = frame!.clientView!.maximumSize
    let convertedSize = frame!.nonClientView!.getWindowBoundsForClientBounds(
      clientBounds: IntRect(size: maxSize)).size
    return IntSize(width: maxSize.width == 0 ? 0 : convertedSize.width,
                   height: maxSize.height == 0 ? 0 : convertedSize.height)
  }

  // private stuff
  private var frameBorderThickness: Int {
    return frame!.isMaximized ? 0 : defaultFrameBorderThickness
  }

  private var nonClientBorderThickness: Int {
    return frameBorderThickness +
      (shouldShowClientEdge ? NonClientFrameView.clientEdgeThickness : 0)
  }

  private var nonClientTopBorderHeight: Int {
    return max(frameBorderThickness + iconSize,
                  captionButtonY + captionButtonHeightWithPadding) +
      titlebarBottomThickness
  }

  private var captionButtonY: Int {
#if os(Linux)
  return frameBorderThickness
#else
  return frame!.isMaximized ? frameBorderThickness : NonClientFrameView.frameShadowThickness
#endif
  }

  private var titlebarBottomThickness: Int {
    return titlebarTopAndBottomEdgeThickness +
      (shouldShowClientEdge ? NonClientFrameView.clientEdgeThickness : 0)
  }

  private var iconSize: Int {
#if os(Windows)
    return Display.Win.ScreenWin.getSystemMetricsInDIP(SM_YSMICON)
#else
    let iconMinimumSize = 16
    return max(getTitleFontList().height, iconMinimumSize)
#endif
  }

  private var iconBounds: IntRect {
    let size = iconSize
    let frameThickness = self.frameBorderThickness
    let unavailablePxAtTop = frame!.isMaximized ?
        frameThickness : titlebarTopAndBottomEdgeThickness
    let y = unavailablePxAtTop + (nonClientTopBorderHeight -
        unavailablePxAtTop - size - titlebarBottomThickness + 1) / 2
    return IntRect(x: frameThickness + iconLeftSpacing + minimumTitleBarX,
                   y: y, 
                   width: size, 
                   height: size)
  }

  private var shouldShowTitleBarAndBorder: Bool {
    if frame!.isFullscreen {
      return false
    }

    //if let views = ViewsDelegate.instance {
      return !ViewsDelegate.instance.windowManagerProvidesTitleBar(
          maximized: frame!.isMaximized)
    //}

    //return true
  }

  private var shouldShowClientEdge: Bool {
    return !frame!.isMaximized && shouldShowTitleBarAndBorder
  }

  
  private var frameColor: Color {
    return frame!.isActive ? defaultColorFrame : defaultColorFrameInactive
  }

  private var frameImage: ImageSkia {
    return ResourceBundle
              .getImage(frame!.isActive ? IDR_FRAME
                                        : IDR_FRAME_INACTIVE)!
  }
  
  private var clientViewBounds: IntRect = IntRect()

  private var titleBounds: IntRect = IntRect()

  private var windowIcon: ImageButton?

  private var minimizeButton: ImageButton?
  private var maximizeButton: ImageButton?
  private var restoreButton: ImageButton?
  private var closeButton: ImageButton?
  private var frameBackground: FrameBackground
  private var minimumTitleBarX: Int
  private var maximumTitleBarX: Int
  private var active: Bool = false

  weak var frame: UIWidget?

  public override init() {
    frameBackground = FrameBackground()
    minimumTitleBarX = 0
    maximumTitleBarX = -1
    super.init()
  }

  public func initialize(frame: UIWidget) {
    self.frame = frame
   
    self.closeButton = initWindowCaptionButton(IDS_APP_ACCNAME_LOSE,
        IDR_LOSE, IDR_LOSE_H, IDR_LOSE_P)
    self.minimizeButton = initWindowCaptionButton(IDS_APP_ACCNAME_MINIMIZE,
        IDR_MINIMIZE, IDR_MINIMIZE_H, IDR_MINIMIZE_P)
    self.maximizeButton = initWindowCaptionButton(IDS_APP_ACCNAME_MAXIMIZE,
        IDR_MAXIMIZE, IDR_MAXIMIZE_H, IDR_MAXIMIZE_P)
    self.restoreButton = initWindowCaptionButton(IDS_APP_ACCNAME_RESTORE,
        IDR_RESTORE, IDR_RESTORE_H, IDR_RESTORE_P)

    if frame.widgetDelegate!.shouldShowWindowIcon {
      self.windowIcon = ImageButton(listener: self)
      addChild(view: self.windowIcon!)
    }
  }

  public override func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect {
    let topHeight = nonClientTopBorderHeight
    let borderThickness = nonClientBorderThickness
    return IntRect(x: clientBounds.x - borderThickness,
                   y: clientBounds.y - topHeight,
                   width: clientBounds.width + (2 * borderThickness),
                   height: clientBounds.height + topHeight + borderThickness) 
  }

  public override func nonClientHitTest(point: IntPoint) -> HitTest {
    if !bounds.contains(point: point) {
      return .HTNOWHERE
    }

    let frameComponent = frame!.clientView!.nonClientHitTest(point: point)

    var sysmenuRect: IntRect = iconBounds
    
    if frame!.isMaximized {
      sysmenuRect.set(x: 0, y: 0, width: sysmenuRect.right, height: sysmenuRect.bottom)
    }
    sysmenuRect.x = getMirroredXForRect(rect: sysmenuRect)
    
    if sysmenuRect.contains(point: point) {
      return (frameComponent == .HTCLIENT) ? .HTCLIENT : .HTSYSMENU
    }

    if frameComponent != .HTNOWHERE {
      return frameComponent
    }

    if self.closeButton!.mirroredBounds.contains(point: point) {
      return .HTCLOSE
    }
    if self.restoreButton!.mirroredBounds.contains(point: point) {
      return .HTMAXBUTTON
    }
    if self.maximizeButton!.mirroredBounds.contains(point: point) {
      return .HTMAXBUTTON
    }
    if self.minimizeButton!.mirroredBounds.contains(point: point) {
      return .HTMINBUTTON
    }
    if let icon = self.windowIcon, icon.mirroredBounds.contains(point: point) {
      return .HTSYSMENU
    }

    let windowComponent = getHTComponentForFrame(
        point: point,
        topResizeBorderHeight: frameBorderThickness,
        resizeBorderThickness: nonClientBorderThickness,
        topResizeCornerHeight: resizeAreaCornerSize,
        resizeCornerWidth: resizeAreaCornerSize,
        canResize: frame!.widgetDelegate!.canResize)
    
    return (windowComponent == .HTNOWHERE) ? .HTCAPTION : windowComponent
  }

  public override func getWindowMask(size: IntSize) -> Path? {
    let windowMask = Path()
    if frame!.isMaximized || !shouldShowTitleBarAndBorder {
      return nil
    }
    getDefaultWindowMask(size: size, scale: frame!.compositor!.deviceScaleFactor, windowMask: windowMask)
    return windowMask
  }

  public override func resetWindowControls() {
    self.restoreButton!.state = Button.State.Normal
    self.minimizeButton!.state = Button.State.Normal
    self.maximizeButton!.state = Button.State.Normal
  }

  public override func updateWindowIcon() {
    if let icon = self.windowIcon {
      icon.schedulePaint()
    }
  }
  
  public override func updateWindowTitle() {
    if frame!.widgetDelegate!.shouldShowWindowTitle {
      schedulePaintInRect(rect: self.titleBounds)
    }
  }
  
  public override func sizeConstraintsChanged() {
    resetWindowControls()
    layoutWindowControls()
  }

  public override func activationChanged(active: Bool) {
    if self.active == active {
      return
    }
    self.active = active
    schedulePaint()
  }

  open override func layout() {
    if shouldShowTitleBarAndBorder {
      layoutWindowControls()
      layoutTitleBar()
    }
    layoutClientView()
  }

  open override func onPaint(canvas: Canvas) {
    if !shouldShowTitleBarAndBorder {
      return
    }

    frameBackground.frameColor = frameColor
    frameBackground.useCustomFrame = true
    frameBackground.isActive = shouldPaintAsActive()
    let image = frameImage
    frameBackground.themeImage = image
    frameBackground.topAreaHeight = Int(image.height)

    if frame!.isMaximized {
      paintMaximizedFrameBorder(canvas: canvas)
    } else {
      paintRestoredFrameBorder(canvas: canvas)
    }
    paintTitleBar(canvas: canvas)
    if shouldShowClientEdge {
      paintRestoredClientEdge(canvas: canvas)
    }
  }

  open override func calculatePreferredSize() -> IntSize {
    return frame!.nonClientView!.getWindowBoundsForClientBounds(
      clientBounds: IntRect(size: frame!.clientView!.preferredSize)).size
  }

  public func buttonPressed(sender: Button, event: Event) {
    if sender === self.closeButton {
      frame!.close()
    } else if sender === self.minimizeButton {
      frame!.minimize()
    } else if sender === self.maximizeButton {
      frame!.maximize()
    } else if sender === self.restoreButton {
      frame!.restore()
    }
  }

  // private stuff
  private func paintRestoredFrameBorder(canvas: Canvas) {
    frameBackground.setCornerImages(
        topLeft: ResourceBundle.getImage(IDR_WINDOW_TOP_LEFT_ORNER)!.toImageSkia(),
        topRight: ResourceBundle.getImage(IDR_WINDOW_TOP_RIGHT_ORNER)!.toImageSkia(),
        bottomLeft: ResourceBundle.getImage(IDR_WINDOW_BOTTOM_LEFT_ORNER)!.toImageSkia(),
        bottomRight: ResourceBundle.getImage(IDR_WINDOW_BOTTOM_RIGHT_ORNER)!.toImageSkia())
    frameBackground.setSideImages(
        left: ResourceBundle.getImage(IDR_WINDOW_LEFT_SIDE)!.toImageSkia(),
        top: ResourceBundle.getImage(IDR_WINDOW_TOP_ENTER)!.toImageSkia(),
        right: ResourceBundle.getImage(IDR_WINDOW_RIGHT_SIDE)!.toImageSkia(),
        bottom: ResourceBundle.getImage(IDR_WINDOW_BOTTOM_ENTER)!.toImageSkia())

    frameBackground.paintRestored(canvas: canvas, view: self)
  }

  private func paintMaximizedFrameBorder(canvas: Canvas) {
    frameBackground.paintMaximized(canvas: canvas, view: self)

    

    let titlebarBottom = ResourceBundle.getImage(IDR_APP_TOP_ENTER)!.toImageSkia()
    let edgeHeight = Int(titlebarBottom.height) -
        (shouldShowClientEdge ? NonClientFrameView.clientEdgeThickness : 0)
    canvas.tileImageInt(
        image: titlebarBottom, 
        x: 0,
        y: frame!.clientView!.y - edgeHeight, 
        w: self.width, 
        h: edgeHeight)
  }
  
  private func paintTitleBar(canvas: Canvas) {
    guard let delegate = frame!.widgetDelegate, delegate.shouldShowWindowTitle else {
      return
    }
    
    var rect = self.titleBounds
    rect.x = getMirroredXForRect(rect: self.titleBounds)
    canvas.drawStringRect(text: delegate.windowTitle, font: getTitleFontList(),
                          color: Color.White, rect: FloatRect(rect))
  }
  
  private func paintRestoredClientEdge(canvas: Canvas) {
    let clientAreaBounds = frame!.clientView!.bounds
    var shadowedAreaBounds = clientAreaBounds
    shadowedAreaBounds.inset(insets: IntInsets(top: 1, left: 1, bottom: 1, right: 1))
    let shadowedAreaTop = shadowedAreaBounds.y

    

    /// Top: left, center, right sides.
    let topLeft = ResourceBundle.getImageSkia(IDR_APP_TOP_LEFT)!
    let topCenter = ResourceBundle.getImageSkia(IDR_APP_TOP_ENTER)!
    let topRight = ResourceBundle.getImageSkia(IDR_APP_TOP_RIGHT)!
    let topEdgeY = shadowedAreaTop - Int(topCenter.height)
    canvas.drawImageInt(image: topLeft,
                        x: shadowedAreaBounds.x - Int(topLeft.width),
                        y: topEdgeY)
    canvas.tileImageInt(image: topCenter,
                        x: shadowedAreaBounds.x,
                        y: topEdgeY,
                        w: shadowedAreaBounds.width,
                        h: Int(topCenter.height))
    canvas.drawImageInt(image: topRight, x: shadowedAreaBounds.right, y: topEdgeY)

    /// Right side.
    let right = ResourceBundle.getImageSkia(IDR_ONTENT_RIGHT_SIDE)!
    let shadowedAreaBottom =
        max(shadowedAreaTop, shadowedAreaBounds.bottom)
    let shadowedAreaHeight = shadowedAreaBottom - shadowedAreaTop
    canvas.tileImageInt(image: right,
                        x: shadowedAreaBounds.right,
                        y: shadowedAreaTop,
                        w: Int(right.width),
                        h: shadowedAreaHeight)

    /// Bottom: left, center, right sides.
    let bottomLeft =
        ResourceBundle.getImageSkia(IDR_ONTENT_BOTTOM_LEFT_ORNER)!
    let bottomCenter =
        ResourceBundle.getImageSkia(IDR_ONTENT_BOTTOM_ENTER)!
    let bottomRight =
        ResourceBundle.getImageSkia(IDR_ONTENT_BOTTOM_RIGHT_ORNER)!

    canvas.drawImageInt(image: bottomLeft,
                        x: shadowedAreaBounds.x - Int(bottomLeft.width),
                        y: shadowedAreaBottom)

    canvas.tileImageInt(image: bottomCenter,
                        x: shadowedAreaBounds.x,
                        y: shadowedAreaBottom,
                        w: shadowedAreaBounds.width,
                        h: Int(bottomRight.height))

    canvas.drawImageInt(image: bottomRight,
                        x: shadowedAreaBounds.right,
                        y: shadowedAreaBottom)
    /// Left side.
    let left = ResourceBundle.getImageSkia(IDR_ONTENT_LEFT_SIDE)!
    canvas.tileImageInt(image: left,
                        x: shadowedAreaBounds.x - Int(left.width),
                        y: shadowedAreaTop,
                        w: Int(left.width),
                        h: shadowedAreaHeight)
  }

  private func layoutWindowControls() {
    minimumTitleBarX = 0
    maximumTitleBarX = self.width

    if bounds.isEmpty {
      return
    }

    let captionY = captionButtonY
    let isMaximized = frame!.isMaximized
   
    let extraWidth = isMaximized ?
        (frameBorderThickness - NonClientFrameView.frameShadowThickness) : 0
    var nextButtonX = frameBorderThickness

    let isRestored = !isMaximized && !frame!.isMinimized
    let invisibleButton = isRestored ? self.restoreButton!
                                     : self.maximizeButton!
    invisibleButton.isVisible = false

    let buttonOrder = WindowButtonOrderProvider.instance
    let leadingButtons: [FrameButton] = buttonOrder.leadingButtons
    let trailingButtons: [FrameButton] = buttonOrder.trailingButtons

    //var button: ImageButton?

    for (index, frameButton) in leadingButtons.enumerated() {
      guard let button = getImageButton(button: frameButton) else {
        continue
      }

      var targetBounds = IntRect(origin: IntPoint(x: nextButtonX, y: captionY), size: button.preferredSize)
      if index == 0 {
        targetBounds.width = targetBounds.width + extraWidth
      }
      layoutButton(button: button, bounds: targetBounds)
      nextButtonX += button.width
      minimumTitleBarX = min(self.width, nextButtonX)
    }

    nextButtonX = self.width - frameBorderThickness
    
    for (index, frameButton) in trailingButtons.reversed().enumerated() {
      guard let button = getImageButton(button: frameButton) else {
        continue
      }
      var targetBounds = IntRect(origin: IntPoint(x: nextButtonX, y: captionY), size: button.preferredSize)
      if index == 0 {
        targetBounds.width = targetBounds.width + extraWidth
      }
      targetBounds.offset(horizontal: -targetBounds.width, vertical: 0)
      layoutButton(button: button, bounds: targetBounds)
      nextButtonX = button.x
      maximumTitleBarX = max(minimumTitleBarX, nextButtonX)
    }
    
  }

  private func layoutTitleBar() {
    let iconRect = self.iconBounds
    let showWindowIcon = self.windowIcon != nil
    if showWindowIcon {
      self.windowIcon!.bounds = iconRect
    }
    
    if !frame!.widgetDelegate!.shouldShowWindowTitle {
      return
    }

    let titleX = showWindowIcon ? iconRect.right + titleIconOffsetX
                                : iconRect.x
    let titleHeight = getTitleFontList().height
   
    titleBounds.set(
        x: titleX,
        y: iconRect.y + ((iconRect.height - titleHeight - 1) / 2),
        width: max(0, maximumTitleBarX - titleCaptionSpacing - titleX), 
        height: titleHeight)
  }
  
  private func layoutClientView() {
    if !shouldShowTitleBarAndBorder {
      clientViewBounds = bounds
      return
    }

    let topHeight = nonClientTopBorderHeight
    let borderThickness = nonClientBorderThickness
    clientViewBounds.set(
        x: borderThickness, 
        y: topHeight,
        width: max(0, self.width - (2 * borderThickness)),
        height: max(0, height - topHeight - borderThickness))
  }

  private func initWindowCaptionButton(_ accessibilityStringId: Int,
                                       _ normalImageId: Int,
                                       _ hotImageId: Int,
                                       _ pushedImageId: Int) -> ImageButton? {
    
    let button = ImageButton(listener: self)
    button.accessibleName = l10n.getStringUTF16(accessibilityStringId)
    button.setImage(state: Button.State.Normal,
                    image: ResourceBundle.getImageSkia(normalImageId)!)
    button.setImage(state: Button.State.Hovered,
                    image: ResourceBundle.getImageSkia(hotImageId)!)
    button.setImage(state: Button.State.Pressed,
                    image: ResourceBundle.getImageSkia(pushedImageId)!)
    addChild(view: button)
    return button
  }

  private func getImageButton(button frameButton: FrameButton) -> ImageButton? {
    var button: ImageButton?
    switch frameButton {
      case FrameButton.minimize:
        button = self.minimizeButton
        let shouldShow = frame!.widgetDelegate!.canMinimize
        button!.isVisible = shouldShow
        if !shouldShow {
          return nil
        }
      case FrameButton.maximize:
        let isRestored = !frame!.isMaximized && !frame!.isMinimized
        button = isRestored ? self.maximizeButton : self.restoreButton
        let shouldShow = frame!.widgetDelegate!.canMaximize
        button!.isVisible = shouldShow
        if !shouldShow {
          return nil
        }
      case FrameButton.close:
        button = self.closeButton
    }
    return button
  }

}

fileprivate func getTitleFontList() -> FontList {
  let titleFontList = FontList()//UIWidget.getWindowTitleFontList()
      //NativeWidgetPrivate.getWindowTitleFontList()
  return titleFontList
}

fileprivate func layoutButton(button: ImageButton, bounds: IntRect) {
  button.isVisible = true
  button.setImageAlignment(horizontal: .left,
                           vertical: .bottom)
  button.bounds = bounds
}