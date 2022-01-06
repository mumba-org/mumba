// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let borderPaddingDueToRoundedCorners: Int = 1

public class MenuScrollViewContainer : View {

  public private(set) var scrollDownButton: View
  public private(set) var scrollUpButton: View
  public var hasBubbleBorder: Bool {
    return arrow != BubbleBorder.Arrow.None
  }
  public var bubbleArrowOffset: Int {
    
    get {
      guard let border = bubbleBorder else {
        return -1
      }
      return border.arrowOffset
    }

    set {
      guard let border = bubbleBorder else {
        return
      }
      border.arrowOffset = newValue
    }

  }

  var scrollView: MenuScrollView
  weak var contentView: SubmenuView?
  var arrow: BubbleBorder.Arrow
  var bubbleBorder: BubbleBorder?
 
  public init(contentView: SubmenuView) {
    self.contentView = contentView
    self.arrow = BubbleBorder.Arrow.None
    scrollUpButton = MenuScrollButton(host: contentView, isUp: true)
    scrollDownButton = MenuScrollButton(host: contentView, isUp: false)
    scrollView = MenuScrollView(child: contentView)
    
    super.init()
    addChild(view: scrollUpButton)
    addChild(view: scrollDownButton)

    addChild(view: scrollView)

    arrow = bubbleBorderTypeFromAnchor(
      anchor: contentView.menuItem!.controller!.anchorPosition)

    if arrow != BubbleBorder.Arrow.None {
      createBubbleBorder()
    } else {
      createDefaultBorder()
    }
  }

  public override func calculatePreferredSize() -> IntSize {
    var prefsize = scrollView.contents.preferredSize
    prefsize.enlarge(width: insets.width, height: insets.height)
    return prefsize
  }

  public override func layout() {
    let x = insets.left
    let y = insets.top
    let width = super.width - insets.width
    var contentHeight = height - insets.height
    if !scrollUpButton.isVisible {
      scrollView.bounds = IntRect(x: x, y: y, width: width, height: contentHeight)
      scrollView.layout()
      return
    }

    var pref = scrollUpButton.preferredSize
    scrollUpButton.bounds = IntRect(x: x, y: y, width: width, height: pref.height)
    contentHeight = contentHeight - pref.height

    let scrollViewY = y + pref.height

    pref = scrollDownButton.preferredSize
    scrollDownButton.bounds = IntRect(x: x, y: height - pref.height - insets.top, width: width, height: pref.height)
    contentHeight = contentHeight - pref.height

    scrollView.bounds = IntRect(x: x, y: scrollViewY, width: width, height: contentHeight)
    scrollView.layout()
  }

  public override func onThemeChanged(theme: Theme) {
    if arrow == BubbleBorder.Arrow.None {
      createDefaultBorder()
    }
  }

  public override func onPaintBackground(canvas: Canvas) {
    if background != nil {
      super.onPaintBackground(canvas: canvas)
      return
    }

    let bounds = IntRect(x: 0, y: 0, width: width, height: height)
    let extra = Theme.ExtraParams()
    let menuConfig = MenuConfig.instance()
    extra.menuBackground.cornerRadius = menuConfig.cornerRadius
    if let controller = contentView!.menuItem?.controller {
      if controller.useTouchableLayout {
        extra.menuBackground.cornerRadius = menuConfig.touchableCornerRadius
      }
    }
    theme.paint(
        canvas: canvas.paintCanvas,
        part: Theme.Part.MenuPopupBackground, 
        state: Theme.State.Normal, 
        rect: bounds, 
        params: extra)
  }

  public override func onBoundsChanged(previousBounds: IntRect) {
    let contentPref = scrollView.contents.preferredSize
    scrollUpButton.isVisible = contentPref.height > height
    scrollDownButton.isVisible = contentPref.height > height
    layout()
  }

  func createDefaultBorder() {
    bubbleBorder = nil

    let menuConfig = MenuConfig.instance()
    let useOuterBorder =
        menuConfig.useOuterBorder || theme.usesHighContrastColors

    let padding = useOuterBorder && menuConfig.cornerRadius > 0
                      ? borderPaddingDueToRoundedCorners
                      : 0

    let verticalInset = menuConfig.menuVerticalBorderSize + padding
    let horizontalInset = menuConfig.menuHorizontalBorderSize + padding

    if useOuterBorder {
      let color = theme.getSystemColor(id: Theme.ColorId.MenuBorderColor)
      border = createBorderPainter(
          painter: RoundRectPainter(borderColor: color, cornerRadius: menuConfig.cornerRadius),
          insets: IntInsets(vertical: verticalInset, horizontal: horizontalInset))
    } else {
      border = createEmptyBorder(top: verticalInset, left: horizontalInset, bottom: verticalInset, right: horizontalInset)
    }
  }

  func createBubbleBorder() {
    bubbleBorder = BubbleBorder(arrow: arrow, shadow: BubbleBorder.Shadow.SmallShadow, color: Color.White)
    if contentView!.menuItem!.controller!.useTouchableLayout {
      let menuConfig = MenuConfig.instance()
      bubbleBorder!.cornerRadius = menuConfig.touchableCornerRadius
      bubbleBorder!.mdShadowElevation = Color(menuConfig.touchableMenuShadowElevation)
      scrollView.contents.border = createEmptyBorder(insets: IntInsets(vertical: menuConfig.verticalTouchableMenuItemPadding, horizontal: 0))
    }

    border = bubbleBorder
    background = BubbleBackground(border: bubbleBorder!)
  }

  func bubbleBorderTypeFromAnchor(anchor: MenuAnchorPosition) -> BubbleBorder.Arrow {
    switch anchor {
      case .BubbleLeft:
        return BubbleBorder.Arrow.RightCenter
      case .BubbleRight:
        return BubbleBorder.Arrow.LeftCenter
      case .BubbleAbove:
        return BubbleBorder.Arrow.BottomCenter
      case .BubbleBelow:
        return BubbleBorder.Arrow.TopCenter
      case .BubbleTouchableAbove:
        fallthrough
      case .BubbleTouchableLeft:
        return BubbleBorder.Arrow.Float
      default:
        return BubbleBorder.Arrow.None
    }
  }
  
}

internal class MenuScrollButton : View {

  weak var host: SubmenuView?
  var isUp: Bool
  var prefHeight: Int
  
  public init(host: SubmenuView, isUp: Bool) {
    self.host = host
    self.isUp = isUp
    prefHeight = MenuItemView.prefMenuHeight
  }

  public override func calculatePreferredSize() -> IntSize {
    return IntSize(width: MenuConfig.instance().scrollArrowHeight * 2 - 1, height: prefHeight)
  }

  public override func onDragEntered(event: DropTargetEvent) {
    if let controller = host?.menuItem?.controller {
      controller.onDragEnteredScrollButton(source: host!, isUp: isUp)
    }
  }

  public override func onDragUpdated(event: DropTargetEvent) -> DragOperation { 
    return .DragNone 
  }
  
  public override func onDragExited() {
    if let controller = host?.menuItem?.controller {
      controller.onDragExitedScrollButton(source: host!)
    }
  }
  
  public override func onPerformDrop(event: DropTargetEvent) -> DragOperation { 
    return .DragNone 
  }

  public override func onPaint(canvas: Canvas) {
    let config = MenuConfig.instance()

    // The background.
    let itemBounds = IntRect(x: 0, y: 0, width: width, height: height)
    let extra = Theme.ExtraParams()
    theme.paint(canvas: canvas.paintCanvas,
                part: Theme.Part.MenuItemBackground,
                state: Theme.State.Normal, 
                rect: itemBounds, 
                params: extra)

    // Then the arrow.
    let x = width / 2
    var y = (height - config.scrollArrowHeight) / 2

    let xLeft = x - config.scrollArrowHeight
    let xRight = x + config.scrollArrowHeight
    var yBottom = 0

    if !isUp {
      yBottom = y
      y = yBottom + config.scrollArrowHeight
    } else {
      yBottom = y + config.scrollArrowHeight
    }
    let path = Path()
    path.fill = Path.Fill.Winding
    path.moveTo(x: x, y: y)
    path.lineTo(x: xLeft, y: yBottom)
    path.lineTo(x: xRight, y: yBottom)
    path.lineTo(x: x, y: y)
    let flags = PaintFlags()
    flags.style = Paint.Style.Fill
    flags.antiAlias = true
    flags.color = config.arrowColor
    canvas.drawPath(path: path, flags: flags)
  }

}

internal class MenuScrollView : View {
  
  public var contents: View {
    return childAt(index: 0)!
  }

  public init(child: View) {
    super.init()
    addChild(view: child)
  }

  public override func scrollRectToVisible(rect: IntRect) {
    
    if localBounds.contains(rect: rect) {
      return
    }

    var dy = 0
    if rect.bottom > localBounds.bottom {
      dy = rect.bottom - localBounds.bottom
    } else {
      dy = rect.y
    }

    let child = contents
    child.y = -max(0, min(child.preferredSize.height - self.height, dy - child.y))

  }

}