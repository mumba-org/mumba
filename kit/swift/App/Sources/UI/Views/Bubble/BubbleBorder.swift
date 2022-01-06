// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let materialDesignCornerRadius = 2
fileprivate let borderThicknessDip = 1

// TODO: fix with the real thing
fileprivate let IDR_BUBBLE_TL = 0
fileprivate let IDR_BUBBLE_T = 1
fileprivate let IDR_BUBBLE_TR = 2
fileprivate let IDR_BUBBLE_L = 3
fileprivate let IDR_BUBBLE_R = 4
fileprivate let IDR_BUBBLE_BL = 5
fileprivate let IDR_BUBBLE_B = 6
fileprivate let IDR_BUBBLE_BR = 7
fileprivate let IDR_BUBBLE_L_ARROW = 8 
fileprivate let IDR_BUBBLE_T_ARROW = 9
fileprivate let IDR_BUBBLE_R_ARROW = 10 
fileprivate let IDR_BUBBLE_B_ARROW = 11
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP_LEFT = 12
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP = 13
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP_RIGHT = 14
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_LEFT = 15
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_RIGHT = 16
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM_LEFT = 17
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM = 18
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM_RIGHT = 19
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_LEFT = 20
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_TOP = 21
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_RIGHT = 22
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_BOTTOM = 23 
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP_LEFT = 24
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP = 25
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP_RIGHT = 26
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_LEFT = 27
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_RIGHT = 28
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM_LEFT = 29
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM = 30
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM_RIGHT = 31 
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_LEFT = 32
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_TOP = 33
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_RIGHT = 34
fileprivate let IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_BOTTOM = 35

fileprivate func enterTop(_ rect: IntRect) -> IntPoint {
  return IntPoint(x: rect.centerPoint.x, y: rect.y)
}

fileprivate func centerBottom(_ rect: IntRect) -> IntPoint {
  return IntPoint(x: rect.centerPoint.x, y: rect.bottom)
}

fileprivate func leftCenter(_ rect: IntRect) -> IntPoint {
  return IntPoint(x: rect.x, y: rect.centerPoint.y)
}

fileprivate func rightCenter(_ rect: IntRect) -> IntPoint {
  return IntPoint(x: rect.right, y: rect.centerPoint.y)
}

public class BorderImages {

  public var borderPainter: Painter?
  public var borderThickness: Int
  public var leftArrow: ImageSkia?
  public var topArrow: ImageSkia?
  public var rightArrow: ImageSkia?
  public var bottomArrow: ImageSkia?
  public var borderInteriorThickness: Int
  public var arrowThickness: Int
  public var arrowInteriorThickness: Int
  public var arrowWidth: Int
  public var cornerRadius: Int
  
  public init(borderImages borderImageIds: [Int]?,
              arrowImages arrowImageIds: [Int]?,
              borderThickness borderInteriorThickness: Int,
              arrowThickness arrowInteriorThickness: Int,
              cornerRadius: Int) {

      borderThickness = borderInteriorThickness
      self.borderInteriorThickness = borderInteriorThickness
      arrowThickness = arrowInteriorThickness
      self.arrowInteriorThickness = arrowInteriorThickness
      arrowWidth = (2 * arrowInteriorThickness)
      self.cornerRadius = cornerRadius

      if let images = borderImageIds {
        borderPainter = PainterFactory.makeImageGridPainter(imageIds: images)
        if let image = ResourceBundle.getImageSkia(images[0]) {
          borderThickness = Int(image.width)
        }
      }

      if let images = arrowImageIds {
        leftArrow = ResourceBundle.getImageSkia(images[0])
        topArrow = ResourceBundle.getImageSkia(images[1])
        rightArrow = ResourceBundle.getImageSkia(images[2])
        bottomArrow = ResourceBundle.getImageSkia(images[3])
        arrowWidth = topArrow != nil ? Int(topArrow!.width) : 0
        arrowThickness = topArrow != nil ? Int(topArrow!.height) : 0
      }

      //leftArrow = ImageSkia()
      //topArrow = ImageSkia()
      //rightArrow = ImageSkia()
      //bottomArrow = ImageSkia()
  }

}

// Bubble border and arrow image resource ids. They don't use the IMAGE_GRID
// macro because there is no center image.
fileprivate let noShadowImages = [
    IDR_BUBBLE_TL, IDR_BUBBLE_T, IDR_BUBBLE_TR,
    IDR_BUBBLE_L,  0,            IDR_BUBBLE_R,
    IDR_BUBBLE_BL, IDR_BUBBLE_B, IDR_BUBBLE_BR ]

fileprivate let noShadowArrows = [
    IDR_BUBBLE_L_ARROW, IDR_BUBBLE_T_ARROW,
    IDR_BUBBLE_R_ARROW, IDR_BUBBLE_B_ARROW
]

fileprivate let bigShadowImages = [
    IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_TOP_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_LEFT,
    0,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM,
    IDR_WINDOW_BUBBLE_SHADOW_BIG_BOTTOM_RIGHT 
]

fileprivate let bigShadowArrows = [
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_TOP,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_BIG_BOTTOM 
]

fileprivate let smallShadowImages = [
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_TOP_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_LEFT,
    0,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM,
    IDR_WINDOW_BUBBLE_SHADOW_SMALL_BOTTOM_RIGHT 
]

fileprivate let smallShadowArrows = [
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_LEFT,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_TOP,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_RIGHT,
    IDR_WINDOW_BUBBLE_SHADOW_SPIKE_SMALL_BOTTOM 
]

fileprivate var borderImages: ContiguousArray<BorderImages?> = ContiguousArray<BorderImages?>(repeating: nil, count: BubbleBorder.Shadow.count)

// Returns the cached BorderImages for the given |shadow| type.
fileprivate func getBorderImages(shadow: BubbleBorder.Shadow) -> BorderImages? {
  var imageSet: BorderImages?
  
  if let images = borderImages[shadow.rawValue] {
    return images
  }
  
  switch shadow {
    case .NoShadow:
      fallthrough
    case .NoShadowOpaqueBorder:
      imageSet = BorderImages(
        borderImages: noShadowImages, 
        arrowImages: noShadowArrows, 
        borderThickness: 6, 
        arrowThickness: 7, 
        cornerRadius: 4)
    case .BigShadow:
      imageSet = BorderImages(
        borderImages: bigShadowImages, 
        arrowImages: bigShadowArrows, 
        borderThickness: 23,
        arrowThickness: 9, 
        cornerRadius: 2)
    case .SmallShadow:
      imageSet = BorderImages(
        borderImages: smallShadowImages, 
        arrowImages: smallShadowArrows, 
        borderThickness: 5, 
        arrowThickness: 6, 
        cornerRadius: 2)
    case .NoAssets:
      imageSet = BorderImages(
        borderImages: nil, 
        arrowImages: nil, 
        borderThickness: 17, 
        arrowThickness: 8, 
        cornerRadius: 2)
  }

  return imageSet!
}

public class BubbleBorder : Border {

  public struct Arrow: OptionSet {

    public let rawValue: Int

    public static let Right        = Arrow(rawValue: 2)
    public static let Bottom       = Arrow(rawValue: 3)
    public static let Vertical     = Arrow(rawValue: 4)
    public static let Center       = Arrow(rawValue: 5)
    public static let TopLeft      = Arrow(rawValue: 1)
    public static let TopRight     = Arrow(rawValue: Arrow.Right.rawValue)
    public static let BottomLeft   = Arrow(rawValue: Arrow.Bottom.rawValue)
    public static let BottomRight  = Arrow(rawValue: Arrow.Bottom.rawValue | Arrow.Right.rawValue)
    public static let LeftTop      = Arrow(rawValue: Arrow.Vertical.rawValue)
    public static let RightTop     = Arrow(rawValue: Arrow.Vertical.rawValue | Arrow.Right.rawValue)
    public static let LeftBottom   = Arrow(rawValue: Arrow.Vertical.rawValue | Arrow.Bottom.rawValue)
    public static let RightBottom  = Arrow(rawValue: Arrow.Vertical.rawValue | Arrow.Bottom.rawValue | Arrow.Right.rawValue)
    public static let TopCenter    = Arrow(rawValue: Arrow.Center.rawValue)
    public static let BottomCenter = Arrow(rawValue: Arrow.Center.rawValue | Arrow.Bottom.rawValue)
    public static let LeftCenter   = Arrow(rawValue: Arrow.Center.rawValue | Arrow.Vertical.rawValue)
    public static let RightCenter  = Arrow(rawValue: Arrow.Center.rawValue | Arrow.Vertical.rawValue | Arrow.Right.rawValue)
    public static let None         = Arrow(rawValue: 17)  // No arrow. Positioned under the supplied rect.
    public static let Float        = Arrow(rawValue: 18)  // No arrow. Centered over the supplied rect.

    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    public static func ^(left: Arrow, right: Arrow) -> Arrow {
      return Arrow(rawValue: left.rawValue ^ right.rawValue)
    }
    public static func |(left: Arrow, right: Arrow) -> Arrow {
      return Arrow(rawValue: left.rawValue | right.rawValue)
    }
    public static func &(left: Arrow, right: Arrow) -> Arrow {
      return Arrow(rawValue: left.rawValue & right.rawValue)
    }
  }

  public enum Shadow : Int {
    case NoShadow = 0
    case NoShadowOpaqueBorder = 1
    case BigShadow = 2
    case SmallShadow = 3
    case NoAssets = 4

    #if os(macOS)
    // On Mac, the native window server should provide its own shadow for
    // windows that could overlap the browser window.
    public static let DialogShadow: Shadow = .NoAssets
#else
    public static let DialogShadow: Shadow = .SmallShadow
#endif


    public static var count: Int {
      return Shadow.NoAssets.rawValue + 1
    }
    
  }

  // The position of the bubble in relation to the anchor.
  public enum BubbleAlignment {
    case AlignArrowToMidAnchor
    case AlignEdgeToAnchorEdge
  }

  // The way the arrow should be painted.
  public enum ArrowPaintType {
    case PaintNormal
    case PaintTransparent
    case PaintNone
  }

  private static let stroke = 1
  public static let shadowBlur = 6
  public static let shadowVerticalOffset = 2

  public var insets: IntInsets {
    guard let imageSet = images else {
      return IntInsets()
    }
    // The insets contain the stroke and shadow pixels outside the bubble fill.
    let inset = borderThickness
    
    if paintArrow != .PaintNormal || !BubbleBorder.hasArrow(arrow) {
      return IntInsets(all: inset)
    }

    var firstInset = inset
    var secondInset = max(inset, imageSet.arrowThickness)
    
    if BubbleBorder.isArrowOnHorizontal(arrow) ? BubbleBorder.isArrowOnTop(arrow) : BubbleBorder.isArrowOnLeft(arrow) {
      // swap
      let mem = secondInset
      secondInset = firstInset
      firstInset = mem
    }
    
    return BubbleBorder.isArrowOnHorizontal(arrow) ?
        IntInsets(top: firstInset, left: inset, bottom: secondInset, right: inset) :
        IntInsets(top: inset, left: firstInset, bottom: inset, right: secondInset)
  }

  public var minimumSize: IntSize {
    return getSizeForContentsSize(contentsSize: IntSize())
  }

  public var borderThickness: Int {
    if let imageSet = images {
      return imageSet.borderThickness - imageSet.borderInteriorThickness
    }
    return 0
  }

  public var borderInteriorThickness: Int {
    get {
      if let imageSet = images {
        return imageSet.borderInteriorThickness
      }
      return 0
    } 
    set {
      if let imageSet = images {
        imageSet.borderInteriorThickness = newValue
        if !BubbleBorder.hasArrow(self.arrow) || self.paintArrow != .PaintNormal {
          imageSet.borderThickness = newValue
        }
      }
    }
  }

  public var borderCornerRadius: Int {
    if let imageSet = images {
      return imageSet.cornerRadius
    }
    return cornerRadius ?? 0
  }

  public var alignment: BubbleAlignment

  public var paintArrow: ArrowPaintType//arrowPaintType: ArrowPaintType

  public var shadow: Shadow

  public var cornerRadius: Int? {
    didSet {
      initialize()
    }
  }

  public var mdShadowElevation: Color?

  public var arrow: Arrow

  public var backgroundColor: Color

  internal var arrowOffset: Int
  
  internal var useThemeBackgroundColor: Bool

  private var images: BorderImages?

  private var arrowImage: ImageSkia? {
    guard let imageSet = images, BubbleBorder.hasArrow(arrow) else {
      return nil
    }
    if BubbleBorder.isArrowOnHorizontal(arrow) {
      return BubbleBorder.isArrowOnTop(arrow) ?
          imageSet.topArrow : imageSet.bottomArrow
    }
    return BubbleBorder.isArrowOnLeft(arrow) ?
        imageSet.leftArrow : imageSet.rightArrow
  }

  private static var shadowMap: [Int: ShadowValues] = [:]
  private static var flagMap: [Int: PaintFlags] = [:]

  public static func hasArrow(_ a: Arrow) -> Bool { 
    return a.rawValue < Arrow.None.rawValue
  }

  public static func isArrowOnLeft(_ a: Arrow) -> Bool {
    return BubbleBorder.hasArrow(a) && (a == Arrow.LeftCenter || (a & (Arrow.Right | Arrow.Center)).rawValue == 0)
  }

  public static func isArrowOnTop(_ a: Arrow) -> Bool {
    return BubbleBorder.hasArrow(a) && (a == Arrow.TopCenter || (a & (Arrow.Bottom | Arrow.Center)).rawValue == 0)
  }

  public static func isArrowOnHorizontal(_ a: Arrow) -> Bool {
    return a.rawValue >= Arrow.None.rawValue ? false : (a & Arrow.Vertical).rawValue == 0
  }

  public static func isArrowAtCenter(_ a: Arrow) -> Bool {
    return BubbleBorder.hasArrow(a) && (a & Arrow.Center).rawValue != 0 //!!(a.rawValue & Arrow.Center.rawValue)
  }

  public static func horizontalMirror(_ a: Arrow) -> Arrow {
    return (a == Arrow.TopCenter || a == Arrow.BottomCenter || a.rawValue >= Arrow.None.rawValue) ?
        a : Arrow(rawValue: a.rawValue ^ Arrow.Right.rawValue)
  }

  public static func verticalMirror(_ a: Arrow) -> Arrow {
    return (a == Arrow.LeftCenter || a == Arrow.RightCenter || a.rawValue >= Arrow.None.rawValue) ?
        a : Arrow(rawValue: a.rawValue ^ Arrow.Bottom.rawValue)
  }

  public static func getBorderAndShadowInsets(elevation: Int?) -> IntInsets {
    if let elevationValue = elevation {
      return -IntInsets(ShadowValue.getMargin(shadows: BubbleBorder.getShadowValues(elevation: elevationValue)))
    }

    let blur = IntInsets(all: shadowBlur + borderThicknessDip)
    let offset = IntInsets(top: -shadowVerticalOffset, left: 0, bottom: shadowVerticalOffset, right: 0)
    return blur + offset
  }

  public init(arrow: Arrow, shadow: Shadow, color: Color) {
    self.arrow = arrow
    paintArrow = .PaintNormal
    alignment = .AlignArrowToMidAnchor
    self.shadow = shadow
    backgroundColor = color
    arrowOffset = 0
    useThemeBackgroundColor = false

    initialize()
  }

  public func paint(view: View, canvas: Canvas) {
    guard let imageSet = images else {
      return
    }

    var bounds = IntRect(view.contentsBounds)
    bounds.inset(horizontal: -self.borderThickness, vertical: -self.borderThickness)
    let arrowBounds = getArrowRect(bounds: view.localBounds)
    if arrowBounds.isEmpty {
      if let borderPainter = imageSet.borderPainter {
        PainterHelper.paintPainterAt(canvas: canvas, painter: borderPainter, rect: bounds)
      }
      return
    }
    if imageSet.borderPainter == nil {
      drawArrow(canvas: canvas, bounds: arrowBounds)
      return
    }

    // Clip the arrow bounds out to avoid painting the overlapping edge area.
    canvas.save()
    canvas.clipRect(rect: arrowBounds, op: ClipOp.difference)
    if let borderPainter = imageSet.borderPainter {
      PainterHelper.paintPainterAt(canvas: canvas, painter: borderPainter, rect: bounds)
    }
    canvas.restore()

    drawArrow(canvas: canvas, bounds: arrowBounds)
  }

  public func getBounds(anchorRect: IntRect,
                        contentsSize: IntSize) -> IntRect {

    guard let imageSet = images else {
      return IntRect()
    }

    var x = anchorRect.x
    var y = anchorRect.y
    let w = anchorRect.width
    let h = anchorRect.height
    let size = getSizeForContentsSize(contentsSize: contentsSize)
    let arrowOffset = getArrowOffset(borderSize: size)
    let strokeWidth = self.shadow == .NoAssets ? 0 : BubbleBorder.stroke
    // |arrow_shift| is necessary to visually align the tip of the bubble arrow
    // with the anchor point. This shift is an inverse of the shadow thickness.
    var arrowShift = imageSet.arrowInteriorThickness + strokeWidth - imageSet.arrowThickness
    // When arrow is painted transparently the visible border of the bubble needs
    // to be positioned at the same bounds as when the arrow is shown.
    if self.paintArrow == .PaintTransparent {
      arrowShift += imageSet.arrowInteriorThickness
    }
    let midAnchor = self.alignment == .AlignArrowToMidAnchor

    // Calculate the bubble coordinates based on the border and arrow settings.
    if BubbleBorder.isArrowOnHorizontal(self.arrow) {
      if BubbleBorder.isArrowOnLeft(self.arrow) {
        x += midAnchor ? w / 2 - arrowOffset
                        : strokeWidth - self.borderThickness
      } else if BubbleBorder.isArrowAtCenter(self.arrow) {
        x += w / 2 - arrowOffset
      } else {
        x += midAnchor ? w / 2 + arrowOffset - size.width
                        : w - size.width + self.borderThickness - strokeWidth
      }
      y += BubbleBorder.isArrowOnTop(self.arrow) ? h + arrowShift
                                  : -arrowShift - size.height
    } else if BubbleBorder.hasArrow(self.arrow) {
      x += BubbleBorder.isArrowOnLeft(self.arrow) ? w + arrowShift
                                    : -arrowShift - size.width
      if BubbleBorder.isArrowOnTop(self.arrow) {
        y += midAnchor ? h / 2 - arrowOffset
                        : strokeWidth - self.borderThickness
      } else if BubbleBorder.isArrowAtCenter(self.arrow) {
        y += h / 2 - arrowOffset
      } else {
        y += midAnchor ? h / 2 + arrowOffset - size.height
                        : h - size.height + borderThickness - strokeWidth
      }
    } else {
      x += (w - size.width) / 2
      y += (self.arrow == .None) ? h : (h - size.height) / 2
    }

    return IntRect(x: x, y: y, width: size.width, height: size.height)
  }

  public func getArrowPath(bounds viewBounds: IntRect) -> Path? {
    if !BubbleBorder.hasArrow(arrow) || paintArrow != .PaintNormal {
      return nil
    }

    return getArrowPathFromArrowBounds(bounds: getArrowRect(bounds: viewBounds))
  }

  public func getArrowOffset(borderSize: IntSize) -> Int {
    guard let imageSet = images else {
      return 0
    }

    let edgeLength = BubbleBorder.isArrowOnHorizontal(self.arrow) ?
        borderSize.width : borderSize.height
    if BubbleBorder.isArrowAtCenter(self.arrow) && arrowOffset == 0 {
      return edgeLength / 2
    }

    // Calculate the minimum offset to not overlap arrow and corner images.
    let minimum = imageSet.borderThickness + (imageSet.arrowWidth / 2)
    // Ensure the returned value will not cause image overlap, if possible.
    return max(minimum, min(self.arrowOffset, edgeLength - minimum))
  }


  private func initialize() {
    images = getBorderImages(shadow: self.shadow)
  }

  private static func getShadowValues(elevation: Int? = nil) -> ShadowValues {
    let mapGuard = 444
    let currentKey = elevation ?? mapGuard
    
    if let result = BubbleBorder.shadowMap[currentKey] {
      return result
    }
    
    //var shadows = ShadowValues()
    //if let elevationValue = elevation {
    //  shadows = ShadowValue.makeMdShadowValues(elevationValue)
    //} else {
    let smallShadowVerticalOffset = 2
    let smallShadowBlur = 4
    var smallShadowColor = Color.Black
    smallShadowColor.a = 0x33
    
    var largeShadowColor = Color.Black
    largeShadowColor.a = 0x1a
    // gfx::ShadowValue counts blur pixels both inside and outside the shape,
    // whereas these blur values only describe the outside portion, hence they
    // must be doubled.
    var shadows = ShadowValues()
    shadows.append(
      ShadowValue(
        offset: FloatVec2(x: 0, y: Float(smallShadowVerticalOffset)), 
        blur:  Double(2 * smallShadowBlur), 
        color: smallShadowColor))
    shadows.append(
      ShadowValue(
        offset: FloatVec2(x: 0, y: Float(shadowVerticalOffset)), 
        blur: Double(2.0 * Double(shadowBlur)),
        color: largeShadowColor))
    //}

    BubbleBorder.shadowMap[currentKey] = shadows
    return BubbleBorder.shadowMap[currentKey]!
  }

  private static func getBorderAndShadowFlags(elevation: Int? = nil) -> PaintFlags {
    let mapGuard = 444
    let currentKey = elevation ?? mapGuard
    
    if let result = BubbleBorder.flagMap[currentKey] {
      return result
    }

    var borderColor = Color.Black
    borderColor.a = 0x26

    let flags = PaintFlags()
    flags.color = borderColor
    flags.antiAlias = true
    flags.looper = DefaultDrawLooperFactory.makeShadow(shadows: BubbleBorder.getShadowValues(elevation: elevation))
    flagMap[currentKey] = flags
    return flagMap[currentKey]!
  }

  private func getSizeForContentsSize(contentsSize: IntSize) -> IntSize {
    guard let imageSet = images else {
      return IntSize()
    }
    
    var size = contentsSize
    let insets = self.insets
    size.enlarge(width: insets.width, height: insets.height)
    
    // Ensure the bubble is large enough to not overlap border and arrow images.
    let min = 2 * imageSet.borderThickness
    // Only take arrow image sizes into account when the bubble tip is shown.
    if paintArrow != .PaintNormal || !BubbleBorder.hasArrow(arrow) {
      size.setToMax(other: IntSize(width: min, height: min))
      return size
    }
    let minWithArrowWidth = min + imageSet.arrowWidth
    let minWithArrowThickness = imageSet.borderThickness +
        max(imageSet.arrowThickness + imageSet.borderInteriorThickness,
            imageSet.borderThickness)
    if BubbleBorder.isArrowOnHorizontal(arrow) {
      size.setToMax(other: IntSize(width: minWithArrowWidth, height: minWithArrowThickness))
    } else {
      size.setToMax(other: IntSize(width: minWithArrowThickness, height: minWithArrowWidth))
    }
    return size
  }

  private func getArrowRect(bounds: IntRect) -> IntRect {
    guard let imageSet = images else {
      return IntRect()
    }

    if !BubbleBorder.hasArrow(arrow) || paintArrow != .PaintNormal {
      return IntRect()
    }

    var origin = IntPoint()
    let offset = getArrowOffset(borderSize: bounds.size)
    let halfLength = imageSet.arrowWidth / 2
  
    if BubbleBorder.isArrowOnHorizontal(arrow) {
      origin.x = BubbleBorder.isArrowOnLeft(arrow) || BubbleBorder.isArrowAtCenter(arrow) ? offset : bounds.width - offset
      origin.offset(x: -halfLength, y: 0)
      if BubbleBorder.isArrowOnTop(arrow) {
        origin.y = insets.top - imageSet.arrowThickness
      } else {
        origin.y = bounds.height - insets.bottom
      }
    } else {
      origin.y = BubbleBorder.isArrowOnTop(arrow) || BubbleBorder.isArrowAtCenter(arrow) ? offset : bounds.height - offset
      origin.offset(x: 0, y: -halfLength)
      if BubbleBorder.isArrowOnLeft(arrow) {
        origin.x = insets.left - imageSet.arrowThickness
      } else {
        origin.x = bounds.width - insets.right
      }
    }

    if shadow != .NoAssets {
      return IntRect(origin: origin, size: IntSize(arrowImage!.size))
    }

    // With no assets, return the size enclosing the path filled in DrawArrow().
    var width = imageSet.arrowWidth
    var height = imageSet.arrowInteriorThickness
    if !BubbleBorder.isArrowOnHorizontal(arrow) {
      // swap
      let mem = width
      width = height
      height = mem
    }
    return IntRect(origin: origin, size: IntSize(width: width, height: height))
  }

  private func getArrowPathFromArrowBounds(bounds arrowBounds: IntRect) -> Path? {
    guard let imageSet = images else {
      return nil
    }

    let horizontal = BubbleBorder.isArrowOnHorizontal(arrow) 
    let thickness = imageSet.arrowInteriorThickness

    let tipX: Float = horizontal ? Float(arrowBounds.centerPoint.x) :
        BubbleBorder.isArrowOnLeft(arrow) ? Float(arrowBounds.right) - Float(thickness) :
                               Float(arrowBounds.x) + Float(thickness)
    let tipY: Float = !horizontal ? Float(arrowBounds.centerPoint.y) + 0.5 :
        BubbleBorder.isArrowOnTop(arrow) ? Float(arrowBounds.bottom) - Float(thickness) :
                              Float(arrowBounds.y) + Float(thickness)
    
    let positiveOffset = horizontal ?
        BubbleBorder.isArrowOnTop(arrow) : BubbleBorder.isArrowOnLeft(arrow)

    let offsetToNextVertex = positiveOffset ?
        imageSet.arrowInteriorThickness : -imageSet.arrowInteriorThickness

    let path = Path()
    //path.incReserve(4)
    path.moveTo(x: tipX, y: tipY)
    path.lineTo(x: tipX + Float(offsetToNextVertex),
                y: tipY + Float(offsetToNextVertex))

    let multiplier = horizontal ? 1 : -1
    path.lineTo(x: tipX - Float(multiplier * offsetToNextVertex),
                y: tipY + Float(multiplier * offsetToNextVertex))
    path.close()

    return path
  }

  private func drawArrow(canvas: Canvas, bounds arrowBounds: IntRect) {
    canvas.drawImageInt(image: self.arrowImage!, x: arrowBounds.x, y: arrowBounds.y)
    if let path = getArrowPathFromArrowBounds(bounds: arrowBounds) {
      let flags = PaintFlags()
      flags.style = Paint.Style.Fill
      flags.color = backgroundColor
      canvas.drawPath(path: path, flags: flags)
    }
  }

  private func getClientRect(view: View) -> FloatRRect {
    var bounds = FloatRect(view.localBounds)
    bounds.inset(insets: FloatInsets(self.insets))
    //           makeRectXY
    return FloatRRect(rect: bounds,
                      x: Float(borderCornerRadius), 
                      y: Float(borderCornerRadius))
  }

  private func paintNoAssets(view: View, canvas: Canvas) {
    let _ = ScopedCanvas(canvas: canvas)
    canvas.clipRRect(getClientRect(view: view), clip: ClipOp.difference, antiAlias: true)
    canvas.drawColor(color: Color.Transparent, mode: BlendMode.Src)
  }

}

public class BubbleBackground : Background {

  var border: BubbleBorder

  public init(border: BubbleBorder) {
    self.border = border
  }

  public func paint(canvas: Canvas, view: View) {

    if border.shadow == .NoShadowOpaqueBorder {
      canvas.drawColor(color: border.backgroundColor)
    }

    // Fill the contents with a round-rect region to match the border images.
    let flags = PaintFlags()
    flags.antiAlias = true
    flags.style = Paint.Style.Fill
    flags.color = border.backgroundColor
    //let path = Path()
    let _ = Path() // ??
    var bounds = FloatRect(view.localBounds)
    bounds.inset(insets: FloatInsets(border.insets))
    canvas.drawRoundRect(rect: bounds, radius: Float(border.borderCornerRadius), flags: flags)
  }

}
