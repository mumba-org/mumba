// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class ImageButton : Button {

  public static let viewClassName = "ImageButton"

  public enum HorizontalAlignment {
    case left
    case center
    case right
  }

  public enum VerticalAlignment {
    case top
    case middle
    case bottom
  }

  public var minimumImageSize: IntSize {
    didSet {
      preferredSizeChanged()
    }
  }

  public override var className: String {
    return ImageButton.viewClassName
  }

  public override var paintScaleType: PaintInfo.ScaleType {
    return PaintInfo.ScaleType.uniformScaling
  }

  internal var imageToPaint: ImageSkia {
    var img = ImageSkia()

    if !images[State.Hovered.rawValue].isNull && self.hoverAnimation.isAnimating {
      img = ImageSkia.createBlendedImage(
          first: images[State.Normal.rawValue], 
          second: images[State.Hovered.rawValue],
          alpha: self.hoverAnimation.currentValue)
    } else {
      img = images[self.state.rawValue]
    }

    return !img.isNull ? img : images[State.Normal.rawValue]
  }

  public var drawImageMirrored: Bool

  internal var images: ContiguousArray<ImageSkia>
  internal var backgroundImage: ImageSkia
  private var horizontalAlignment: HorizontalAlignment
  private var verticalAlignment: VerticalAlignment

  fileprivate static let defaultWidth: Int = 16
  fileprivate static let defaultHeight: Int = 14
  
  public init(listener: ButtonListener) {
    backgroundImage = ImageSkia()
    images = ContiguousArray<ImageSkia>(repeating: ImageSkia(), count: Button.State.count)
    minimumImageSize = IntSize()
    horizontalAlignment = .left
    verticalAlignment = .top
    drawImageMirrored = false
    super.init(listener: listener)

    self.focusPainter = PainterFactory.makeDashedFocusPainter()
    enableCanvasFlippingForRTLUI(enable: true)
  }

  public func getImage(state: Button.State) -> ImageSkia {
    return images[state.rawValue]
  }

  public func setImage(state forState: Button.State, image: ImageSkia) {
    if forState == .Hovered {
      animateOnStateChange = !image.isNull
    }
    
    let oldPreferredSize = preferredSize
    images[forState.rawValue] = image

    if oldPreferredSize != preferredSize {
      preferredSizeChanged()
    }

    if self.state == forState {
      schedulePaint() 
    }
  }

  public func setBackgroudImage(color: Color, image: ImageSkia?, mask: ImageSkia?) {
    if image == nil || mask == nil {
      backgroundImage = ImageSkia()
      return
    }
    backgroundImage = ImageSkia.createButtonBackground(color: color, image: image!, mask: mask!)
  }

  public func setImageAlignment(horizontal: HorizontalAlignment, vertical: VerticalAlignment) {
    self.horizontalAlignment = horizontal
    self.verticalAlignment = vertical
    schedulePaint()
  }

  open override func calculatePreferredSize() -> IntSize {
    var size = IntSize(width: ImageButton.defaultWidth, height: ImageButton.defaultHeight)
    if !images[State.Normal.rawValue].isNull {
      size = IntSize(width: Int(images[State.Normal.rawValue].width),
                     height: Int(images[State.Normal.rawValue].height))
    }
    size.setToMax(other: minimumImageSize)
    size.enlarge(width: self.insets.width, height: self.insets.height)
    return size
  }

  internal override func paintButtonContents(canvas: Canvas) {
    let img = imageToPaint
    if !img.isNull {
      let _ = ScopedCanvas(canvas: canvas)
      if drawImageMirrored {
        canvas.translate(offset: IntVec2(x: width, y: 0))
        canvas.scale(x: -1, y: 1)
      }

      let position = computeImagePaintPosition(image: img)
      if !backgroundImage.isNull {
        canvas.drawImageInt(image: self.backgroundImage, x: position.x, y: position.y)
      }

      canvas.drawImageInt(image: img, x: position.x, y: position.y)
    }
  }

  private func computeImagePaintPosition(image: ImageSkia) -> IntPoint {
    var x = 0
    var y = 0
    let rect = contentsBounds

    var hAlignment = self.horizontalAlignment
    let vAlignment = self.verticalAlignment

    if self.drawImageMirrored {
      if hAlignment == .right {
        hAlignment = .left
      } else if hAlignment == .left {
        hAlignment = .right
      }
    }

    if hAlignment == .center {
      x = (rect.width - Int(image.width)) / 2
    } else if hAlignment == .right {
      x = rect.width - Int(image.width)
    }

    if vAlignment == .middle {
      y = (rect.height - Int(image.height)) / 2
    } else if vAlignment == .bottom {
      y = rect.height - Int(image.height)
    }

    x += rect.x
    y += rect.y

    return IntPoint(x: x, y: y)
  }

}