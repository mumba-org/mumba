// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class ImageView : View {
  
  public enum Alignment {
    case Leading
    case Center
    case Trailing
  }

  public var imageBounds: IntRect {
    let size = imageSize
    return IntRect(origin: computeImageOrigin(size: size), size: size)
  }

  public var imageSize: IntSize {
    get {
      guard let size = _imageSize else {
        return IntSize(_image.size)
      }
      return size
    }
    set {
      _imageSize = newValue
      preferredSizeChanged()
    }
  }

  open override var className: String {
    return "ImageView"
  }

  public override var paintScaleType: PaintInfo.ScaleType {
    return PaintInfo.ScaleType.uniformScaling
  }

  public var horizontalAlignment: Alignment {
    didSet {
      if horizontalAlignment != oldValue {
        schedulePaint()
      }
    }
  }
  public var verticalAlignment: Alignment {
    didSet {
      if verticalAlignment != oldValue {
        schedulePaint()
      }
    }
  }

  // The underlying image.
  public var image: ImageSkia {
    get {
      return _image
    }
    set {
      if isImageEqual(to: newValue) {
        return
      }

      lastPaintedBitmapPixels = nil
      let prefSize = preferredSize
      _image = newValue
      if prefSize != preferredSize {
        preferredSizeChanged()
      }
      schedulePaint()
    }
  }

  // The current tooltip text.
  public var tooltipText: String
  
  // Scale last painted at.
  var lastPaintScale: Float

  // Address of bytes we last painted. This is used only for comparison, so its
  // safe to cache.
  var lastPaintedBitmapPixels: UnsafeMutableRawPointer?

   // The actual image size.
  var _imageSize: IntSize?
  var _image: ImageSkia

  public override init() {
    self._image = ImageSkia()
    tooltipText = String()
    horizontalAlignment = .Center
    verticalAlignment = .Center
    lastPaintScale = 0.0
    super.init()
  }

  public init(image: ImageSkia) {
    self._image = image
    tooltipText = String()
    horizontalAlignment = .Center
    verticalAlignment = .Center
    lastPaintScale = 0.0     
    super.init()
  }

  public func resetImageSize() {
    _imageSize = nil
  }

  // View
  open override func onPaint(canvas: Canvas) {
    super.onPaint(canvas: canvas)
    onPaintImage(canvas: canvas)
  }

  open override func getTooltipText(p: IntPoint) -> String? {
    if tooltipText.isEmpty {
      return nil
    }

    return tooltipText
  }

  open override func calculatePreferredSize() -> IntSize {
    var size = imageSize
    size.enlarge(width: insets.width, height: insets.height)
    return size
  }

  func onPaintImage(canvas: Canvas) {
    lastPaintScale = canvas.imageScale
    lastPaintedBitmapPixels = nil

    if _image.isNull {
      return
    }

    if imageBounds.isEmpty {
      return
    }
    
    let flags = PaintFlags()

    if imageBounds.size != IntSize(width: Int(_image.width), height: Int(_image.height)) {
      // Resize case
      flags.filterQuality = Paint.FilterQuality.Low
      canvas.drawImageInt(image: _image,
                          sx: 0,
                          sy: 0,
                          sw: Int(_image.width),
                          sh: Int(_image.height),
                          dx: imageBounds.x,
                          dy: imageBounds.y,
                          dw: imageBounds.width,
                          dh: imageBounds.height,
                          filter: true,
                          flags: flags)
    } else {
      canvas.drawImageInt(image: _image, x: imageBounds.x, y: imageBounds.y, flags: flags)
    }
    lastPaintedBitmapPixels = getBitmapPixels(_image, scale: lastPaintScale)
  }

  func isImageEqual(to img: ImageSkia) -> Bool {
    return _image.backedBySameObjectAs(other: img) &&
      lastPaintScale != 0.0 &&
      lastPaintedBitmapPixels == getBitmapPixels(img, scale: lastPaintScale)
  }
  
  func computeImageOrigin(size imageSize: IntSize) -> IntPoint {
    var x: Int = 0
    // In order to properly handle alignment of images in RTL locales, we need
    // to flip the meaning of trailing and leading. For example, if the
    // horizontal alignment is set to trailing, then we'll use left alignment for
    // the image instead of right alignment if the UI layout is RTL.
    var actualHorizAlignment = horizontalAlignment
    if i18n.isRTL() && horizontalAlignment != .Center {
      actualHorizAlignment = (horizontalAlignment == .Leading) ? .Trailing : .Leading
    }

    switch actualHorizAlignment {
      case .Leading:  
        x = insets.left  
      case .Trailing: 
        x = width - insets.right - imageSize.width
      case .Center:
        x = (width - insets.width - imageSize.width) / 2 + insets.left
    }

    var y: Int = 0

    switch verticalAlignment {
      case .Leading:  
        y = insets.top
      case .Trailing: 
        y = height - insets.bottom - imageSize.height
      case .Center:
        y = (height - insets.height - imageSize.height) / 2 + insets.top
    }

    return IntPoint(x: x, y: y)
  }

}

fileprivate func getBitmapPixels(_ img: ImageSkia, scale imageScale: Float) -> UnsafeMutableRawPointer? {
  if img.hasBitmapFor(scale: imageScale) {
    let bitmap = img.getBitmapFor(scale: imageScale)!
    return bitmap.getPixels()
  }
  return nil
}