// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public class NineImagePainter {

  public var isEmpty: Bool {
    return images[0].isNull
  }

  public var minimumSize: FloatSize {
    return isEmpty ? FloatSize() : FloatSize(
      width: images[0].width + images[1].width + images[2].width,
      height: images[0].height + images[3].height + images[6].height)
  }

  var images: [Image]

  public init(images: [Image]) {
    self.images = [Image]()
    for i in 0..<images.count {
     self.images.insert(images[i], at: i)
    }
  }

  public init(image: Image, insets: FloatInsets) {
    self.images = [Image]()
    var regions = [FloatRect]()
    let imageSkia = image as! ImageSkia
    NineImagePainter.getSubsetRegions(image: imageSkia, insets: insets, regions: &regions)
    assert(regions.count == 9)

    for i in 0...9 {
      self.images.insert(ImageSkia.extractSubset(image: imageSkia, subset: regions[i]), at: i)
    }
  }

  // static
  public static func getSubsetRegions(image: ImageSkia,
                                      insets: FloatInsets,
                                      regions: inout [FloatRect]) {
    //assert(image.width >= insets.width)
    //assert(image.height >= insets.height)

    let x: [Float] = [ 0.0, insets.left, image.width - insets.right, image.width]
    let y: [Float] = [ 0.0, insets.top, image.height - insets.bottom, image.height]

    for j in 0...3 {
      for i in 0...3 {
        regions[i + j * 3] = FloatRect(x: x[i], y: y[j], width: x[i + 1] - x[i], height: y[j + 1] - y[j])
      }
    }
  }

  public func paint(canvas: Canvas, bounds: FloatRect) {
    paint(canvas: canvas, bounds: bounds, alpha: UInt8.max)
  }

  public func paint(canvas: Canvas, bounds: FloatRect, alpha: UInt8) {
    let _ = ScopedCanvas(canvas: canvas)

    guard !isEmpty else {
      return
    }

    // Painting and doing layout at physical device pixels to avoid cracks or
    // overlap.
    let scale = canvas.undoDeviceScaleFactor()

    // Since the drawing from the following fill() calls assumes the mapped origin
    // is at (0,0), we need to translate the canvas to the mapped origin.
    let leftInPixels = Int(ceilf(bounds.x * scale))
    let topInPixels =  Int(ceilf(bounds.y * scale))
    let rightInPixels = Int(ceilf(bounds.right * scale))
    let bottomInPixels = Int(ceilf(bounds.bottom * scale))

    let widthInPixels = rightInPixels - leftInPixels
    let heightInPixels = bottomInPixels - topInPixels

    // Since the drawing from the following Fill() calls assumes the mapped origin
    // is at (0,0), we need to translate the canvas to the mapped origin.
    canvas.translate(offset: IntVec2(x: leftInPixels, y: topInPixels))

    var imgs: [ImageSkia] = []//(count: 9, repeatedValue: ImageSkia())
    //assert(arraysize(image) == arraysize(self.images))
    for i in 0..<images.count {
      imgs.insert(images[i] as! ImageSkia , at: i)//.getRepresentation(scale)
      //assert(ims[i].isNull || imgs[i].scale == scale)
    }

    // In case the corners and edges don't all have the same width/height, we draw
    // the center first, and extend it out in all directions to the edges of the
    // images with the smallest widths/heights.  This way there will be no
    // unpainted areas, though some corners or edges might overlap the center.
    var i0w = Int(imgs[0].pixelWidth)
    var i2w = Int(imgs[2].pixelWidth)
    var i3w = Int(imgs[3].pixelWidth)
    var i5w = Int(imgs[5].pixelWidth)
    var i6w = Int(imgs[6].pixelWidth)
    var i8w = Int(imgs[8].pixelWidth)

    var i0h = Int(imgs[0].pixelHeight)
    var i1h = Int(imgs[1].pixelHeight)
    var i2h = Int(imgs[2].pixelHeight)
    var i6h = Int(imgs[6].pixelHeight)
    var i7h = Int(imgs[7].pixelHeight)
    var i8h = Int(imgs[8].pixelHeight)

    i0w = min(i0w, widthInPixels)
    i2w = min(i2w, widthInPixels - i0w)
    i3w = min(i3w, widthInPixels)
    i5w = min(i5w, widthInPixels - i3w)
    i6w = min(i6w, widthInPixels)
    i8w = min(i8w, widthInPixels - i6w)

    i0h = min(i0h, heightInPixels)
    i1h = min(i1h, heightInPixels)
    i2h = min(i2h, heightInPixels)
    i6h = min(i6h, heightInPixels - i0h)
    i7h = min(i7h, heightInPixels - i1h)
    i8h = min(i8h, heightInPixels - i2h)

    let i4x = min(min(i0w, i3w), i6w)
    let i4y = min(min(i0h, i1h), i2h)
    let i4w = max(widthInPixels - i4x - min(min(i2w, i5w), i8w), 0)
    let i4h = max(heightInPixels - i4y - min(min(i6h, i7h), i8h), 0)

    let paint = PaintFlags()
    paint.alpha = alpha

    fill(canvas, imgs[4], i4x, i4y, i4w, i4h, paint)
    fill(canvas, imgs[0], 0, 0, i0w, i0h, paint)
    fill(canvas, imgs[1], i0w, 0, widthInPixels - i0w - i2w, i1h, paint)
    fill(canvas, imgs[2], widthInPixels - i2w, 0, i2w, i2h, paint)
    fill(canvas, imgs[3], 0, i0h, i3w, heightInPixels - i0h - i6h, paint)
    fill(canvas, imgs[5], widthInPixels - i5w, i2h, i5w, heightInPixels - i2h - i8h, paint)
    fill(canvas, imgs[6], 0, heightInPixels - i6h, i6w, i6h, paint);
    fill(canvas, imgs[7], i6w, heightInPixels - i7h, widthInPixels - i6w - i8w, i7h, paint)
    fill(canvas, imgs[8], widthInPixels - i8w, heightInPixels - i8h, i8w, i8h, paint)
  }

}

fileprivate func fill(
  _ c: Canvas,
  _ image: ImageSkia,
  _ x: Int,
  _ y: Int,
  _ w: Int,
  _ h: Int,
  _ paint: PaintFlags) {
  
  guard !image.isNull else {
    return
  }
  
  c.drawImageIntInPixel(bitmap: image.bitmap, dx: x, dy: y, dw: w, dh: h, filter: false, flags: paint)
}