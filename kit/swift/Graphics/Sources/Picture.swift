// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Picture {

  private (set) public var approximateBytesUsed: UInt {
    get {
      return UInt(_PictureApproximateBytesUsed(reference))
    }
    set {

    }
  }

  private (set) public var approximateOpCount: Int {
    get {
      return Int(_PictureApproximateOpCount(reference))
    }
    set {

    }
  }

  public var bounds: IntRect {
    var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
    _PictureGetBounds(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }

  public var width: Int {
    return bounds.width
  }

  public var height: Int {
    return bounds.height
  }

  public var reference: PictureRef
  
  public init() {
    reference = _PictureCreate()
  }

  init(reference: PictureRef) {
    self.reference = reference
  }

  deinit {
    _PictureDestroy(reference)
  }

  public func suitableForGpuRasterization(context: GrContext?) -> Bool {
    if context == nil {
      return Bool(_PictureSuitableForGpuRasterization(reference, nil))
    } else {
      return Bool(_PictureSuitableForGpuRasterization(reference, context!.reference))
    }
  }

  public func draw(canvas: Canvas) {
    if let skiaCanvas = canvas.paintCanvas as? SkiaPaintCanvas {
      _PictureDraw(reference, skiaCanvas.nativeCanvas.reference)
    }
  }

}
