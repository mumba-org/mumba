// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class GLXImage {
  var reference: GLXImageRef
  var destroyed: Bool

  public init(size: IntSize, internalFormat: Int) {
    reference = _GLXImageCreate(Int32(size.width), Int32(size.height), Int32(internalFormat))
    destroyed = false
  }

  deinit {
    //_GLXImageFree(reference)
    if !destroyed {
      _GLXImageDestroy(reference)
    }
  }

  public func initialize(pixmap: AcceleratedWidget) -> Bool {
    return Bool(_GLXImageInitialize(reference, pixmap))
  }

}

extension GLXImage : GLImage {

  public var size: IntSize {
    var w: Int32 = 0, h: Int32 = 0
    _GLXImageGetSize(reference, &w, &h)
    return IntSize(width: Int(w), height: Int(h))
  }

  public var internalFormat: UInt {
    return UInt(_GLXImageGetInternalFormat(reference))
  }

  public func destroy() {
    _GLXImageDestroy(reference)
    destroyed = true
  }

  public func bindTexImage(target: UInt) -> Bool {
    return Bool(_GLXImageBindTexImage(reference, Int32(target)))
  }

  public func releaseTexImage(target: UInt) {
    _GLXImageReleaseTexImage(reference, Int32(target))
  }

  public func copyTexImage(target: UInt) -> Bool {
    return Bool(_GLXImageCopyTexImage(reference, Int32(target)))
  }

  public func copyTexSubImage(target: UInt,
                              offset: IntPoint,
                              rect: IntRect) -> Bool {
    return Bool(_GLXImageCopyTexSubImage(reference,
      Int32(target),
      Int32(offset.x),
      Int32(offset.y),
      Int32(rect.x),
      Int32(rect.y),
      Int32(rect.width),
      Int32(rect.height)))
  }

  public func scheduleOverlayPlane(widget: AcceleratedWidget,
                                   zOrder: Int,
                                   transform: OverlayTransform,
                                   boundsRect: IntRect,
                                   cropRect: FloatRect,
                                   enableBlend: Bool) -> Bool {
    return Bool(
      _GLXImageScheduleOverlayPlane(reference,
        widget,
        Int32(zOrder),
        transform.rawValue,
        Int32(boundsRect.x),
        Int32(boundsRect.y),
        Int32(boundsRect.width),
        Int32(boundsRect.height),
        cropRect.x,
        cropRect.y,
        cropRect.width,
        cropRect.height,
        enableBlend.intValue)
    )
  }
}
