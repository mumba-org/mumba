// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class Display {

  public var deviceScaleFactor: Float = 1.0
  public var bounds: IntRect = IntRect(width: 1366, height: 744)
  public var workArea: IntRect = IntRect(width: 1366, height: 744)
  public var size: IntSize {
    return bounds.size
  }
  public var sizeInPixel: IntSize {
    return size//scaleToFlooredSize(size, deviceScaleFactor)
  }
  public var colorspace: ColorSpace {
    return ColorSpace()
  }

  public var id: Int64 {
    return 1
  }

  public init() {}
}