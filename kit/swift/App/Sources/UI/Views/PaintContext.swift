// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class PaintContext {

  public var canCheckInvalid: Bool {
    return !invalidation.isEmpty
  }
  
  public private(set) var deviceScaleFactor: Float
  public let isPixelCanvas: Bool
  public let externalDisplayList: Bool
  public let list: DisplayItemList
  var invalidation: IntRect
  var offset: IntVec2

  /// Create a PaintContext that may only repaint the area in the invalidation rect
  public init(list: DisplayItemList, scaleFactor: Float, invalidation: IntRect, isPixelCanvas: Bool, externalDisplayList: Bool = false) {
    self.list = list
    deviceScaleFactor = scaleFactor
    self.invalidation = IntRect.toRoundedRect(invalidation, scale: isPixelCanvas ? scaleFactor : 1.0)
    offset = IntVec2()
    self.isPixelCanvas = isPixelCanvas
    self.externalDisplayList = externalDisplayList
  }

  /// Clone a PaintContext from a existing one with the given offset
  public init(other: PaintContext, offset: IntVec2) {
    list = other.list
    deviceScaleFactor = other.deviceScaleFactor
    invalidation = other.invalidation
    self.offset = other.offset + offset
    self.isPixelCanvas = other.isPixelCanvas
    self.externalDisplayList = other.externalDisplayList
  }

  public func isRectInvalid(bounds: IntRect) -> Bool {
    return invalidation.intersects(rect: bounds + offset)
  }

  func toLayerSpaceBounds(size sizeInContext: IntSize) -> IntRect {
    return IntRect(size: sizeInContext) + offset
  }

}
