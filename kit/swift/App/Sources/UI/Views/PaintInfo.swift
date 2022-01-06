// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

// TODO: PaintInfo should replace just the PaintContext ont the paint process
// of the view
public class PaintInfo {

  public enum ScaleType {
    case uniformScaling
    case scaleWithEdgeSnapping
  }

  public class func createRootPaintInfo(context: PaintContext, size: IntSize) -> PaintInfo {
    return PaintInfo(context: context, size: size)
  }

  public class func createChildPaintInfo(
    info parentPaintInfo: PaintInfo, 
    bounds: IntRect,
    size parentSize: IntSize,
    scaleType: ScaleType,
    isLayer: Bool) -> PaintInfo {
    return PaintInfo(info: parentPaintInfo, bounds: bounds, size: parentSize, scaleType: scaleType, isLayer: isLayer)
  }

  public var paintRecordingSize: IntSize {
    return paintRecordingBounds.size
  }

  public var isPixelCanvas: Bool {
    return context.isPixelCanvas
  }

  public var offsetFromRoot: IntVec2 {
    return paintRecordingBounds.offsetFromOrigin
  }

  public var context: PaintContext {
    return _rootContext ?? _context
  }
  
  public private(set) var paintRecordingBounds: IntRect
  public private(set) var paintRecordingScaleX: Float
  public private(set) var paintRecordingScaleY: Float
  public private(set) var offsetFromParent: IntVec2
  private var _rootContext: PaintContext?
  private var _context: PaintContext

  private init(context: PaintContext, size: IntSize) {
    paintRecordingScaleX = (context.isPixelCanvas ? 
                            context.deviceScaleFactor : 
                            1.0)
    paintRecordingScaleY = self.paintRecordingScaleX
    paintRecordingBounds = scaleToEnclosingRect(
          rect: IntRect(size: size), 
          xScale: self.paintRecordingScaleX, 
          yScale: self.paintRecordingScaleY)
    offsetFromParent = IntVec2()
    _context = PaintContext(other: context, offset: IntVec2())
    _rootContext = context
  }

  private init(info parentPaintInfo: PaintInfo, 
               bounds: IntRect,
               size parentSize: IntSize,
               scaleType: ScaleType,
               isLayer: Bool) {
    paintRecordingScaleX = 1.0
    paintRecordingScaleY = 1.0
    paintRecordingBounds = 
          isLayer
           ? getViewsLayerRecordingBounds(parentPaintInfo.context, bounds)
           : parentPaintInfo.getSnappedRecordingBounds(parentSize: parentSize, childBounds: bounds)

    offsetFromParent = 
         paintRecordingBounds.offsetFromOrigin -
         parentPaintInfo.paintRecordingBounds.offsetFromOrigin

    _context = PaintContext(other: parentPaintInfo.context, offset: offsetFromParent)
    
    if isPixelCanvas {
      if scaleType == .uniformScaling {
        paintRecordingScaleX = context.deviceScaleFactor
        paintRecordingScaleY = context.deviceScaleFactor
      } else if scaleType == .scaleWithEdgeSnapping {
        if bounds.size.width > 0 {
          paintRecordingScaleX = Float(paintRecordingBounds.width) / Float(bounds.size.width)
        }
        if bounds.size.height > 0 {
          paintRecordingScaleY = Float(paintRecordingBounds.height) / Float(bounds.size.height)
        }
      }
    }

  }

  private func getSnappedRecordingBounds(parentSize: IntSize,
                                         childBounds: IntRect) -> IntRect {
    if !isPixelCanvas {
      return childBounds + paintRecordingBounds.offsetFromOrigin
    }

    return getSnappedRecordingBoundsInternal(paintRecordingBounds,
                                             context.deviceScaleFactor,
                                             parentSize, 
                                             childBounds)
  }

}

fileprivate func getSnappedRecordingBoundsInternal(
    _ paintRecordingBounds: IntRect,
    _ deviceScaleFactor: Float,
    _ parentSize: IntSize,
    _ childBounds: IntRect) -> IntRect {
  
  let childOrigin = childBounds.offsetFromOrigin

  let right = childOrigin.x + childBounds.width
  let bottom = childOrigin.y + childBounds.height

  // original: was std::round
  let newX = Int((Float(childOrigin.x) * deviceScaleFactor).rounded())
  let newY = Int((Float(childOrigin.y) * deviceScaleFactor).rounded())

  var newRight: Int
  var newBottom: Int

  let empty = paintRecordingBounds.isEmpty

  if right == parentSize.width && !empty {
    newRight = paintRecordingBounds.width
  } else {
    newRight = Int((Float(right) * deviceScaleFactor).rounded())
  }

  if bottom == parentSize.height && !empty {
    newBottom = paintRecordingBounds.height
  } else {
    newBottom = Int((Float(bottom) * deviceScaleFactor).rounded())
  }

  return IntRect(x: newX + paintRecordingBounds.x,
                 y: newY + paintRecordingBounds.y, 
                 width: newRight - newX,
                 height: newBottom - newY)
}

fileprivate func getViewsLayerRecordingBounds(_ context: PaintContext,
                                              _ childBounds: IntRect) -> IntRect {
  if !context.isPixelCanvas {
    return IntRect(size: childBounds.size)
  }
  
  let boundsSize = getSnappedRecordingBoundsInternal(
    IntRect(), 
    context.deviceScaleFactor, 
    IntSize(), 
    childBounds).size
  
  return IntRect(size: boundsSize)
}
