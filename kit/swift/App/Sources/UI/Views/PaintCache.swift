// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class PaintCache {

  internal var paintOpBuffer: PaintRecord?

  public init() {}

  public func useCache(context: PaintContext, size sizeInContext: IntSize) -> Bool {
    guard let paintBuf = paintOpBuffer else {
    	return false
    }
  	
    //assert(context.list != nil)
    context.list.startPaint()
    context.list.push(.drawRecord(paintBuf))
    let boundsInLayer: IntRect = context.toLayerSpaceBounds(size: sizeInContext)
    context.list.endPaintOfUnpaired(rect: boundsInLayer)
    return true
  }

}
