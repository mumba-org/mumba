// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public enum InputTopControlsState: Int32 {
 case Shown  = 1
 case Hidden = 2
 case Both   = 3
}

public protocol InputHandlerClient : class {
  func willShutdown()
  func animate(time: TimeTicks)
  func mainThreadHasStoppedFlinging()
  func reconcileElasticOverscrollAndRootScroll()
  func updateRootLayerStateForSynchronousInputHandler(
      totalScrollOffset: ScrollOffset,
      maxScrollOffset: ScrollOffset,
      scrollableSize: FloatSize,
      pageScaleFactor: Float,
      minPageScaleFactor: Float,
      maxPageScaleFactor: Float)
  func deliverInputForBeginFrame()
}

public class InputHandler {

  var reference: InputHandlerRef

  public init(reference: InputHandlerRef) {
    self.reference = reference
  }

  public func getScrollOffsetForLayer(layerId: Int) -> ScrollOffset? {
    var x: Float = 0.0
    var y: Float = 0.0
    if _InputHandlerGetScrollOffsetForLayer(reference, CInt(layerId), &x, &y) == 1 {
      return ScrollOffset(x: x, y: y)
    }
    return nil
  }
  
  public func scrollLayerTo(layerId: Int, offset: ScrollOffset) -> Bool {
    return _InputHandlerScrollLayerTo(reference, CInt(layerId), offset.x, offset.y) == 0 ? false : true
  }
}
