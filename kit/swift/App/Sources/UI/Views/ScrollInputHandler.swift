// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Compositor
import Graphics

public class ScrollInputHandler : InputHandlerClient {

  var inputHandler: InputHandler?

  public init(inputHandler: InputHandler?) {
    self.inputHandler = inputHandler
  }

  // InputHandlerClient
  public func willShutdown() {

  }
  
  public func animate(time: TimeTicks) {

  }
  
  public func mainThreadHasStoppedFlinging() {

  }
  
  public func reconcileElasticOverscrollAndRootScroll() {

  }
  
  public func updateRootLayerStateForSynchronousInputHandler(
      totalScrollOffset: ScrollOffset,
      maxScrollOffset: ScrollOffset,
      scrollableSize: FloatSize,
      pageScaleFactor: Float,
      minPageScaleFactor: Float,
      maxPageScaleFactor: Float) {

  }
  
  public func deliverInputForBeginFrame() {

  }
  
}