// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public enum VisualStateUpdate { 
  case PrePaint
  case All 
}

public protocol LayerTreeHostClient : class {

  var isForSubframe: Bool { get }

  func willBeginMainFrame()
  func beginMainFrame(args: BeginFrameArgs)
  func beginMainFrameNotExpectedSoon()
  func beginMainFrameNotExpectedUntil(time: TimeTicks)
  func didBeginMainFrame()  
  func updateLayerTreeHost(requestedUpdate: VisualStateUpdate)
  func applyViewportDeltas(
    innerDelta: FloatVec2,
    outerDelta: FloatVec2,
    elasticOverscrollDelta: FloatVec2,
    pageScale: Float,
    topControlsDelta: Float)
  func recordWheelAndTouchScrollingCount(
      hasScrolledByWheel: Bool,
      hasScrolledByTouch: Bool)
  func requestNewLayerTreeFrameSink()
  func didInitializeLayerTreeFrameSink()
  func didFailToInitializeLayerTreeFrameSink()
  func willCommit()
  func didCommit()
  func didCommitAndDrawFrame()
  func didReceiveCompositorFrameAck()
  func didCompletePageScaleAnimation()
}


public protocol LayerTreeHostSingleThreadClient : LayerTreeHostClient {
  func didSubmitCompositorFrame()
  func didLoseLayerTreeFrameSink()
  func requestScheduleComposite()
  func requestScheduleAnimation()
}