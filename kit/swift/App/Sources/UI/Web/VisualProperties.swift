// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import Web

public struct VisualProperties {
  public var screenInfo: ScreenInfo = ScreenInfo()
  public var autoResizeEnabled: Bool = false
  public var minSizeForAutoResize: IntSize = IntSize()
  public var maxSizeForAutoResize: IntSize = IntSize()
  public var newSize: IntSize = IntSize(width: 400, height: 400)
  public var compositorViewportPixelSize: IntSize = IntSize()//IntSize(width: 400, height: 400)
  public var browserControlsShrinkBlinkSize: Bool = true
  public var scrollFocusedNodeIntoView: Bool = false
  public var topControlsHeight: Float = 0.0
  public var bottomControlsHeight: Float = 0.0
  public var localSurfaceId: LocalSurfaceId?
  public var visibleViewportSize: IntSize = IntSize()//IntSize(width: 400, height: 400)
  public var isFullscreenGranted: Bool = false
  public var displayMode: WebDisplayMode = WebDisplayMode.Browser
  public var needsResizeAck: Bool = true
  public var contentSourceId: UInt32 = 0
  public var captureSequenceNumber: UInt32 = 0
}