// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Gpu

public typealias ViewportSelection = Int

public struct GLFrameData {
  public var mailbox: Mailbox
  public var syncToken: SyncToken
  public var size: IntSize
  public var subBufferRect: IntRect

  public init() {
    mailbox = Mailbox()
    syncToken = SyncToken()
    size = IntSize()
    subBufferRect = IntRect()
  }
}

public struct CompositorFrameMetadata {
  public var deviceScaleFactor: Float
  public var rootScrollOffset: FloatVec2
  public var pageScaleFactor: Float
  public var scrollableViewportSize: FloatSize
  public var rootLayerSize: FloatSize
  public var minPageScaleFactor: Float
  public var maxPageScaleFactor: Float
  public var rootOverflowXHidden: Bool
  public var rootOverflowYHidden: Bool
  public var locationBarIffset: FloatVec2
  public var locationBarContentTranslation: FloatVec2
  public var rootBackgroundColor: Color
  public var selection: ViewportSelection
  public var latencyInfo: [LatencyInfo]
  public var satisfiesSequences: [UInt32]

  public init() {
    deviceScaleFactor = 0
    rootScrollOffset = FloatVec2()
    pageScaleFactor = 0
    scrollableViewportSize = FloatSize()
    rootLayerSize = FloatSize()
    minPageScaleFactor = 0
    maxPageScaleFactor = 0
    rootOverflowXHidden = false
    rootOverflowYHidden = false
    locationBarIffset = FloatVec2()
    locationBarContentTranslation = FloatVec2()
    rootBackgroundColor = Color()
    selection = ViewportSelection()
    latencyInfo = [LatencyInfo]()
    satisfiesSequences = [UInt32]()
  }
}

public class CompositorFrame {

  public var metadata: CompositorFrameMetadata {
    get {
      return _metadata
    }
    set {
      _metadata = newValue
      //_CompositorFrameSetMetadata(reference, _metadata.deviceScaleFactor)
      _CompositorFrameSetMetadata(reference)
    }
  }

  public var glFrameData: GLFrameData

  public var reference: CompositorFrameRef
  private var _metadata: CompositorFrameMetadata

  public init(reference: CompositorFrameRef) {
    self.reference = reference
    glFrameData = GLFrameData()
    _metadata = CompositorFrameMetadata()
  }

  deinit {
    _CompositorFrameDestroy(reference)
  }

}
