// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class CompositorDisplay {
   
  public var reference: DisplayRef

  public init(outputSurface: OutputSurface, frameSinkId: FrameSinkId, beginFrameSource: BeginFrameSource) {
    outputSurface.owned = false
    reference = _DisplayCreate(frameSinkId.clientId, frameSinkId.sinkId, outputSurface.reference, beginFrameSource.reference)
  }

  internal init(reference: DisplayRef) {
    self.reference = reference
  }

  deinit {
    _DisplayDestroy(reference)
  }

  public func setVisible(_ visible: Bool) {
    _DisplaySetVisible(reference, visible ? 1 : 0)
  }

  public func resize(size: IntSize) {
    _DisplayResize(reference, CInt(size.width), CInt(size.height))
  }

  public func setColorMatrix(_ matrix: Mat4) {
    _DisplaySetColorMatrix(reference, matrix.reference)
  }

  public func setColorSpace(blendingColorSpace: ColorSpace,
                            deviceColorSpace: ColorSpace) {
   
    // We are setting both to SRGB here. Fix
    _DisplaySetColorSpace(reference, 0, 0)
  }
 

}
