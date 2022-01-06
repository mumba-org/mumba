// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import MumbaShims

public class DirectOutputSurface : OutputSurface {

  public override func swapBuffers(frame: CompositorFrame) {
    //let context = contextProvider as! InProcessContextProvider
    //if frame.glFrameData.subBufferRect == IntRect(size: frame.glFrameData.size) {
    //  context.contextSupport.swap()
    //} else {
    //  context.contextSupport.partialSwapBuffers(frame.glFrameData.subBufferRect)
    //}
    //let syncPoint = context.contextGL.insertSyncPointCHROMIUM()
    //context.contextSupport.signalSyncPoint(
    //    syncPoint, callback: self.onSwapBuffersComplete)
    //client!.didSwapBuffers()
    _DirectOutputSurfaceSwapBuffers(self.reference, frame.reference)
  }
}
