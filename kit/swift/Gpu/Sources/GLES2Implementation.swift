// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import GL

public class GLES2Implementation {

  public static let NoLimit: UInt32 = 0

  public var capabilities: GpuCapabilities

  var reference: GLES2ImplementationRef

  public init(reference: GLES2ImplementationRef) {
    self.reference = reference
    capabilities = GpuCapabilities()
  }

  deinit {
    //_GLES2ImplementationDestroy(reference)
  }
}


extension GLES2Implementation : GLES2Interface {
  public func insertSyncPointCHROMIUM() -> GLuint { return 0 }
  public func getGraphicsResetStatusKHR() -> GLenum { return 0}
  public func traceBeginCHROMIUM(categoryName: String,
                                 traceName: String) {}
}

extension GLES2Implementation : ContextSupport {

  public func signalSyncPoint(syncPoint: UInt32,
                       callback: () -> Void) {}

  public func signalSyncToken(syncToken: SyncToken,
                       callback: () -> Void) {}

  public func signalQuery(query: UInt32, callback: () -> Void) {}

  public func setSurfaceVisible(visible: Bool) {}

  public func setAggressivelyFreeResources(aggressivelyFreeResources: Bool) {}

  public func swap() {}

  public func partialSwapBuffers(subBuffer: IntRect) {}

  public func scheduleOverlayPlane(planeZOrder: Int,
                            planeTransform: OverlayTransform,
                            overlayTextureID: UInt,
                            displayBounds: IntRect,
                            uvRect: FloatRect) {}

  public func insertFutureSyncPointCHROMIUM() -> UInt32 { return 0 }
  public func retireSyncPointCHROMIUM(syncPoint: UInt32) {}
  public func shareGroupTracingGUID() -> UInt64 { return 0 }
}
