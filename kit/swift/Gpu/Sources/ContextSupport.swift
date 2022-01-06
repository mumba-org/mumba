// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol ContextSupport {

  func signalSyncPoint(syncPoint: UInt32,
                       callback: () -> Void)

  func signalSyncToken(syncToken: SyncToken,
                       callback: () -> Void)

  func signalQuery(query: UInt32, callback: () -> Void)

  func setSurfaceVisible(visible: Bool)

  func setAggressivelyFreeResources(aggressivelyFreeResources: Bool)

  func swap()

  func partialSwapBuffers(subBuffer: IntRect)

  func scheduleOverlayPlane(planeZOrder: Int,
                            planeTransform: OverlayTransform,
                            overlayTextureID: UInt,
                            displayBounds: IntRect,
                            uvRect: FloatRect)

  func insertFutureSyncPointCHROMIUM() -> UInt32
  func retireSyncPointCHROMIUM(syncPoint: UInt32)
  func shareGroupTracingGUID() -> UInt64
}
