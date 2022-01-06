// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Graphics
import MumbaShims

public struct CompositorFrameAck {}
public struct OverlayCandidateValidator {}

// TODO: como o OutputSurface agora é um objeto c++, tem que ver
// se e como o client é necessario, e se esta roteando corretamente
// senao vamos ter que criar callbacks para o runtime c++ chamar
// e rotear de voltar para o ambiente swift

/*public protocol OutputSurfaceClient {
  func commitVSyncParameters(timebase: TimeInterval, interval: TimeInterval)
  func setNeedsRedrawRect(damageRect: IntRect)
  func didSwapBuffers()
  func didSwapBuffersComplete()
  func reclaimResources(ack: CompositorFrameAck)
  func didLoseOutputSurface()
  func setExternalDrawConstraints(
    transform: Transform,
    viewport: IntRect,
    clip: IntRect,
    viewportRectForTilePriority: IntRect,
    transformForTilePriority: Transform,
    resourcelessSoftwareDraw: Bool)
  func setMemoryPolicy(policy: ManagedMemoryPolicy)
  func setTreeActivationCallback(callback: () -> Void)
  func onDraw()
}*/

open class OutputSurface {

 //var capabilities: OutputSurfaceCapabilities
 //public var contextProvider: ContextProvider?
 //public var workerContextProvider: ContextProvider?
 //public var client: OutputSurfaceClient?

  public var reference: OutputSurfaceRef
  public var owned: Bool

  public init(contextProvider: ContextProvider, workerProvider: ContextProvider) {
    self.reference = _OutputSurfaceCreate(contextProvider.reference, workerProvider.reference)!
    //self.contextProvider = contextProvider
    //self.workerContextProvider = sharedWorkerContextProvider
    owned = true
  }

  public init(reference: OutputSurfaceRef) {
    self.reference = reference
    owned = true
  }

  deinit {
    if owned {
      _OutputSurfaceDestroy(reference)
    }
  }

  // this is probably only used directly on the cc::
  //public func bindToClient(client: OutputSurfaceClient) -> Bool {
  //  assert(true)
  //  return false
    //return Bool(_OutputSurfaceBindToClient(reference))
  //}

  // open func detachFromClient() {
  //   _OutputSurfaceDetachFromClient(reference)
  // }

  open func ensureBackbuffer() {
    _OutputSurfaceEnsureBackbuffer(reference)
  }

  open func discardBackbuffer() {
    _OutputSurfaceDiscardBackbuffer(reference)
  }

  open func reshape(size: IntSize, scaleFactor: Float, hasAlpha: Bool, useStencil: Bool) {
    _OutputSurfaceReshape(reference, 
      Int32(size.width), 
      Int32(size.height), 
      scaleFactor,
      hasAlpha.intValue,
      useStencil.intValue)
  }

  // open func surfaceSize() -> IntSize {
  //   var w: Int32 = 0, h: Int32 = 0
  //   _OutputSurfaceSurfaceSize(reference, &w, &h)
  //   return IntSize(width: Int(w), height: Int(h))
  // }

  // open func deviceScaleFactor() -> Float {
  //   return (_OutputSurfaceDeviceScaleFactor(reference))
  // }

  // open func forceReclaimResources() {
  //   _OutputSurfaceForceReclaimResources(reference)
  // }

  open func bindFramebuffer() {
    _OutputSurfaceBindFramebuffer(reference)
  }

  open func swapBuffers(frame: CompositorFrame) {}

  // open func onSwapBuffersComplete() {
  //   _OutputSurfaceOnSwapBuffersComplete(reference)
  // }

  // open func updateSmoothnessTakesPriority(preferSmoothness: Bool) {
  //   _OutputSurfaceUpdateSmoothnessTakesPriority(reference, preferSmoothness.intValue)
  // }

  // open func hasClient() -> Bool {
  //   return Bool(_OutputSurfaceHasClient(reference))
  // }

  open func getOverlayCandidateValidator() -> OverlayCandidateValidator {
    _OutputSurfaceGetOverlayCandidateValidator(reference)
    return OverlayCandidateValidator()
  }

  open func isDisplayedAsOverlayPlane() -> Bool {
    return Bool(_OutputSurfaceIsDisplayedAsOverlayPlane(reference))
  }

  open func getOverlayTextureId() -> UInt {
    return UInt(_OutputSurfaceGetOverlayTextureId(reference))
  }

  // open func didLoseOutputSurface() {
  //   _OutputSurfaceDidLoseOutputSurface(reference)
  // }

  // open func setMemoryPolicy(policy: ManagedMemoryPolicy) {
  //   _OutputSurfaceSetMemoryPolicy(reference)
  // }

  // open func invalidate() {
  //   _OutputSurfaceInvalidate(reference)
  // }

  // open func setWorkerContextShouldAggressivelyFreeResources(isVisible: Bool) {
  //   _OutputSurfaceSetWorkerContextShouldAggressivelyFreeResources(reference, isVisible.intValue)
  // }

  open func surfaceIsSuspendForRecycle() -> Bool {
    return Bool(_OutputSurfaceSurfaceIsSuspendForRecycle(reference))
  }

}
