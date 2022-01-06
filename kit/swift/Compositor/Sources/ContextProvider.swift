// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Gpu
import Graphics
import MumbaShims

public struct ContextProviderCapabilities {
  //public var gpu: GpuCapabilities?
  public var maxTransferBufferUsageBytes: UInt = 0

  public init() {}
}

open class ContextProvider {

  //public var contextGL: GLES2Interface
  //public var contextSupport: ContextSupport
  //public lazy var grContext: GrContext
  //public var capabilities: ContextProviderCapabilities

  var reference: ContextProviderRef
  var name: String

  public init(attributes: ContextCreationAttribHelper,
              widget: SurfaceHandle,
              name: String,
              offscreen: Bool) {

    let provider = _ContextProviderCreate(
      attributes.alphaSize,
      attributes.blueSize,
      attributes.greenSize,
      attributes.redSize,
      attributes.depthSize,
      attributes.stencilSize,
      attributes.samples,
      attributes.sampleBuffers,
      attributes.bufferPreserved.intValue,
      attributes.bindGeneratesResource.intValue,
      attributes.failIfMajorPerfCaveat.intValue,
      attributes.loseContextWhenOutOfMemory.intValue,
      attributes.contextType.rawValue,
      widget,
      offscreen.intValue)

    assert(provider != nil)
    self.reference = provider!
    self.name = name
  }


  public init(reference: ContextProviderRef) {
    self.reference = reference
    self.name = "default"
  }

  deinit {
    _ContextProviderDestroy(reference)
  }

  open func bindToCurrentThread() -> Bool {
    return Bool(_ContextProviderBindToCurrentThread(reference))
  }

  // open func detachFromThread() {
  //   _ContextProviderDetachFromThread(reference)
  // }

  // open func invalidateGrContext(state: UInt) {
  //   _ContextProviderInvalidateGrContext(reference, UInt32(state))
  // }

  // open func deleteCachedResources() {
  //   _ContextProviderDeleteCachedResources(reference)
  // }

  // open func setupLock() {
  //   _ContextProviderSetupLock(reference)
  // }

}
