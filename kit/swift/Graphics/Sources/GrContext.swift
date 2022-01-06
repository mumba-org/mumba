// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public typealias GrBackendContext = UnsafeRawPointer

public enum GrBackend {
  case OpenGL
  case Vulkan
}

public class GrContext {

  public class func create(backend: GrBackend, context: GrBackendContext) -> GrContext? {
    return nil
  }

  var reference: GrContextRef

  init(reference: GrContextRef) {
    self.reference = reference
  }

  public func resetContext(state: UInt) {}
  public func abandonContext() {}
  public func getResourceCacheUsage() -> (resourceCount: Int, resourceBytes: UInt) {
    return (0, 0)
  }
  public func getResourceCacheLimits() -> (maxResources: Int, maxResourceBytes: UInt) {
    return (0, 0)
  }
  public func setResourceCacheLimits(maxResources: Int, maxResourceBytes: UInt) {}
  public func freeGpuResources() {}
  public func purgeAllUnlockedResources() {}
  public func flush(flags: Int) {}
  public func flushIfNecessary() {}
}
