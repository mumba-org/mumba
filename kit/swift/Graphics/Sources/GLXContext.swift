// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class GLXContext {
  var _handle: GLXContextRef

  public init(shareGroup: GLShareGroup) {
    _handle = _GLXContextCreate(shareGroup._handle)
  }

  init(reference: GLXContextRef) {
    _handle = reference
  }

  deinit {
    _GLXContextDestroy(_handle)
  }
}

extension GLXContext : GLContext {

  public var reference: UnsafeMutableRawPointer {
    return _GLXContextGetHandle(_handle)
  }

  public func initialize(surface: GLSurface, gpuPreference: GpuPreference) -> Bool {
    let glxSurface = surface as! GLXSurface
    return Bool(_GLXContextInitialize(_handle, glxSurface._handle, gpuPreference.rawValue))
  }

  public func makeCurrent(surface: GLSurface) -> Bool {
    let glxSurface = surface as! GLXSurface
    return Bool(_GLXContextMakeCurrent(_handle, glxSurface._handle))
  }

  public func releaseCurrent(surface: GLSurface) {
    let glxSurface = surface as! GLXSurface
    _GLXContextReleaseCurrent(_handle, glxSurface._handle)
  }

  public func isCurrent(surface: GLSurface) -> Bool {
    let glxSurface = surface as! GLXSurface
    return Bool(_GLXContextIsCurrent(_handle, glxSurface._handle))
  }

}
