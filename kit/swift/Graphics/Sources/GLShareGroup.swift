// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class GLShareGroup {

  public var reference: UnsafeMutableRawPointer {
    return _GLShareGroupGetHandle(_handle)
  }

  public var context: GLContext? {
    let ctx = _GLShareGroupGetContext(_handle)
    if ctx != nil {
      return GLXContext(reference: ctx!)
    }
    return nil
  }

  var _handle: GLShareGroupRef

  public init() {
    _handle = _GLShareGroupCreate()
  }

  deinit {
    _GLShareGroupDestroy(_handle)
  }

  public func addContext(context: GLContext) {
    let glxContext = context as! GLXContext
    _GLShareGroupAddContext(_handle, glxContext._handle)
  }

  public func getSharedContext(surface: GLXSurface) -> GLContext {
      let handl = _GLShareGroupGetSharedContext(_handle, surface._handle)
      return GLXContext(reference: handl!)
  }
  
  public func setSharedContext(context: GLXContext, surface: GLXSurface) {
      _GLShareGroupSetSharedContext(_handle, context._handle, surface._handle)
  }

  public func removeContext(context: GLContext) {
    let glxContext = context as! GLXContext
    _GLShareGroupRemoveContext(_handle, glxContext._handle)
  }
  
}
