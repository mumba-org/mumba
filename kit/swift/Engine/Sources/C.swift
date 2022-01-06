// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public typealias Callbacks = CEngineCallbacks

@inlinable
public func engineCreate(_ handle: UnsafeMutableRawPointer, _ cbs: Callbacks) -> EngineInstanceRef {
  return _EngineCreate(handle, cbs)
}

@inlinable
public func engineDestroy(_ state: EngineInstanceRef) {
  _EngineDestroy(state)
}

@inlinable
public func engineGetClient(_ state: EngineInstanceRef) -> UnsafeMutableRawPointer {
  return _EngineGetClient(state)
}