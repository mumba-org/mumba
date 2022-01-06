// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//public protocol HostFrameSinkClient : class {
//  func onFirstSurfaceActivation(surfaceInfo: SurfaceInfo)
//  func onFrameTokenChanged(frameToken: UInt32)
//}

// unfortunatelly it has to be a class, and be overrided cause wew need the handle
// for the C callbacks :(
open class HostFrameSinkClient {
  public init() {}
  open func onFirstSurfaceActivation(surfaceInfo: SurfaceInfo) {
    assert(false)
  }
  open func onFrameTokenChanged(frameToken: UInt32) {
    assert(false)
  }
}