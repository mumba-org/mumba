// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public class HostFrameSinkManager {

  internal var reference: HostFrameSinkManagerRef
  
  public init() {
    self.reference = _HostFrameSinkManagerCreate()!
  }
  
  internal init(reference: HostFrameSinkManagerRef) {
    self.reference = reference
  }

  deinit {
    _HostFrameSinkManagerDestroy(reference)
  }
  
  public func registerFrameSinkId(id: FrameSinkId,
                                  client: HostFrameSinkClient) {
    let clientPtr = Unmanaged.passUnretained(client).toOpaque()
    var callbacks = HostFrameSinkClientCallbacks()
    callbacks.OnFrameTokenChanged = { (handle: UnsafeMutableRawPointer?, token: UInt32) in
      guard handle != nil else {
        return
      }
      let p = unsafeBitCast(handle, to: HostFrameSinkClient.self)
      p.onFrameTokenChanged(frameToken: token)
    }
    callbacks.OnFirstSurfaceActivation = { (handle: UnsafeMutableRawPointer?, 
      surfaceInfoClientId: UInt32, 
      surfaceInfoSinkId: UInt32,
      surfaceInfoParentSequenceNumber: UInt32,
      surfaceInfoChildSequenceNumber: UInt32,
      surfaceInfoTokenHigh: UInt64, 
      surfaceInfoTokenLow: UInt64,
      deviceScaleFactor: Float,
      sizeWidth: CInt,
      sizeHeight: CInt) in
      
      guard handle != nil else {
        return
      }
      
      let surfaceId = SurfaceId(
        frameSinkId: FrameSinkId(clientId: surfaceInfoClientId, sinkId: surfaceInfoSinkId),
        localSurfaceId: LocalSurfaceId(
              parent: surfaceInfoParentSequenceNumber, 
              child: surfaceInfoChildSequenceNumber, 
              token: UnguessableToken(high: surfaceInfoTokenHigh, low: surfaceInfoTokenLow)))
      
      let surfaceInfo = SurfaceInfo(
        id: surfaceId,
        deviceScaleFactor: deviceScaleFactor,
        sizeInPixels: IntSize(width: Int(sizeWidth), height: Int(sizeHeight)))

      let p = unsafeBitCast(handle, to: HostFrameSinkClient.self)
      p.onFirstSurfaceActivation(surfaceInfo: surfaceInfo)
    }
    _HostFrameSinkManagerRegisterFrameSinkId(reference, id.clientId, id.sinkId, clientPtr, callbacks)
  }

  public func setFrameSinkDebugLabel(id: FrameSinkId,
                                     label: String) {
    label.withCString { labelCstr in
      _HostFrameSinkManagerSetFrameSinkDebugLabel(reference, id.clientId, id.sinkId, labelCstr)
    }
  }

  public func registerFrameSinkHierarchy(parent: FrameSinkId,
                                         child: FrameSinkId) -> Bool {
    return _HostFrameSinkManagerRegisterFrameSinkHierarchy(
      reference, 
      parent.clientId, parent.sinkId,
      child.clientId, child.sinkId) != 0
  }

  public func unregisterFrameSinkHierarchy(parent: FrameSinkId,
                                           child: FrameSinkId) {
     _HostFrameSinkManagerUnregisterFrameSinkHierarchy(
        reference, 
        parent.clientId, parent.sinkId,
        child.clientId, child.sinkId)
  }

  public func invalidateFrameSinkId(_ id: FrameSinkId) {
     _HostFrameSinkManagerInvalidateFrameSinkId(
        reference, 
        id.clientId, 
        id.sinkId)
  }

  public func setLocalManager(_ frameSinkManagerImpl: FrameSinkManagerImpl) {
     _HostFrameSinkManagerSetLocalManager(
        reference,
        frameSinkManagerImpl.reference)
  }

}