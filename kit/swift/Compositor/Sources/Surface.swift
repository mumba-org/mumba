// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public struct LocalSurfaceId {

  public var isValid: Bool {
    return parentSequenceNumber != 0 &&
           childSequenceNumber != 0 &&
           !token.isEmpty
  }

  public var parentSequenceNumber: UInt32
  public var childSequenceNumber: UInt32
  public var token: UnguessableToken

  public init() {
    parentSequenceNumber = 0
    childSequenceNumber = 0
    token = UnguessableToken()
  }

  public init(parent: UInt32, 
              child: UInt32, 
              token: UnguessableToken) {
    self.parentSequenceNumber = parent
    self.childSequenceNumber = child
    self.token = token
  }
}

public struct SurfaceId {
  public let frameSinkId: FrameSinkId
  public let localSurfaceId: LocalSurfaceId

  public init() {
    frameSinkId = FrameSinkId()
    localSurfaceId = LocalSurfaceId()
  }

  public init(frameSinkId: FrameSinkId,
              localSurfaceId: LocalSurfaceId) {
    self.frameSinkId = frameSinkId
    self.localSurfaceId = localSurfaceId
  }
}

public class SurfaceInfo {
  public let id: SurfaceId
  public private(set) var deviceScaleFactor: Float
  public private(set) var sizeInPixels: IntSize

  public init() {
    id = SurfaceId()
    deviceScaleFactor = 1.0
    sizeInPixels = IntSize()
  }

  public init(id: SurfaceId,
              deviceScaleFactor: Float,
              sizeInPixels: IntSize) {
    self.id = id
    self.deviceScaleFactor = deviceScaleFactor
    self.sizeInPixels = sizeInPixels
  }
}

public struct SurfaceSequence {
  public var namespace: UInt32
  public var sequence: UInt32

  public init(namespace: UInt32, sequence: UInt32) {
    self.namespace = namespace
    self.sequence = sequence
  }
}

public class SurfaceIdAllocator {
  
  public var idNamespace: UInt
  
  public init() {
    idNamespace = 0
  }
}

public struct LocalSurfaceIdAllocator {
  
  public private(set) var currentLocalSurfaceId: LocalSurfaceId

  public init() {
    currentLocalSurfaceId = LocalSurfaceId()    
  }

  public mutating func updateFromParent(parentAllocatedLocalSurfaceId: LocalSurfaceId) -> LocalSurfaceId {
    if parentAllocatedLocalSurfaceId.parentSequenceNumber >
        currentLocalSurfaceId.parentSequenceNumber {
      currentLocalSurfaceId.parentSequenceNumber =
          parentAllocatedLocalSurfaceId.parentSequenceNumber
      currentLocalSurfaceId.token =
          parentAllocatedLocalSurfaceId.token
    }
    return currentLocalSurfaceId
  }

  public mutating func generateId() -> LocalSurfaceId {
    // updateFromParent must be called before we can generate a valid ID.
    assert(currentLocalSurfaceId.parentSequenceNumber != 0)

    currentLocalSurfaceId.childSequenceNumber += 1
    return currentLocalSurfaceId
  }

}