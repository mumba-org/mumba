// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct FrameSinkId : Hashable {
  public let clientId: UInt32
  public let sinkId: UInt32

  public var isValid: Bool {
    return clientId != 0 && sinkId != 0
  }

  public init() {
    clientId = 0
    sinkId = 0
  }

  public init(clientId: UInt32, sinkId: UInt32) {
    self.clientId = clientId
    self.sinkId = sinkId
  }

  public var hashValue: Int {
    // a simple hash between two ints
    let value1 = UInt64(clientId)
    let value2 = UInt64(sinkId)
    return Int((value1 << 32) | value2)
  }

}

public struct FrameSinkIdAllocator {
  private let clientId: UInt32
  private var nextSinkId: UInt32

  public init(clientId: UInt32) {
    self.clientId = clientId
    nextSinkId = 1
  }

  public mutating func nextFrameSinkId() -> FrameSinkId {
    let next = FrameSinkId(clientId: clientId, sinkId: nextSinkId)
    nextSinkId += 1
    return next
  }

}