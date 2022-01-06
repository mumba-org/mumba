// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public enum BeginFrameArgsType {
  case invalid
  case normal
  case missed
}

public struct BeginFrameArgs {

  public var frameTime: TimeTicks = TimeTicks()
  public var deadline: TimeTicks = TimeTicks()
  public var interval: TimeDelta = TimeDelta()
  public var sourceId: UInt64 = 0
  public var sequenceNumber: UInt64 = 0
  public var type: BeginFrameArgsType = BeginFrameArgsType.invalid
  public var onCriticalPath: Bool = false
  public var animateOnly: Bool = false

  public var isValid: Bool {
    assert(false)
    return false
  }

  public static var defaultInterval: TimeDelta {
    assert(false)
    return TimeDelta()
  }

  public init() {}

  public init(sourceId: UInt64,
              sequenceNumber: UInt64,
              frameTime: TimeTicks,
              deadline: TimeTicks,
              interval: TimeDelta,
              type: BeginFrameArgsType) {

    self.sourceId = sourceId
    self.sequenceNumber = sequenceNumber
    self.frameTime = frameTime
    self.deadline = deadline
    self.type = type 
    self.interval = interval
  }

}

public struct BeginFrameAck {

  public var sourceId: UInt64 = 0
  public var sequenceNumber: UInt64 = 0
  public var hasDamage: Bool = false

  public init() {}

  public init(sourceId: UInt64, sequenceNumber: UInt64, hasDamage: Bool) {
    self.sourceId = sourceId
    self.sequenceNumber = sequenceNumber
    self.hasDamage = hasDamage
  }

}
