// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct PortRange {
  public var minPort: UInt16 = 0
  public var maxPort: UInt16 = 0

  public init() {}
  public init(min: UInt16, max: UInt16) {
    self.minPort = min
    self.maxPort = max
  }
}
