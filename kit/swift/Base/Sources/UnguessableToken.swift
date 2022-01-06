// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import SwiftShims

public struct UnguessableToken {
  
  public static func create() -> UnguessableToken {
    var result = UnguessableToken()
    swift_stdlib_random(&result.high, MemoryLayout<UInt64>.size)
    swift_stdlib_random(&result.low, MemoryLayout<UInt64>.size)
    return result
  }

  public var isEmpty: Bool {
    return high == 0 && low == 0
  }

  public var high: UInt64
  public var low: UInt64

  public init () {
    // wrong but just to start. FIX
    high = 0
    low = 0
  }

  public init (high: UInt64, low: UInt64) {
    self.high = high
    self.low = low 
  }
}