// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

public struct RouteBuffer {

  public var rawData: UnsafeRawPointer? {
    return data.withUnsafeBytes { return $0.baseAddress }
  }

  public var size: UInt64 {
    return UInt64(data.count)
  }

  public private(set) var data: Data

  public init() {
    data = Data()
  }

  public init(size: UInt64) {
    data = Data(count: Int(size))
  }

  public init(string: String) {
    data = Data(bytes: string, count: string.count)
  }

  public func copy() -> Data {
    return copy(offset: 0, length: Int(self.size))
  }

  public func copy(length: Int) -> Data {
    return copy(offset: 0, length: length)
  }

  public func copy(offset: Int, length: Int) -> Data {
    guard size > 0 else {
      return Data()
    }
    return Data(bytes: rawData!, count: Int(size))
  }

}