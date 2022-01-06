// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct WebIconUrlType : OptionSet {

  public let rawValue: Int
  
  public static let Invalid          = WebIconUrlType(rawValue: 0)
  public static let Favicon          = WebIconUrlType(rawValue: 1)
  public static let Touch            = WebIconUrlType(rawValue: 2)
  public static let TouchPrecomposed = WebIconUrlType(rawValue: 4)

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }

  public static func | (left: WebIconUrlType, right: WebIconUrlType) -> WebIconUrlType {
    return WebIconUrlType(rawValue: left.rawValue | right.rawValue)
  }

  public static func & (left: WebIconUrlType, right: WebIconUrlType) -> WebIconUrlType {
    return WebIconUrlType(rawValue: left.rawValue & right.rawValue)
  }
}

public struct WebIconUrl {
  public var type: WebIconUrlType 
  public var url: String?
  public var sizes: ContiguousArray<IntSize>

  public init() {
    type = .Invalid
    sizes = ContiguousArray<IntSize>()
  }
}