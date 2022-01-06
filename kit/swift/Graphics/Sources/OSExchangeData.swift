// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol OSExchangeDataProvider : class {
  var dragImage: Image? { get }
  func setDragImage(_ image: Image, cursorOffset: IntVec2)
}

public struct OSExchangeData {
  
  public let provider: OSExchangeDataProvider

  public init() {
    provider = LameOSExchangeDataProvider()
  }
}

public class LameOSExchangeDataProvider : OSExchangeDataProvider {
  
  public var dragImage: Image?
  
  public init() {}
  
  public func setDragImage(_ image: Image, cursorOffset: IntVec2) {}
}
