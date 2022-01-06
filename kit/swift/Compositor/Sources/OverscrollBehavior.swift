// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum OverscrollBehaviorType : Int {
  case None = 0
  case Auto
  case Contain
}

public struct OverscrollBehavior {
  public var x: OverscrollBehaviorType
  public var y: OverscrollBehaviorType
  
  public init() {
    x = .Auto
    y = .Auto
  }
  
  public init(type: OverscrollBehaviorType) {
    x = type
    y = type
  }

  public init(x: OverscrollBehaviorType, y: OverscrollBehaviorType) {
    self.x = x
    self.y = y
  }
}