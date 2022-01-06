// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum SelectionBoundType { 
  case Left 
  case Right
  case Center
  case Empty
}

public struct SelectionBound {

  public var type: SelectionBoundType
  public var edgeTop: FloatPoint {
    didSet {
      edgeTopRounded = IntPoint.toRounded(point: edgeTop)
    }
  }
  public var edgeBottom: FloatPoint {
    didSet {
      edgeBottomRounded = IntPoint.toRounded(point: edgeBottom)
    }
  }
  public var visible: Bool
  public private(set) var edgeTopRounded: IntPoint 
  public private(set) var edgeBottomRounded: IntPoint

  // Returns the vertical difference between rounded top and bottom.
  public var height: Int {
    return edgeBottomRounded.y - edgeTopRounded.y
  }

  public mutating func setEdge(top: FloatPoint, bottom: FloatPoint) {
    edgeTop = top
    edgeBottom = bottom
  }

  public func toString() -> String {
    return String()
  }

}


extension SelectionBound : Equatable {}

public func == (left: SelectionBound, right: SelectionBound) -> Bool {
  return left.type == right.type && left.visible == right.visible &&
         left.edgeTop == right.edgeTop &&
         left.edgeBottom == right.edgeBottom
}

public func != (left: SelectionBound, right: SelectionBound) -> Bool {
  return !(left == right)
}