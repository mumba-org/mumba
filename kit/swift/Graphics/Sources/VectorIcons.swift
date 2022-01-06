// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fileprivate let referenceSizeDip: Int = 48

public enum CommandType {
  case newPath
  case pathColorAlpha
  case pathColorArgb
  case pathModeClear
  case stroke
  case capSquare
  case moveTo
  case rMoveTo
  case arcTo
  case rArcTo
  case lineTo
  case RLineTo
  case HLineTo
  case RHLineTo
  case VLineTo
  case RVLineTo
  case cubicTo
  case rCubicTo
  case cubicToShorthand
  case circle
  case roundRect
  case close
  case canvasDimensions
  case clip
  case disableAA
  case flipsInRtl
  case transitionFrom
  case transitionTo
  case transitionEnd
}

public enum PathElement {
  case command(_: CommandType)
  case arg(_: Float)
}

public struct VectorIconRep {
  public var path: PathElement?
  public var pathSize: Int = 0

  public init() {}
}

public struct VectorIcon {
  
  public var isEmpty: Bool {
    return reps.isEmpty
  }

  var reps: [VectorIconRep]

  public init() {
    reps = []
  }

}