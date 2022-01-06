// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Path {

  public enum Direction : Int {
    /** clockwise direction for adding closed contours */
    case CWDirection = 0
    /** counter-clockwise direction for adding closed contours */
    case CCWDirection = 1
  }

  public enum Fill : Int {
    case Winding = 0
    case EvenOdd = 1
    case InverseWinding = 2
    case InverseEvenOdd = 3
  }

  public var fill: Fill {
    get {
      return Fill(rawValue: Int(_PathGetFillType(reference)))!
    }
    set {
      _PathSetFillType(reference, CInt(newValue.rawValue))
    }
  }

  // problem: Compositor module need access to this reference to pass
  // we are making it public for now
  // maybe create a withUnsafeHandle closure? 
  public var reference: PathRef

  public var pointCount: Int {
    return Int(_PathCountPoints(reference))
  }

  public var isInverseFillType: Bool {
    return _PathIsInverseFillType(reference) == 0 ? false : true
  }

  public var isEmpty: Bool {
    return _PathIsEmpty(reference) == 0 ? false : true
  }

  public init() {
    reference = _PathCreate()
  }

  init(reference: PathRef) {
    self.reference = reference
  }

  deinit {
    _PathDestroy(reference)
  }

  public func isRect(_ rect: FloatRect) -> Bool {
     return _PathIsRect(reference, rect.x, rect.y, rect.width, rect.height) == 0 ? false : true
  }

  public func isOval(_ oval: FloatRect) -> Bool {
    return _PathIsOval(reference, oval.x, oval.y, oval.width, oval.height) == 0 ? false : true
  }

  public func isRRect(_ rect: FloatRRect) -> Bool {
    return _PathIsRRect(reference, rect.x, rect.y, rect.width, rect.height) == 0 ? false : true
  }

  public func moveTo(x: Float, y: Float) {
    _PathMoveTo(reference, x, y)
  }

  public func moveTo(x: Int, y: Int) {
    _PathMoveTo(reference, Float(x), Float(y))
  }

  public func moveTo(point p : IntPoint) {
    _PathMoveTo(reference, Float(p.x), Float(p.y))
  }

  public func moveTo(point p : FloatPoint) {
    _PathMoveTo(reference, p.x, p.y)
  }

  public func lineTo(x: Float, y: Float) {
    _PathLineTo(reference, x, y)
  }

  public func lineTo(x: Int, y: Int) {
    _PathLineTo(reference, Float(x), Float(y))
  }

  public func lineTo(point p : IntPoint) {
    _PathLineTo(reference, Float(p.x), Float(p.y))
  }

  public func lineTo(point p : FloatPoint) {
    _PathLineTo(reference, p.x, p.y)
  }

  public func arcTo(_ rect: FloatRect, startAngle: Double, sweepAngle: Double, forceMoveTo: Bool) {
    _PathArcTo(reference, rect.x, rect.y, rect.width, rect.height,
      startAngle*180.0/PI, sweepAngle*180.0/PI, forceMoveTo.intValue)
  }

  public func addRect(_ rect: FloatRect, direction: Direction = .CWDirection) {
    _PathAddRect(reference, rect.x, rect.y, rect.width, rect.height, Int32(direction.rawValue))
  }

  public func addRoundRect(_ rect: FloatRect, x: Float, y: Float, direction: Direction = .CWDirection) {
    _PathAddRoundRect(reference, rect.x, rect.y, rect.width, rect.height, x, y, Int32(direction.rawValue))
  }

  public func addPath(_ path: Path, x: Float, y: Float) {
    _PathAddPath(reference, path.reference, x, y)
  }

  public func addOval(_ oval: FloatRect) {
    _PathAddOval(reference, oval.x, oval.y, oval.width, oval.height)
  }

  public func close() {
    _PathClose(reference)
  }

  public func reset() {
    _PathReset(reference)
  }

  public func getPoints(points: inout [FloatPoint], max: Int) -> Int {
    let count = Int(_PathCountPoints(reference))
    for i in 0...count {
      points.append(getPoint(at: i))
    }
    return Int(count)
  }

  public func getPoint(at pi: Int) -> FloatPoint {
    var x: Float = 0, y: Float = 0
    if _PathGetPoint(reference, Int32(pi), &x, &y) == 1 {
      return FloatPoint(x: x, y: y)
    }
    return FloatPoint()
  }

  public func transform(matrix m: Mat4, dst: inout Path) {
    _PathTransformMatrix44(reference, m.reference, dst.reference)
  }

  public func transform(matrix m: Mat) {
    _PathTransformMatrix(reference, m.reference)
  }
}
