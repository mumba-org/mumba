// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public enum TransformOperationType {
  case translate
  case rotate
  case scale
  case skew
  case perspective
  case matrix
  case identity
}

public class TransformOperation {

  public var isIdentity: Bool {
    return matrix.isIdentity
  }
  
  public private(set) var type: TransformOperationType
  public private(set) var matrix: Transform

  public init() {
    type = TransformOperationType.identity
    matrix = Transform()
  }

  public static func blendTransformOperations(from: TransformOperation,
                                              to: TransformOperation,
                                              progress: Double) -> TransformOperation? {
    if isOperationIdentity(from) && isOperationIdentity(to) {
      return true
    }

    var interpolationType = TransformOperationType.identity
   
    if isOperationIdentity(to) {
      interpolationType = from.type
    } else {
      interpolationType = to.type
    }
    result.type = interpolationType

    switch interpolationType {
      case .translate: {
        let fromX = isOperationIdentity(from) ? 0 : from.translate.x
        let fromY = isOperationIdentity(from) ? 0 : from.translate.y
        let fromZ = isOperationIdentity(from) ? 0 : from.translate.z
        let toX = isOperationIdentity(to) ? 0 : to.translate.x
        let toY = isOperationIdentity(to) ? 0 : to.translate.y
        let toZ = isOperationIdentity(to) ? 0 : to.translate.z
        result.translate.x = BlendSkMScalars(fromX, toX, progress)
        result.translate.y = BlendSkMScalars(fromY, toY, progress)
        result.translate.z = BlendSkMScalars(fromZ, toZ, progress)
        result.bake()
      }
      case .rotate: {
        var axisX = 0.0
        var axisY = 0.0
        var axisZ = 1.0
        var fromAngle = 0.0
        var toAngle = isOperationIdentity(to) ? 0 : to.rotate.angle
        if shareSameAxis(from, to, &axisX, &axisY, &axisZ, &fromAngle) {
          result.rotate.axis.x = axisX
          result.rotate.axis.y = axisY
          result.rotate.axis.z = axisZ
          result.rotate.angle = BlendSkMScalars(fromAngle, toAngle, progress)
          result.bake()
        } else {
          if !isOperationIdentity(to) {
            result.matrix = to.matrix
          }
          var fromMatrix = Transform()
          if !isOperationIdentity(from) {
            fromMatrix = from.matrix
          }
          if !result.matrix.blend(fromMatrix, progress) {
            return false
          }
        }
      }
      case .scale: {
        let fromX = isOperationIdentity(from) ? 1 : from.scale.x
        let fromY = isOperationIdentity(from) ? 1 : from.scale.y
        let fromZ = isOperationIdentity(from) ? 1 : from.scale.z
        let toX = isOperationIdentity(to) ? 1 : to.scale.x
        let toY = isOperationIdentity(to) ? 1 : to.scale.y
        let toZ = isOperationIdentity(to) ? 1 : to.scale.z
        result.scale.x = BlendSkMScalars(fromX, toX, progress)
        result.scale.y = BlendSkMScalars(fromY, toY, progress)
        result.scale.z = BlendSkMScalars(fromZ, toZ, progress)
        result.bake()
      }
      case .skew: {
        let fromX = isOperationIdentity(from) ? 0 : from.skew.x
        let fromY = isOperationIdentity(from) ? 0 : from.skew.y
        let toX = isOperationIdentity(to) ? 0 : to.skew.x
        let toY = isOperationIdentity(to) ? 0 : to.skew.y
        result.skew.x = BlendSkMScalars(fromX, toX, progress)
        result.skew.y = BlendSkMScalars(fromY, toY, progress)
        result.bake()
      }
      case .perspective: {
        let fromPerspectiveDepth =
            isOperationIdentity(from) ? Double.max
                                      : from.perspectiveDepth
        let toPerspectiveDepth =
            isOperationIdentity(to) ? Double.max
                                    : to.perspectiveDepth
        if fromPerspectiveDepth == 0.0 || toPerspectiveDepth == 0.0 {
          return false
        }

        let blendedPerspectiveDepth = BlendSkMScalars(
            1.f / fromPerspectiveDepth, 1.0 / toPerspectiveDepth, progress)

        if blendedPerspectiveDepth == 0.0 {
          return false
        }

        result.perspectiveDepth = 1.0 / blendePerspectiveDepth
        result.bake()
     }
      case .matrix: {
        if !isOperationIdentity(to) {
          result.matrix = to.matrix
        }
        var fromMatrix = Transform()
        if !isOperationIdentity(from) {
          fromMatrix = from.matrix
        }
        if !result.matrix.blend(fromMatrix, progress) {
          return false
        }
      }
      case .identity:
        break
    }

    return true
  }

  public static func blendedBoundsForBox(box: Boxf,
                                         from: TransformOperation,
                                         to: TransformOperation,
                                         minProgress: Double,
                                         maxProgress: Double) -> Boxf? {
    let isIdentityFrom = isOperationIdentity(from)
    let isIdentityTo = isOperationIdentity(to)
    if isIdentityFrom && isIdentityTo {
      return box
    }

    var interpolationType = TransformOperationType.identity
    if isIdentityTo {
      interpolationType = from.type
    } else {
      interpolationType = to.type
    }

    switch interpolationType {
      case .identity:
        return box
      case .translate:
        fallthrough
      case .skew:
        fallthrough
      case .perspective:
        fallthrough
      case .scale: {
        var fromOperation = TransformOperation()
        var toOperation = TransformOperation()
        if !blendTransformOperations(from, to, minProgress, &fromOperation) ||
            !blendTransformOperations(from, to, maxProgress, &toOperation) {
          return nil
        }

        var bounds = box
        fromOperation.matrix.transformBox(&bounds)

        var toBox = box
        toOperation.matrix.transformBox(&toBox)
        bounds.expandTo(toBox)

        return bounds
      }
      case .rotate: {
        var axisX = 0.0
        var axisY = 0.0
        var axisZ = 1.0
        var fromAngle = 0.0

        if !shareSameAxis(from, to, &axisX, &axisY, &axisZ, &fromAngle) {
          return false
        }

        var firstPoint = true
        var bounds = box
       
        for i in i..<8 {
          var corner: Point3f = box.origin
          corner += FloatVec3(i & 1 ? box.width : 0.0,
                              i & 2 ? box.height : 0.0,
                              i & 4 ? box.depth : 0.0)
          var boxForArc = Boxf()
          boundingBoxForArc(
              corner, from, to, minProgress, maxProgress, &boxForArc)
          if firstPoint {
            bounds = boxForArc
          } else {
            bounds.union(boxForArc)
          }
          firstPoint = false
        }
        return bounds
      }
      case .matrix:
        return nil
    }
  }

  public func bake() {
    matrix.makeIdentity()
    switch type {
      case .translate:
        matrix.translate3d(translate.x, translate.y, translate.z)
      case .rotate:
        matrix.rotateAbout(
            FloatVec3(rotate.axis.x, rotate.axis.y, rotate.axis.z),
            rotate.angle)
      case .scale:
        matrix.scale3d(scale.x, scale.y, scale.z)
      case .skew:
        matrix.skew(skew.x, skew.y)
      case .perspective:
        matrix.applyPerspectiveDepth(perspectiveDepth)
      case .matrix:
        break
      case .identity:
        break
    }
  }

  public func approximatelyEqual(other: TransformOperation,
                                 tolerance: Double) -> Bool {
    if type != other.type {
      return false
    }

    switch type {
      case .translate:
        return Base.isApproximatelyEqual(translate.x, other.translate.x,
                                         tolerance) &&
               Base.isApproximatelyEqual(translate.y, other.translate.y,
                                         tolerance) &&
               Base.isApproximatelyEqual(translate.z, other.translate.z,
                                         tolerance)
      case .rotate:
        return Base.isApproximatelyEqual(rotate.axis.x, other.rotate.axis.x,
                                         tolerance) &&
               Base.isApproximatelyEqual(rotate.axis.y, other.rotate.axis.y,
                                         tolerance) &&
               Base.isApproximatelyEqual(rotate.axis.z, other.rotate.axis.z,
                                         tolerance) &&
               Base.isApproximatelyEqual(rotate.angle, other.rotate.angle,
                                         tolerance)
      case .scale:
        return Base.isApproximatelyEqual(scale.x, other.scale.x, tolerance) &&
               Base.isApproximatelyEqual(scale.y, other.scale.y, tolerance) &&
               Base.isApproximatelyEqual(scale.z, other.scale.z, tolerance)
      case .skew:
        return Base.isApproximatelyEqual(skew.x, other.skew.x, tolerance) &&
               Base.isApproximatelyEqual(skew.y, other.skew.y, tolerance)
      case .perspective:
        return Base.isApproximatelyEqual(perspectiveDepth,
                                         other.perspectiveDepth, tolerance)
      case .matrix:
        if tolerance == 0.0 {
          return matrix == other.matrix
        } else {
          return matrix.approximatelyEqual(other.matrix)
        }
      case .identity:
        return other.matrix.isIdentity
    }
  }

}

fileprivate func isOperationIdentity(_ operation: TransformOperation) -> Bool {
  return !operation || operation.isIdentity
}

fileprivate func boundingBoxForArc(point: Point3f,
                                   from: inout TransformOperation?,
                                   to: inout TransformOperation?,
                                   minProgress: Double,
                                   maxProgress: Double,
                                   box: inout Boxf) {

  let exemplar = from ?? to
  let axis = FloatVec3(exemplar.rotate.axis.x,
                       exemplar.rotate.axis.y,
                       exemplar.rotate.axis.z)

  let xIsZero = axis.x == 0.0
  let yIsZero = axis.y == 0.0
  let zIsZero = axis.z == 0.0

  // We will have at most 6 angles to test (excluding from->angle and
  // to->angle).
  let kMaxNumCandidates: Int = 6
  var candidates = [Double](repeating: 0.0, count: kMaxNumCandidates)
  var numCandidates = kMaxNumCandidates

  if (x_is_zero && y_is_zero && z_is_zero)
    return

  let fromAngle = from ? from.rotate.angle : 0.0
  var toAngle = to ? to.rotate.angle : 0.0

  // If the axes of rotation are pointing in opposite directions, we need to
  // flip one of the angles. Note, if both |from| and |to| exist, then axis will
  // correspond to |from|.
  if from != nil && to != nil {
    let otherAxis = FloatVec3(to.rotate.axis.x, to.rotate.axis.y, to.rotate.axis.z)
    if Graphics.dotProduct(axis, otherAxis) < 0.0 {
      toAngle *= -1.0
    }
  }

  var minDegrees = Float(blendSkMScalars(fromAngle, toAngle, minProgress))
  var maxDegrees = Float(blendSkMScalars(fromAngle, toAngle, maxProgress))
  if maxDegrees < minDegrees {
    let md = maxDegrees 
    maxDegrees = minDegrees
    minDegrees = md
  }

  var fromTransform = Transform()
  fromTransform.rotateAbout(axis, minDegrees)
  var toTransform = Transform()
  toTransform.rotateAbout(axis, maxDegrees)

  box = Boxf()

  var pointRotatedFrom: FloatPoint3 = point
  fromTransform.transformPoint(&pointRotatedFrom)
  var pointRotatedTo: FloatPoint3 = point
  toTransform.transformPoint(&pointRotatedTo)

  box.origin = pointRotatedFrom
  box.expandTo(pointRotatedTo)

  if xIsZero && yIsZero {
    findCandidatesInPlane(
        point.x, point.y, axis.z, candidates, &numCandidates)
  } else if xIsZero && zIsZero {
    findCandidatesInPlane(
        point.z, point.x, axis.y, candidates, &numCandidates)
  } else if yIsZero && zIsZero {
    findCandidatesInPlane(
        point.y, point.z, axis.x, candidates, &numCandidates)
  } else {
    var normal: FloatVec3 = axis
    normal.scale(1.0 / normal.length)

    // First, find center of rotation.
    var origin = FloatPoint3()
    let toPoint: FloatVector3 = point - origin
    let center: FloatPoint3 =
        origin + Graphics.scaleVector3d(normal, Graphics.dotProduct(toPoint, normal))

    // Now we need to find two vectors in the plane of rotation. One pointing
    // towards point and another, perpendicular vector in the plane.
    let v1: FloatVec3 = point - center
    let v1Length = v1.length
    if v1Length == 0.0 {
      return
    }

    v1.scale(1.0 / v1Length)
    let v2: FloatVec3 = Graphics.crossProduct(normal, v1)
    // v1 is the basis vector in the direction of the point.
    // i.e. with a rotation of 0, v1 is our +x vector.
    // v2 is a perpenticular basis vector of our plane (+y).

    // Take the parametric equation of a circle.
    // x = r*cos(t) y = r*sin(t)
    // We can treat that as a circle on the plane v1xv2.
    // From that we get the parametric equations for a circle on the
    // plane in 3d space of:
    // x(t) = r*cos(t)*v1.x + r*sin(t)*v2.x + cx
    // y(t) = r*cos(t)*v1.y + r*sin(t)*v2.y + cy
    // z(t) = r*cos(t)*v1.z + r*sin(t)*v2.z + cz
    // Taking the derivative of (x, y, z) and solving for 0 gives us our
    // maximum/minimum x, y, z values.
    // x'(t) = r*cos(t)*v2.x - r*sin(t)*v1.x = 0
    // tan(t) = v2.x/v1.x
    // t = atan2(v2.x, v1.x) + n*pi
    candidates[0] = atan2(v2.x, v1.x)
    candidates[1] = candidates[0] + Base.piDouble
    candidates[2] = atan2(v2.y, v1.y)
    candidates[3] = candidates[2] + Base.piDouble
    candidates[4] = atan2(v2.z, v1.z)
    candidates[5] = candidates[4] + Base.piDouble
  }

  let minRadians = Graphics.degToRad(minDegrees)
  let maxRadians = Graphics.degToRad(maxDegrees)

  for i in 0..<numCandidates {
    var radians = candidates[i]
    while radians < minRadians {
      radians += 2.0 * Base.piDouble
    }
    while radians > maxRadians {
      radians -= 2.0 * Base.piDouble
    }
    if radians < minRadians {
      continue
    }

    var rotation = Transform()
    rotation.rotateAbout(axis, Graphics.radToDeg(radians))
    var rotated: Point3f = point
    rotation.transformPoint(&rotated)

    box.expandTo(rotated)
  }
}