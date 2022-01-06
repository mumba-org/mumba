// Copyright (c) 2015-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

let scalar1: Double = 1.0

public class DecomposedTransform {
  
  public var translate: Array<Double>
  public var scale: Array<Double>
  public var skew: Array<Double>
  public var perspective: Array<Double>
  public var quaternion: Quaternion

  public init () {
    translate = Array<Double>(repeating: 0.0, count: 3)
    scale = Array<Double>(repeating: 1.0, count: 3)
    skew = Array<Double>(repeating: 0.0, count: 3)
    perspective = Array<Double>(repeating: 0.0, count: 4)
    quaternion = Quaternion()

    perspective[3] = 1.0
  }

}


public struct Transform {

  public var matrix: Mat4

  public var isIdentity: Bool {
    return matrix.isIdentity
  }

  public var isScaleOrTranslation: Bool { 
    return matrix.isScaleTranslate
  }

  public var isIdentityOrTranslation: Bool { 
    return matrix.isTranslate
  }

  public init(skipInitialization: Bool = false) {
    if skipInitialization {
      matrix = Mat4(identity: false)
    } else {
      matrix = Mat4(identity: true)
    }
  }

  public init(_ col1row1: Double,
              _ col2row1: Double,
              _ col3row1: Double,
              _ col4row1: Double,
              _ col1row2: Double,
              _ col2row2: Double,
              _ col3row2: Double,
              _ col4row2: Double,
              _ col1row3: Double,
              _ col2row3: Double,
              _ col3row3: Double,
              _ col4row3: Double,
              _ col1row4: Double,
              _ col2row4: Double,
              _ col3row4: Double,
              _ col4row4: Double) {
    matrix = Mat4()
    matrix[0, 0] = col1row1
    matrix[1, 0] = col1row2
    matrix[2, 0] = col1row3
    matrix[3, 0] = col1row4

    matrix[0, 1] = col2row1
    matrix[1, 1] = col2row2
    matrix[2, 1] = col2row3
    matrix[3, 1] = col2row4

    matrix[0, 2] = col3row1
    matrix[1, 2] = col3row2
    matrix[2, 2] = col3row3
    matrix[3, 2] = col3row4

    matrix[0, 3] = col4row1
    matrix[1, 3] = col4row2
    matrix[2, 3] = col4row3
    matrix[3, 3] = col4row4
  }

  public init(matrix: Mat4) {
    self.matrix = matrix
  }

  public init(quaternion q: Quaternion) {
    let x = q.x
    let y = q.y
    let z = q.z
    let w = q.w
    
    matrix = Mat4()
    // Implicitly calls matrix.setIdentity()
    matrix.set3x3(1.0 - 2.0 * (y * y + z * z),
                  2.0 * (x * y + z * w),
                  2.0 * (x * z - y * w),
                  2.0 * (x * y - z * w),
                  1.0 - 2.0 * (x * x + z * z),
                  2.0 * (y * z + x * w),
                  2.0 * (x * z + y * w),
                  2.0 * (y * z - x * w),
                  1.0 - 2.0 * (x * x + y * y))
  }

  public subscript(row: Int, col: Int) -> Double {
    return matrix[row, col]
  }

  public mutating func scale(x: Float, y: Float) {
    matrix.preScale(x: Double(x), y: Double(y), z: 1.0)
  }

  public mutating func scale3d(x: Float, y: Float, z: Float) {
    matrix.preScale(x: Double(x), y: Double(y), z: Double(z))
  }

  public mutating func translate(x: Float, y: Float) {
    matrix.preTranslate(x: Double(x), y: Double(y), z: 0.0)
  }

  public mutating func translate(vector v: FloatVec2) {
    matrix.preTranslate(x: Double(v.x), y: Double(v.y), z: 0.0)
  }

  public mutating func concatTransform(transform: Transform) {
    matrix.postConcat(matrix: transform.matrix)
  }

  public mutating func preconcatTransform(transform: Transform) {
    matrix.preConcat(matrix: transform.matrix)
  }

  public mutating func toIdentity() {
    matrix.toIdentity()
  }

  public func getInverse(invert: inout Transform) -> Bool {
    if !matrix.invert(matrix: &invert.matrix) {
      // Initialize the return value to identity if this matrix turned
      // out to be un-invertible.
      invert.toIdentity()
      return false
    }

    return true
  }

  public func transformRect(rect: inout FloatRect) {
    guard !matrix.isIdentity else {
      return
    }
    matrix.map(rect: &rect)
  }

  public func transformRectReverse(rect: inout FloatRect) -> Bool {

    guard !matrix.isIdentity else {
      return false
    }

    var inverse = Mat4()

    if !matrix.invert(matrix: &inverse) {
      return false
    }

    inverse.map(rect: &rect)

    return true
  }

  public func applyPerspectiveDepth(depth: Float) {
    if depth == 0 {
      return
    }
    if matrix.isIdentity {
      matrix[3, 2] = -scalar1 / Double(depth)
    } else {
      let m = Mat4(identity: true)
      matrix[3, 2] = -scalar1 / Double(depth)
      matrix.preConcat(matrix: m)
    }
  }

  public func transformPoint(point: inout FloatPoint3) {
    transformPointInternal(xform: matrix, point: &point)
  }

  public func transformPointReverse(point: inout FloatPoint3) -> Bool {
    var inverse = Mat4()

    if !matrix.invert(matrix: &inverse) {
      return false
    }

    transformPointInternal(xform: inverse, point: &point)

    return true
  }

  public mutating func blend(from: Transform, progress: Double) -> Bool {
    guard var toDecomp = decomposeTransform(self) else {
      return false
    } 
    
    guard let fromDecomp = decomposeTransform(from) else {
      return false
    }

    toDecomp = blendDecomposedTransforms(toDecomp, fromDecomp, progress)

    self.matrix = composeTransform(toDecomp).matrix
    
    return true
  }

  public mutating func translate3d(x: Float, y: Float, z: Float) {
    matrix.preTranslate(x: Double(x), y: Double(y), z: Double(z))
  }

  public func rotateAbout(axis: FloatVec3, degrees: Double) {
    if matrix.isIdentity {
      matrix.setRotateDegreesAbout(x: Double(axis.x),
                                   y: Double(axis.y),
                                   z: Double(axis.z),
                                   degrees: degrees)
    } else {
      let rot = Mat4()
      rot.setRotateDegreesAbout(x: Double(axis.x),
                                y: Double(axis.y),
                                z: Double(axis.z),
                                degrees: degrees)
      matrix.preConcat(matrix: rot)
    }
  }

  func transformPointInternal(xform: Mat4, point: inout FloatPoint3) {

    guard !xform.isIdentity else {
      return
    }

    var p: [Double] = [ Double(point.x), Double(point.y), Double(point.z), 1.0 ]

    xform.map(scalars: &p)

    if p[3] != scalar1 && p[3] != 0.0 {
      let wInverse = scalar1 / p[3]
      point.set(x: Float(p[0] * wInverse), y: Float(p[1] * wInverse), z: Float(p[2] * wInverse))
    } else {
      point.set(x: Float(p[0]), y: Float(p[1]), z: Float(p[2]))
    }

  }
}

public func * (left: Transform, right: Transform) -> Transform {
  let result = left.matrix * right.matrix
  return Transform(matrix: result)
}

public func blendDecomposedTransforms(_ from: DecomposedTransform, _ to: DecomposedTransform, _ progress: Double) -> DecomposedTransform {
  let out = DecomposedTransform()
  let scalea = progress
  let scaleb = 1.0 - progress
  combine(&out.translate, to.translate, from.translate, scalea, scaleb)
  combine(&out.scale, to.scale, from.scale, scalea, scaleb)
  combine(&out.skew, to.skew, from.skew, scalea, scaleb)
  combine(&out.perspective, to.perspective, from.perspective, scalea, scaleb)
  out.quaternion = from.quaternion.slerp(to.quaternion, progress)
  return out
}

public func decomposeTransform(_ t: Transform) -> DecomposedTransform? {
  let decomp = DecomposedTransform()
  // We'll operate on a copy of the matrix.
  var matrix = t.matrix

  // If we cannot normalize the matrix, then bail early as we cannot decompose.
  if !normalize(&matrix) {
    return nil
  }

  let perspectiveMatrix = matrix

  for i in 0..<3 {
    perspectiveMatrix[3, i] = 0.0
  }

  perspectiveMatrix[3, 3] = 1.0

  // If the perspective matrix is not invertible, we are also unable to
  // decompose, so we'll bail early. Constant taken from SkMatrix44::invert.
  if abs(perspectiveMatrix.determinant) < 1e-8 {
    return nil 
  }

  if matrix[3, 0] != 0.0 || matrix[3, 1] != 0.0 || matrix[3, 2] != 0.0 {
    // rhs is the right hand side of the equation.
    var rhs: [Double] = [
      matrix[3, 0],
      matrix[3, 1],
      matrix[3, 2],
      matrix[3, 3]
    ]

    // Solve the equation by inverting perspectiveMatrix and multiplying
    // rhs by the inverse.
    var inversePerspectiveMatrix = Mat4()
    if !perspectiveMatrix.invert(matrix: &inversePerspectiveMatrix) {
      return nil
    }

    let transposedInversePerspectiveMatrix = inversePerspectiveMatrix

    transposedInversePerspectiveMatrix.transpose()
    transposedInversePerspectiveMatrix.map(scalars: &rhs)

    for i in 0..<4 {
      decomp.perspective[i] = rhs[i]
    }

  } else {
    // No perspective.
    for i in 0..<3 {
      decomp.perspective[i] = 0.0
    }
    decomp.perspective[3] = 1.0
  }

  for i in 0..<3 {
    decomp.translate[i] = matrix[i, 3]
  }

  var row: Array<Array<Double>> = Array<Array<Double>>(repeating: Array<Double>(repeating: 0.0, count: 3), count: 3)
  for i in 0..<3 {
    for j in 0..<3 {
      row[i][j] = matrix[j, i]
    }
  }

  // Compute X scale factor and normalize first row.
  decomp.scale[0] = length3(row[0])
  if decomp.scale[0] != 0.0 {
    row[0][0] /= decomp.scale[0]
    row[0][1] /= decomp.scale[0]
    row[0][2] /= decomp.scale[0]
  }

  // Compute XY shear factor and make 2nd row orthogonal to 1st.
  decomp.skew[0] = dot(row[0], row[1])
  combine(&row[1], row[1], row[0], 1.0, -decomp.skew[0])

  // Now, compute Y scale and normalize 2nd row.
  decomp.scale[1] = length3(row[1])
  if decomp.scale[1] != 0.0 {
    row[1][0] /= decomp.scale[1]
    row[1][1] /= decomp.scale[1]
    row[1][2] /= decomp.scale[1]
  }

  decomp.skew[0] /= decomp.scale[1]

  // Compute XZ and YZ shears, orthogonalize 3rd row
  decomp.skew[1] = dot(row[0], row[2])
  combine(&row[2], row[2], row[0], 1.0, -decomp.skew[1])
  decomp.skew[2] = dot(row[1], row[2])
  combine(&row[2], row[2], row[1], 1.0, -decomp.skew[2])

  // Next, get Z scale and normalize 3rd row.
  decomp.scale[2] = length3(row[2])
  if decomp.scale[2] != 0.0 {
    row[2][0] /= decomp.scale[2]
    row[2][1] /= decomp.scale[2]
    row[2][2] /= decomp.scale[2]
  }

  decomp.skew[1] /= decomp.scale[2]
  decomp.skew[2] /= decomp.scale[2]

  // At this point, the matrix (in rows) is orthonormal.
  // Check for a coordinate system flip.  If the determinant
  // is -1, then negate the matrix and the scaling factors.
  var pdum3 = Array<Double>(repeating: 0.0, count: 3)
  cross3(&pdum3, row[1], row[2])
  if dot(row[0], pdum3) < 0 {
    for i in 0..<3 {
      decomp.scale[i] *= -1.0
      for j in 0..<3 {
        row[i][j] *= -1.0
      }
    }
  }

  let row00 = row[0][0]
  let row11 = row[1][1]
  let row22 = row[2][2]

  decomp.quaternion.x =
      0.5 * sqrt(max(1.0 + row00 - row11 - row22, 0.0))
  decomp.quaternion.y =
      0.5 * sqrt(max(1.0 - row00 + row11 - row22, 0.0))
  decomp.quaternion.z = 
      0.5 * sqrt(max(1.0 - row00 - row11 + row22, 0.0))
  decomp.quaternion.w =
      0.5 * sqrt(max(1.0 + row00 + row11 + row22, 0.0))

  if row[2][1] > row[1][2] {
    decomp.quaternion.x = -decomp.quaternion.x
  }
  if row[0][2] > row[2][0] {
    decomp.quaternion.y = -decomp.quaternion.y
  }
  if row[1][0] > row[0][1] {
    decomp.quaternion.z = -decomp.quaternion.z
  }

  return decomp
}

public func composeTransform(_ decomp: DecomposedTransform) -> Transform {
  let perspective = buildPerspectiveMatrix(decomp)
  let translation = buildTranslationMatrix(decomp)
  let rotation = buildRotationMatrix(decomp)
  let skew = buildSkewMatrix(decomp)
  let scale = buildScaleMatrix(decomp)

  return composeTransform(perspective, translation, rotation, skew, scale)
}

public func getScaleTransform(anchor: IntPoint, scale: Float) -> Transform {
  var transform = Transform()
  transform.translate(x: Float(anchor.x) * (1 - scale),
                      y: Float(anchor.y) * (1 - scale))
  transform.scale(x: scale, y: scale)
  return transform
}

func composeTransform(_ perspective: Mat4,
                      _ translation: Mat4,
                      _ rotation: Mat4,
                      _ skew: Mat4,
                      _ scale: Mat4) -> Transform {
  let matrix = Mat4()
  matrix.preConcat(matrix: perspective)
  matrix.preConcat(matrix: translation)
  matrix.preConcat(matrix: rotation)
  matrix.preConcat(matrix: skew)
  matrix.preConcat(matrix: scale)

  return Transform(matrix: matrix)
}

func buildPerspectiveMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  let matrix = Mat4()

  for i in 0..<4 {
    matrix[3, i] = decomp.perspective[i]
  }
  
  return matrix
}

func buildTranslationMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  let matrix = Mat4()
  // Implicitly calls matrix.setIdentity()
  matrix.translate(x: decomp.translate[0],
                   y: decomp.translate[1],
                   z: decomp.translate[2])
  return matrix
}

func buildSnappedTranslationMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  decomp.translate[0] = round(decomp.translate[0])
  decomp.translate[1] = round(decomp.translate[1])
  decomp.translate[2] = round(decomp.translate[2])
  return buildTranslationMatrix(decomp)
}

func buildRotationMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  return Transform(quaternion: decomp.quaternion).matrix
}

func buildSnappedRotationMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  // Create snapped rotation.
  let rotationMatrix = buildRotationMatrix(decomp)
  for i in 0..<3 {
    for j in 0..<3 {
      var value = rotationMatrix[i, j]
      // Snap values to -1, 0 or 1.
      if value < -0.5 {
        value = -1.0
      } else if value > 0.5 {
        value = 1.0
      } else {
        value = 0.0
      }
      rotationMatrix[i, j] = value
    }
  }
  return rotationMatrix
}

func buildSkewMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  let matrix = Mat4()

  let temp = Mat4()
  if decomp.skew[2] != 0 {
    temp[1, 2] = decomp.skew[2]
    matrix.preConcat(matrix: temp)
  }

  if decomp.skew[1] != 0 {
    temp[1, 2] = 0
    temp[0, 2] = decomp.skew[1]
    matrix.preConcat(matrix: temp)
  }

  if decomp.skew[0] != 0 {
    temp[0, 2] = 0
    temp[0, 1] = decomp.skew[0]
    matrix.preConcat(matrix: temp)
  }
  return matrix
}

func buildScaleMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  let matrix = Mat4()
  matrix.scale(x: decomp.scale[0],
               y: decomp.scale[1],
               z: decomp.scale[2])
  return matrix
}

func buildSnappedScaleMatrix(_ decomp: DecomposedTransform) -> Mat4 {
  decomp.scale[0] = round(decomp.scale[0])
  decomp.scale[1] = round(decomp.scale[1])
  decomp.scale[2] = round(decomp.scale[2])
  return buildScaleMatrix(decomp)
}

@inline(__always)
fileprivate func length3(_ v: [Double]) -> Double {
  let vd: [Double] = [v[0], v[1], v[2]]
  return sqrt(vd[0] * vd[0] + vd[1] * vd[1] + vd[2] * vd[2])
}

@inline(__always)
fileprivate func dot(_ a: [Double], _ b: [Double]) -> Double {
  var total = 0.0
  for i in 0..<a.count {
    total += a[i] * b[i]
  }
  return total
}

@inline(__always)
fileprivate func cross3(_ out: inout [Double], _ a: [Double], _ b: [Double]) {
  let x = a[1] * b[2] - a[2] * b[1]
  let y = a[2] * b[0] - a[0] * b[2]
  let z = a[0] * b[1] - a[1] * b[0]
  out[0] = x
  out[1] = y
  out[2] = z
}

@inline(__always)
fileprivate func round(_ n: Double) -> Double {
  return floor(n + 0.5)
}

@inline(__always)
fileprivate func combine(
  _ out: inout [Double],
  _ a: [Double],
  _ b: [Double],
  _ scaleA: Double,
  _ scaleB: Double) {
  for i in 0..<out.count {
    out[i] = (a[i] * scaleA) + (b[i] * scaleB)
  }
}

@inline(__always)
fileprivate func normalize(_ m: inout Mat4) -> Bool {
  if m[3, 3] == 0.0 {
    return false
  }

  let scale = 1.0 / m[3, 3]
  for i in 0..<4 {
    for j in 0..<4 {
      m[i, j] = m[i, j] * scale
    }
  }

  return true
}

