// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class Mat {

  public static let scaleXOffset = 0
  public static let skewXOffset  = 1
  public static let transXOffset = 2
  public static let skewYOffset  = 3
  public static let scaleYOffset = 4
  public static let transYOffset = 5
  public static let persp0Offset = 6
  public static let persp1Offset = 7
  public static let persp2Offset = 8

  public static func fromMat4(_ mat4: Mat4) -> Mat {
    let dst = Mat()

    dst[Mat.scaleXOffset] = mat4[0, 0]
    dst[Mat.skewXOffset]  = mat4[1, 0]
    dst[Mat.transXOffset] = mat4[3, 0]

    dst[Mat.skewYOffset]  = mat4[0, 1]
    dst[Mat.scaleYOffset] = mat4[1, 1]
    dst[Mat.transYOffset] = mat4[3, 1]

    dst[Mat.persp0Offset] = mat4[0, 3]
    dst[Mat.persp1Offset] = mat4[1, 3]
    dst[Mat.persp2Offset] = mat4[3, 3]

    return dst
  }

  public var scaleX: Double {
    get {
      return self[Mat.scaleXOffset]
    }
    set {
      self[Mat.scaleXOffset] = newValue
    }
  }

  public var skewX: Double {
    get {
      return self[Mat.skewXOffset]
    }
    set {
      self[Mat.skewXOffset] = newValue
    }
  }

  public var transX: Double {
    get {
      return self[Mat.transXOffset]
    }
    set {
      self[Mat.transXOffset] = newValue
    }
  }

  public var skewY: Double {
    get {
      return self[Mat.skewYOffset]
    }
    set {
      self[Mat.skewYOffset] = newValue
    }
  }

  public var scaleY: Double {
    get {
      return self[Mat.scaleYOffset]
    }
    set {
      self[Mat.scaleYOffset] = newValue
    }
  }

  public var transY: Double {
    get {
      return self[Mat.transYOffset]
    }
    set {
      self[Mat.transYOffset] = newValue
    }
  }

  public var persp0: Double {
    get {
      return self[Mat.persp0Offset]
    }
    set {
      self[Mat.persp0Offset] = newValue
    }
  }

  public var persp1: Double {
    get {
      return self[Mat.persp1Offset]
    }
    set {
      self[Mat.persp1Offset] = newValue
    }
  }

  public var persp2: Double {
    get {
      return self[Mat.persp2Offset]
    }
    set {
      self[Mat.persp2Offset] = newValue
    }
  }

  public var rectStaysRect: Bool {
    return _MatrixRectStaysRect(reference) == 0 ? false : true
  }

  public var reference: MatrixRef
  var owned: Bool

  public init() {
    reference = _MatrixCreate()
    owned = true
  }

  public init(reference: MatrixRef, owned: Bool = true) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    if owned {
      _MatrixDestroy(reference)
    }
  }

  public subscript(index: Int) -> Double {
    get {
      return _MatrixGet(reference, Int32(index))
    }
    set {
      _MatrixSet(reference, Int32(index), newValue)
    }
  }

  public func toIdentity() {
    _MatrixToIdentity(reference)
  }

  public func scale(x: Double, y: Double) {
    _MatrixScale(reference, x, y)
  }

  public func translate(x: Double, y: Double) {
    _MatrixTranslate(reference, x, y)
  }

  public func preTranslate(x: Double, y: Double) {
    _MatrixPreTranslate(reference, x, y)
  }

  public func preScale(x: Double, y: Double) {
    _MatrixPreScale(reference, x, y)
  }

  public func postTranslate(x: Double, y: Double) {
    _MatrixPostTranslate(reference, x, y)
  }

  public func postConcat(matrix: Mat) {
    _MatrixPostConcat(reference, matrix.reference)
  }

  public func preConcat(matrix: Mat) {
    _MatrixPreConcat(reference, matrix.reference)
  }

  public func invert(matrix: inout Mat) -> Bool {
    return _MatrixInvert(reference, &matrix.reference) == 1 ? true : false
  }

}

public class Mat4 {

 public static let identity: Mat4 = Mat4(identity: true)

 public var isIdentity: Bool {
   return _Matrix44IsIdentity(reference) != 0
 }

 public var isScaleTranslate: Bool {
   return _Matrix44IsScaleTranslate(reference) != 0
 }

 public var isTranslate: Bool {
   return _Matrix44IsTranslate(reference) != 0
 }

 public var determinant: Double {
   return _Matrix44GetDeterminant(reference)
 }

 public var reference: Matrix44Ref
 private var owned: Bool

 public init(identity: Bool = false) {
   reference = _Matrix44Create(identity ? 1 : 0)
   owned = true
 }

 public init(reference: Matrix44Ref, owned: Bool = true) {
   self.reference = reference
   self.owned = owned
 }

 deinit {
   if owned {
    _Matrix44Destroy(reference)
   }
 }

 public subscript(row: Int, col: Int) -> Double {
   get {
     return _Matrix44Get(reference, Int32(row), Int32(col))
   }
   set {
     _Matrix44Set(reference, Int32(row), Int32(col), newValue)
   }
 }

 public func toIdentity() {
   _Matrix44ToIdentity(reference)
 }

 public func preTranslate(x: Double, y: Double, z: Double) {
   _Matrix44PreTranslate(reference, x, y, z)
 }

 public func preScale(x: Double, y: Double, z: Double) {
   _Matrix44PreScale(reference, x, y, z)
 }

 public func postConcat(matrix: Mat4) {
   _Matrix44PostConcat(reference, matrix.reference)
 }

 public func preConcat(matrix: Mat4) {
   _Matrix44PreConcat(reference, matrix.reference)
 }

 public func invert(matrix: inout Mat4) -> Bool {
   return _Matrix44Invert(reference, &matrix.reference) == 1 ? true : false
 }

 public func map(rect: inout IntRect) {
    var x: Int32 = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
   _Matrix44MapRect(reference, &x, &y, &w, &h)
   rect.origin = IntPoint(x: Int(x), y: Int(y))
   rect.size = IntSize(width: Int(w), height: Int(h))
 }

 public func map(rect: inout FloatRect) {
    var x: Float = 0, y: Float = 0, w: Float = 0, h: Float = 0
   _Matrix44MapRectf(reference, &x, &y, &w, &h)
   rect.origin = FloatPoint(x: x, y: y)
   rect.size = FloatSize(width: w, height: h)
 }

 public func map(scalars: inout [Double]) {
    assert(scalars.count >= 4)
    var a = scalars[0] 
    var b = scalars[1]
    var c = scalars[2]
    var d = scalars[3]
   _Matrix44MapScalars(reference, &a, &b, &c, &d)
   scalars[0] = a
   scalars[1] = b
   scalars[2] = c
   scalars[3] = d
 }

 public func map(input: [Double], output: inout[Double]) {
    assert(input.count >= 4)
    assert(output.count >= 4)
    var a: Double = 0.0
    var b: Double = 0.0
    var c: Double = 0.0 
    var d: Double = 0.0 
   _Matrix44MapScalars2(reference, input[0], input[1], input[2], input[3], &a, &b, &c, &d)
   output[0] = a
   output[1] = b
   output[2] = c
   output[3] = d
 }

 public func toMat3() -> Mat {
   return Mat.fromMat4(self)
 }

 public func set3x3(_ m00: Double, _ m10: Double, _ m20: Double,
                    _ m01: Double, _ m11: Double, _ m21: Double,
                    _ m02: Double, _ m12: Double, _ m22: Double) {
   _Matrix44Set3x3(reference, m00, m10, m20, m01, m11, m21, m02, m12, m22)
 }

 public func scale(x: Double, y: Double, z: Double) {
   _Matrix44Scale(reference, x, y, z)
 }

 public func setRotateDegreesAbout(x: Double, y: Double, z: Double, degrees: Double) {
   _Matrix44SetRotateDegreesAbout(reference, x, y, z, degrees)
 }

 public func transpose() {
   _Matrix44Transpose(reference)
 }

 public func translate(x: Double, y: Double, z: Double) {
   _Matrix44Translate(reference, x, y, z)
 }

}

extension Mat4 : Equatable {}

public func * (left: Mat4, right: Mat4) -> Mat4 {
  let newhandle = _Matrix44Multiply(left.reference, right.reference)
  return Mat4(reference: newhandle!)
}

public func == (left: Mat4, right: Mat4) -> Bool {
  return _Matrix44Equals(left.reference, right.reference) == 1 ? true : false
}

public func != (left: Mat4, right: Mat4) -> Bool {
  return _Matrix44NotEquals(left.reference, right.reference) == 1 ? true : false
}
