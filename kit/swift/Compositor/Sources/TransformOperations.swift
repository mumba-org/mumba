// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public enum TransformOperationType : Int {
  case translate = 0
  case rotate = 1
  case scale = 2
  case skew = 3
  case perspective = 4
  case matrix = 5
  case identity = 6
}

public class TransformOperation {

  public var type: TransformOperationType {
    return TransformOperationType(rawValue: Int(_TransformOperationGetType(reference)))!
  }
  
  public var reference: TransformOperationRef

  init(reference: TransformOperationRef) {
    self.reference = reference
  }

  // theres no destruction, because they should be owned
  // by the TransformOperations
}

public class TransformOperations {

  public var isTranslation: Bool {
    return _TransformOperationsIsTranslation(reference) == 0 ? false : true
  }

  public var preservesAxisAlignment: Bool {
    return _TransformOperationsPreservesAxisAlignment(reference) == 0 ? false : true
  }

  public var isIdentity: Bool {
    return _TransformOperationsIsIdentity(reference) == 0 ? false : true
  }

  public var count: Int { 
    return Int(_TransformOperationsCount(reference))
  }

  public subscript(index: Int) -> TransformOperation? {
    let ref = _TransformOperationsGet(reference, CInt(index))
    if ref == nil {
      return nil
    }
    return TransformOperation(reference: ref!)
  }

  public var reference: TransformOperationsRef 

  public init() {
    reference = _TransformOperationsCreate()
  }

  init(reference: TransformOperationsRef) {
    self.reference = reference
  }
  
  deinit {
    _TransformOperationsDestroy(reference)
  }
  
  public func apply() -> Transform {
    let matrix = _TransformOperationsApply(reference)
    return Transform(matrix: Mat4(reference: matrix!, owned: true))
  }

  public func blend(from: TransformOperations, progress: Float) -> TransformOperations {
    let ref = _TransformOperationsBlend(reference, from.reference, progress)
    return TransformOperations(reference: ref!)
  }

  public func matchesTypes(other: TransformOperations) -> Bool {
    return _TransformOperationsMatchesTypes(reference, other.reference) == 0 ? false : true
  }

  public func canBlendWith(other: TransformOperations) -> Bool {
    return _TransformOperationsCanBlendWith(reference, other.reference) == 0 ? false : true
  }

  public func scaleComponent(scale: inout Float) -> Bool {
    return _TransformOperationsScaleComponent(reference, &scale) == 0 ? false : true
  }

  public func appendTranslate(x: Float, y: Float, z: Float) {
    _TransformOperationsAppendTranslate(reference, x, y, z)
  }

  public func appendRotate(x: Float, y: Float, z: Float, degrees: Float) {
    _TransformOperationsAppendRotate(reference, x, y, z, degrees)
  }

  public func appendScale(x: Float, y: Float, z: Float) {
    _TransformOperationsAppendScale(reference, x, y, z)
  }

  public func appendSkew(x: Float, y: Float) {
    _TransformOperationsAppendSkew(reference, x, y)
  }

  public func appendPerspective(depth: Float) {
    _TransformOperationsAppendPerspective(reference, depth)
  }

  public func appendMatrix(matrix: Transform) {
    _TransformOperationsAppendMatrix(reference, matrix.matrix.reference)
  }

  public func appendIdentity() {
    _TransformOperationsAppendIdentity(reference)
  }

  public func append(operation: TransformOperation) {
    _TransformOperationsAppend(reference, operation.reference)
  }
  
  public func approximatelyEqual(other: TransformOperations,
                                 tolerance: Float) -> Bool {
    return _TransformApproximatelyEqual(reference, other.reference, tolerance) == 0 ? false : true
  }

}
