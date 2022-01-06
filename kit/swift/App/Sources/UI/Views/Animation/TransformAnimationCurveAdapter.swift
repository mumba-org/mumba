// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import MumbaShims

public class TransformAnimationCurveAdapter : TransformAnimationCurve {
  
  public var isTranslation: Bool {
    return initialValue.isIdentityOrTranslation && targetValue.isIdentityOrTranslation
  }
  
  public var preservesAxisAlignment: Bool {
    return (initialValue.isIdentity ||
          initialValue.isScaleOrTranslation) &&
         (targetValue.isIdentity || targetValue.isScaleOrTranslation)
  }

  public private(set) var duration: TimeDelta
  var tweenType: TweenType
  var initialValue: Transform
  var initialWrappedValue: TransformOperations
  var targetValue: Transform
  var targetWrappedValue: TransformOperations
  var decomposedInitialValue: DecomposedTransform
  var decomposedTargetValue: DecomposedTransform
  var nativeCurve: NativeAnimationCurve?
  
  public init(tween: TweenType, 
              initialValue: Transform, 
              targetValue: Transform, 
              duration: TimeDelta) {
    tweenType = tween
    self.initialValue = initialValue
    initialWrappedValue = wrapTransform(initialValue)
    self.targetValue = targetValue
    targetWrappedValue = wrapTransform(targetValue)
    self.duration = duration
    decomposedInitialValue = Graphics.decomposeTransform(initialValue)!
    decomposedTargetValue = Graphics.decomposeTransform(targetValue)!

    var callbacks = TransformAnimationCurveCallbacks()
    callbacks.GetDuration = { (curve: UnsafeMutableRawPointer?) -> Int64 in
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      let dur = p.duration
      return dur.milliseconds
    }
    callbacks.GetValue = { (curve: UnsafeMutableRawPointer?, t: Int64) -> TransformOperationsRef? in
      guard curve != nil else {
        return nil
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      let tops = p.getValue(TimeDelta.from(milliseconds: t))
      return tops.reference
    }
    callbacks.GetAnimatedBoundsForBox = { (curve: UnsafeMutableRawPointer?, 
      ix: Float, iy: Float, iz: Float, iw: Float, ih: Float, id: Float,
      ox: UnsafeMutablePointer<Float>?, oy: UnsafeMutablePointer<Float>?, oz: UnsafeMutablePointer<Float>?, ow: UnsafeMutablePointer<Float>?, oh: UnsafeMutablePointer<Float>?, od: UnsafeMutablePointer<Float>?) -> CInt in 
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      if let box = p.animatedBoundsForBox(box: FloatBox(x: ix, y: iy, z: iz, width: iw, height: ih, depth: id)) {
        ox?.pointee = box.x
        oy?.pointee = box.y
        oz?.pointee = box.z
        ow?.pointee = box.width
        oh?.pointee = box.height
        od?.pointee = box.depth
        return 1
      }
      return 0
    }

    callbacks.GetIsTranslation = {(curve: UnsafeMutableRawPointer?) -> CInt in
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      return p.isTranslation ? 1 : 0
    }
    
    callbacks.GetPreservesAxisAlignment = {(curve: UnsafeMutableRawPointer?) -> CInt in 
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      return p.preservesAxisAlignment ? 1 : 0
    }
    
    callbacks.GetAnimationStartScale = {(curve: UnsafeMutableRawPointer?, forwardDirection: CInt, startScale: UnsafeMutablePointer<Float>?) -> CInt in 
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      if let v = p.animationStartScale(forwardDirection: forwardDirection == 0 ? false : true) {
        startScale?.pointee = v 
        return 1
      }
      return 0
    }
    
    callbacks.GetMaximumTargetScale = {(curve: UnsafeMutableRawPointer?, forwardDirection: CInt, maxScale: UnsafeMutablePointer<Float>?) -> CInt in
      guard curve != nil else {
        return 0
      }
      let p = unsafeBitCast(curve, to: TransformAnimationCurveAdapter.self)
      if let v = p.maximumTargetScale(forwardDirection: forwardDirection == 0 ? false : true) {
        maxScale?.pointee = v 
        return 1
      }
      return 0
    }
    
    let selfptr = Unmanaged.passRetained(self).toOpaque()//unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    nativeCurve = NativeAnimationCurve.createTransformAnimation(selfptr, callbacks)
  }

  public func getValue(_ t: TimeDelta) -> TransformOperations {
    if t >= duration {
      return targetWrappedValue
    }

    if t <= TimeDelta() {
      return initialWrappedValue
    }
  
    let progress = Double(t.microseconds) / Double(duration.microseconds)

    let toReturn: DecomposedTransform = Graphics.blendDecomposedTransforms(
      decomposedTargetValue, decomposedInitialValue,
      Tween.calculateValue(type: tweenType, state: progress))

    return wrapTransform(Graphics.composeTransform(toReturn))
  }

  public func clone() -> AnimationCurve {
    return TransformAnimationCurveAdapter(
      tween: tweenType, 
      initialValue: initialValue, 
      targetValue: targetValue, 
      duration: duration)
  }
  
  public func animatedBoundsForBox(box: FloatBox) -> FloatBox? {
    return nil
  }
  
  public func animationStartScale(forwardDirection: Bool) -> Float? {
    return nil
  }

  public func maximumTargetScale(forwardDirection: Bool) -> Float? {
    return nil
  }

}

public class InverseTransformCurveAdapter : TransformAnimationCurve {
  
  public var isTranslation: Bool {
    return initialValue.isIdentityOrTranslation && baseCurve.isTranslation
  }
  
  public var preservesAxisAlignment: Bool {
    return (initialValue.isIdentity ||
          initialValue.isScaleOrTranslation) && baseCurve.preservesAxisAlignment
  }

  public private(set) var duration: TimeDelta
  var baseCurve: TransformAnimationCurveAdapter
  var initialValue: Transform
  var initialWrappedValue: TransformOperations
  var effectiveInitialValue: Transform
  
  public init(baseCurve: TransformAnimationCurveAdapter,
              initialValue: Transform,
              duration: TimeDelta) {
    
    self.baseCurve = baseCurve
    self.initialValue = initialValue
    initialWrappedValue = wrapTransform(initialValue)
    self.duration = duration
    effectiveInitialValue =
      baseCurve.getValue(TimeDelta()).apply() * initialValue

  }

  public func clone() -> AnimationCurve {
    return InverseTransformCurveAdapter(baseCurve: baseCurve, initialValue: initialValue, duration: duration)
  }

  public func getValue(_ t: TimeDelta) -> TransformOperations {
    if t <= TimeDelta() {
      return initialWrappedValue
    }

    let baseTransform: Transform = baseCurve.getValue(t).apply()
  
    var toReturn = Transform(skipInitialization: true)
    let isInvertible = baseTransform.getInverse(invert: &toReturn)
    assert(isInvertible)
  
    toReturn.preconcatTransform(transform: effectiveInitialValue)

    return wrapTransform(toReturn)
  }
  
  public func animatedBoundsForBox(box: FloatBox) -> FloatBox? {
    return nil
  }
  
  public func animationStartScale(forwardDirection: Bool) -> Float? {
    return nil
  }

  public func maximumTargetScale(forwardDirection: Bool) -> Float? {
    return nil
  }

}

fileprivate func wrapTransform(_ transform: Transform) -> TransformOperations {
  let operations = TransformOperations()
  operations.appendMatrix(matrix: transform)
  return operations
}