// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class InterpolatedTransform {
  
  public var child: InterpolatedTransform?
  
  public var startTime: Float
  public var endTime: Float
  public var reversed: Bool

  public init () {
    startTime = 0.0
    endTime = 1.0
    reversed = false
  }

  public init (startTime: Float, endTime: Float) {
    self.startTime = startTime
    self.endTime = endTime
    reversed = false
  }

  public func interpolate(_ t: Float) -> Transform {
    var tx = t
    if reversed {
      tx = 1.0 - tx
    }
    var result = interpolateButDoNotCompose(tx)
    if let c = child {
      result.concatTransform(transform: c.interpolate(tx))
    }
    return result
  }

  public func valueBetween(time: Float, startValue: Float, endValue: Float) -> Float {
    
    if time != time || startTime != startTime || endTime != endTime {
      return startValue
    }

    if time < startTime {
      return startValue
    }

    if time >= endTime {
      return endValue
    }

    let t = Double((time - startTime) / (endTime - startTime))
    return Float(Tween.doubleValueBetween(value: t, start: Double(startValue), target: Double(endValue)))
  }

  // should be implemented by inheritance
  public func interpolateButDoNotCompose(_ t: Float) -> Transform {
    assert(false)
    return Transform()
  }

}

public class InterpolatedTranslation : InterpolatedTransform {

   public var startPos: FloatPoint3
   public var endPos: FloatPoint3

   public init(startPos: FloatPoint, endPos: FloatPoint) {
     self.startPos = FloatPoint3(startPos)
     self.endPos = FloatPoint3(endPos)
     super.init()
   }

   public init(startPos: FloatPoint, endPos: FloatPoint,
               startTime: Float, endTime: Float) {
     self.startPos = FloatPoint3(startPos)
     self.endPos = FloatPoint3(endPos)
     super.init(startTime: startTime, endTime: endTime)
   }

   public init(startPos: FloatPoint3, endPos: FloatPoint3) {
     self.startPos = startPos
     self.endPos = endPos
     super.init()
   }

   public init(startPos: FloatPoint3, endPos: FloatPoint3, 
               startTime: Float, endTime: Float) {
     self.startPos = startPos
     self.endPos = endPos
     super.init(startTime: startTime, endTime: endTime)
   }

   
  public override func interpolateButDoNotCompose(_ t: Float) -> Transform {
    var result = Transform()
    result.translate3d(x: valueBetween(time: t, startValue: startPos.x, endValue: endPos.x),
                       y: valueBetween(time: t, startValue: startPos.y, endValue: endPos.y),
                       z: valueBetween(time: t, startValue: startPos.z, endValue: endPos.z))
    return result
  }

}

public class InterpolatedScale : InterpolatedTransform {
 
  public var startScale: FloatPoint3
  public var endScale: FloatPoint3

  public init(startScale: Float, endScale: Float) {
    self.startScale = FloatPoint3(x: startScale, y: startScale, z: startScale)
    self.endScale = FloatPoint3(x: endScale, y: endScale, z: endScale)
    super.init()
  }
  
  public init(startScale: Float, endScale: Float,
              startTime: Float, endTime: Float) {
    self.startScale = FloatPoint3(x: startScale, y: startScale, z: startScale)
    self.endScale = FloatPoint3(x: endScale, y: endScale, z: endScale)
    super.init(startTime: startTime, endTime: endTime)
  }
  
  public init(startScale: FloatPoint3, endScale: FloatPoint3) {
    self.startScale = startScale
    self.endScale = endScale
    super.init()
  }
  
  public init(startScale: FloatPoint3,
              endScale: FloatPoint3,
              startTime: Float,
              endTime: Float) {
    self.startScale = startScale
    self.endScale = endScale
    super.init(startTime: startTime, endTime: endTime)
  }

  public override func interpolateButDoNotCompose(_ t: Float) -> Transform {
    var result = Transform()
    let scaleX = valueBetween(time: t, startValue: startScale.x, endValue: endScale.x)
    let scaleY = valueBetween(time: t, startValue: startScale.y, endValue: endScale.y)
    let scaleZ = valueBetween(time: t, startValue: startScale.z, endValue: endScale.z)
    result.scale3d(x: scaleX, y: scaleY, z: scaleZ)
    return result
  }

}

public class InterpolatedConstantTransform : InterpolatedTransform {
  
  public let transform: Transform

  public init(transform: Transform) {
    self.transform = transform
    super.init()
  }
  
  public override func interpolateButDoNotCompose(_ t: Float) -> Transform {
    return transform
  }
}

public class InterpolatedTransformAboutPivot : InterpolatedTransform {
  
  private var transform: InterpolatedTransform?
  
  public init(pivot: IntPoint, transform: InterpolatedTransform) {
    super.init()
    initialize(pivot: pivot, transform: transform)
  }

  // Takes ownership of the passed transform.
  public init(pivot: IntPoint, transform: InterpolatedTransform, startTime: Float, endTime: Float) {
    super.init()
    initialize(pivot: pivot, transform: transform)
  }

  public override func interpolateButDoNotCompose(_ t: Float) -> Transform {
    if let xform = transform {
      return xform.interpolate(t)
    }
    return Transform()
  }

  private func initialize(pivot: IntPoint, transform xform: InterpolatedTransform) {
    var toPivot = Transform()
    var fromPivot = Transform()

    toPivot.translate(x: Float(-pivot.x), y: Float(-pivot.y))
    fromPivot.translate(x: Float(pivot.x), y: Float(pivot.y))

    let preTransform = InterpolatedConstantTransform(transform: toPivot)
    let postTransform = InterpolatedConstantTransform(transform: fromPivot)
    xform.child = postTransform
    preTransform.child = xform
    self.transform = preTransform
  }

}

public class InterpolatedAxisAngleRotation : InterpolatedTransform {
  
  private var axis: FloatVec3
  private var startDegrees: Float
  private var endDegrees: Float

  public init(axis: FloatVec3, startDegrees: Float, endDegrees: Float) {
    self.axis = axis
    self.startDegrees = startDegrees
    self.endDegrees = endDegrees
    super.init()
  }

  public init(
    axis: FloatVec3,
    startDegrees: Float,
    endDegrees: Float,
    startTime: Float,
    endTime: Float) {
    self.axis = axis
    self.startDegrees = startDegrees
    self.endDegrees = endDegrees
    super.init(startTime: startTime, endTime: endTime)
  }

  public override func interpolateButDoNotCompose(_ t: Float) -> Transform {
    var result = Transform()
    result.rotateAbout(axis: axis, degrees: Double(valueBetween(time: t, startValue: startDegrees, endValue: endDegrees)))
    return result
  }

}