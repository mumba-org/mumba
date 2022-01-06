// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import MumbaShims

public class FloatAnimationCurveAdapter : FloatAnimationCurve {
  
  public private(set) var duration: TimeDelta
  private var tweenType: TweenType
  private var initialValue: Float
  private var targetValue: Float
  internal var nativeCurve: NativeAnimationCurve?
  
  public init(tweenType: TweenType,
              initialValue: Float,
              targetValue: Float,
              duration: TimeDelta) {
    self.tweenType = tweenType
    self.initialValue = initialValue
    self.targetValue = targetValue
    self.duration = duration
    
    var callbacks = FloatAnimationCurveCallbacks()
    callbacks.GetDuration = { (curve: UnsafeMutableRawPointer?) -> Int64 in
      let p = unsafeBitCast(curve, to: FloatAnimationCurveAdapter.self)
      let dur = p.duration
      return dur.milliseconds
    }
    
    callbacks.GetValue = { (curve: UnsafeMutableRawPointer?, t: Int64) -> Float in
      let p = unsafeBitCast(curve, to: FloatAnimationCurveAdapter.self)
      return p.getValue(TimeDelta.from(milliseconds: t))
    }
    
    let selfptr = Unmanaged.passRetained(self).toOpaque()//unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    nativeCurve = NativeAnimationCurve.createFloatAnimation(selfptr, callbacks)
  }

  public func clone() -> AnimationCurve {
    return FloatAnimationCurveAdapter(
      tweenType: tweenType,
      initialValue: initialValue,
      targetValue: targetValue,
      duration: duration
    )
  }

  public func getValue(_ t: TimeDelta) -> Float {
    if t >= duration {
      return targetValue
    }
    if t <= TimeDelta() {
      return initialValue
    }
    let progress = Double(t.milliseconds) / Double(duration.milliseconds)
    return Tween.floatValueBetween(
      value: Tween.calculateValue(type: tweenType, state: progress),
      start: initialValue,
      target: targetValue) 
  }

}