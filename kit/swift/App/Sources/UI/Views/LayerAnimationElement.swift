// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

fileprivate let slowDurationScaleMultiplier: Int = 4
fileprivate let fastDurationScaleDivisor: Int = 4
fileprivate let nonZeroDurationScaleDivisor: Int = 20

public class LayerAnimationElement {

  public struct AnimatableProperty: OptionSet {
    public let rawValue: Int

    static let Unknown       = AnimatableProperty(rawValue: 1 << 0)
    static let Transform     = AnimatableProperty(rawValue: 1 << 1)
    static let Bounds        = AnimatableProperty(rawValue: 1 << 2)
    static let Opacity       = AnimatableProperty(rawValue: 1 << 3)
    static let Visibility    = AnimatableProperty(rawValue: 1 << 4)
    static let Brightness    = AnimatableProperty(rawValue: 1 << 5)
    static let Grayscale     = AnimatableProperty(rawValue: 1 << 6)
    static let Color         = AnimatableProperty(rawValue: 1 << 7)

    // Used when iterating over properties.
    static let FirstProperty = AnimatableProperty(rawValue: Transform.rawValue)
    static let Sentinel      = AnimatableProperty(rawValue: 1 << 8)

    public init(rawValue: Int) {
      self.rawValue = rawValue
    }
  }

  // FIX: Maybe this can be a ADT enum in swift
  public struct TargetValue {
    
    public var bounds: IntRect
    public var transform: Transform
    public var opacity: Float
    public var visibility: Bool
    public var brightness: Float
    public var grayscale: Float
    public var color: Color

    public init() {
      bounds = IntRect()
      transform = Transform()
      opacity = 0.0
      visibility = false
      brightness = 0.0
      grayscale = 0.0
      color = Color.Black
    }

    public init(delegate: LayerAnimationDelegate?) {
      bounds = delegate != nil ? delegate!.boundsForAnimation : IntRect()
      transform = delegate != nil ? delegate!.transformForAnimation : Transform()
      opacity = delegate != nil ? delegate!.opacityForAnimation : 0.0
      visibility = delegate != nil ? delegate!.visibilityForAnimation : false
      brightness = delegate != nil ? delegate!.brightnessForAnimation : 0.0
      grayscale = delegate != nil ? delegate!.grayscaleForAnimation : 0.0
      color = delegate != nil ? delegate!.colorForAnimation : Color.Transparent
    }
  }

  public typealias AnimatableProperties = AnimatableProperty

  class func toAnimatableProperty(property: TargetProperty) -> AnimatableProperty {
    switch property {
      case TargetProperty.Transform:
        return AnimatableProperty.Transform
      case TargetProperty.Bounds:
        return AnimatableProperty.Bounds
      case TargetProperty.Opacity:
        return AnimatableProperty.Opacity
      default:
        assert(false)
        return AnimatableProperty.Unknown
    }
  }

  class func animatablePropertiesToString(properties: AnimatableProperties) -> String {
    return "NOT IMPLEMENTED"
  }

  class func createTransformElement(transform: Transform, duration: TimeDelta) -> LayerAnimationElement {
     return ThreadedTransformTransition(target: transform, duration: duration)
  }

  class func createInterpolatedTransformElement(
      interpolatedTransform: InterpolatedTransform,
      duration: TimeDelta) -> LayerAnimationElement {
    return InterpolatedTransformTransition(transform: interpolatedTransform, duration: duration)
  }

  class func createBoundsElement(
      bounds: IntRect,
      duration: TimeDelta) -> LayerAnimationElement {
    return BoundsTransition(target: bounds, duration: duration)
  }

  class func createOpacityElement(
      opacity: Float,
      duration: TimeDelta) -> LayerAnimationElement {
    return ThreadedOpacityTransition(target: opacity, duration: duration)
  }

  class func createVisibilityElement(
      visibility: Bool,
      duration: TimeDelta) -> LayerAnimationElement {
    return VisibilityTransition(target: visibility, duration: duration)
  }

  class func createBrightnessElement(
      brightness: Float,
      duration: TimeDelta) -> LayerAnimationElement {
    return BrightnessTransition(target: brightness, duration: duration)
  }

  class func createGrayscaleElement(
      grayscale: Float ,
      duration: TimeDelta) -> LayerAnimationElement {
    return GrayscaleTransition(target: grayscale, duration: duration)
  }

  class func createPauseElement(
      properties: AnimatableProperties,
      duration: TimeDelta) -> LayerAnimationElement {
    return Pause(properties: properties, duration: duration)
  }

  class func createColorElement(
      color: Color,
      duration: TimeDelta) -> LayerAnimationElement {
    return ColorTransition(target: color, duration: duration)
  }
  
  public var started: Bool { 
    return !firstFrame
  }

  public var requestedStartTime: TimeTicks = TimeTicks()
  public internal(set) var effectiveStartTime: TimeTicks = TimeTicks()
  public var tweenType: TweenType = TweenType.Linear
  public var animationGroupId: Int = 0
  public private(set) var keyframeModelId: Int
  public private(set) var duration: TimeDelta = TimeDelta()
  public private(set) var lastProgressedFraction: Double = 0.0
  public let properties: AnimatableProperties
  fileprivate var firstFrame: Bool = true
  fileprivate var startFrameNumber: Int = 0

  public init(properties: AnimatableProperties,
              duration: TimeDelta) {
     self.properties = properties
     keyframeModelId = AnimationIdProvider.nextKeyframeModelId
     self.duration = getEffectiveDuration(delta: duration)
  }

  public func start(delegate: LayerAnimationDelegate?, animationGroupId: Int) {
    self.animationGroupId = animationGroupId
    lastProgressedFraction = 0.0
    onStart(delegate: delegate)
    if let d = delegate {
      startFrameNumber = d.frameNumber
    }
    requestEffectiveStart(delegate: delegate)
    firstFrame = false
  }

  public func progress(now: TimeTicks, delegate: LayerAnimationDelegate?) -> Bool {
    var needDraw: Bool
    var t: Double = 1.0

    if (effectiveStartTime == TimeTicks()) || (now < effectiveStartTime)  {
      // This hasn't actually started yet.
      needDraw = false
      lastProgressedFraction = 0.0
      return needDraw
    }

    let elapsed: TimeDelta = now - effectiveStartTime
    if (duration > TimeDelta()) && (elapsed < duration) {
      t = Double(elapsed.milliseconds / duration.milliseconds)
    }
    needDraw = onProgress(t: Tween.calculateValue(type: tweenType, state: t), delegate: delegate)
    firstFrame = t == 1.0
    lastProgressedFraction = t
    return needDraw
  }

  public func isFinished(time: TimeTicks, totalDuration: inout TimeDelta) -> Bool {
    if !firstFrame && (effectiveStartTime == TimeTicks()) {
      return false
    }

    var queueingDelay = TimeDelta()
    if !firstFrame {
      queueingDelay = effectiveStartTime - requestedStartTime
    }

    let elapsed: TimeDelta = time - requestedStartTime
    if elapsed >= duration + queueingDelay {
      totalDuration = duration + queueingDelay
      return true
    }
    return false
  }

  public func progressToEnd(delegate: LayerAnimationDelegate?)  -> Bool {
    let frameNumber = delegate != nil ? delegate!.frameNumber : 0
     if firstFrame {
      onStart(delegate: delegate)
      startFrameNumber = frameNumber
    }
    let needDraw = onProgress(t: 1.0, delegate: delegate)

    lastProgressedFraction = 1.0
    firstFrame = true
    return needDraw
  }

  public func abort(delegate: LayerAnimationDelegate?) {
    onAbort(delegate: delegate)
    firstFrame = true
  }

  public func getTargetValue(target: inout TargetValue) {
    onGetTarget(target: &target)
  }

  public func isThreaded(delegate: LayerAnimationDelegate?) -> Bool {
    return true//false
  }

  public func toString() -> String {
    return "NOT IMPLEMENTED"
  }

  // Actually start the animation, dispatching to another thread if needed.
  internal func requestEffectiveStart(delegate: LayerAnimationDelegate?) {
     assert(requestedStartTime != TimeTicks())
     effectiveStartTime = requestedStartTime
  }

  fileprivate func getEffectiveDuration(delta: TimeDelta) -> TimeDelta {
    //switch ScopedAnimationDurationScaleMode.durationScaleMode {
    //  case ScopedAnimationDurationScaleMode.NormalDuration:
        return delta
    //  case ScopedAnimationDurationScaleMode.FastDuration:
   //     return duration / fastDurationScaleDivisor
   //   case ScopedAnimationDurationScaleMode.SlowDuration:
   //     return duration * slowDurationScaleMultiplier
   //   case ScopedAnimationDurationScaleMode.NonZeroDuration:
   //     return duration / nonZeroDurationScaleDivisor
   //   case ScopedAnimationDurationScaleMode.ZeroDuration:
   //     return TimeDelta()
   //   default:
   //     assert(false)
   //     return TimeDelta()
   // }
  }

  // TODO: consider putting these as a side protocol
  internal func onStart(delegate: LayerAnimationDelegate?) {}
  internal func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
      return false
  }
  internal func onGetTarget(target: inout TargetValue) {}
  internal func onAbort(delegate: LayerAnimationDelegate?) {}

}

internal class Pause : LayerAnimationElement {
  
  public override init(properties: AnimatableProperties,
                       duration: TimeDelta) {
    super.init(properties: properties, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {}
  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    return false
  }
  internal override func onGetTarget(target: inout TargetValue) {}
  internal override func onAbort(delegate: LayerAnimationDelegate?) {}

}

internal class InterpolatedTransformTransition : LayerAnimationElement {
  let transform: InterpolatedTransform
  public init(transform: InterpolatedTransform,
              duration: TimeDelta) {
    self.transform = transform
    super.init(properties: .Transform, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {}
  
  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate {
      d.setTransformFromAnimation(
        transform: transform.interpolate(Float(t)),
        reason: PropertyChangeReason.FromAnimation)
    }
    return true
  }
  internal override func onGetTarget(target: inout TargetValue) {
    target.transform = transform.interpolate(1.0)
  }
  
  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class BoundsTransition : LayerAnimationElement {
  var start: IntRect
  var target: IntRect

  public init(target: IntRect, duration: TimeDelta) {
    start = IntRect()
    self.target = target
    super.init(properties: .Bounds, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.boundsForAnimation
    }
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate {
      d.setBoundsFromAnimation(
          bounds: Tween.rectValueBetween(value: t, start: start, target: target),
          reason: PropertyChangeReason.FromAnimation)
    }
    return true
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.bounds = self.target
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class VisibilityTransition : LayerAnimationElement {
  var start: Bool
  var target: Bool

  public init(target: Bool, duration: TimeDelta) { 
    start = false
    self.target = target
    super.init(properties: .Visibility, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.visibilityForAnimation
    }
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate { 
      d.setVisibilityFromAnimation(
        visibility: t == 1.0 ? target : start, 
        reason: PropertyChangeReason.FromAnimation)
    }
    return t == 1.0
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.visibility = self.target
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class BrightnessTransition: LayerAnimationElement {
  
  var start: Float
  var target: Float

  public init(target: Float, duration: TimeDelta) {
     self.start = 0.0
     self.target = target
     super.init(properties: .Brightness, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.brightnessForAnimation
    }
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate {
      d.setBrightnessFromAnimation(
          brightness: Tween.floatValueBetween(value: t, start: start, target: target),
          reason: PropertyChangeReason.FromAnimation)
    }
    return true
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.brightness = self.target
  }
  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class GrayscaleTransition: LayerAnimationElement {
  var start: Float
  var target: Float

  public init(target: Float, duration: TimeDelta) {
    start = 0.0
    self.target = target
    super.init(properties: .Grayscale, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.grayscaleForAnimation
    }
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate { 
      d.setGrayscaleFromAnimation(
        grayscale: Tween.floatValueBetween(value: t, start: start, target: target),
        reason: PropertyChangeReason.FromAnimation)
    }
    return true
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.grayscale = self.target
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class ColorTransition: LayerAnimationElement {
  var start: Color
  var target: Color

  public init(target: Color, duration: TimeDelta) {
    self.start = Color.Black
    self.target = target
    super.init(properties: .Color, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.colorForAnimation
    }
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if let d = delegate {
      d.setColorFromAnimation(
          color: Tween.colorValueBetween(value: t, start: start, target: target),
          reason: PropertyChangeReason.FromAnimation)
    }
    return true
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.color = self.target
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {}
}

internal class ThreadedLayerAnimationElement: LayerAnimationElement {
  
  public override init(properties: AnimatableProperties,
                       duration: TimeDelta) {
    super.init(properties: properties, duration: duration)
  }

  internal override func isThreaded(delegate: LayerAnimationDelegate?) -> Bool {
    return !duration.isZero
  }

  internal override func onProgress(t: Double, delegate: LayerAnimationDelegate?) -> Bool {
    if t < 1.0 {
      return false
    }

    if started && isThreaded(delegate: delegate) {
      if let threaded = delegate?.threadedAnimationDelegate {
        threaded.removeThreadedAnimation(keyframeModelId: keyframeModelId)
      }
    }

    onEnd(delegate: delegate)
    return true
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {
    guard let d = delegate else {
      return
    }
    if started && isThreaded(delegate: d) {
      if let threaded = d.threadedAnimationDelegate {
        threaded.removeThreadedAnimation(keyframeModelId: keyframeModelId)
      }
    }
  }

  internal override func requestEffectiveStart(delegate: LayerAnimationDelegate?) {
    guard let d = delegate else {
      return
    }
    if !isThreaded(delegate: d) {
      effectiveStartTime = requestedStartTime
      return
    }
    effectiveStartTime = TimeTicks()
    if let keyframeModel = createKeyframeModel() {
      keyframeModel.needsSynchronizedStartTime = true
      if let threaded = d.threadedAnimationDelegate {
        threaded.addThreadedAnimation(keyframeModel: keyframeModel)
      }
    }
  }

  internal func onEnd(delegate: LayerAnimationDelegate?) {}
  internal func createKeyframeModel() -> KeyframeModel? { return nil }

}

internal class ThreadedOpacityTransition: ThreadedLayerAnimationElement {
  var start: Float
  var target: Float

  public init(target: Float, duration: TimeDelta) {
    start = 0.0
    self.target = target
    super.init(properties: .Opacity, duration: duration)
  }
  
  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.opacityForAnimation
      d.setOpacityFromAnimation(opacity: d.opacityForAnimation,
                                reason: PropertyChangeReason.FromAnimation)
    }
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.opacity = self.target
  }
  internal override func onAbort(delegate: LayerAnimationDelegate?) {
    if started {
      if let d = delegate {
        super.onAbort(delegate: delegate)
        d.setOpacityFromAnimation(
            opacity: Tween.floatValueBetween(
              value: Tween.calculateValue(type: tweenType, state: lastProgressedFraction),
              start: start, 
              target: target),
            reason: PropertyChangeReason.FromAnimation)
      }
    }
  }

  internal override func isThreaded(delegate: LayerAnimationDelegate?) -> Bool {
    if duration.isZero {
      return false
    }

    if started {
      return start != target
    }

    guard let d = delegate else {
      return false
    }

    return d.opacityForAnimation != target
  }
  
  internal override func onEnd(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      d.setOpacityFromAnimation(opacity: target,
                                reason: PropertyChangeReason.FromAnimation)
    }
  }
  
  internal override func createKeyframeModel() -> KeyframeModel? {
    let animationCurve = FloatAnimationCurveAdapter(
      tweenType: tweenType, initialValue: start, targetValue: target, duration: duration)
    let keyframeModel = KeyframeModel.create(
        curve: animationCurve.nativeCurve!, id: keyframeModelId, group: animationGroupId, property: .Opacity)
    return keyframeModel
  }

}

internal class ThreadedTransformTransition: ThreadedLayerAnimationElement {
  
  var target: Transform
  var start: Transform

  public init(target: Transform,
              duration: TimeDelta) {
    self.start = Transform(skipInitialization: true)
    self.target = target
    super.init(properties: .Transform, duration: duration)
  }

  internal override func onStart(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      start = d.transformForAnimation
      d.setTransformFromAnimation(transform: d.transformForAnimation,
                                  reason: PropertyChangeReason.FromAnimation)
    }
  }

  internal override func onGetTarget(target: inout TargetValue) {
    target.transform = self.target
  }

  internal override func onAbort(delegate: LayerAnimationDelegate?) {
    if started {
      if let d = delegate {
        super.onAbort(delegate: d)
        d.setTransformFromAnimation(
          transform: Tween.transformValueBetween(
              value: Tween.calculateValue(type: tweenType, state: lastProgressedFraction),
              startTransform: start, 
              endTransform: target),
          reason: PropertyChangeReason.FromAnimation)
      }
    }
  }

  internal override func onEnd(delegate: LayerAnimationDelegate?) {
    if let d = delegate {
      d.setTransformFromAnimation(transform: target, reason: PropertyChangeReason.FromAnimation)
    }
  }

  internal override func createKeyframeModel() -> KeyframeModel? {
    let animationCurve = TransformAnimationCurveAdapter(
      tween: tweenType, 
      initialValue: start, 
      targetValue: target, 
      duration: duration)
    let keyframeModel = KeyframeModel.create(
        curve: animationCurve.nativeCurve!, id: keyframeModelId, 
        group: animationGroupId, property: .Transform)
    return keyframeModel
  }

}

extension LayerAnimationElement.AnimatableProperty : Hashable {
  /// based on Bob Jenkins int hash
  /// https://burtleburtle.net/bob/hash/integer.html
  public var hashValue: Int {
    var hash = self.rawValue
    hash -= (hash << 6)
    hash ^= (hash >> 17)
    hash -= (hash << 9)
    hash ^= (hash << 4)
    hash -= (hash << 3)
    hash ^= (hash << 10)
    hash ^= (hash >> 15)
    return hash
  }

}
