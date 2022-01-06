// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

fileprivate func _animationStarted(_: CallbackLayerAnimationObserver?) { }
fileprivate func _animationEnded(_: CallbackLayerAnimationObserver?) -> Bool { return false }

public protocol InkDropHighlightObserver {
  func animationStarted(animationType: InkDropHighlight.AnimationType)
  func animationEnded(animationType: InkDropHighlight.AnimationType,
                      reason: InkDropAnimationEndedReason)

}

public class InkDropHighlight {
  
  public enum AnimationType { 
    case FadeIn
    case FadeOut
  }
  
  public var isFadingInOrVisible: Bool {
    return lastAnimationInitiatedWasFadeIn
  }
  public var observer: InkDropHighlightObserver?
  public var layer: Layer
  public var explodeSize: IntSize = IntSize()
  public var visibleOpacity: Float
  fileprivate var layerDelegate: PaintedLayerDelegate? 
  fileprivate var size: IntSize = IntSize()
  fileprivate var centerPoint: FloatPoint 
  fileprivate var lastAnimationInitiatedWasFadeIn: Bool

  public init(centerPoint: FloatPoint,
              layerDelegate: PaintedLayerDelegate?) {
    self.centerPoint = centerPoint
    visibleOpacity = 1.0
    lastAnimationInitiatedWasFadeIn = false
    self.layerDelegate = layerDelegate
    self.layer = try! Layer()
    if let delegate = self.layerDelegate {
      let paintedBounds = delegate.paintedBounds
      size = IntSize(paintedBounds.size)
      explodeSize = IntSize(paintedBounds.size)
      layer.bounds = IntRect(paintedBounds)
    }
    layer.fillsBoundsOpaquely = false
    layer.delegate = layerDelegate
    layer.isVisible = false
    layer.masksToBounds = false
    layer.name = "InkDropHighlight:layer"
  }

  public convenience init(size: IntSize,
              cornerRadius: Int,
              centerPoint: FloatPoint,
              color: Color) {
    
    self.init(
          centerPoint: centerPoint,
          layerDelegate: RoundedRectangleLayerDelegate(color: color, size: FloatSize(size), cornerRadius: cornerRadius))
    visibleOpacity = 0.128
    layer.opacity = visibleOpacity
  }

  deinit {
    layer.animator.abortAllAnimations()
  }

  public func fadeIn(duration: TimeDelta) {
    layer.opacity = kHiddenOpacity
    layer.isVisible = true
    animateFade(animationType: .FadeIn, duration: duration, initialSize: size, targetSize: size)
  }

  public func fadeOut(duration: TimeDelta, explode: Bool) {
    animateFade(animationType: .FadeOut, duration: duration, initialSize: size, targetSize: explode ? explodeSize : size)
  }

  func animateFade(animationType: AnimationType,
                   duration: TimeDelta,
                   initialSize: IntSize,
                   targetSize: IntSize) {
    let effectiveDuration: TimeDelta =
      Animation.shouldRenderRichAnimation ? duration : TimeDelta()
    lastAnimationInitiatedWasFadeIn = animationType == AnimationType.FadeIn

    layer.transform = calculateTransform(size: initialSize)

    // The |animation_observer| will be destroyed when the
    // AnimationStartedCallback() returns true.
    let animationObserver = 
      CallbackLayerAnimationObserver(
            startedCallback: _animationStarted,//bind(&InkDropHighlight.animationStartedCallback, self, animationType),
            animationEnded: _animationEnded)//bind(&InkDropHighlight.animationEndedCallback, self, animationType))

    assert(false) // make sure the code breaks til we fix the above
  
    let animator = layer.animator
    let animation = ScopedLayerAnimationSettings(animator: animator)
    animation.tweenType = TweenType.EaseInOut
    animation.preemptionStrategy = PreemptionStrategy.ImmediatelyAnimateToNewTarget

    let opacityElement = LayerAnimationElement.createOpacityElement(
            opacity: animationType == AnimationType.FadeIn ? visibleOpacity : kHiddenOpacity,
            duration: effectiveDuration)
    let opacitySequence = LayerAnimationSequence(element: opacityElement)
    opacitySequence.addObserver(observer: animationObserver)
    animator.startAnimation(animation: opacitySequence)

    if initialSize != targetSize {
      let transformElement =
          LayerAnimationElement.createTransformElement(
             transform: calculateTransform(size: targetSize), duration: effectiveDuration)

      let transformSequence = LayerAnimationSequence(element: transformElement)

      transformSequence.addObserver(observer:  animationObserver)
      animator.startAnimation(animation: transformSequence)
    }

    animationObserver.active = true
  }

  func calculateTransform(size: IntSize) -> Transform {
    var transform = Transform()
    transform.translate(x: centerPoint.x, y: centerPoint.y)
    // TODO(bruthig): Fix the InkDropHighlight to work well when initialized with
    // a (0x0) size. See https://crbug.com/661618.
    transform.scale(x: size.width == 0 ? 0 : Float(size.width / size.width),
                    y: size.height == 0 ? 0 : Float(size.height / size.height))
    let layerOffset = layerDelegate!.centeringOffset
    transform.translate(x: Float(-layerOffset.x), y: Float(-layerOffset.y))

    // Add subpixel correction to the transform.
    transform.concatTransform(transform: getTransformSubpixelCorrection(transform: transform, deviceScaleFactor: layer.deviceScaleFactor))

    return transform
  }

  func animationStartedCallback(
        animationType: AnimationType,
        observer callback: CallbackLayerAnimationObserver) {
    if let obs = observer {
      obs.animationStarted(animationType: animationType)
    }
  }

  // The callback that will be invoked when a fade in/out animation is complete.
  func animationEndedCallback(
        animationType: AnimationType,
        observer callback: CallbackLayerAnimationObserver) {
    // AnimationEndedCallback() may be invoked when this is being destroyed and
    // |layer_| may be null.
    if animationType == .FadeOut {
      layer.isVisible = false
    }

    if let obs = observer {
      obs.animationEnded(animationType: animationType,
                         reason: callback.abortedCount > 0
                                    ? InkDropAnimationEndedReason.PreEmpted
                                    : InkDropAnimationEndedReason.Success)
    }
    //return true
  }

}

fileprivate let kHiddenOpacity: Float = 0.0