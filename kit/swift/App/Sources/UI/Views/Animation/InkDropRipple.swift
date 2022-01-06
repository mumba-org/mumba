// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

fileprivate func doNothing(_: CallbackLayerAnimationObserver?) {}
fileprivate func doNothingWithBool(_: CallbackLayerAnimationObserver?) -> Bool { return false }


public protocol InkDropRippleObserver {
  func animationStarted(inkDropState: InkDropState)
  func animationEnded(inkDropState: InkDropState,
                      reason: InkDropAnimationEndedReason) 
}

public enum InkDropAnimationEndedReason {
  case Success
  case PreEmpted
}

public class InkDropRipple {
  
  public static let slowAnimationDurationFactor: Double = 3.0
  public static let hiddenOpacity: Float = 0.0
  
  public var isVisible: Bool {
    return rootLayer.isVisible
  }

  public static let useFastAnimations: Bool = true

  public var observer: InkDropRippleObserver?
  public var targetInkDropState: InkDropState
  public var rootLayer: Layer!

  public init() {
    targetInkDropState = InkDropState.Hidden
  }

  public func hostSizeChanged(size newSize: IntSize) {}

  public func animateToState(_ inkDropState: InkDropState) {
    // break here til we fix the code bellow
    assert(false)

    let animationObserver = CallbackLayerAnimationObserver(
          startedCallback: doNothing,//bind(&InkDropRipple.animationStartedCallback,
                     //self, inkDropState),
          animationEnded: doNothingWithBool)//bind(&InkDropRipple.animationEndedCallback,
                     //self, inkDropState))

    let oldInkDropState = targetInkDropState
    // Assign to |target_ink_drop_state_| before calling AnimateStateChange() so
    // that any observers notified as a side effect of the AnimateStateChange()
    // will get the target InkDropState when calling GetInkDropState().
    targetInkDropState = inkDropState

    if oldInkDropState == InkDropState.Hidden && targetInkDropState != InkDropState.Hidden {
      rootLayer.isVisible = true
    }

    animateStateChange(oldInkDropState: oldInkDropState, newInkDropState: targetInkDropState, observer: animationObserver)
    animationObserver.active = true
  }

  public func snapToHidden() {
    abortAllAnimations()
    setStateToHidden()
    targetInkDropState = InkDropState.Hidden
  }

  public func snapToActivated() {
    abortAllAnimations()

    // break here til we fix the code bellow
    assert(false)
    // |animation_observer| will be deleted when AnimationEndedCallback() returns
    // true.
    // TODO(bruthig): Implement a safer ownership model for the
    // |animation_observer|.
    let animationObserver = CallbackLayerAnimationObserver(
            startedCallback: doNothing,//bind(&InkDropRipple.animationStartedCallback,
                      //self, InkDropState.Activated),
            animationEnded: doNothingWithBool)//bind(&InkDropRipple.animationEndedCallback,
                      //self, InkDropState.Activated))
    
    //if let layer = rootLayer {
    //  layer.visible = true
   // }

    rootLayer.isVisible = true
    
    targetInkDropState = InkDropState.Activated
    animationObserver.active = true
  }

  func animateStateChange(oldInkDropState: InkDropState,
                          newInkDropState: InkDropState,
                          observer: LayerAnimationObserver?) {

  }

  // Updates the transforms, opacity, and visibility to a HIDDEN state.
  func setStateToHidden() {}

  func abortAllAnimations() {}

  func animationStartedCallback(
      inkDropState: InkDropState,
      observer layerAnimationObserver: CallbackLayerAnimationObserver?) {
    if let obs = self.observer {
      obs.animationStarted(inkDropState: inkDropState)
    }
  }

  func animationEndedCallback(
      inkDropState: InkDropState,
      observer layerAnimationObserver: CallbackLayerAnimationObserver?) -> Bool {
    if inkDropState == InkDropState.Hidden {
      setStateToHidden()
    }

    if let obs = self.observer {
      if let animObserver = layerAnimationObserver {
         obs.animationEnded(inkDropState: inkDropState,
                            reason: animObserver.abortedCount > 0 ? 
                              InkDropAnimationEndedReason.PreEmpted : InkDropAnimationEndedReason.Success)
      } else {
        obs.animationEnded(inkDropState: inkDropState, reason: InkDropAnimationEndedReason.Success)
      }
    }
    return true
  }

}


fileprivate let minimumRectScale: Float = 0.0001

// The minimum scale factor to use when scaling circle layers. Smaller values
// were causing visual anomalies.
fileprivate let minimumCircleScale: Float = 0.001

public enum InkDropSubAnimations : Int {
  // HIDDEN sub animations.

  // The HIDDEN sub animation that is fading out to a hidden opacity.
  case HiddenFadeOut

  // The HIDDEN sub animation that transforms the shape to a |small_size_|
  // circle.
  case HiddenTransform

  // ACTION_PENDING sub animations.

  // The ACTION_PENDING sub animation that fades in to the visible opacity.
  case ActionPendingFadeIn

  // The ACTION_PENDING sub animation that transforms the shape to a
  // |large_size_| circle.
  case ActionPendingTransform

  // ACTION_TRIGGERED sub animations.

  // The ACTION_TRIGGERED sub animation that is fading out to a hidden opacity.
  case ActionTriggeredFadeOut

  // The ACTION_TRIGGERED sub animation that transforms the shape to a
  // |large_size_|
  // circle.
  case ActionTriggeredTransform
  
  // ALTERNATE_ACTION_PENDING sub animations.

  // The ALTERNATE_ACTION_PENDING animation has only one sub animation which
  // animates
  // to a |small_size_| rounded rectangle at visible opacity.
  case AlternateActionPending

  // ALTERNATE_ACTION_TRIGGERED sub animations.

  // The ALTERNATE_ACTION_TRIGGERED sub animation that is fading out to a hidden
  // opacity.
  case AlternateActionTriggeredFadeOut

  // The ALTERNATE_ACTION_TRIGGERED sub animation that transforms the shape to a
  // |large_size_|
  // rounded rectangle.
  case AlternateActionTriggeredTransform

  // ACTIVATED sub animations.
  case ActivatedFadeIn
  

  case ActivatedTransform

  // The ACTIVATED sub animation that transforms the shape to a |large_size_|
  // circle. This is used when the ink drop is in a HIDDEN state prior to
  // animating to the ACTIVATED state.
  case ActivatedCircleTransform

  // The ACTIVATED sub animation that transforms the shape to a |small_size_|
  // rounded rectangle.
  case ActivatedRectTransform

  // DEACTIVATED sub animations.

  // The DEACTIVATED sub animation that is fading out to a hidden opacity.
  case DeactivatedFadeOut

  // The DEACTIVATED sub animation that transforms the shape to a |large_size_|
  // rounded rectangle.
  case DeactivatedTransform
}

// The scale factor used to burst the ACTION_TRIGGERED bubble as it fades out.
fileprivate let quickActionBurstScale: Float = 1.3

// Duration constants for InkDropStateSubAnimations. See the
// InkDropStateSubAnimations enum documentation for more info.
fileprivate let squareAnimationDurationInMs: [InkDropSubAnimations: Double] = [
    InkDropSubAnimations.HiddenFadeOut: 150,  // HIDDEN_FADE_OUT
    InkDropSubAnimations.HiddenTransform: 200,  // HIDDEN_TRANSFORM
    InkDropSubAnimations.ActionPendingFadeIn: 0,    // ACTION_PENDING_FADE_IN
    InkDropSubAnimations.ActionPendingTransform: 160,  // ACTION_PENDING_TRANSFORM
    InkDropSubAnimations.ActionTriggeredFadeOut: 150,  // ACTION_TRIGGERED_FADE_OUT
    InkDropSubAnimations.ActionTriggeredTransform: 160,  // ACTION_TRIGGERED_TRANSFORM
    InkDropSubAnimations.AlternateActionPending: 200,  // ALTERNATE_ACTION_PENDING
    InkDropSubAnimations.AlternateActionTriggeredFadeOut: 150,  // ALTERNATE_ACTION_TRIGGERED_FADE_OUT
    InkDropSubAnimations.AlternateActionTriggeredTransform: 200,  // ALTERNATE_ACTION_TRIGGERED_TRANSFORM
    InkDropSubAnimations.ActivatedCircleTransform: 200,  // ACTIVATED_IRCLE_TRANSFORM
    InkDropSubAnimations.ActivatedRectTransform: 160,  // ACTIVATED_RECT_TRANSFORM
    InkDropSubAnimations.DeactivatedFadeOut: 150,  // DEACTIVATED_FADE_OUT
    InkDropSubAnimations.DeactivatedTransform: 200   // DEACTIVATED_TRANSFORM
]

// Returns the InkDropState sub animation duration for the given |state|.
fileprivate func getAnimationDuration(state: InkDropSubAnimations) -> TimeDelta {
  if !Animation.shouldRenderRichAnimation {
    return TimeDelta()
  }

  return TimeDelta.from(milliseconds: 
      (InkDropRipple.useFastAnimations
           ? 1
           : Int64(InkDropRipple.slowAnimationDurationFactor) * Int64(squareAnimationDurationInMs[state]!)))
}

public class SquareInkDropRipple : InkDropRipple {
  
  typealias InkDropTransforms = [Transform]
  
  public enum ActivatedShape { 
    case None
    case Circle
    case RoundedRect
  }

  // Enumeration of the different shapes that compose the ink drop.
  fileprivate enum PaintedShape : Int {
    case TopLeftCircle = 0
    case TopRightCircle
    case BottomRightCircle
    case BottomLeftCircle
    case HorizontalRect
    case VerticalRect

    static let count: Int = 6
  }

  public var activatedShape: ActivatedShape = .None

  //public override var rootLayer: Layer?

  fileprivate var visibleOpacity: Float

  fileprivate var largeSize: IntSize

  fileprivate var largeCornerRadius: Int

  fileprivate var smallCornerRadius: Int

  fileprivate var smallSize: IntSize 

  fileprivate var centerPoint: IntPoint

  fileprivate var circleLayerDelegate: CircleLayerDelegate
  
  fileprivate var rectLayerDelegate: RectangleLayerDelegate
  
  fileprivate var paintedLayers: [Layer]

  fileprivate var opacity: Float {
    get {
      return rootLayer.opacity
    }
    set {
      rootLayer.opacity = newValue
    }
  }

  public init(largeSize: IntSize,
              largeCornerRadius: Int,
              smallSize: IntSize,
              smallCornerRadius: Int,
              centerPoint: IntPoint,
              color: Color,
              visibleOpacity: Float) {
    
    self.visibleOpacity = visibleOpacity
    self.activatedShape = ActivatedShape.RoundedRect
    self.largeSize = largeSize
    self.largeCornerRadius = largeCornerRadius
    self.smallSize = smallSize
    self.smallCornerRadius = smallCornerRadius
    self.centerPoint = centerPoint
    self.circleLayerDelegate = CircleLayerDelegate(
        color: color,
        radius: min(largeSize.width, largeSize.height) / 2)
    self.rectLayerDelegate = RectangleLayerDelegate(color: color, size: FloatSize(largeSize))
    self.paintedLayers = []

    super.init()

    for i in 0..<PaintedShape.count {
      addPaintLayer(paintedShape: PaintedShape(rawValue: i)!)
    }

    self.rootLayer = try! Layer(type: .None)//.NotDrawn)
    self.rootLayer.name = "SquareInkDropRipple:ROOT_LAYER"
    self.rootLayer.masksToBounds = false
    self.rootLayer.bounds = IntRect(size: largeSize)

    setStateToHidden()
  }

  deinit {
    abortAllAnimations()
  }

  // InkDropRipple:
  public override func snapToActivated() {
    super.snapToActivated()
    opacity = visibleOpacity
    var localTransforms = InkDropTransforms()
    getActivatedTargetTransforms(transforms: &localTransforms)
    setTransforms(localTransforms)
  }
  
  // Returns a human readable string for the |painted_shape| value.
  fileprivate class func toLayerName(paintedShape: PaintedShape) -> String {
    switch paintedShape {
      case .TopLeftCircle:
        return "TOP_LEFT_IRCLE"
      case .TopRightCircle:
        return "TOP_RIGHT_IRCLE"
      case .BottomRightCircle:
        return "BOTTOM_RIGHT_IRCLE"
      case .BottomLeftCircle:
        return "BOTTOM_LEFT_IRCLE"
      case .HorizontalRect:
        return "HORIZONTAL_RECT"
      case .VerticalRect:
        return "VERTICAL_RECT"
    }
  }

  override func animateStateChange(oldInkDropState: InkDropState,
                                   newInkDropState: InkDropState,
                                   observer animationObserver: LayerAnimationObserver?) {
    
    var transforms = InkDropTransforms()

    switch newInkDropState {
      case .Hidden:
        if !isVisible {
          setStateToHidden()
          break
        } else {
           // opacity: duration: preemptionStrategy: tween: animationObserver:
          animateToOpacity(
            opacity: InkDropRipple.hiddenOpacity, 
            duration: getAnimationDuration(state: InkDropSubAnimations.HiddenFadeOut),
            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
            tween: .EaseInOut, 
            animationObserver: animationObserver)
          
          calculateCircleTransforms(size: smallSize, transforms: &transforms)
          
          animateToTransforms(
              transforms: transforms, 
              duration: getAnimationDuration(state: InkDropSubAnimations.HiddenTransform),
              preemptionStrategy: .ImmediatelyAnimateToNewTarget,
              tween: .EaseInOut, 
              animationObserver: animationObserver)
        }
      case .ActionPending:
        if oldInkDropState == newInkDropState {
          return
        }
         // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: visibleOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingFadeIn),
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseIn, 
                         animationObserver: animationObserver)
         // opacity: duration: preemptionStrategy: tween: animationObserver:                
        animateToOpacity(opacity: visibleOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingTransform),
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseIn, 
                         animationObserver: animationObserver)

        calculateCircleTransforms(size: largeSize, transforms: &transforms)

        animateToTransforms(transforms: transforms,
                            duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingTransform),
                            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                            tween: .EaseInOut, 
                            animationObserver: animationObserver)

      case .ActionTriggered:
        if oldInkDropState == InkDropState.Hidden {
          animateStateChange(oldInkDropState: oldInkDropState, 
                             newInkDropState: InkDropState.ActionPending,
                             observer: animationObserver)
        }
        // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: InkDropRipple.hiddenOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.ActionTriggeredFadeOut),
                         preemptionStrategy: .EnqueueNewAnimation,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)
        let s = IntSize.scaleToRounded(size: largeSize, scaleBy: quickActionBurstScale)
        calculateCircleTransforms(size: s, transforms: &transforms)
        animateToTransforms(transforms: transforms,
                            duration: getAnimationDuration(state: InkDropSubAnimations.ActionTriggeredTransform),
                            preemptionStrategy: .EnqueueNewAnimation,
                            tween: .EaseInOut, 
                            animationObserver: animationObserver)

      case .AlternateActionPending:
         // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: visibleOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionPending),
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseIn, 
                         animationObserver: animationObserver)
        calculateRectTransforms(size: smallSize, cornerRadius: Float(smallCornerRadius), transforms: &transforms)
        animateToTransforms(transforms: transforms,
                            duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionPending),
                            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                            tween: .EaseInOut, 
                            animationObserver: animationObserver)
       case .AlternateActionTriggered:
        let visibleDuration: TimeDelta =
            getAnimationDuration(state: InkDropSubAnimations.AlternateActionTriggeredTransform) -
            getAnimationDuration(state: InkDropSubAnimations.AlternateActionTriggeredFadeOut)
         // opacity: duration: preemptionStrategy: tween: animationObserver:    
        animateToOpacity(opacity: visibleOpacity, 
                         duration: visibleDuration,
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)
         // opacity: duration: preemptionStrategy: tween: animationObserver:                 
        animateToOpacity(
          opacity: InkDropRipple.hiddenOpacity, 
          duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionTriggeredFadeOut),
          preemptionStrategy: .EnqueueNewAnimation,
          tween: .EaseInOut, 
          animationObserver: animationObserver)

        calculateRectTransforms(size: largeSize, cornerRadius: Float(largeCornerRadius), transforms: &transforms)
        
        animateToTransforms(
          transforms: transforms, 
          duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionTriggeredTransform),
          preemptionStrategy: .ImmediatelyAnimateToNewTarget,
          tween: .EaseInOut, 
          animationObserver: animationObserver)

      case .Activated:
        // Animate the opacity so that it cancels any opacity animations already
        // in progress.

         // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(
          opacity: visibleOpacity, 
          duration: TimeDelta(),
          preemptionStrategy: .ImmediatelyAnimateToNewTarget,
          tween: .EaseInOut,
          animationObserver: animationObserver)

        var rectTransformPreemptionStrategy =
            PreemptionStrategy.ImmediatelyAnimateToNewTarget
        
        if oldInkDropState == InkDropState.Hidden {
          rectTransformPreemptionStrategy = .EnqueueNewAnimation

          calculateCircleTransforms(size: largeSize, transforms: &transforms)

          animateToTransforms(
              transforms: transforms, 
              duration: getAnimationDuration(state: InkDropSubAnimations.ActivatedCircleTransform),
              preemptionStrategy: .ImmediatelyAnimateToNewTarget,
              tween: .EaseInOut, 
              animationObserver: animationObserver)

        } else if oldInkDropState == InkDropState.ActionPending {
          rectTransformPreemptionStrategy = .EnqueueNewAnimation
        }

        getActivatedTargetTransforms(transforms: &transforms)
        animateToTransforms(transforms: transforms,
                            duration: getAnimationDuration(state: InkDropSubAnimations.ActivatedRectTransform),
                            preemptionStrategy: rectTransformPreemptionStrategy,
                            tween: .EaseInOut, 
                            animationObserver: animationObserver)
    
      case .Deactivated: 
        let visibleDuration: TimeDelta =
            getAnimationDuration(state: InkDropSubAnimations.DeactivatedTransform) -
            getAnimationDuration(state: InkDropSubAnimations.DeactivatedFadeOut)
         // opacity: duration: preemptionStrategy: tween: animationObserver:    
        animateToOpacity(opacity: visibleOpacity, 
                         duration: visibleDuration,
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)
         // opacity: duration: preemptionStrategy: tween: animationObserver:                 
        animateToOpacity(opacity: InkDropRipple.hiddenOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.DeactivatedFadeOut),
                         preemptionStrategy: .EnqueueNewAnimation,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)
        getDeactivatedTargetTransforms(transforms: &transforms)

        animateToTransforms(transforms: transforms,
                            duration: getAnimationDuration(state: InkDropSubAnimations.DeactivatedTransform),
                            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                            tween: .EaseInOut, 
                            animationObserver: animationObserver)
    }
  }

  override func setStateToHidden() {
    var transforms = InkDropTransforms()
    // Use non-zero size to avoid visual anomalies.
    calculateCircleTransforms(size: IntSize(width: 1, height: 1), transforms: &transforms)
    setTransforms(transforms)
    rootLayer.opacity = InkDropRipple.hiddenOpacity
    rootLayer.isVisible = false
  }

  override func abortAllAnimations() {
    rootLayer.animator.abortAllAnimations()
    for i in 0..<PaintedShape.count {
      paintedLayers[i].animator.abortAllAnimations()
    }  
  }

  fileprivate func animateToTransforms(
      transforms: InkDropTransforms,
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      tween: TweenType,
      animationObserver: LayerAnimationObserver?) {
    
    for i in 0..<PaintedShape.count {
      let animator = paintedLayers[i].animator
      let animation = ScopedLayerAnimationSettings(animator: animator)
      animation.preemptionStrategy = preemptionStrategy
      animation.tweenType = tween
      let element =
        LayerAnimationElement.createTransformElement(transform: transforms[i],
                                                     duration: duration)
      let sequence = LayerAnimationSequence(element: element)
      if let observer = animationObserver {
        sequence.addObserver(observer: observer as! LayerAnimationObserverBase)
      }
      animator.startAnimation(animation: sequence)
    }
  }

  fileprivate func animateToOpacity(
      opacity: Float,
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      tween: TweenType,
      animationObserver: LayerAnimationObserver?) {
    let animator = rootLayer.animator
    let animationSettings = ScopedLayerAnimationSettings(animator: animator)
    animationSettings.preemptionStrategy = preemptionStrategy
    animationSettings.tweenType = tween
    let animationElement = LayerAnimationElement.createOpacityElement(opacity: opacity, duration: duration)
    let animationSequence = LayerAnimationSequence(element: animationElement)
    if let observer = animationObserver {
      animationSequence.addObserver(observer: observer as! LayerAnimationObserverBase)
    }
    animator.startAnimation(animation: animationSequence)
  }

  fileprivate func calculateCircleTransforms(size desiredSize: IntSize,
                                             transforms: inout InkDropTransforms) {
    calculateRectTransforms(size: desiredSize, 
      cornerRadius: Float(min(desiredSize.width, desiredSize.height)) / 2.0, 
      transforms: &transforms)
  }

  fileprivate func setTransforms(_ transforms: InkDropTransforms) {
    for i in 0..<PaintedShape.count {
      paintedLayers[i].transform = transforms[i]
    }
  }

  fileprivate func calculateRectTransforms(size desiredSize: IntSize,
                                           cornerRadius: Float,
                                           transforms: inout InkDropTransforms) {
  var size = FloatSize(desiredSize)
  
  // This function can be called before the layer's been added to a view,
  // either at construction time or in tests.
  
  if let compositor = rootLayer.compositor {
    // Modify |desired_size| so that the ripple aligns to pixel bounds.
    let dsf = compositor.deviceScaleFactor
    var rippleBounds = FloatRect(origin: FloatPoint(centerPoint), size: FloatSize())
    rippleBounds.inset(insets: -FloatInsets(vertical: Float(desiredSize.height) / 2.0,
                                            horizontal: Float(desiredSize.width) / 2.0))
    rippleBounds.scale(by: dsf)
    rippleBounds = FloatRect(IntRect.toEnclosingRect(rect: rippleBounds))
    rippleBounds.scale(by: 1.0 / dsf)
    size = rippleBounds.size
  }

  // The shapes are drawn such that their center points are not at the origin.
  // Thus we use the CalculateCircleTransform() and CalculateRectTransform()
  // methods to calculate the complex Transforms.

  let circleScale: Float = max(
      minimumCircleScale,
      cornerRadius / Float(circleLayerDelegate.radius))

  let circleTargetXOffset = size.width / 2.0 - cornerRadius
  let circleTargetYOffset = size.height / 2.0 - cornerRadius

  transforms[PaintedShape.TopLeftCircle.rawValue] = calculateCircleTransform(
      scale: circleScale, x: -circleTargetXOffset, y: -circleTargetYOffset)
  transforms[PaintedShape.TopRightCircle.rawValue] = calculateCircleTransform(
      scale: circleScale, x: circleTargetXOffset, y: -circleTargetYOffset)
  transforms[PaintedShape.BottomRightCircle.rawValue] = calculateCircleTransform(
      scale: circleScale, x: circleTargetXOffset, y: circleTargetYOffset)
  transforms[PaintedShape.BottomLeftCircle.rawValue] = calculateCircleTransform(
      scale: circleScale, x: -circleTargetXOffset, y: circleTargetYOffset)

  let rectDelegateWidth = rectLayerDelegate.size.width
  let rectDelegateHeight = rectLayerDelegate.size.height

  transforms[PaintedShape.HorizontalRect.rawValue] = calculateRectTransform(
      x: max(minimumRectScale, size.width / rectDelegateWidth),
      y: max(minimumRectScale,
               (size.height - 2.0 * cornerRadius) / rectDelegateHeight))

  transforms[PaintedShape.VerticalRect.rawValue] = calculateRectTransform(
      x: max(minimumRectScale,
               (size.width - 2.0 * cornerRadius) / rectDelegateWidth),
      y: max(minimumRectScale, size.height / rectDelegateHeight))
  }

  fileprivate func calculateCircleTransform(scale: Float,
                                            x targetCenterX: Float,
                                            y targetCenterY: Float) -> Transform {
    var transform = Transform()
    // Offset for the center point of the ripple.
    transform.translate(x: Float(centerPoint.x), y: Float(centerPoint.y))
    // Move circle to target.
    transform.translate(x: targetCenterX, y: targetCenterY)
    transform.scale(x: scale, y: scale)
    // Align center point of the painted circle.
    let circleCenterOffset: FloatVec2 = circleLayerDelegate.centeringOffset
    transform.translate(x: -circleCenterOffset.x, y: -circleCenterOffset.y)
    return transform
  }

  fileprivate func calculateRectTransform(x xScale: Float, y yScale: Float) -> Transform {
    var transform = Transform()
    transform.translate(x: Float(centerPoint.x), y: Float(centerPoint.y))
    transform.scale(x: xScale, y: yScale)
    let rectCenterOffset: FloatVec2 = rectLayerDelegate.centeringOffset
    transform.translate(x: -rectCenterOffset.x, y: -rectCenterOffset.y)
    return transform
  }

  fileprivate func getCurrentTransforms(transforms: inout InkDropTransforms) {
    for i in 0..<PaintedShape.count {
      transforms[i] = paintedLayers[i].transform
    }  
  }

  fileprivate func getActivatedTargetTransforms(transforms: inout InkDropTransforms) {
    switch activatedShape {
      case .Circle:
        calculateCircleTransforms(size: smallSize, transforms: &transforms)
      case .RoundedRect:
        calculateRectTransforms(size: smallSize, 
                                cornerRadius: Float(smallCornerRadius),
                                transforms: &transforms)
      case .None:
       assert(false)
    }
  }

  fileprivate func getDeactivatedTargetTransforms(transforms: inout InkDropTransforms) {
    switch activatedShape {
      case .Circle:
        calculateCircleTransforms(size: largeSize, transforms: &transforms)
      case .RoundedRect:
        calculateRectTransforms(size: largeSize, cornerRadius: Float(smallCornerRadius), transforms: &transforms)
      case .None:
       assert(false)   
    }
  }

  fileprivate func addPaintLayer(paintedShape: PaintedShape) {
    var delegate: LayerDelegate?
    switch paintedShape {
      case .TopLeftCircle, .TopRightCircle, .BottomRightCircle, .BottomLeftCircle:
        delegate = circleLayerDelegate
      case .HorizontalRect, .VerticalRect:
        delegate = rectLayerDelegate
    }

    let layer = try! Layer()
    rootLayer.add(child: layer)

    layer.bounds = IntRect(size: largeSize)
    layer.fillsBoundsOpaquely = false
    layer.delegate = delegate
    layer.isVisible = true
    layer.opacity = 1.0
    layer.masksToBounds = false
    layer.name = "PAINTED_SHAPE_OUNT:" + SquareInkDropRipple.toLayerName(paintedShape: paintedShape)

    paintedLayers[paintedShape.rawValue] = layer
  }
}

fileprivate let minRadius: Float = 1.0

internal func calculateClipBounds(hostSize: IntSize,
                                  clipInsets: IntInsets) -> IntRect {
  var clipBounds = IntRect(size: hostSize)
  clipBounds.inset(insets: clipInsets)
  return clipBounds
}

internal func calculateCircleLayerRadius(clipBounds: IntRect) -> Int {
  return max(clipBounds.width, clipBounds.height) / 2
}

fileprivate let floodFillAnimationDurationInMs: [InkDropSubAnimations: Double] = [
    InkDropSubAnimations.HiddenFadeOut: 200,  // HIDDEN_FADE_OUT
    InkDropSubAnimations.HiddenTransform: 300,  // HIDDEN_TRANSFORM
    InkDropSubAnimations.ActionPendingFadeIn: 0,    // ACTION_PENDING_FADE_IN
    InkDropSubAnimations.ActionPendingTransform: 240,  // ACTION_PENDING_TRANSFORM
    InkDropSubAnimations.ActionTriggeredFadeOut: 300,  // ACTION_TRIGGERED_FADE_OUT
    InkDropSubAnimations.AlternateActionPending: 200,  // ALTERNATE_ACTION_PENDING
    InkDropSubAnimations.AlternateActionTriggeredFadeOut: 300,  // ALTERNATE_ACTION_TRIGGERED_FADE_OUT
    InkDropSubAnimations.ActivatedFadeIn: 150,  // ACTIVATED_FADE_IN
    InkDropSubAnimations.ActivatedTransform: 200,  // ACTIVATED_TRANSFORM
    InkDropSubAnimations.DeactivatedFadeOut: 300  // DEACTIVATED_FADE_OUT
]

public class FloodFillInkDropRipple : InkDropRipple {
  
  //public var rootLayer: Layer?
  public var durationFactor: Float
  public var useHideTransformDurationForHideFadeOut: Bool
  fileprivate var paintedLayer: Layer
  fileprivate var clipInsets: IntInsets
  fileprivate var centerPoint: IntPoint
  fileprivate var visibleOpacity: Float
  fileprivate var inkDropState: InkDropState
  fileprivate var circleLayerDelegate: CircleLayerDelegate
  fileprivate var maxSizeTargetTransform: Transform {
    return calculateTransform(targetRadius: maxDistanceToCorners(point: centerPoint))
  }

  fileprivate var opacity: Float {
    get {
      return rootLayer.opacity
    }
    set {
      rootLayer.opacity = newValue
    }
  }


  public init(hostSize: IntSize,
              clipInsets: IntInsets,
              centerPoint: IntPoint,
              color: Color,
              visibleOpacity: Float) {
                
    self.clipInsets = clipInsets
    self.centerPoint = centerPoint
    self.visibleOpacity = visibleOpacity
    useHideTransformDurationForHideFadeOut = false
    durationFactor = 1.0
    
    circleLayerDelegate = CircleLayerDelegate(
      color: color,
      radius: calculateCircleLayerRadius(clipBounds: calculateClipBounds(hostSize: hostSize, clipInsets: clipInsets)))
    inkDropState = InkDropState.Hidden

    let clipBounds = calculateClipBounds(hostSize: hostSize, clipInsets: clipInsets)
    let paintedSizeLength = max(clipBounds.width, clipBounds.height)

    paintedLayer = try! Layer()
    paintedLayer.bounds = IntRect(width: paintedSizeLength, height: paintedSizeLength)
    paintedLayer.fillsBoundsOpaquely = false
    paintedLayer.delegate = circleLayerDelegate
    paintedLayer.isVisible = true
    paintedLayer.opacity = 1.0
    paintedLayer.masksToBounds = false
    paintedLayer.name = "FloodFillInkDropRipple:PAINTED_LAYER"
   
    super.init()

    rootLayer = try! Layer(type: .None)//.NotDrawn)
    rootLayer.name = "FloodFillInkDropRipple:ROOT_LAYER"
    rootLayer.masksToBounds = true
    rootLayer.bounds = clipBounds
    
    rootLayer.add(child: paintedLayer)

    setStateToHidden()
  }

  public convenience init(hostSize: IntSize,
              centerPoint: IntPoint,
              color: Color,
              visibleOpacity: Float) {
    
    self.init(hostSize: hostSize,
              clipInsets: IntInsets(),
              centerPoint: centerPoint,
              color: color,
              visibleOpacity: visibleOpacity)
  }

  public override func hostSizeChanged(size newSize: IntSize) {
    rootLayer.bounds = calculateClipBounds(hostSize: newSize, clipInsets: clipInsets)
   
    switch targetInkDropState {
      case .ActionPending, .AlternateActionPending, .Activated:
        paintedLayer.transform = maxSizeTargetTransform
      default:
        break
    }
  }
  
  public override func snapToActivated() {
    super.snapToActivated()
    opacity = visibleOpacity
    paintedLayer.transform = maxSizeTargetTransform
  }
  
  override func animateStateChange(oldInkDropState: InkDropState,
                                   newInkDropState: InkDropState,
                                   observer animationObserver: LayerAnimationObserver?) {
    switch newInkDropState {
      case .Hidden:
        if !isVisible {
          setStateToHidden()
        } else {
           // opacity: duration: preemptionStrategy: tween: animationObserver:
          animateToOpacity(
            opacity: InkDropRipple.hiddenOpacity, 
            duration: getAnimationDuration(state: InkDropSubAnimations.HiddenFadeOut),
            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
            tween: .EaseInOut, 
            animationObserver: animationObserver)
          
          let transform = calculateTransform(targetRadius: minRadius)
          
          animateToTransform(
            transform: transform, 
            duration: getAnimationDuration(state: InkDropSubAnimations.HiddenTransform),
            preemptionStrategy: .ImmediatelyAnimateToNewTarget,
            tween: .EaseInOut, 
            animationObserver: animationObserver)
        }
      case .ActionPending:
         // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: visibleOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingFadeIn),
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseIn, 
                         animationObserver: animationObserver)
        // duration: preemptionStrategy: animationObserver:
        pauseOpacityAnimation(
          duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingTransform) -
                    getAnimationDuration(state: InkDropSubAnimations.ActionPendingFadeIn),
          preemptionStrategy: .EnqueueNewAnimation,
          animationObserver: animationObserver)

        animateToTransform(transform: maxSizeTargetTransform,
                           duration: getAnimationDuration(state: InkDropSubAnimations.ActionPendingTransform),
                           preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                           tween: .FastOutSlowIn, 
                           animationObserver: animationObserver)

      case .ActionTriggered:
        if oldInkDropState == InkDropState.Hidden {
          animateStateChange(oldInkDropState: oldInkDropState, newInkDropState: InkDropState.ActionPending,
                             observer: animationObserver)
        }
        animateToOpacity(opacity: InkDropRipple.hiddenOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.ActionTriggeredFadeOut),
                         preemptionStrategy: .EnqueueNewAnimation,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)

      case .AlternateActionPending:
         // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: visibleOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionPending),
                         preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                         tween: .EaseIn, 
                         animationObserver: animationObserver)

        animateToTransform(transform: maxSizeTargetTransform,
                           duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionPending),
                           preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                           tween: .EaseInOut, 
                           animationObserver: animationObserver)

      case .AlternateActionTriggered:
        // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(
            opacity: InkDropRipple.hiddenOpacity,
            duration: getAnimationDuration(state: InkDropSubAnimations.AlternateActionTriggeredFadeOut),
            preemptionStrategy: .EnqueueNewAnimation, 
            tween: .EaseInOut,
            animationObserver: animationObserver)
      case .Activated:
        if oldInkDropState == InkDropState.ActionPending {
          // The final state of pending animation is the same as the final state
          // of activated animation. We only need to enqueue a zero-length pause
          // so that animation observers are notified in order.
          pauseOpacityAnimation(
              duration: TimeDelta(),
              preemptionStrategy: .EnqueueNewAnimation,
              animationObserver: animationObserver)

          pauseTransformAnimation(
              duration: TimeDelta(),
              preemptionStrategy: .EnqueueNewAnimation,
              animationObserver: animationObserver)

        } else {
          animateToOpacity(opacity: visibleOpacity,
                           duration: getAnimationDuration(state: InkDropSubAnimations.ActivatedFadeIn),
                           preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                           tween: .EaseIn,
                           animationObserver: animationObserver)

          animateToTransform(transform: maxSizeTargetTransform,
                             duration: getAnimationDuration(state: InkDropSubAnimations.ActivatedTransform),
                             preemptionStrategy: .ImmediatelyAnimateToNewTarget,
                             tween: .EaseInOut, 
                             animationObserver: animationObserver)
        }
      case .Deactivated:
        // opacity: duration: preemptionStrategy: tween: animationObserver:
        animateToOpacity(opacity: InkDropRipple.hiddenOpacity,
                         duration: getAnimationDuration(state: InkDropSubAnimations.DeactivatedFadeOut),
                         preemptionStrategy: .EnqueueNewAnimation,
                         tween: .EaseInOut, 
                         animationObserver: animationObserver)
    }
  }

  override func setStateToHidden() {
    paintedLayer.transform = calculateTransform(targetRadius: minRadius)
    rootLayer.opacity = InkDropRipple.hiddenOpacity
    rootLayer.isVisible = false
  }

  override func abortAllAnimations() {
    rootLayer.animator.abortAllAnimations()
    paintedLayer.animator.abortAllAnimations()
  }

  fileprivate func animateToTransform(
      transform: Transform,
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      tween: TweenType,
      animationObserver: LayerAnimationObserver?) {

    let animator = paintedLayer.animator
    let animation = ScopedLayerAnimationSettings(animator: animator)
    animation.preemptionStrategy = preemptionStrategy
    animation.tweenType = tween

    let element = LayerAnimationElement.createTransformElement(transform: transform, duration: duration)

    let sequence = LayerAnimationSequence(element: element)

    if let observer = animationObserver {
      sequence.addObserver(observer: observer as! LayerAnimationObserverBase)
    }

    animator.startAnimation(animation: sequence)
  }

  // Creates a pause animation for transform property.
  fileprivate func pauseTransformAnimation(
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      animationObserver: LayerAnimationObserver?) {
    let animator = paintedLayer.animator
    let animation = ScopedLayerAnimationSettings(animator: animator)
    animation.preemptionStrategy = preemptionStrategy

    let element = LayerAnimationElement.createPauseElement(
      properties: LayerAnimationElement.AnimatableProperties(rawValue: LayerAnimationElement.AnimatableProperty.Transform.rawValue), duration: duration)

    let sequence = LayerAnimationSequence(element: element)

    if let observer = animationObserver {
      sequence.addObserver(observer: observer as! LayerAnimationObserverBase)
    }

    animator.startAnimation(animation: sequence)
  }

  fileprivate func animateToOpacity(
      opacity: Float,
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      tween: TweenType,
      animationObserver: LayerAnimationObserver?) {
    
    let animator = rootLayer.animator
    let animationSettings = ScopedLayerAnimationSettings(animator: animator)
    animationSettings.preemptionStrategy = preemptionStrategy
    animationSettings.tweenType = tween
    let animationElement = LayerAnimationElement.createOpacityElement(opacity: opacity, duration: duration)
    let animationSequence = LayerAnimationSequence(element: animationElement)

    if let observer = animationObserver {
      animationSequence.addObserver(observer: observer as! LayerAnimationObserverBase)
    }

    animator.startAnimation(animation: animationSequence)
  }

  fileprivate func pauseOpacityAnimation(
      duration: TimeDelta,
      preemptionStrategy: PreemptionStrategy,
      animationObserver: LayerAnimationObserver?) {

    let animator = rootLayer.animator
    let animation = ScopedLayerAnimationSettings(animator: animator)
    animation.preemptionStrategy = preemptionStrategy

    let element = LayerAnimationElement.createPauseElement(
          properties: LayerAnimationElement.AnimatableProperties(rawValue: LayerAnimationElement.AnimatableProperty.Opacity.rawValue), duration: duration)

    let sequence = LayerAnimationSequence(element: element)

    if let observer = animationObserver {
      sequence.addObserver(observer: observer as! LayerAnimationObserverBase)
    }

    animator.startAnimation(animation: sequence)
  }

  fileprivate func calculateTransform(targetRadius: Float) -> Transform {
    let targetScale = targetRadius / Float(circleLayerDelegate.radius)

    var transform = Transform()
    transform.translate(x: Float(centerPoint.x - rootLayer.bounds.x),
                        y: Float(centerPoint.y - rootLayer.bounds.y))
    transform.scale(x: targetScale, y: targetScale)

    let drawnCenterOffset: FloatVec2 = circleLayerDelegate.centeringOffset
    transform.translate(x: -drawnCenterOffset.x,  y: -drawnCenterOffset.y)

    // Add subpixel correction to the transform.
    transform.concatTransform(transform: getTransformSubpixelCorrection(
        transform: transform, deviceScaleFactor: paintedLayer.deviceScaleFactor))

    return transform
  }

  fileprivate func maxDistanceToCorners(point: IntPoint) -> Float {
    let bounds = rootLayer.bounds
    let distanceToTopLeft: Float = (bounds.origin - point).length
    let distanceToTopRight: Float = (bounds.topRight - point).length
    let distanceToBottomLeft: Float = (bounds.bottomLeft - point).length
    let distanceToBottomRight: Float = (bounds.bottomRight - point).length

    var largestDistance = max(distanceToTopLeft, distanceToTopRight)
    largestDistance = max(largestDistance, distanceToBottomLeft)
    largestDistance = max(largestDistance, distanceToBottomRight)
    return largestDistance
  }

  fileprivate func getAnimationDuration(state: InkDropSubAnimations) -> TimeDelta {
    if !Animation.shouldRenderRichAnimation {
      return TimeDelta()
    }

    var stateOverride = state
    // Override the requested state if needed.
    if useHideTransformDurationForHideFadeOut && state == InkDropSubAnimations.HiddenFadeOut {
      stateOverride = InkDropSubAnimations.HiddenTransform
    }

    return TimeDelta.from(milliseconds: 
        (InkDropRipple.useFastAnimations
            ? 1
            : Int64(InkDropRipple.slowAnimationDurationFactor)) *
        Int64(floodFillAnimationDurationInMs[stateOverride]!) * Int64(durationFactor))
  }

}