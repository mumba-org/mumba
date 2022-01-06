// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public enum ElementListType: Int { 
  case active = 0
  case pending = 1
}

//public class AnimationCurve {
//  internal var reference: AnimationCurveRef

//  init(reference: AnimationCurveRef) {
//    self.reference = reference
//  }
//}

public protocol AnimationDelegate {

  func notifyAnimationStarted(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int)

  func notifyAnimationFinished(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int)

  func notifyAnimationAborted(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int)

  func notifyAnimationTakeover(
      monotonicTime: TimeTicks,
      targetProperty: Int,
      animationStartTime: TimeTicks,
      curve: AnimationCurve)
}

public enum LayerAnimationObserverType {
  case ActiveObserver
  case PendingObserver
}

public protocol LayerAnimationEventObserver {
  func onAnimationStarted(event: AnimationEvent)
}

public protocol LayerAnimationValueObserver {
  func onFilterAnimated(filters: FilterOperations)
  func onOpacityAnimated(opacity: Float)
  func onTransformAnimated(transform: Transform)
  func onScrollOffsetAnimated(scrollOffset: ScrollOffset)
  func onAnimationWaitingForDeletion()
  func onTransformIsPotentiallyAnimatingChanged(isAnimating: Bool)
  func isActive() -> Bool
}

public protocol LayerAnimationValueProvider {
  func scrollOffsetForAnimation() -> ScrollOffset
}

public class Animation {

  public var id: Int {
    return Int(_AnimationGetId(reference))
  }

  public var hasElementAnimations: Bool {
    return _AnimationHasElementAnimations(reference) == 0 ? false : true
  }

  public var hasAnimationHost: Bool {
    return _AnimationHasAnimationHost(reference) == 0 ? false : true
  }

  public var tickingKeyframeModelsCount: UInt64 {
    return _AnimationTickingKeyframeModelsCount(reference)
  }

  public var nextKeyframeEffectId: UInt64 {
    return _AnimationNextKeyframeEffectId(reference)
  }

  public var isWorkletAnimation: Bool {
    return _AnimationIsWorkletAnimation(reference) == 0 ? false : true
  }

  public var animationDelegate: AnimationDelegate? {
    get {
      return _animationDelegate
    }
    set {
      _animationDelegate = newValue
      var cdelegate = CAnimationDelegate()
      cdelegate.NotifyAnimationStarted = { (handle: UnsafeMutableRawPointer?, time: Int64, property: CInt, group: CInt) in
//        //print("\n\n ---****--- Animation.NotifyAnimationStarted ---****--- \n\n")
        let selfPtr = unsafeBitCast(handle, to: Animation.self)
        if let delegate = selfPtr.animationDelegate {
          delegate.notifyAnimationStarted(
              monotonicTime: TimeTicks(microseconds: time),
              targetProperty: Int(property),
              group: Int(group))
        }
      }
      cdelegate.NotifyAnimationFinished = { (handle: UnsafeMutableRawPointer?, time: Int64, property: CInt, group: CInt) in
        let selfPtr = unsafeBitCast(handle, to: Animation.self)
        if let delegate = selfPtr.animationDelegate {
          delegate.notifyAnimationFinished(
              monotonicTime: TimeTicks(microseconds: time),
              targetProperty: Int(property),
              group: Int(group))
        }
      }
      cdelegate.NotifyAnimationAborted = { (handle: UnsafeMutableRawPointer?, time: Int64, property: CInt, group: CInt) in
        let selfPtr = unsafeBitCast(handle, to: Animation.self)
        if let delegate = selfPtr.animationDelegate {
          delegate.notifyAnimationAborted(
            monotonicTime: TimeTicks(microseconds: time),
            targetProperty: Int(property),
            group: Int(group))
        }
      }
      cdelegate.NotifyAnimationTakeover = { (handle: UnsafeMutableRawPointer?, time: Int64, property: CInt, startTime: Int64, curve: AnimationCurveRef?) in
        let selfPtr = unsafeBitCast(handle, to: Animation.self)
        if let delegate = selfPtr.animationDelegate {
          delegate.notifyAnimationTakeover(
            monotonicTime: TimeTicks(microseconds: time),
            targetProperty: Int(property),
            animationStartTime: TimeTicks(microseconds: startTime),
            curve: NativeAnimationCurve(reference: curve!, owned: true))
        }
      }
      
      let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _AnimationSetAnimationDelegate(reference, selfptr, cdelegate)
    }
  }

  public var animationHost: AnimationHost? {
    get {
      if animationHostCache == nil || animationHostDirty {
        if let ref = _AnimationGetAnimationHost(reference) {
          animationHostCache = AnimationHost(reference: ref, owned: false)
        }
        animationHostDirty = false
      }
      return animationHostCache
    }
    set {
      let hostRef = newValue != nil ? newValue!.reference : nil
      _AnimationSetAnimationHost(reference, hostRef)
      animationHostCache = newValue
      animationHostDirty = true
    }
  }

  public var animationTimeline: AnimationTimeline? {
    get {
      if animationTimelineCache == nil || animationTimelineDirty {
        if let ref = _AnimationGetAnimationTimeline(reference) {
          animationTimelineCache = AnimationTimeline(reference: ref, owned: false)
        }
        animationTimelineDirty = false
      }
      return animationTimelineCache
    }
    set {
      let timelineRef = newValue != nil ? newValue!.reference : nil
      _AnimationSetAnimationTimeline(reference, timelineRef)
      animationTimelineCache = newValue
      animationTimelineDirty = true
    }
  }

  private var animationHostCache: AnimationHost?
  private var animationHostDirty: Bool = false
  private var animationTimelineCache: AnimationTimeline?
  private var animationTimelineDirty: Bool = false
  private var _animationDelegate: AnimationDelegate?
  internal var reference: AnimationRef

  public init(reference: AnimationRef) {
    self.reference = reference
  }

  deinit {
    _AnimationDestroy(reference)
  }

  public func isElementAttached(id: UInt64) -> Bool {
    return _AnimationIsElementAttached(reference, id) == 0 ? false : true
  }

  public func getElementIdOfKeyframeEffect(keyframeEffectId: UInt64) -> UInt64? {
    var elementId: UInt64 = 0
    if _AnimationGetElementIdOfKeyframeEffect(reference, keyframeEffectId, &elementId) == 1 {
      return elementId
    }
    return nil
  }

  // Disabled for now

  //public func getElementAnimations(keyframeEffectId: UInt64) -> ElementAnimations? {
  //  if let ref = _AnimationGetElementAnimations(reference, keyframeEffectId) {
  //    return ElementAnimations(reference: ref)
  //  }
  //  return nil
  //}

  public func attachElementForKeyframeEffect(elementId: UInt64,
                                             keyframeEffectId: UInt64) {
    _AnimationAttachElementForKeyframeEffect(reference, elementId, keyframeEffectId)
  }
  
  public func detachElementForKeyframeEffect(elementId: UInt64,
                                             keyframeEffectId: UInt64) {
    _AnimationDetachElementForKeyframeEffect(reference, elementId, keyframeEffectId)
  }
  
  public func detachElement() {
    _AnimationDetachElement(reference)
  }

  // NOTE: this animation will OWN the inner KeyframeModel reference
  //       so it should not try to destroy (manually) its c reference anymore
  public func addKeyframeModelForKeyframeEffect(
      keyframeModel: KeyframeModel,
      keyframeEffectId: UInt64) {
    keyframeModel.owned = false 
    _AnimationAddKeyframeModelForKeyframeEffect(reference, keyframeModel.reference, keyframeEffectId)
  }
  
  public func pauseKeyframeModelForKeyframeEffect(keyframeModelId: Int,
                                                  timeOffset: Double ,
                                                  keyframeEffectId: UInt64) {
    _AnimationPauseKeyframeModelForKeyframeEffect(reference, CInt(keyframeModelId), timeOffset, keyframeEffectId)
  }
  
  public func removeKeyframeModelForKeyframeEffect(
      keyframeModelId: Int,
      keyframeEffectId: UInt64) {
    _AnimationRemoveKeyframeModelForKeyframeEffect(reference, CInt(keyframeModelId), keyframeEffectId)
  }
  
  public func abortKeyframeModelForKeyframeEffect(
      keyframeModelId: Int,
      keyframeEffectId: UInt64) {
    _AnimationAbortKeyframeModelForKeyframeEffect(reference, CInt(keyframeModelId), keyframeEffectId)
  }
  
  public func abortKeyframeModels(targetProperty: TargetProperty,
                                  needsCompletion: Bool) {
    _AnimationAbortKeyframeModels(reference, CInt(targetProperty.rawValue), needsCompletion ? 1 : 0)
  }
  
  public func pushPropertiesTo(other: Animation) {
    _AnimationPushPropertiesTo(reference, other.reference)
  }

  public func updateState(startReadyKeyframeModels: Bool, events: AnimationEvents) {
    _AnimationUpdateState(reference, startReadyKeyframeModels ? 1 : 0, events.reference)
  }
  
  public func tick(monotonicTime: TimeTicks) {
    _AnimationTick(reference, monotonicTime.microseconds)
  }

  public func addToTicking() {
    _AnimationAddToTicking(reference)
  }
  
  public func keyframeModelRemovedFromTicking() {
    _AnimationKeyframeModelRemovedFromTicking(reference)
  }

  public func notifyKeyframeModelStarted(event: AnimationEvent) {
    _AnimationNotifyKeyframeModelStarted(reference, event.reference)
  }
  
  public func notifyKeyframeModelFinished(event: AnimationEvent) {
    _AnimationNotifyKeyframeModelFinished(reference, event.reference)
  }
  
  public func notifyKeyframeModelAborted(event: AnimationEvent) {
    _AnimationNotifyKeyframeModelAborted(reference, event.reference)
  }
  
  public func notifyKeyframeModelTakeover(event: AnimationEvent) {
    _AnimationNotifyKeyframeModelTakeover(reference, event.reference)
  }
  
  public func setNeedsPushProperties() {
    _AnimationSetNeedsPushProperties(reference)
  }

  public func activateKeyframeEffects() {
    _AnimationActivateKeyframeEffects(reference)
  }

  public func getKeyframeModelForKeyframeEffect(
      targetProperty: TargetProperty,
      keyframeEffectId: UInt64) -> KeyframeModel? {
    if let ref = _AnimationGetKeyframeModelForKeyframeEffect(reference, CInt(targetProperty.rawValue), keyframeEffectId) {
      return KeyframeModel(reference: ref, owned: false)
    }
    return nil
  }

  public func setNeedsCommit() {
    _AnimationSetNeedsCommit(reference)
  }

  // NOTE: this animation will OWN the inner KeyframeEffect reference
  //       so it should not try to destroy (manually) its c reference anymore
  public func addKeyframeEffect(_ keyframeEffect: KeyframeEffect) {
    _AnimationAddKeyframeEffect(reference, keyframeEffect.reference)
  }

  public func getKeyframeEffectById(keyframeEffectId: UInt64) -> KeyframeEffect? {
    if let ref = _AnimationGetKeyframeEffectById(reference, keyframeEffectId) {
      return KeyframeEffect(reference: ref, owned: false)
    }
    return nil
  }
 
}

public enum AnimationEventType : Int {
  case Started = 1
  case Finished = 2 
  case Aborted = 3
  case TakeOver = 4
}

public class AnimationEvent {

  public var type: AnimationEventType {
    return AnimationEventType(rawValue: Int(_AnimationEventGetType(reference)))!
  }
  
  public var elementId: UInt64 {
    return _AnimationEventGetElementId(reference)
  }
  
  public var groupID: Int {
    return Int(_AnimationEventGetGroupId(reference))
  }
  
  public var targetProperty: Int  {
    return Int(_AnimationEventGetTargetProperty(reference))
  }

  public var monotonicTime: TimeTicks {
    return TimeTicks(microseconds: _AnimationEventGetMonotonicTime(reference))
  }
  
  public var isImplOnly: Bool {
    return _AnimationEventIsImplOnly(reference) == 0 ? false : true
  }
  
  public var opacity: Float {
    return _AnimationEventGetOpacity(reference)
  }

  public var transform: Transform {
    let mat = _AnimationEventGetTransform(reference)
    return Transform(matrix: Mat4(reference: mat!, owned: false))
  }
  
  public var filters: FilterOperations {
    let filterRef = _AnimationEventGetFilterOperations(reference)
    return FilterOperations(reference: filterRef!)
  }

  var reference: AnimationEventRef

  init(reference: AnimationEventRef) {
    self.reference = reference
  }
}

public class AnimationEvents {

  public var isEmpty: Bool {
    return _AnimationEventsIsEmpty(reference) == 0 ? false : true
  }

  var reference: AnimationEventsRef

  init(reference: AnimationEventsRef) {
    self.reference = reference
  }

  // we dont own this anywhere, so theres no destructor
}

// public class AnimationRegistrar {

//   var reference: AnimationRegistrarRef

//   public init(reference: AnimationRegistrarRef) {
//     self.reference = reference
//   }

//   deinit {
//     _AnimationRegistrarDestroy(reference);
//   }

//   public func didActivateAnimationController(controller: LayerAnimationController) {

//   }

//   public func didDeactivateAnimationController(controller: LayerAnimationController) {

//   }

//   public func registerAnimationController(controller: LayerAnimationController) {

//   }

//   public func unregisterAnimationController(controller: LayerAnimationController) {

//   }

//   public func setSupportsScrollAnimations(supportsScrollAnimations: Bool) {

//   }

//   public func supportsScrollAnimations() -> Bool {
//     return false
//   }

//   public func needsAnimateLayers() -> Bool {
//     return false
//   }

//   public func activateAnimations() -> Bool {
//     return false
//   }

//   public func animateLayers(monotonicTime: TimeInterval) -> Bool {
//     return false
//   }

//   public func updateAnimationState(startReadyAnimations: Bool, events: [AnimationEvent]) -> Bool {
//     return false
//   }

//   public func createEvents() ->[AnimationEvent]? {
//     return nil
//   }

//   public func setAnimationEvents(events: [AnimationEvent]) {

//   }
// }

// public class LayerAnimationController {

//   public var id: Int {
//     return 0
//   }

//   var reference: LayerAnimationControllerRef

//   public init(reference: LayerAnimationControllerRef) {
//     self.reference = reference
//   }

//   public func addAnimation(animation: Animation) {

//   }

//   public func pauseAnimation(animationId: Int, timeOffset: TimeInterval) {

//   }

//   public func removeAnimation(animationId: Int, targetProperty: AnimationTargetProperty) {

//   }

//   public func removeAnimationByID(animationId: Int) {

//   }

//   public func abortAnimations(targetProperty: AnimationTargetProperty) {

//   }

//   public func pushAnimationUpdatesTo(controller: LayerAnimationController) {

//   }

//   public func animate(monotonicTime: NSDate) {

//   }

//   public func accumulatePropertyUpdates(monotonicTime: NSDate, events: [AnimationEvent]) {

//   }

//   public func updateState(startReadyAnimations: Bool, events: [AnimationEvent]) {

//   }

//   public func activateAnimations() {

//   }

//   public func getAnimation(targetProperty: AnimationTargetProperty) -> Animation? {
//     return nil
//   }

//   public func getAnimationByID(animationId: Int) -> Animation? {
//     return nil
//   }

//   public func hasActiveAnimation() -> Bool {
//     return false
//   }

//   public func hasAnyAnimation() -> Bool {
//     return false
//   }

//   public func isPotentiallyAnimatingProperty(targetProperty: AnimationTargetProperty,
//     observerType: LayerAnimationObserverType) -> Bool {
//     return false
//   }

//   public func isCurrentlyAnimatingProperty(targetProperty: AnimationTargetProperty,
//     observerType: LayerAnimationObserverType) -> Bool {
//     return false
//   }

//   public func setAnimationRegistrar(registrar: AnimationRegistrar) {

//   }

//   public func animationRegistrar() -> AnimationRegistrar? {
//     return nil
//   }

//   public func notifyAnimationStarted(event: AnimationEvent) {

//   }

//   public func notifyAnimationFinished(event: AnimationEvent) {

//   }

//   public func notifyAnimationAborted(event: AnimationEvent) {

//   }

//   public func notifyAnimationPropertyUpdate(event: AnimationEvent) {

//   }

//   public func addValueObserver(observer: LayerAnimationValueObserver) {

//   }

//   public func removeValueObserver(observer: LayerAnimationValueObserver) {

//   }

//   public func addEventObserver(observer: LayerAnimationEventObserver) {

//   }

//   public func removeEventObserver(observer: LayerAnimationEventObserver) {

//   }

//   public func setValueProvider(provider: LayerAnimationValueProvider) {

//   }

//   public func removeValue_provider(provider: LayerAnimationValueProvider) {

//   }

//   public func setLayerAnimationDelegate(delegate: AnimationDelegate) {

//   }

//   public func removeLayerAnimationDelegate(delegate: AnimationDelegate) {

//   }

//   public func hasFilterAnimationThatInflatesBounds() -> Bool {
//     return false
//   }

//   public func hasTransformAnimationThatInflatesBounds() -> Bool {
//     return false
//   }

//   public func hasAnimationThatInflatesBounds() -> Bool {
//     return false
//   }

//   public func filterAnimationBoundsForBox(box: FloatBox, bounds: inout FloatBox) -> Bool {
//     return false
//   }

//   public func transformAnimationBoundsForBox(box: FloatBox, bounds: inout FloatBox) -> Bool {
//     return false
//   }

//   public func hasAnimationThatAffectsScale() -> Bool {
//     return false
//   }

//   public func hasOnlyTranslationTransforms(observerType: LayerAnimationObserverType) -> Bool {
//     return false
//   }

//   public func animationsPreserveAxisAlignment() -> Bool {
//     return false
//   }

//   public func animationStartScale(observerType: LayerAnimationObserverType, scale: inout Float) -> Bool {
//     return false
//   }

//   public func maximumTargetScale(eventObservers: LayerAnimationObserverType, scale: inout Float) -> Bool {
//     return false
//   }

//   public func scrollOffsetAnimationWasInterrupted() -> Bool {
//     return false
//   }

// }