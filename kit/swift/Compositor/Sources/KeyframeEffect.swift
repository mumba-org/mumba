// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import _C

public struct PropertyAnimationState {
  public var currentlyRunning: TargetProperties
  public var potentiallyAnimating: TargetProperties
}

public protocol AnimationTimeProvider : class {
  func getTimeForKeyframeModel(_: KeyframeModel) -> TimeTicks
}

public class KeyframeEffect {
  
  public var id: Int {
    return Int(_C.keyframeEffectGetId(reference))
  }

  public var hasBoundElementAnimations: Bool {
    return _C.keyframeEffectHasBoundElementAnimations(reference) == 1
  }

  public var hasAttachedElement: Bool {
    return _C.keyframeEffectHasAttachedElement(reference) == 1
  }

  public var elementId: Int {
    return Int(_C.keyframeEffectGetElementId(reference))
  }

  public var hasAnyKeyframeModel: Bool {
    return _C.keyframeEffectHasAnyKeyframeModel(reference) == 1
  }

  public var scrollOffsetAnimationWasInterrupted: Bool {
    return _C.keyframeEffectScrollOffsetAnimationWasInterrupted(reference) == 1
  }

  public var needsPushProperties: Bool {
    get {
      return _C.keyframeEffectGetNeedsPushProperties(reference) == 1
    }
    set {
      if newValue == true {
        _C.keyframeEffectSetNeedsPushProperties(reference)
      }
    }
  }

  public var animationsPreserveAxisAlignment: Bool {
    return _C.keyframeEffectAnimationsPreserveAxisAlignment(reference) == 1
  }

  public var isTicking: Bool {
    return _C.keyframeEffectIsTicking(reference) == 1
  }

  public var hasTickingKeyframeModel: Bool {
    return _C.keyframeEffectHasTickingKeyframeModel(reference) == 1
  }
  
  public var tickingKeyframeModelsCount: Int {
    return Int(_C.keyframeEffectTickingKeyframeModelsCount(reference))
  }

  public var hasNonDeletedKeyframeModel: Bool {
    return _C.keyframeEffectHasNonDeletedKeyframeModel(reference) == 1
  }

  internal var reference: KeyframeEffectRef
  internal var owned: Bool 

  private var tickProvider: AnimationTimeProvider?
 
  // static public func tickKeyframeModel(monotonicTime: TimeTicks,
  //                                      keyframeModel: KeyframeModel,
  //                                      target: AnimationTarget) {
    
  // }

  internal init(reference: KeyframeEffectRef, owned: Bool) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    if owned {
      _C.keyframeEffectDestroy(reference)
    }
  }
  
  public func bindElementAnimations(elementAnimations: ElementAnimations) {
    _C.keyframeEffectBindElementAnimations(reference, elementAnimations.reference)
  }

  public func unbindElementAnimations() {
    _C.keyframeEffectUnbindElementAnimations(reference)
  }

  public func attachElement(elementId: Int) {
    _C.keyframeEffectAttachElement(reference, CInt(elementId))
  }

  public func detachElement() {
    _C.keyframeEffectDetachElement(reference)
  }

  public func tick(monotonicTime: TimeTicks, tickProvider: AnimationTimeProvider) {
    self.tickProvider = tickProvider
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _KeyframeEffectTick(reference, monotonicTime.microseconds, state, { (ptr: UnsafeMutableRawPointer?, _ ref: KeyframeModelRef?) -> Int64 in
      guard ptr != nil else {
        return 0
      }
      let state = unsafeBitCast(ptr, to: KeyframeEffect.self)
      return state.tickProvider!.getTimeForKeyframeModel(KeyframeModel(reference: ref!, owned: false)).microseconds
    })
  }
  
  public func removeFromTicking() {
    _C.keyframeEffectRemoveFromTicking(reference)
  }
 
  public func updateState(startReadyKeyframeModels: Bool, events: AnimationEvents) {
    _C.keyframeEffectUpdateState(reference, startReadyKeyframeModels ? 1 : 0, events.reference)
  }
  
  public func updateTickingState(type: UpdateTickingType) {
     _C.keyframeEffectUpdateTickingState(reference, CInt(type.rawValue))
  }
  
  public func addKeyframeModel(model: KeyframeModel) {
    _C.keyframeEffectAddKeyframeModel(reference, model.reference)
  }
  
  public func pauseKeyframeModel(id: Int, timeOffset: Double) {
    _C.keyframeEffectPauseKeyframeModel(reference, CInt(id), timeOffset)
  }
  
  public func removeKeyframeModel(id: Int) {
    _C.keyframeEffectRemoveKeyframeModel(reference, CInt(id))
  }
  
  public func abortKeyframeModel(id: Int) {
    _C.keyframeEffectAbortKeyframeModel(reference, CInt(id))
  }
  
  public func abortKeyframeModels(target: TargetProperty,
                                  needsCompletion: Bool) {
    _C.keyframeEffectAbortKeyframeModels(reference, CInt(target.rawValue), needsCompletion ? 1 : 0)
  }

  public func activateKeyframeEffects() {
    _C.keyframeEffectActivateKeyframeEffects(reference)
  }

  public func keyframeModelAdded() {
    _C.keyframeEffectKeyframeModelAdded(reference)
  }

  public func notifyKeyframeModelStarted(event: AnimationEvent) -> Bool {
    return _C.keyframeEffectNotifyKeyframeModelStarted(reference, event.reference) == 1
  }

  public func notifyKeyframeModelFinished(event: AnimationEvent) -> Bool {
    return _C.keyframeEffectNotifyKeyframeModelFinished(reference, event.reference) == 1
  }
  
  public func notifyKeyframeModelTakeover(event: AnimationEvent) {
    return _C.keyframeEffectNotifyKeyframeModelTakeover(reference, event.reference)
  }
  
  public func notifyKeyframeModelAborted(event: AnimationEvent) -> Bool {
    return _C.keyframeEffectNotifyKeyframeModelAborted(reference, event.reference) == 1
  }

  public func hasOnlyTranslationTransforms(type: ElementListType) -> Bool {
    return _C.keyframeEffectHasOnlyTranslationTransforms(reference, CInt(type.rawValue)) == 1
  }

  public func animationStartScale(type: ElementListType) -> Float? {
    var retval: Float = 0.0
    
    if _C.keyframeEffectAnimationStartScale(reference, CInt(type.rawValue), &retval) == 1 {
      return retval
    }

    return nil
  }

  public func maximumTargetScale(type: ElementListType) -> Float? {
    var retval: Float = 0.0
    
    if _C.keyframeEffectMaximumTargetScale(reference, CInt(type.rawValue), &retval) == 1 {
      return retval
    }
    
    return nil
  }

  public func isPotentiallyAnimatingProperty(targetProperty: TargetProperty,
                                             type: ElementListType) -> Bool {
    return _C.keyframeEffectIsPotentiallyAnimatingProperty(reference, CInt(targetProperty.rawValue), CInt(type.rawValue)) == 1
  }

  public func isCurrentlyAnimatingProperty(targetProperty: TargetProperty,
                                           type: ElementListType) -> Bool {
   return _C.keyframeEffectIsCurrentlyAnimatingProperty(reference, CInt(targetProperty.rawValue), CInt(type.rawValue)) == 1
  }

  public func getKeyframeModel(targetProperty: TargetProperty) -> KeyframeModel? {
    if let ref = _C.keyframeEffectGetKeyframeModel(reference, CInt(targetProperty.rawValue)) {
      return KeyframeModel(reference: ref, owned: false)
    }
    return nil
  }
  
  public func getKeyframeModelById(keyframeModelId: Int) -> KeyframeModel? {
    if let ref = _C.keyframeEffectGetKeyframeModelById(reference, CInt(keyframeModelId)) {
      return KeyframeModel(reference: ref, owned: false)
    }
    return nil
  }

  public func getPropertyAnimationState(pendingState: inout PropertyAnimationState, activeState: inout PropertyAnimationState) {
    var pendingStateCurrentlyRunning: CInt = 0
    var pendingStatePotentiallyAnimating: CInt = 0 
    var activeStateCurrentlyRunning: CInt  = 0
    var activeStatePotentiallyAnimating: CInt = 0
    
    _C.keyframeEffectGetPropertyAnimationState(reference, &pendingStateCurrentlyRunning, &pendingStatePotentiallyAnimating, &activeStateCurrentlyRunning, &activeStatePotentiallyAnimating)

    pendingState.currentlyRunning = TargetProperties(rawValue: Int(pendingStateCurrentlyRunning))
    pendingState.potentiallyAnimating = TargetProperties(rawValue: Int(pendingStatePotentiallyAnimating))

    activeState.currentlyRunning = TargetProperties(rawValue: Int(activeStateCurrentlyRunning))
    activeState.potentiallyAnimating = TargetProperties(rawValue: Int(activeStatePotentiallyAnimating))
  }

  public func markAbortedKeyframeModelsForDeletion(effect: KeyframeEffect) {
    _C.keyframeEffectMarkAbortedKeyframeModelsForDeletion(reference, effect.reference)
  }
  
  public func purgeKeyframeModelsMarkedForDeletion(implOnly: Bool) {
    _C.keyframeEffectPurgeKeyframeModelsMarkedForDeletion(reference, implOnly ? 1 : 0)
  }

  public func pushNewKeyframeModelsToImplThread(effect: KeyframeEffect) {
    _C.keyframeEffectPushNewKeyframeModelsToImplThread(reference, effect.reference)
  }
  
  public func removeKeyframeModelsCompletedOnMainThread(effect: KeyframeEffect) {
    _C.keyframeEffectRemoveKeyframeModelsCompletedOnMainThread(reference, effect.reference)
  }
  
  public func pushPropertiesTo(effect: KeyframeEffect) {
    _C.keyframeEffectPushPropertiesTo(reference, effect.reference)
  }

  public func setAnimation(animation: Animation) {
    _C.keyframeEffectSetAnimation(reference, animation.reference)
  }

}

public class KeyframeEffectsList {

  var reference: KeyframeEffectListRef

  internal init(reference: KeyframeEffectListRef) {
    self.reference = reference
  }

  deinit {
    _KeyframeEffectListDestroy(reference)
  }
}