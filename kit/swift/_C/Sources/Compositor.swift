// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

// KeyframeModel
public func keyframeModelCreate(_ curve: AnimationCurveRef, _ id: CInt, _ group: CInt, _ property: CInt) -> KeyframeModelRef {
  return _KeyframeModelCreate(curve, id, group, property)
}

public func keyframeModelDestroy(_ reference: KeyframeModelRef) {
  _KeyframeModelDestroy(reference)
}

public func keyframeModelGetId(_ reference: KeyframeModelRef) -> CInt {
  return _KeyframeModelId(reference)
}

public func keyframeModelGetGroup(_ reference: KeyframeModelRef) -> CInt {
  return _KeyframeModelGroup(reference)
}

public func keyframeModelGetTargetProperty(_ reference: KeyframeModelRef) -> CInt {
  return _KeyframeModelTargetProperty(reference)
}

// _KeyframeModelRunState(reference)
public func keyframeModelRunState(_ reference: KeyframeModelRef) -> CInt {
  return _KeyframeModelRunState(reference)
}

// _KeyframeModelIterations(reference)
public func keyframeModelIterations(_ reference: KeyframeModelRef) -> Double {
  return _KeyframeModelIterations(reference)
}

// _KeyframeModelSetIterations(reference, newValue)
public func keyframeModelSetIterations(_ reference: KeyframeModelRef, _ value: Double) {
  _KeyframeModelSetIterations(reference, value)
}

// _KeyframeModelIterationStart(reference)
public func keyframeModelIterationStart(_ reference: KeyframeModelRef) -> Double {
  return _KeyframeModelIterationStart(reference)
}

// _KeyframeModelSetIterationStart(reference, newValue)
public func keyframeModelSetIterationStart(_ reference: KeyframeModelRef, _ value: Double) {
  _KeyframeModelSetIterationStart(reference, value)
}

// _KeyframeModelStartTime(reference)
public func keyframeModelStartTime(_ reference: KeyframeModelRef) -> Int64 {
  return _KeyframeModelStartTime(reference)
}

// _KeyframeModelSetStartTime(reference, newValue.microseconds)
public func keyframeModelSetStartTime(_ reference: KeyframeModelRef, _ value: Int64) {
  _KeyframeModelSetStartTime(reference, value)
}

// _KeyframeModelTimeOffset(reference)
// _KeyframeModelSetTimeOffset(reference, newValue.microseconds)

// _KeyframeModelDirection(reference)
// _KeyframeModelSetDirection(reference, newValue.rawValue)
// _KeyframeModelFillMode(reference)
// _KeyframeModelSetFillMode(reference, newValue.rawValue)
// _KeyframeModelPlaybackRate(reference)
// _KeyframeModelSetPlaybackRate(reference, newValue)
// _KeyframeModelAnimationCurve(reference)
// _KeyframeModelNeedsSynchronizedStartTime(reference)
// _KeyframeModelSetNeedsSynchronizedStartTime(reference, newValue.intValue)
// _KeyframeModelReceivedFinishedEvent(reference)
// _KeyframeModelSetReceivedFinishedEvent(reference, newValue.intValue)
// _KeyframeModelIsControllingInstance(reference)
// _KeyframeModelSetIsControllingInstance(reference, newValue.intValue)
// _KeyframeModelIsImplOnly(reference)
// _KeyframeModelSetIsImplOnly(reference, newValue.intValue)
// _KeyframeModelAffectsActiveElements(reference)
// _KeyframeModelSetAffectsActiveElements(reference, newValue.intValue)
// _KeyframeModelAffectsPendingElements(reference))
// _KeyframeModelSetAffectsPendingElements(reference, newValue.intValue)
// _KeyframeModelCreate(curve.reference, id, group, property.rawValue)
// _KeyframeModelDestroy(reference)
// _KeyframeModelSetRunState(reference, runState.rawValue, monotonicTime.microseconds)
// _KeyframeModelIsFinishedAt(reference, monotonicTime.microseconds)
// _KeyframeModelSetRunState(reference, state.rawValue, monotonicTime.microseconds)
 
// KeyframeEffect

public func keyframeEffectDestroy(_ reference: KeyframeEffectRef) {
  _KeyframeEffectDestroy(reference)
}

public func keyframeEffectGetId(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectGetId(reference)
}

public func keyframeEffectHasBoundElementAnimations(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectHasBoundElementAnimations(reference)
}

public func keyframeEffectGetElementId(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectGetElementId(reference)
}

public func keyframeEffectHasAnyKeyframeModel(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectHasAnyKeyframeModel(reference)
}

public func keyframeEffectScrollOffsetAnimationWasInterrupted(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectScrollOffsetAnimationWasInterrupted(reference)
}

public func keyframeEffectGetNeedsPushProperties(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectGetNeedsPushProperties(reference)
}

public func keyframeEffectSetNeedsPushProperties(_ reference: KeyframeEffectRef) {
  _KeyframeEffectSetNeedsPushProperties(reference)
}

public func keyframeEffectAnimationsPreserveAxisAlignment(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectAnimationsPreserveAxisAlignment(reference)
}

public func keyframeEffectIsTicking(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectIsTicking(reference)
}

public func keyframeEffectHasTickingKeyframeModel(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectHasTickingKeyframeModel(reference)
}

public func keyframeEffectTickingKeyframeModelsCount(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectTickingKeyframeModelsCount(reference)
}

public func keyframeEffectHasNonDeletedKeyframeModel(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectHasNonDeletedKeyframeModel(reference)
}

public func keyframeEffectBindElementAnimations(_ reference: KeyframeEffectRef, _ elementAnimations: ElementAnimationsRef) {
  _KeyframeEffectBindElementAnimations(reference, elementAnimations)
}

public func keyframeEffectUnbindElementAnimations(_ reference: KeyframeEffectRef) {
  _KeyframeEffectUnbindElementAnimations(reference)
}

public func keyframeEffectHasAttachedElement(_ reference: KeyframeEffectRef) -> CInt {
  return _KeyframeEffectHasAttachedElement(reference)
}

public func keyframeEffectAttachElement(_ reference: KeyframeEffectRef, _ elementId: CInt) {
  _KeyframeEffectAttachElement(reference, elementId)
}

public func keyframeEffectDetachElement(_ reference: KeyframeEffectRef) {
  _KeyframeEffectDetachElement(reference)
}

//public func keyframeEffectTick(_ reference: KeyframeEffectRef, _ monotonicTime: Int64, _ tickProvider: AnimationTimeProviderRef) {
//  _KeyframeEffectTick(reference, monotonicTime, tickProvider)
//}

public func keyframeEffectRemoveFromTicking(_ reference: KeyframeEffectRef) {
  _KeyframeEffectRemoveFromTicking(reference)
}

public func keyframeEffectUpdateState(_ reference: KeyframeEffectRef, _ startReadyKeyframeModels: CInt, _ events: AnimationEventsRef) {
  _KeyframeEffectUpdateState(reference, startReadyKeyframeModels, events)
}

public func keyframeEffectUpdateTickingState(_ reference: KeyframeEffectRef, _ type: CInt) {
  _KeyframeEffectUpdateTickingState(reference, type)
}

public func keyframeEffectAddKeyframeModel(_ reference: KeyframeEffectRef, _ model: KeyframeModelRef) {
  _KeyframeEffectAddKeyframeModel(reference, model)
}

public func keyframeEffectPauseKeyframeModel(_ reference: KeyframeEffectRef, _ id: CInt, _ timeOffset: Double) {
  _KeyframeEffectPauseKeyframeModel(reference, id, timeOffset)
}

public func keyframeEffectRemoveKeyframeModel(_ reference: KeyframeEffectRef, _ id: CInt) {
  _KeyframeEffectRemoveKeyframeModel(reference, id)
}

public func keyframeEffectAbortKeyframeModel(_ reference: KeyframeEffectRef, _ id: CInt) {
  _KeyframeEffectAbortKeyframeModel(reference, id)
}

public func keyframeEffectAbortKeyframeModels(
    _ reference: KeyframeEffectRef,
    _ target: CInt,
    _ needsCompletion: CInt) {

  _KeyframeEffectAbortKeyframeModels(reference, target, needsCompletion)
}

public func keyframeEffectActivateKeyframeEffects(_ reference: KeyframeEffectRef) {
  _KeyframeEffectActivateKeyframeEffects(reference)
}

public func keyframeEffectKeyframeModelAdded(_ reference: KeyframeEffectRef) {
  _KeyframeEffectActivateKeyframeModelAdded(reference)
}

public func keyframeEffectNotifyKeyframeModelStarted(_ reference: KeyframeEffectRef, _ event: AnimationEventRef) -> CInt {
  return _KeyframeEffectNotifyKeyframeModelStarted(reference, event)
}

public func keyframeEffectNotifyKeyframeModelFinished(_ reference: KeyframeEffectRef, _ event: AnimationEventRef) -> CInt {
  return _KeyframeEffectNotifyKeyframeModelFinished(reference, event)
}

public func keyframeEffectNotifyKeyframeModelTakeover(_ reference: KeyframeEffectRef, _ event: AnimationEventRef) {
  _KeyframeEffectNotifyKeyframeModelTakeover(reference, event)
}

public func keyframeEffectNotifyKeyframeModelAborted(_ reference: KeyframeEffectRef, _ event: AnimationEventRef) -> CInt {
  return _KeyframeEffectNotifyKeyframeModelAborted(reference, event)
}

public func keyframeEffectHasOnlyTranslationTransforms(_ reference: KeyframeEffectRef, _ type: CInt) -> CInt {
  return _KeyframeEffectHasOnlyTranslationTransforms(reference, type)
}

public func keyframeEffectAnimationStartScale(_ reference: KeyframeEffectRef, _ type: CInt, _ scale: inout Float) -> CInt {
  return _KeyframeEffectAnimationStartScale(reference, type, &scale)
}

public func keyframeEffectAnimationsPreserveAxisAlignment(_ reference: KeyframeEffectRef) -> Bool {
  return _KeyframeEffectAnimationsPreserveAxisAlignment(reference) == 0 ? false : true
}

public func keyframeEffectMaximumTargetScale(_ reference: KeyframeEffectRef, _ type: CInt, _ scale: inout Float) -> CInt {
  return _KeyframeEffectMaximumTargetScale(reference, type, &scale)
}

public func keyframeEffectIsPotentiallyAnimatingProperty(_ reference: KeyframeEffectRef, 
  _ targetProperty: CInt,
  _ type: CInt) -> CInt {
  return _KeyframeEffectIsPotentiallyAnimatingProperty(reference, targetProperty, type)
}

public func keyframeEffectIsCurrentlyAnimatingProperty(
  _ reference: KeyframeEffectRef,
  _ targetProperty: CInt,
  _ type: CInt) -> CInt {
  return _KeyframeEffectIsCurrentlyAnimatingProperty(reference, targetProperty, type)
}

public func keyframeEffectGetKeyframeModel(_ reference: KeyframeEffectRef, _ targetProperty: CInt) -> KeyframeModelRef? {
  let ref = _KeyframeEffectGetKeyframeModel(reference, targetProperty)
  return ref == nil ? nil : ref!
}

public func keyframeEffectGetKeyframeModelById(_ reference: KeyframeEffectRef, _ keyframeModelId: CInt) -> KeyframeModelRef? {
  let ref = _KeyframeEffectGetKeyframeModelById(reference, keyframeModelId)
  return ref == nil ? nil : ref!
}

public func keyframeEffectGetPropertyAnimationState(_ reference: KeyframeEffectRef, _ pendingStateCurrentlyRunning: inout CInt, _ pendingStatePotentiallyAnimating: inout CInt, _ activeStateCurrentlyRunning: inout CInt , _ activeStatePotentiallyAnimating: inout CInt) {
  _KeyframeEffectGetPropertyAnimationState(reference, &pendingStateCurrentlyRunning, &pendingStatePotentiallyAnimating, &activeStateCurrentlyRunning, &activeStatePotentiallyAnimating)
}

public func keyframeEffectMarkAbortedKeyframeModelsForDeletion(_ reference: KeyframeEffectRef, _ effect: KeyframeEffectRef) {
  _KeyframeEffectMarkAbortedKeyframeModelsForDeletion(reference, effect)
}

public func keyframeEffectPurgeKeyframeModelsMarkedForDeletion(_ reference: KeyframeEffectRef, _ implOnly: CInt) {
  _KeyframeEffectPurgeKeyframeModelsMarkedForDeletion(reference, implOnly)
}

public func keyframeEffectPushNewKeyframeModelsToImplThread(_ reference: KeyframeEffectRef, _ effect: KeyframeEffectRef) {
  _KeyframeEffectPushNewKeyframeModelsToImplThread(reference, effect)
}

public func keyframeEffectRemoveKeyframeModelsCompletedOnMainThread(_ reference: KeyframeEffectRef, _ effect: KeyframeEffectRef) {
  _KeyframeEffectRemoveKeyframeModelsCompletedOnMainThread(reference, effect)
}

public func keyframeEffectPushPropertiesTo(_ reference: KeyframeEffectRef, _ effect: KeyframeEffectRef) {
  _KeyframeEffectPushPropertiesTo(reference, effect)
}

public func keyframeEffectSetAnimation(_ reference: KeyframeEffectRef, _ animation: AnimationRef) {
  _KeyframeEffectSetAnimation(reference, animation)
}

// KeyframeEffectsList

public func keyframeEffectsListDestroy(_ reference: KeyframeEffectListRef) {
  _KeyframeEffectListDestroy(reference)
}

// ElementAnimations
public func elementAnimationsDestroy(_ reference: ElementAnimationsRef) {
  _ElementAnimationsDestroy(reference)
}

public func elementAnimationsIsEmpty(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsIsEmpty(reference)
}

public func elementAnimationsGetElementId(_ reference: ElementAnimationsRef) -> UInt64 {
  return _ElementAnimationsGetElementId(reference)
}
   
public func elementAnimationsSetElementId(_ reference: ElementAnimationsRef, _ id: UInt64) {
  _ElementAnimationsSetElementId(reference, id)
}

public func elementAnimationsGetAnimationHost(_ reference: ElementAnimationsRef) -> AnimationHostRef {
  return _ElementAnimationsGetAnimationHost(reference)
}

public func elementAnimationsSetAnimationHost(_ reference: ElementAnimationsRef, _ animHost: AnimationHostRef) {
  _ElementAnimationsSetAnimationHost(reference, animHost)
}

public func elementAnimationsGetScrollOffsetForAnimation(_ reference: ElementAnimationsRef, _ x: inout Float, _ y: inout Float) {
  _ElementAnimationsGetScrollOffsetForAnimation(reference, &x, &y)
}

public func elementAnimationsKeyframeEffectsList(_ reference: ElementAnimationsRef) -> KeyframeEffectListRef {
  return _ElementAnimationsKeyframeEffectListGet(reference)
}

public func elementAnimationsHasTickingKeyframeEffect(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsHasTickingKeyframeEffect(reference)
}

public func elementAnimationsHasAnyKeyframeModel(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsHasAnyKeyframeModel(reference)
}

public func elementAnimationsHasElementInActiveList(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsHasElementInActiveList(reference)
}

public func elementAnimationsHasElementInPendingList(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsHasElementInPendingList(reference)
}
  
public func elementAnimationsHasElementInAnyList(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsHasElementInAnyList(reference)
}

public func elementAnimationsScrollOffsetAnimationWasInterrupted(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsScrollOffsetAnimationWasInterrupted(reference)
}

public func elementAnimationsGetNeedsPushProperties(_ reference: ElementAnimationsRef) -> CInt {
  return _ElementAnimationsGetNeedsPushProperties(reference)
}

public func elementAnimationsSetNeedsPushProperties(_ reference: ElementAnimationsRef) {
  _ElementAnimationsSetNeedsPushProperties(reference)
}

public func elementAnimationsInitAffectedElementTypes(_ reference: ElementAnimationsRef) {
  _ElementAnimationsInitAffectedElementTypes(reference)
}

public func elementAnimationsClearAffectedElementTypes(_ reference: ElementAnimationsRef) {
  _ElementAnimationsClearAffectedElementTypes(reference)
}

public func elementAnimationsElementRegistered(_ reference: ElementAnimationsRef, _ elementId: UInt64, _ type: CInt) {
  _ElementAnimationsElementRegistered(reference, elementId, type)
}

public func elementAnimationsElementUnregistered(_ reference: ElementAnimationsRef, _ elementId: UInt64, _ type: CInt) {
  _ElementAnimationsElementUnregistered(reference, elementId, type)
}

public func elementAnimationsAddKeyframeEffect(_ reference: ElementAnimationsRef, _ effect: KeyframeEffectRef) {
  _ElementAnimationsAddKeyframeEffect(reference, effect)
}

public func elementAnimationsRemoveKeyframeEffect(_ reference: ElementAnimationsRef, _ effect: KeyframeEffectRef) {
  _ElementAnimationsRemoveKeyframeEffect(reference, effect)
}

public func elementAnimationsPushPropertiesTo(_ reference: ElementAnimationsRef, _ animations: ElementAnimationsRef) {
  _ElementAnimationsPushPropertiesTo(reference, animations)
}

public func elementAnimationsHasAnyAnimationTargetingProperty(_ reference: ElementAnimationsRef, _ property: CInt) -> CInt {
  return _ElementAnimationsHasAnyAnimationTargetingProperty(reference, property)
}

public func elementAnimationsIsPotentiallyAnimatingProperty(_ reference: ElementAnimationsRef, 
                                           _ property: CInt,
                                           _ type: CInt) -> CInt {
  return _ElementAnimationsIsPotentiallyAnimatingProperty(reference, property, type)
}

public func elementAnimationsIsCurrentlyAnimatingProperty(_ reference: ElementAnimationsRef,
                                         _ property: CInt,
                                         _ type: CInt) -> CInt {
  return _ElementAnimationsIsCurrentlyAnimatingProperty(reference, property, type)
}

public func elementAnimationsNotifyAnimationStarted(_ reference: ElementAnimationsRef, _ event: AnimationEventRef) {
  _ElementAnimationsNotifyAnimationStarted(reference, event)
}

public func elementAnimationsNotifyAnimationFinished(_ reference: ElementAnimationsRef, _ event: AnimationEventRef) {
  _ElementAnimationsNotifyAnimationFinished(reference, event)
}

public func elementAnimationsNotifyAnimationAborted(_ reference: ElementAnimationsRef, _ event: AnimationEventRef) {
  _ElementAnimationsNotifyAnimationAborted(reference, event)
}

//public func elementAnimationsNotifyAnimationPropertyUpdate(_ reference: ElementAnimationsRef, _ event: AnimationEventRef) {
//  _ElementAnimationsNotifyAnimationPropertyUpdate(reference, event)
//}

public func elementAnimationsNotifyAnimationTakeover(_ reference: ElementAnimationsRef, _ event: AnimationEventRef) {
  _ElementAnimationsNotifyAnimationTakeover(reference, event)
}
  
public func elementAnimationsSetHasElementInActiveList(_ reference: ElementAnimationsRef, _ hasElementInActiveList: CInt) {
  _ElementAnimationsSetHasElementInActiveList(reference, hasElementInActiveList)
}

public func elementAnimationsSetHasElementInPendingList(_ reference: ElementAnimationsRef, _ hasElementInPendingList: CInt) {
  _ElementAnimationsSetHasElementInPendingList(reference, hasElementInPendingList)
}

//public func elementAnimationsTransformAnimationBoundsForBox(
//  _ reference: ElementAnimationsRef,
//  _ x: inout Float,
//  _ y: inout Float,
//  _ z: inout Float,
//  _ w: inout Float,
//  _ h: inout Float,
//  _ depth: inout Float) -> CInt {
//  return _ElementAnimationsTransformAnimationBoundsForBox(reference, &x, &y, &z, &w, &h, &depth)
//}

public func elementAnimationsHasOnlyTranslationTransforms(_ reference: ElementAnimationsRef, _ type: CInt) -> CInt {
  return _ElementAnimationsHasOnlyTranslationTransforms(reference, type)
}

public func elementAnimationsAnimationStartScale(_ reference: ElementAnimationsRef, _ type: CInt, _ scale: inout Float) -> CInt {
  return _ElementAnimationsAnimationStartScale(reference, type, &scale)
}

public func elementAnimationsMaximumTargetScale(_ reference: ElementAnimationsRef, _ type: CInt, _ scale: inout Float) -> CInt {
  return _ElementAnimationsMaximumTargetScale(reference, type, &scale)
}

public func elementAnimationsUpdateClientAnimationState(_ reference: ElementAnimationsRef) {
  _ElementAnimationsUpdateClientAnimationState(reference)
}

public func elementAnimationsNotifyClientFloatAnimated(
                                      _ reference: ElementAnimationsRef,
                                      _ opacity: Float,
                                      _ target: CInt,
                                      _ model: KeyframeModelRef) {
  _ElementAnimationsNotifyClientFloatAnimated(reference, opacity, target, model)
}

// public func elementAnimationsNotifyClientTransformOperationsAnimated(
//     _ reference: ElementAnimationsRef,
//     _ operations: TransformOperations,
//     _ target: CInt,
//     _ model: KeyframeModelRef) {
//   _ElementAnimationsNotifyClientTransformOperationsAnimated(reference, target, model)
// }

public func elementAnimationsNotifyClientScrollOffsetAnimated(
  _ reference: ElementAnimationsRef,
  _ scrollOffsetX: Float,
  _ scrollOffsetY: Float,
  _ target: CInt,
  _ model: KeyframeModelRef) {
  
  _ElementAnimationsNotifyClientScrollOffsetAnimated(reference, 
    scrollOffsetX, 
    scrollOffsetY, 
    target,
    model)
}


