// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import _C
import MumbaShims
import Graphics

public enum UpdateTickingType: Int { 
  case normal = 0
  case force = 1
}

public class ElementAnimations {

  public var isEmpty: Bool {
    return _C.elementAnimationsIsEmpty(reference) == 1
  }

  public var elementId: UInt64 {
    get {
      return _C.elementAnimationsGetElementId(reference)
    }
   
    set {
      _C.elementAnimationsSetElementId(reference, newValue)
    }
  }

  public var animationHost: AnimationHost {
    get {
      let ref = _C.elementAnimationsGetAnimationHost(reference)
      return AnimationHost(reference: ref, owned: false)
    }
    set {
      _C.elementAnimationsSetAnimationHost(reference, newValue.reference)
    }
  }

  public var scrollOffsetForAnimation: ScrollOffset {
    var x: Float = 0.0, y: Float = 0.0
    _C.elementAnimationsGetScrollOffsetForAnimation(reference, &x, &y)
    return ScrollOffset(x: x, y: y)
  }

  //public var keyframeEffectsList: KeyframeEffectsList {
  //  let ref = _C.elementAnimationsKeyframeEffectsListGet(reference)
  //  return KeyframeEffectsList(reference: ref)
  //}

  public var hasTickingKeyframeEffect: Bool {
    return _C.elementAnimationsHasTickingKeyframeEffect(reference) == 1
  }

  public var hasAnyKeyframeModel: Bool {
    return _C.elementAnimationsHasAnyKeyframeModel(reference) == 1
  }

  public var hasElementInActiveList: Bool {
    return _C.elementAnimationsHasElementInActiveList(reference) == 1
  }

  public var hasElementInPendingList: Bool {
    return _C.elementAnimationsHasElementInPendingList(reference) == 1
  }
    
  public var hasElementInAnyList: Bool {
    return _C.elementAnimationsHasElementInAnyList(reference) == 1
  }

  //public var animationsPreserveAxisAlignment: Bool {
  //  return _C.elementAnimationsAnimationsPreserveAxisAlignment(reference) == 1
  //}

  public var scrollOffsetAnimationWasInterrupted: Bool {
    return _C.elementAnimationsScrollOffsetAnimationWasInterrupted(reference) == 1
  }

  public var needsPushProperties: Bool {
    get {
      return _C.elementAnimationsGetNeedsPushProperties(reference) == 1
    }
    set {
      _C.elementAnimationsSetNeedsPushProperties(reference)
    }
  }

  var reference: ElementAnimationsRef

  internal init(reference: ElementAnimationsRef) {
    self.reference = reference
  }

  deinit {
    _C.elementAnimationsDestroy(reference)
  }

  public func initAffectedElementTypes() {
    _C.elementAnimationsInitAffectedElementTypes(reference)
  }
  
  public func clearAffectedElementTypes() {
    _C.elementAnimationsClearAffectedElementTypes(reference)
  }

  public func elementRegistered(elementId: UInt64, type: ElementListType) {
    _C.elementAnimationsElementRegistered(reference, elementId, CInt(type.rawValue))
  }
 
  public func elementUnregistered(elementId: UInt64, type: ElementListType) {
    _C.elementAnimationsElementUnregistered(reference, elementId, CInt(type.rawValue))
  }

  public func addKeyframeEffect(effect: KeyframeEffect) {
    _C.elementAnimationsAddKeyframeEffect(reference, effect.reference)
  }
  
  public func removeKeyframeEffect(effect: KeyframeEffect) {
    _C.elementAnimationsRemoveKeyframeEffect(reference, effect.reference)
  }

  public func pushPropertiesTo(animations: ElementAnimations) {
    _C.elementAnimationsPushPropertiesTo(reference, animations.reference)
  }

  public func hasAnyAnimationTargetingProperty(property: TargetProperty) -> Bool {
    return _C.elementAnimationsHasAnyAnimationTargetingProperty(reference,  CInt(property.rawValue)) == 1
  }

  public func isPotentiallyAnimatingProperty(property: TargetProperty,
                                             type: ElementListType) -> Bool {
    return _C.elementAnimationsIsPotentiallyAnimatingProperty(reference, CInt(property.rawValue), CInt(type.rawValue)) == 1
  }

  public func isCurrentlyAnimatingProperty(property: TargetProperty,
                                           type: ElementListType) -> Bool {
    return _C.elementAnimationsIsCurrentlyAnimatingProperty(reference, CInt(property.rawValue), CInt(type.rawValue)) == 1
  }

  public func notifyAnimationStarted(event: AnimationEvent) {
    _C.elementAnimationsNotifyAnimationStarted(reference, event.reference)
  }
  
  public func notifyAnimationFinished(event: AnimationEvent) {
    _C.elementAnimationsNotifyAnimationFinished(reference, event.reference)
  }
  
  public func notifyAnimationAborted(event: AnimationEvent) {
    _C.elementAnimationsNotifyAnimationAborted(reference, event.reference)
  }
  
  //public func notifyAnimationPropertyUpdate(event: AnimationEvent) {
  //  _C.elementAnimationsNotifyAnimationPropertyUpdate(reference, event.reference)
  //}
  
  public func notifyAnimationTakeover(event: AnimationEvent) {
    _C.elementAnimationsNotifyAnimationTakeover(reference, event.reference)
  }
    
  public func setHasElementInActiveList(_ hasElementInActiveList: Bool) {
    _C.elementAnimationsSetHasElementInActiveList(reference, hasElementInActiveList ? 1 : 0)
  }

  public func setHasElementInPendingList(_ hasElementInPendingList: Bool) {
    _C.elementAnimationsSetHasElementInPendingList(reference, hasElementInPendingList ? 1 : 0)
  }

  // public func transformAnimationBoundsForBox(box: FloatBox) -> FloatBox? {
  //   var x: Float = 0.0
  //   var y: Float = 0.0
  //   var z: Float = 0.0
  //   var w: Float = 0.0
  //   var h: Float = 0.0
  //   var depth: Float = 0.0
    
  //   if _C.elementAnimationsTransformAnimationBoundsForBox(reference, &x, &y, &z, &w, &h, &depth) == 1 {
  //     return FloatBox(x: x, y: y, width: w, height: h, depth: depth)
  //   }
  //   return nil
  // }

  public func hasOnlyTranslationTransforms(type: ElementListType) -> Bool {
    return _C.elementAnimationsHasOnlyTranslationTransforms(reference, CInt(type.rawValue)) == 1
  }

  public func animationStartScale(type: ElementListType) -> Float? {
    var scale: Float = 0.0
    if _C.elementAnimationsAnimationStartScale(reference, CInt(type.rawValue), &scale) == 1 {
      return scale
    }
    return nil
  }

  public func maximumTargetScale(type: ElementListType) -> Float? {
    var scale: Float = 0.0
    if _C.elementAnimationsMaximumTargetScale(reference, CInt(type.rawValue), &scale) == 1 {
      return scale
    }
    return nil
  }

  public func updateClientAnimationState() {
    _C.elementAnimationsUpdateClientAnimationState(reference)
  }

  public func notifyClientFloatAnimated(opacity: Float,
                                        targetPropertyId: Int,
                                        model: KeyframeModel) {
    _C.elementAnimationsNotifyClientFloatAnimated(reference, opacity, CInt(targetPropertyId), model.reference)
  }
  
  public func notifyClientFilterAnimated(filter: FilterOperations,
                                         targetPropertyId: Int,
                                         model: KeyframeModel) {
    assert(false)
    //_C.elementAnimationsNotifyClientFilterAnimated(reference, targetPropertyId, model.reference)
  }
  
  //public func notifyClientTransformOperationsAnimated(
  //    operations: TransformOperations,
  //    targetPropertyId: Int,
  //    model: KeyframeModel) {
  //  _C.elementAnimationsNotifyClientTransformOperationsAnimated(reference, targetPropertyId, model.reference)
  //}
  
  public func notifyClientScrollOffsetAnimated(scrollOffset: ScrollOffset,
                                               targetPropertyId: Int,
                                               model: KeyframeModel) {
    _C.elementAnimationsNotifyClientScrollOffsetAnimated(reference, 
      scrollOffset.x, 
      scrollOffset.y, 
      CInt(targetPropertyId),
      model.reference)
  }

}