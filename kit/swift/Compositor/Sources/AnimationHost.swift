// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims
import Foundation

//public protocol AnimationPlayer {}
public protocol MutatorHostClient {}

public class AnimationHost {

  public static func createMainInstance() -> AnimationHost {
    let ref = _AnimationHostCreate()
    return AnimationHost(reference: ref!, owned: true)
  }

  public var mutatorHostClient: MutatorHostClient? {
    get {
      return nil
    }
    set {

    }
  }

  public var needsPushProperties: Bool {
    return _AnimationHostGetNeedsPushProperties(reference) == 0 ? false : true
  }

  public var supportsScrollAnimations: Bool {
    return _AnimationHostSupportsScrollAnimations(reference) == 0 ? false : true
  }

  public private(set) var reference: AnimationHostRef
  private var owned: Bool

  public init(reference: AnimationHostRef, owned: Bool) {
    //print("AnimationHost: created with reference = \(reference)")
    self.reference = reference
    self.owned = owned
  }

  deinit {
    if owned {
      //print("AnimationHost destructor: destroying AnimationHost native handle")
      _AnimationHostDestroy(reference)
    }
  }

  public func addAnimationTimeline(timeline: AnimationTimeline) {
    _AnimationHostAddAnimationTimeline(reference, timeline.reference)
  }

  public func removeAnimationTimeline(timeline: AnimationTimeline) {
    _AnimationHostRemoveAnimationTimeline(reference, timeline.reference)
  }

  public func getTimelineById(timelineID: Int) -> AnimationTimeline? {
    if let ref = _AnimationHostGetTimelineById(reference, CInt(timelineID)){
      return AnimationTimeline(reference: ref, owned: false)
    }
    return nil
  }

  //public func clearTimelines() {
  //  _AnimationHostClearTimelines(reference)
  //}

  public func registerKeyframeEffectForElement(elementId: UInt64,
                                               keyframeEffect: KeyframeEffect) {
    _AnimationHostRegisterKeyframeEffectForElement(reference, elementId, keyframeEffect.reference)
  }
  
  public func unregisterKeyframeEffectForElement(elementId: UInt64,
                                                 keyframeEffect: KeyframeEffect) {
    _AnimationHostUnregisterKeyframeEffectForElement(reference, elementId, keyframeEffect.reference)
  }

  public func getElementAnimationsForLayerId(layerId: Int) -> ElementAnimations? {
    return nil
  }

  public func setNeedsCommit() {
    _AnimationHostSetNeedsCommit(reference)
  }

  public func setNeedsPushProperties() {
    _AnimationHostSetNeedsPushProperties(reference)
  }

  // func pushPropertiesTo(hostImpl: AnimationHost) {

  // }

  // func activateAnimations() -> Bool {
  //   return false
  // }

  // func updateAnimationState(startReadyAnimations: Bool, events: [AnimationEvent]) -> Bool {
  //   return false
  // }

  // func createEvents() -> [AnimationEvent]? {
  //   return nil
  // }

  // func setAnimationEvents(events: [AnimationEvent]) {

  // }

  // func scrollOffsetAnimationWasInterrupted(layerId: Int) -> Bool {
  //   return false
  // }

  // func isAnimatingFilterProperty(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func isAnimatingOpacityProperty(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func isAnimatingTransformProperty(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func hasPotentiallyRunningFilterAnimation(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func hasPotentiallyRunningOpacityAnimation(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func hasPotentiallyRunningTransformAnimation(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func hasAnyAnimationTargetingProperty(layerId: Int, property: Int) -> Bool {
  //   return false
  // }

  // func filterIsAnimatingOnImplOnly(layerId: Int) -> Bool {
  //   return false
  // }

  // func opacityIsAnimatingOnImplOnly(layerId: Int) -> Bool {
  //   return false
  // }

  // func transformIsAnimatingOnImplOnly(layerId: Int) -> Bool {
  //   return false
  // }

  // func hasFilterAnimationThatInflatesBounds(layerId: Int) -> Bool {
  //   return false
  // }

  // func hasTransformAnimationThatInflatesBounds(layerId: Int) -> Bool {
  //   return false
  // }

  // func hasAnimationThatInflatesBounds(layerId: Int) -> Bool {
  //   return false
  // }

  // func filterAnimationBoundsForBox(layerId: Int, box: FloatBox, bounds: inout FloatBox) -> Bool {
  //   return false
  // }

  // func transformAnimationBoundsForBox(layerId: Int, box: FloatBox, bounds: inout FloatBox) -> Bool {
  //   return false
  // }

  // func hasOnlyTranslationTransforms(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return false
  // }

  // func animationsPreserveAxisAlignment(layerId: Int) -> Bool {
  //   return false
  // }

  // func maximumTargetScale(layerId: Int, treeType: LayerTreeType, startScale: inout Float) -> Bool {
  //   return false
  // }

  // func animationStartScale(layerId: Int, treeType: LayerTreeType, startScale: inout Float) -> Bool {
  //   return false
  // }

  // func hasAnyAnimation(layerId: Int) -> Bool {
  //   return false
  // }

  // func hasActiveAnimation(layerId: Int) -> Bool {
  //   return false
  // }

  // func implOnlyScrollAnimationCreate(layerId: Int, targetOffset: ScrollOffset, currentOffset: ScrollOffset) -> Bool {
  //   return false
  // }

  // func implOnlyScrollAnimationUpdateTarget(layerId: Int, scrollDelta: FloatVec2, maxScrollOffset: ScrollOffset, frameMonotonicTime: NSDate) -> Bool {
  //   return false
  // }

}
