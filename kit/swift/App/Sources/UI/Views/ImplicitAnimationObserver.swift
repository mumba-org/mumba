// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class ImplicitLayerAnimationObserver : LayerAnimationObserverBase {
  
  internal enum AnimationStatus {
    case Unknown
    case Completed
    case Aborted
  }

  internal typealias PropertyAnimationStatusMap = Dictionary<LayerAnimationElement.AnimatableProperty, AnimationStatus>
  
  internal var active: Bool {
    didSet {
      checkCompleted()
    }
  }
  fileprivate var propertyAnimationStatus: PropertyAnimationStatusMap
  fileprivate var firstSequenceScheduled: Bool

  public override init() {
    active = false
    firstSequenceScheduled = false
    propertyAnimationStatus = PropertyAnimationStatusMap()
  }

  public override func onLayerAnimationEnded(sequence: LayerAnimationSequence) {
    updatePropertyAnimationStatus(sequence: sequence, status: .Completed)
    sequence.removeObserver(observer: self)
    checkCompleted()
  }
  
  public override func onLayerAnimationAborted(sequence: LayerAnimationSequence) {
    updatePropertyAnimationStatus(sequence: sequence, status: .Aborted)
    sequence.removeObserver(observer: self)
    checkCompleted()
  }

  public override func onLayerAnimationScheduled(sequence: LayerAnimationSequence) {
    if !firstSequenceScheduled {
      firstSequenceScheduled = true
      onImplicitAnimationsScheduled()
    }
  }

  public override func onAttachedToSequence(sequence: LayerAnimationSequence) {

  }

  public override func onDetachedFromSequence(sequence: LayerAnimationSequence) {
    checkCompleted()
  }

  internal func stopObservingImplicitAnimations() {
    active = false
    stopObserving()
  }

  internal func wasAnimationAbortedForProperty(
    property: LayerAnimationElement.AnimatableProperty) -> Bool {
    return animationStatusForProperty(property: property) == .Aborted
  }

  
  internal func wasAnimationCompletedForProperty(
    property: LayerAnimationElement.AnimatableProperty) -> Bool {
    if let status = animationStatusForProperty(property: property) { 
      return status == .Completed
    }
    return false
  }

  internal func checkCompleted() {
    if active && attachedSequences.isEmpty {
      active = false
      onImplicitAnimationsCompleted()
    }
  }

  internal func updatePropertyAnimationStatus(
    sequence: LayerAnimationSequence,
    status: AnimationStatus) {
      
    let properties: LayerAnimationElement.AnimatableProperties = sequence.properties
    
    // for (unsigned i = LayerAnimationElement::FIRST_PROPERTY;
    //    i != LayerAnimationElement::SENTINEL;
    //    i = i << 1) {
    //   if (i & properties) {
    //     LayerAnimationElement::AnimatableProperty property =
    //         static_cast<LayerAnimationElement::AnimatableProperty>(i);
    //     property_animation_status_[property] = status;
    //   }
    // }
    var i = LayerAnimationElement.AnimatableProperty.FirstProperty
    while i != LayerAnimationElement.AnimatableProperty.Sentinel {
      if properties.contains(i) {
        let property = i as LayerAnimationElement.AnimatableProperty
        propertyAnimationStatus[property] = status
      }
      i = LayerAnimationElement.AnimatableProperty(rawValue: i.rawValue << 1)
    }
  }

  internal func animationStatusForProperty(
    property: LayerAnimationElement.AnimatableProperty) -> AnimationStatus? {
    if propertyAnimationStatus.contains(where: { property == $0.key } ) {
      return propertyAnimationStatus[property]
    }
    return AnimationStatus.Unknown
  }

  public func onImplicitAnimationsScheduled() {}
  public func onImplicitAnimationsCompleted() {}
}