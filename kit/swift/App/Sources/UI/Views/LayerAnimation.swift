// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Foundation
import Compositor

//public typealias LayerAnimationElementAnimatableProperties = Int
//public typealias LayerAnimationElementAnimatableProperty = Int
//public typealias PreemptionStrategy = Int

// public protocol LayerAnimationDelegate {
//     var animatorCollection: LayerAnimatorCollection? { get }
//     var deviceScaleFactor: Float { get }
//     var boundsForAnimation: IntRect { get set }
//     var transformForAnimation: Transform { get set }
//     var opacityForAnimation: Float { get set }
//     var visibilityForAnimation: Bool { get set }
//     var brightnessForAnimation: Float { get set }
//     var grayscaleForAnimation: Float { get set }
//     var colorForAnimation: Color { get set }

//     func scheduleDrawForAnimation()
//     func addThreadedAnimation(animation: Compositor.Animation)
//     func removeThreadedAnimation(animationId: Int)
// }

public protocol LayerAnimationDelegate : class {
  var boundsForAnimation: IntRect { get }
  var transformForAnimation: Transform { get }
  var opacityForAnimation: Float { get }
  var visibilityForAnimation: Bool { get }
  var brightnessForAnimation: Float { get }
  var grayscaleForAnimation: Float { get }
  var colorForAnimation: Color { get }
  var deviceScaleFactor: Float { get }
  var uiLayer: UI.Layer? { get }
  var compositorLayer: Compositor.Layer? { get }
  var layerAnimatorCollection: LayerAnimatorCollection? { get }
  var threadedAnimationDelegate: LayerThreadedAnimationDelegate? { get }
  var frameNumber: Int { get }
  var refreshRate: Float { get }

  func setBoundsFromAnimation(bounds: IntRect, reason: PropertyChangeReason)
  func setTransformFromAnimation(transform: Transform, reason: PropertyChangeReason)
  func setOpacityFromAnimation(opacity: Float, reason: PropertyChangeReason)
  func setVisibilityFromAnimation(visibility: Bool, reason: PropertyChangeReason)
  func setBrightnessFromAnimation(brightness: Float, reason: PropertyChangeReason)
  func setGrayscaleFromAnimation(grayscale: Float,reason: PropertyChangeReason)
  func setColorFromAnimation(color: Color, reason: PropertyChangeReason)
  func scheduleDrawForAnimation()
}

public protocol LayerThreadedAnimationDelegate {
  func addThreadedAnimation(keyframeModel: Compositor.KeyframeModel)
  func removeThreadedAnimation(keyframeModelId: Int)
}

public protocol LayerAnimationObserver : class {
  var requiresNotificationWhenAnimatorDestroyed: Bool { get }
  func onLayerAnimationStarted(sequence: LayerAnimationSequence)
  func onLayerAnimationEnded(sequence: LayerAnimationSequence)
  func onLayerAnimationAborted(sequence: LayerAnimationSequence)
  func onLayerAnimationScheduled(sequence: LayerAnimationSequence)
  func onAttachedToSequence(sequence: LayerAnimationSequence)
  func onDetachedFromSequence(sequence: LayerAnimationSequence)
  
  func attachedToSequence(sequence: LayerAnimationSequence)
  func detachedFromSequence(sequence: LayerAnimationSequence, sendNotification: Bool)
}

extension LayerAnimationObserver {
  public func attachedToSequence(sequence: LayerAnimationSequence) {}
  public func detachedFromSequence(sequence: LayerAnimationSequence, sendNotification: Bool) {}
}

public class LayerAnimationObserverBase : LayerAnimationObserver {
  
  public var requiresNotificationWhenAnimatorDestroyed: Bool {
    return false
  }

  internal typealias AttachedSequences = Set<LayerAnimationSequence>

  internal var attachedSequences: AttachedSequences

  internal init() {
    attachedSequences = AttachedSequences()
  }
  
  deinit {
    stopObserving()
  }
  
  public func onLayerAnimationStarted(sequence: LayerAnimationSequence) {}
  public func onLayerAnimationEnded(sequence: LayerAnimationSequence) {}
  public func onLayerAnimationAborted(sequence: LayerAnimationSequence) {}
  public func onLayerAnimationScheduled(sequence: LayerAnimationSequence) {}
  
  internal func stopObserving() {
    while !attachedSequences.isEmpty {
      let sequence: LayerAnimationSequence = attachedSequences[attachedSequences.startIndex]
      sequence.removeObserver(observer: self)
    }
  }

  
  public func onAttachedToSequence(sequence: LayerAnimationSequence) {}
  public func onDetachedFromSequence(sequence: LayerAnimationSequence) {}

  public func attachedToSequence(sequence: LayerAnimationSequence) {
    attachedSequences.insert(sequence)
    onAttachedToSequence(sequence: sequence)
  }

  public func detachedFromSequence(sequence: LayerAnimationSequence, sendNotification: Bool) {
    attachedSequences.remove(sequence)
    if sendNotification {
      onDetachedFromSequence(sequence: sequence)
    }
  }

}

public class ImplicitAnimationObserver : LayerAnimationObserverBase {
  
  enum AnimationStatus {
    case Unknown
    case Completed
    case Aborted
  }

  var active: Bool
  var firstSequenceScheduled: Bool
  var propertyAnimationStatus: [LayerAnimationElement.AnimatableProperty: AnimationStatus]

  override init() {
    active = false
    firstSequenceScheduled = false
    propertyAnimationStatus = [:]
  }

  public func onImplicitAnimationsScheduled() {

  }
  
  public func onImplicitAnimationsCompleted() {

  }
  
  public func stopObservingImplicitAnimations() {

  }
  
  public func wasAnimationAbortedForProperty(property: LayerAnimationElement.AnimatableProperty) -> Bool {
    return false
  }
  
  public func wasAnimationCompletedForProperty(property: LayerAnimationElement.AnimatableProperty) -> Bool {
    return false
  }

  
  override public func onLayerAnimationEnded(sequence: LayerAnimationSequence)  {

  }

  override public func onLayerAnimationAborted(sequence: LayerAnimationSequence) {

  }
  
  override public func onLayerAnimationScheduled(sequence: LayerAnimationSequence) {

  }
  
  override public func onAttachedToSequence(sequence: LayerAnimationSequence) {

  }
  
  override public func onDetachedFromSequence(sequence: LayerAnimationSequence) {

  }

  func checkCompleted() {

  }

  func updatePropertyAnimationStatus(sequence: LayerAnimationSequence, status: AnimationStatus) {

  }

  func animationStatusForProperty(property: LayerAnimationElement.AnimatableProperty) -> AnimationStatus {
    return AnimationStatus.Unknown
  }
}

extension ImplicitAnimationObserver : Hashable {

  public func hash(into hasher: inout Hasher) {
    hasher.combine(active)
    hasher.combine(firstSequenceScheduled)
  }
  
}

extension ImplicitAnimationObserver : Equatable {

  public static func ==(lhs: ImplicitAnimationObserver, rhs: ImplicitAnimationObserver) -> Bool {
    assert(false)
    return false
  }

}