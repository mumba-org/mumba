// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class CallbackLayerAnimationObserver : LayerAnimationObserverBase {
  public typealias AnimationStartedCallback = (_: CallbackLayerAnimationObserver?) -> Void
  public typealias AnimationEndedCallback = (_: CallbackLayerAnimationObserver?) -> Bool

  public var active: Bool = false {
    didSet {
      checkAllSequencesStarted()
      checkAllSequencesCompleted()
    }
  }
  public private(set) var abortedCount: Int = 0
  public private(set) var successfulCount: Int = 0
  private var startedCount: Int = 0
  private var attachedSequenceCount: Int = 0
  private var detachedSequenceCount: Int = 0
  private var animationStartedCallback: AnimationStartedCallback
  private var animationEndedCallback: AnimationEndedCallback
  private var numSequencesCompleted: Int {
    return abortedCount + successfulCount
  }

  public init(startedCallback: @escaping AnimationStartedCallback, animationEnded: @escaping AnimationEndedCallback) {
    animationStartedCallback = startedCallback
    animationEndedCallback = animationEnded
  }

  public func onImplicitAnimationsScheduled() {}
  public func onImplicitAnimationsCompleted() {}

  public override func onLayerAnimationStarted(sequence: LayerAnimationSequence) {
    startedCount += 1
    checkAllSequencesStarted()
  }

  public override func onLayerAnimationEnded(sequence: LayerAnimationSequence) {
    successfulCount += 1
    checkAllSequencesCompleted()
  }
  
  public override func onLayerAnimationAborted(sequence: LayerAnimationSequence) {
    abortedCount += 1
    checkAllSequencesCompleted()
  }
  
  public override func onLayerAnimationScheduled(sequence: LayerAnimationSequence) {

  }

  public override func onAttachedToSequence(sequence: LayerAnimationSequence) {
    attachedSequenceCount += 1
  }
  
  public override func onDetachedFromSequence(sequence: LayerAnimationSequence) {
    detachedSequenceCount += 1
  }

  func requiresNotificationWhenAnimatorDestroyed() -> Bool { 
    return false 
  }

  func checkAllSequencesStarted() {
    if active && attachedSequenceCount == startedCount {
      animationStartedCallback(self)
    }
  }

  func checkAllSequencesCompleted() {
    if active && numSequencesCompleted == attachedSequenceCount {
      active = false
      let _ = animationEndedCallback(self)
    }
  }

}