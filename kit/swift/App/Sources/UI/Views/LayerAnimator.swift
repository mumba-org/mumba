// Copyright (c) 2015-2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base
import Graphics
import Compositor

fileprivate let layerAnimatorDefaultTransitionDurationMs: Int = 120

public enum PreemptionStrategy {
  case ImmediatelySetNewTarget
  case ImmediatelyAnimateToNewTarget
  case EnqueueNewAnimation
  case ReplaceQueuedAnimations
}

public class LayerAnimator {

  internal class RunningAnimation {

    public var isSequenceAlive: Bool { 
      return sequence != nil 
    }

    public var hasAnimation: Bool {
      return sequence != nil
    }

    public weak var sequence: LayerAnimationSequence?

    public init(sequence: LayerAnimationSequence) {
      self.sequence = sequence
    }
    
    public init(other: RunningAnimation) {

    }
  }

  typealias RunningAnimations = [RunningAnimation]

  // was base::circular_deque
  typealias AnimationQueue = ContiguousArray<LayerAnimationSequence>

  public var transform: Transform {

    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.transform
    }

    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Transform)
          d.setTransformFromAnimation(transform: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createTransformElement(transform: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }

  }

  public var bounds: IntRect {

    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.bounds
    }
    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Bounds)
          d.setBoundsFromAnimation(bounds: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createBoundsElement(bounds: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }

  }

  public var opacity: Float {

    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.opacity
    }

    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Opacity)
          d.setOpacityFromAnimation(opacity: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createOpacityElement(opacity: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }
  }

  public var visibility: Bool {
    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.visibility
    }
    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Visibility)
          d.setVisibilityFromAnimation(visibility: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createVisibilityElement(visibility: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }
  }


  public var brightness: Float {
    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.brightness
    }
    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Brightness)
          d.setBrightnessFromAnimation(brightness: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createBrightnessElement(brightness: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }
  }

  public var grayscale: Float {

    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.grayscale
    }
    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Grayscale)
          d.setGrayscaleFromAnimation(grayscale: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createGrayscaleElement(grayscale: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }
  }

  public var color: Color {
    get {
      var target = LayerAnimationElement.TargetValue(delegate: delegate)
      getTargetValue(target: &target)
      return target.color
    }
    set {
      let duration = transitionDuration
      if duration.isZero && preemptionStrategy != .EnqueueNewAnimation {
        if let d = delegate {           
          stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty.Color)
          d.setColorFromAnimation(color: newValue, reason: PropertyChangeReason.NotFromAnimation)
          return
        }
      }
      let element = LayerAnimationElement.createColorElement(color: newValue, duration: duration)
      element.tweenType = tweenType
      startAnimation(animation: LayerAnimationSequence(element: element))
    }
  }

  public var delegate: LayerAnimationDelegate? {
    get {
      return _delegate
    }
    set {
      if _delegate != nil  && isStarted {
        
        if let collection = layerAnimatorCollection {
          collection.stopAnimator(animator: self)
        }
      }
      switchToLayer(newValue != nil ? newValue!.uiLayer : nil)
      _delegate = newValue
      if _delegate != nil && isStarted {
        if let collection = layerAnimatorCollection {
          collection.startAnimator(animator: self)
        }
      }
    }
  }

  public var isAnimating: Bool { 
    return !animationQueue.isEmpty 
  }
  public var layerAnimatorCollection: LayerAnimatorCollection? {
     return _delegate != nil ? _delegate!.layerAnimatorCollection : nil
  }
  public var tweenType: TweenType
  public var preemptionStrategy: PreemptionStrategy
  public var lastStepTime: TimeTicks = TimeTicks()
  public internal(set) var transitionDuration: TimeDelta = TimeDelta()
  internal var isTransitionDurationLocked: Bool
  internal var observers: [LayerAnimationObserverBase] = []
  private var animation: SingleKeyframeEffectAnimation
  private var runningAnimations: RunningAnimations = RunningAnimations()
  private var animationQueue: AnimationQueue = AnimationQueue()
  private var isStarted: Bool
  private var addingAnimations: Bool
  private var ownedObserverList: [ImplicitAnimationObserver] = []
  private weak var _delegate: LayerAnimationDelegate?
  //fileprivate var animationMetricsReporter: AnimationMetricsReporter?
  
  public class func createDefaultAnimator() -> LayerAnimator {
    return LayerAnimator(transitionDuration: TimeDelta(milliseconds: 0))
  }

  public class func createImplicitAnimator() -> LayerAnimator {
    return LayerAnimator(transitionDuration: TimeDelta.from(
      milliseconds: Int64(layerAnimatorDefaultTransitionDurationMs)))
  }

  public init(transitionDuration: TimeDelta) {
    preemptionStrategy = .ImmediatelySetNewTarget
    isTransitionDurationLocked = false
    self.transitionDuration = transitionDuration
    tweenType = TweenType.Linear
    isStarted = false
    addingAnimations = false
    animation = SingleKeyframeEffectAnimation(id: AnimationIdProvider.nextAnimationId)
  }

  deinit {
    for runningAnimation in runningAnimations {
      if runningAnimation.isSequenceAlive {
        runningAnimation.sequence!.onAnimatorDestroyed()
      }
    }
    clearAnimationsInternal()
    delegate = nil
  }

  public func switchToLayer(_ newLayer: Layer?) {
    if _delegate != nil {
      detachLayerFromAnimation()
    }
    if let layer = newLayer {
      attachLayerToAnimation(id: UInt64(layer.id))
    }
  }

  public func attachLayerAndTimeline(compositor: UICompositor) {
    let timeline = compositor.animationTimeline
    timeline.attachAnimation(self.animation)
    guard let ccLayer = delegate?.compositorLayer else {
      // TODO: really use exceptions
      return
    }
    attachLayerToAnimation(id: UInt64(ccLayer.id))
  }

  public func detachLayerAndTimeline(compositor: UICompositor) {
    let timeline = compositor.animationTimeline
    detachLayerFromAnimation()
    timeline.detachAnimation(animation)
  }
  
  public func addOwnedObserver(animationObserver: ImplicitAnimationObserver) {
    ownedObserverList.append(animationObserver)
  }
  
  public func removeAndDestroyOwnedObserver(animationObserver: ImplicitAnimationObserver) {
    if let index = ownedObserverList.index(of: animationObserver) {
      ownedObserverList.remove(at: index)
    }
  }

  public func startAnimation(animation: LayerAnimationSequence) {
    onScheduled(sequence: animation)
    if !startSequenceImmediately(sequence: animation) {
      switch preemptionStrategy {
        case .ImmediatelySetNewTarget:
          immediatelySetNewTarget(sequence: animation)
        case .ImmediatelyAnimateToNewTarget:
          immediatelyAnimateToNewTarget(sequence: animation)
        case .EnqueueNewAnimation:
          enqueueNewAnimation(sequence: animation)
        case .ReplaceQueuedAnimations:
          replaceQueuedAnimations(sequence: animation)
      }
    }
    finishAnyAnimationWithZeroDuration()
    updateAnimationState()
  }

  public func scheduleAnimation(animation: LayerAnimationSequence) {
    onScheduled(sequence: animation)
    if isAnimating {
      animationQueue.append(animation)
      processQueue()
    } else {
      let _ = startSequenceImmediately(sequence: animation)
    }
    updateAnimationState()
  }

  public func startTogether(animations: [LayerAnimationSequence]) {
    if preemptionStrategy == .ImmediatelySetNewTarget {
      for animation in animations {
        startAnimation(animation: animation)
      }
      return
    }

    addingAnimations = true
    if !isAnimating {
      if let collection = layerAnimatorCollection {
        if collection.hasActiveAnimators {
          lastStepTime = collection.lastTickTime
        }
      } else {
        lastStepTime = TimeTicks.now
      }
    }

   
    var animatedProperties: LayerAnimationElement.AnimatableProperties =
        LayerAnimationElement.AnimatableProperty.Unknown

    // FIX: this probably wont work as intended
    for animation in animations {
      animatedProperties.insert(animation.properties)
    }

    // Starting a zero duration pause that affects all the animated properties
    // will prevent any of the sequences from animating until there are no
    // running animations that affect any of these properties, as well as
    // handle preemption strategy.
    startAnimation(animation: LayerAnimationSequence(
        element: LayerAnimationElement.createPauseElement(properties: animatedProperties, duration: TimeDelta())))

    var waitForGroupStart = 0

    for animation in animations {
      waitForGroupStart |= (animation.isFirstElementThreaded(delegate: delegate!) ? 1 : 0)
    }

    let groupId = AnimationIdProvider.nextGroupId

    for animation in animations {
      animation.animationGroupId = groupId
      animation.waitingForGroupStart = (waitForGroupStart == 0 ? false : true)
      scheduleAnimation(animation: animation)
    }

    addingAnimations = false
    updateAnimationState()
  }

  public func scheduleTogether(animations: [LayerAnimationSequence]) {
    var animatedProperties: LayerAnimationElement.AnimatableProperties =
        LayerAnimationElement.AnimatableProperty.Unknown

    for animation in animations {
      animatedProperties.insert(animation.properties)
    }

    scheduleAnimation(
      animation: LayerAnimationSequence(
          element: LayerAnimationElement.createPauseElement(properties: animatedProperties, duration: TimeDelta())
      )
    )

    var waitForGroupStart = 0
    for animation in animations {
      waitForGroupStart |= (animation.isFirstElementThreaded(delegate: delegate!) ? 1 : 0)
    }

    let groupId = AnimationIdProvider.nextGroupId

    for animation in animations {
      animation.animationGroupId = groupId
      animation.waitingForGroupStart = (waitForGroupStart == 0 ? false : true)
      scheduleAnimation(animation: animation)
    }

    updateAnimationState()
  }

  public func schedulePauseForProperties(duration: TimeDelta,
    propertiesToPause: LayerAnimationElement.AnimatableProperties) {
    scheduleAnimation(animation: LayerAnimationSequence(
                      element: LayerAnimationElement.createPauseElement(
                        properties: propertiesToPause, duration: duration)))
  }

  public func isAnimatingProperty(property: LayerAnimationElement.AnimatableProperty) -> Bool {
    return isAnimatingOnePropertyOf(properties:  LayerAnimationElement.AnimatableProperties(rawValue: property.rawValue))
  }

  public func isAnimatingOnePropertyOf(properties: LayerAnimationElement.AnimatableProperties) -> Bool {
    for layerAnimationSequence in animationQueue {
      if layerAnimationSequence.properties.contains(properties) {
        return true
      }
    }
    return false
  }

  public func stopAnimatingProperty(property: LayerAnimationElement.AnimatableProperty) {
    while true {
      // GetRunningAnimation purges deleted animations before searching, so we are
      // guaranteed to find a live animation if any is returned at all.
      guard let running = getRunningAnimation(property: property) else {
        break
      }
      // As was mentioned above, this sequence must be alive.
      //assert(running.isSequenceAlive)
      finishAnimation(sequence: running.sequence!, abort: false)
    }
  }

  public func stopAnimating() {
    stopAnimatingInternal(abort: false)
  }

  public func abortAllAnimations() {
    stopAnimatingInternal(abort: true)
  }

  public func addObserver(observer: LayerAnimationObserver) {
    let elem = observer as! LayerAnimationObserverBase
    guard observers.index(where: { elem === $0 }) == nil else {
      return
    }

    observers.append(elem)
    for layerAnimationSequence in animationQueue {
      layerAnimationSequence.addObserver(observer: elem)
    }
  }

  public func removeObserver(observer: LayerAnimationObserver) {
    let elem = observer as! LayerAnimationObserverBase
    if let index = observers.index(where: { elem === $0 }) {
      observers.remove(at: index)
    }
    
    // Remove the observer from all sequences as well.
    for anim in animationQueue {
      anim.removeObserver(observer: observer as! LayerAnimationObserverBase)
    }
  }

  public func onThreadedAnimationStarted(monotonicTime: TimeTicks,
                                         targetProperty: TargetProperty,
                                         groupId: Int) {
    let property = LayerAnimationElement.toAnimatableProperty(property: targetProperty)

    guard let running = getRunningAnimation(property: property) else {
      return
    }
    //assert(running.isSequenceAlive)

    if running.sequence!.animationGroupId != groupId {
      return
    }

    running.sequence!.onThreadedAnimationStarted(monotonicTime: monotonicTime, targetProperty: targetProperty, groupId: groupId)
    if !running.sequence!.waitingForGroupStart {
      return
    }

    let startTime = monotonicTime

    running.sequence!.waitingForGroupStart = false

    // The call to GetRunningAnimation made above already purged deleted
    // animations, so we are guaranteed that all the animations we iterate
    // over now are alive.
    for anim in runningAnimations {
      if let sequence = anim.sequence {
      // Ensure that each sequence is only Started once, regardless of the
      // number of sequences in the group that have threaded first elements.
        if (sequence.animationGroupId == groupId) &&
            !sequence.isFirstElementThreaded(delegate: delegate!) &&
            sequence.waitingForGroupStart {
           sequence.startTime = startTime
           sequence.waitingForGroupStart = false
           sequence.start(delegate: delegate!)
        }
      }
    }
  }

  public func step(now: TimeTicks) {
    lastStepTime = now

    purgeDeletedAnimations()

    // We need to make a copy of the running animations because progressing them
    // and finishing them may indirectly affect the collection of running
    // animations.
    //let runningAnimationsCopy = runningAnimations
    for runningAnimation in runningAnimations {//runningAnimationsCopy {
      if !hasAnimation(sequence: runningAnimation.sequence) {
        continue
      }
      guard let sequence = runningAnimation.sequence else {
        continue
      }
      if sequence.isFinished(time: now) {
        finishAnimation(sequence: sequence, abort: false)
      } else {
        progressAnimation(sequence: sequence, now: now)
      }
    }
  }

  public func addToCollection(collection: LayerAnimatorCollection) {
    if isAnimating && !isStarted {
      collection.startAnimator(animator: self)
      isStarted = true
    }
  }

  public func removeFromCollection(collection: LayerAnimatorCollection) {
    if isStarted {
      collection.stopAnimator(animator: self)
      isStarted = false
    }
  }

  internal func progressAnimation(sequence: LayerAnimationSequence,
                                  now: TimeTicks) {
    if delegate == nil || sequence.waitingForGroupStart {
      return
    }

    sequence.progress(now: now, delegate: delegate!)
  }

  internal func progressAnimationToEnd(sequence: LayerAnimationSequence) {
    guard let d = delegate else {
      return
    }

    sequence.progressToEnd(delegate: d)
  }

  internal func hasAnimation(sequence: LayerAnimationSequence?) -> Bool {
    guard let seq = sequence else {
      return false
    }
    for anim in animationQueue {
      if anim === seq {
        return true
      }
    }
    return false
  }

  fileprivate func stopAnimatingInternal(abort: Bool) {
    while isAnimating && delegate != nil {
      // We're going to attempt to finish the first running animation. Let's
      // ensure that it's valid.
      purgeDeletedAnimations()

      // If we've purged all running animations, attempt to start one up.
      if runningAnimations.isEmpty {
        processQueue()
      }

      assert(!runningAnimations.isEmpty)

      // Still no luck, let's just bail and clear all animations.
      if runningAnimations.isEmpty {
        clearAnimationsInternal()
        break
      }

      finishAnimation(sequence: runningAnimations[runningAnimations.startIndex].sequence!, abort: abort)
    }
  }

  fileprivate func updateAnimationState() {
    let shouldStart = isAnimating
    if let collection = layerAnimatorCollection {
      if shouldStart && !isStarted {
        collection.startAnimator(animator: self)
      }
      else if !shouldStart && isStarted {
        collection.stopAnimator(animator: self)
      }
      isStarted = shouldStart
    } else {
      isStarted = false
    }
  }

  fileprivate func removeAnimation(sequence: LayerAnimationSequence) -> LayerAnimationSequence? {
    var toReturn: LayerAnimationSequence?

    var isRunning = false

    // First remove from running animations
    for anim in runningAnimations {
      if anim.sequence === sequence {
        if let index = runningAnimations.index(where: { $0 === anim }) {
          runningAnimations.remove(at: index)
        }
        isRunning = true
        break
      }
    }

    // Then remove from the queue
    for anim in animationQueue {
      if anim === sequence {
        toReturn = anim
        if let index = animationQueue.firstIndex(where: { $0 === anim }) {
          animationQueue.remove(at: index)
        }
        break
      }
    }

    if toReturn == nil || !toReturn!.waitingForGroupStart || !toReturn!.isFirstElementThreaded(delegate: delegate!) {
      return toReturn
    }

    // The removed sequence may have been responsible for making other sequences
    // wait for a group start. If no other sequences in the group have a
    // threaded first element, the group no longer needs the additional wait.
    var isWaitStillNeeded = false
    let groupId = toReturn!.animationGroupId
    for anim in animationQueue {
      if anim.animationGroupId == groupId &&
          anim.isFirstElementThreaded(delegate: delegate!) {
        isWaitStillNeeded = true
        break
      }
    }

    if isWaitStillNeeded {
      return toReturn
    }

    for anim in animationQueue {
      if anim.animationGroupId == groupId && anim.waitingForGroupStart {
        anim.waitingForGroupStart = false
        if isRunning {
          anim.startTime = lastStepTime
          anim.start(delegate: delegate!)
        }
      }
    }
    return toReturn
  }

  fileprivate func finishAnimation(sequence: LayerAnimationSequence, abort: Bool) {
    let _ = removeAnimation(sequence: sequence)
    if abort {
      sequence.abort(delegate: delegate!)
    } else {
      progressAnimationToEnd(sequence: sequence)
    }
    if delegate == nil {
      return
    }
    processQueue()
    updateAnimationState()
  }

  fileprivate func finishAnyAnimationWithZeroDuration() {
    // Special case: if we've started a 0 duration animation, just finish it now
    // and get rid of it. We need to make a copy because Progress may indirectly
    // cause new animations to start running.
    for anim in runningAnimations {
      if !anim.hasAnimation {
        continue
      }

      if let sequence = anim.sequence {
        if sequence.isFinished(time: sequence.startTime) {
          progressAnimationToEnd(sequence: sequence)
          let _ = removeAnimation(sequence: sequence)
        }
      }
    }
    processQueue()
    updateAnimationState()
  }

  fileprivate func clearAnimations() {
    clearAnimationsInternal()
  }

  fileprivate func getRunningAnimation(
    property: LayerAnimationElement.AnimatableProperty) -> RunningAnimation? {
    purgeDeletedAnimations()
    for anim in runningAnimations {
      if let sequence = anim.sequence {
        if sequence.properties.contains(property) {
          return anim
        }
      }
    }
    return nil
  }

  fileprivate func addToQueueIfNotPresent(sequence: LayerAnimationSequence) {
    var foundSequence = false
    for anim in animationQueue {
      if anim === sequence {
        foundSequence = true
        break
      }
    }

    if !foundSequence {
      //animationQueue.insert(sequence, at: 0)
      animationQueue.append(sequence)
    }
  }

  fileprivate func removeAllAnimationsWithACommonProperty(sequence: LayerAnimationSequence, abort: Bool) {
    for runningAnimation in runningAnimations {
      if !runningAnimation.hasAnimation {
        continue
      }

      if let runningSequence = runningAnimation.sequence {
        if runningSequence.hasConflictingProperty(other: sequence.properties) {
          let _ = removeAnimation(sequence: runningSequence)
          if abort {
            runningSequence.abort(delegate: delegate!)
          } else {
            progressAnimationToEnd(sequence: runningSequence)
          }
        }
      }
    }

    // Same for the queued animations that haven't been started. Again, we'll
    // need to operate on a copy.
    var sequences = Array<LayerAnimationSequence>()

    for anim in animationQueue {
      sequences.append(anim)
    }

    for sequence in sequences {
      if !hasAnimation(sequence: sequence) {
        continue
      }

      if sequence.hasConflictingProperty(other: sequence.properties) {
        let _ = removeAnimation(sequence: sequence)
        if abort {
          sequence.abort(delegate: delegate!)
        } else {
          progressAnimationToEnd(sequence: sequence)
        }
      }
    }
  }

  fileprivate func immediatelySetNewTarget(sequence: LayerAnimationSequence) {
    let abort = false
    removeAllAnimationsWithACommonProperty(sequence: sequence, abort: abort)
    let _ = removeAnimation(sequence: sequence)
    //assert(removed == nil || removed === sequence)
    progressAnimationToEnd(sequence: sequence)

    /* delete sequence */
  }

  fileprivate func immediatelyAnimateToNewTarget(sequence: LayerAnimationSequence) {
    let abort = true
    removeAllAnimationsWithACommonProperty(sequence: sequence, abort: abort)
    addToQueueIfNotPresent(sequence: sequence)
    let _ = startSequenceImmediately(sequence: sequence)
  } 

  fileprivate func enqueueNewAnimation(sequence: LayerAnimationSequence) {
    animationQueue.append(sequence)
    processQueue()
  }

  fileprivate func replaceQueuedAnimations(sequence: LayerAnimationSequence) {
    // Remove all animations that aren't running. Note: at each iteration i is
    // incremented or an element is removed from the queue, so
    // animation_queue_.size() - i is always decreasing and we are always making
    // progress towards the loop terminating.
    var i = 0
    while i < animationQueue.count {
      purgeDeletedAnimations()

      var isRunning = false
      for runninAnimation in runningAnimations {
        if runninAnimation === animationQueue[i] {
          isRunning = true
          break
        }
      }

      if !isRunning {
        /* delete */ 
        let _ = removeAnimation(sequence: animationQueue[i])
      } else {
        i += 1
      }
    }
    animationQueue.append(sequence)
    processQueue()
  }

  fileprivate func processQueue() {
    var startedSequence = false
    repeat {
      startedSequence = false
      // Build a list of all currently animated properties.
      var animated: LayerAnimationElement.AnimatableProperties = LayerAnimationElement.AnimatableProperty.Unknown
      for runningAnimation in runningAnimations {
        if !runningAnimation.isSequenceAlive {
          continue
        }

        //animated |= runningAnimation.sequence!.properties
        animated.insert(runningAnimation.sequence!.properties)
      }

      // Try to find an animation that doesn't conflict with an animated
      // property or a property that will be animated before it. Note: starting
      // the animation may indirectly cause more animations to be started, so we
      // need to operate on a copy.
      var sequences = Array<LayerAnimationSequence>()
      for anim in animationQueue {
        sequences.append(anim)
      }

      for sequence in sequences {
        // if sequence == nil || !hasAnimation(sequence) {
        //   continue
        // }
        if !hasAnimation(sequence: sequence) {
          continue
        }

        if !sequence.hasConflictingProperty(other: animated) {
          let _ = startSequenceImmediately(sequence: sequence)
          startedSequence = true
          break
        }

        // Animation couldn't be started. Add its properties to the collection so
        // that we don't start a conflicting animation. For example, if our queue
        // has the elements { {T,B}, {B} } (that is, an element that animates both
        // the transform and the bounds followed by an element that animates the
        // bounds), and we're currently animating the transform, we can't start
        // the first element because it animates the transform, too. We cannot
        // start the second element, either, because the first element animates
        // bounds too, and needs to go first.
        //animated |= sequence.properties
        animated.insert(sequence.properties)
      }

      // If we started a sequence, try again. We may be able to start several.
    } while startedSequence
  }

  fileprivate func startSequenceImmediately(sequence: LayerAnimationSequence) -> Bool {
    purgeDeletedAnimations()

    // Ensure that no one is animating one of the sequence's properties already.
    for anim in runningAnimations {
      if anim.sequence!.hasConflictingProperty(other: sequence.properties) {
        return false
      }
    }

    // All clear, actually start the sequence.
    // All LayerAnimators share the same LayerAnimatorCollection. Use the
    // last_tick_time() from there to ensure animations started during the same
    // event complete at the same time.
    var startTime = TimeTicks()
    if isAnimating || addingAnimations {
      startTime = lastStepTime
    } else if layerAnimatorCollection != nil && layerAnimatorCollection!.hasActiveAnimators {
      startTime = layerAnimatorCollection!.lastTickTime
    } else {
      startTime = TimeTicks.now
    }

    if sequence.animationGroupId == 0 {
      sequence.animationGroupId = AnimationIdProvider.nextGroupId
    }

    runningAnimations.append(RunningAnimation(sequence: sequence))

    // Need to keep a reference to the animation.
    addToQueueIfNotPresent(sequence: sequence)

    if (!sequence.waitingForGroupStart ||
        sequence.isFirstElementThreaded(delegate: delegate!)) {
      sequence.startTime = startTime
      sequence.start(delegate: delegate!)
    }

    // Ensure that animations get stepped at their start time.
    step(now: startTime)

    return true
  }

  fileprivate func getTargetValue(target: inout LayerAnimationElement.TargetValue) {
    for anim in animationQueue {
      anim.getTargetValue(target: &target)
    }
  }

  fileprivate func onScheduled(sequence: LayerAnimationSequence) {
    for observer in observers {
      sequence.addObserver(observer: observer)
    }
    sequence.onScheduled()
  }

  fileprivate func setTransitionDuration(duration: TimeDelta) {
    if isTransitionDurationLocked {
      return
    }
    transitionDuration = duration
  }

  fileprivate func clearAnimationsInternal() {
    purgeDeletedAnimations()

    // Abort should never affect the set of running animations, but just in case
    // clients are badly behaved, we will use a copy of the running animations.
    for anim in runningAnimations {
      if !hasAnimation(sequence: anim.sequence!) {
        continue
      }

      if let removed = removeAnimation(sequence: anim.sequence!) {
        removed.abort(delegate: delegate!)
      }
    }
    // This *should* have cleared the list of running animations.
    //assert(runningAnimations.isEmpty)
    runningAnimations.removeAll()
    animationQueue.removeAll()
    updateAnimationState()
  }

  fileprivate func purgeDeletedAnimations() {
    var i = 0
    while i < runningAnimations.count {
      if !runningAnimations[i].isSequenceAlive {
        runningAnimations.remove(at: i)
      } else {
        i += 1
      }
    }
  }

  fileprivate func attachLayerToAnimation(id layerId: UInt64) {
    let elementId = animation.elementId
    ////print("LayerAnimator.attachLayerToAnimation: given id = \(layerId) element id = \(elementId)")
    // TODO: i guess this check is suppose to find a elementId
    // attached to the animation.. if not it means the anim 
    // was not attached, so it does.. otherwise it checks
    // if they are the same

    // what we need to do is, set Animation.elementId a optional!
    // so this will work as intended

    if elementId == 0 {
      animation.attachElement(id: layerId)
    } //else {
    //  assert(animation.elementId == layerId)
    //}
    animation.animationDelegate = self
  }
  
  fileprivate func detachLayerFromAnimation() {
    animation.animationDelegate = nil

    if animation.elementId != 0 {
      animation.detachElement()
    }
  }

}
  
extension LayerAnimator : Compositor.AnimationDelegate {
  
  public func notifyAnimationStarted(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int) {
    
    onThreadedAnimationStarted(
      monotonicTime: monotonicTime, 
      targetProperty: TargetProperty(rawValue: targetProperty)!,
      groupId: group)
  }

  public func notifyAnimationFinished(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int) {

  }

  public func notifyAnimationAborted(
    monotonicTime: TimeTicks,
    targetProperty: Int,
    group: Int) {

  }

  public func notifyAnimationTakeover(
      monotonicTime: TimeTicks,
      targetProperty: Int,
      animationStartTime: TimeTicks,
      curve: AnimationCurve) {

  }
}

extension LayerAnimator : LayerThreadedAnimationDelegate {
  
  public func addThreadedAnimation(keyframeModel: Compositor.KeyframeModel) {
    animation.addKeyframeModel(keyframeModel)
  }
  
  public func removeThreadedAnimation(keyframeModelId: Int) {
    animation.removeKeyframeModel(keyframeModelId)
  }
}
