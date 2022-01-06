// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public enum AutoHighlightMode {
  case None
  case HideOnRipple
  case ShowOnRipple
}

public enum InkDropState {
  case Hidden
  case ActionPending
  case ActionTriggered
  case AlternateActionPending
  case AlternateActionTriggered
  case Activated
  case Deactivated
}

public protocol InkDropObserver : class {
  func inkDropAnimationStarted()
  func inkDropRippleAnimationEnded(state: InkDropState)
}

public protocol InkDrop : class {

  var observers: [InkDropObserver] {
    get
  }
  
  var targetInkDropState: InkDropState {
    get
  }
  
  var isHovered: Bool {
    get
    set
  }
  
  var isFocused: Bool {
    get
    set
  }

  var isHighlightFadingInOrVisible: Bool { 
    get 
  }
  
  var showHighlightOnHover: Bool {
    get
    set
  }

  var showHighlightOnFocus: Bool {
    get 
    set
  }

  func hostSizeChanged(size :IntSize)
  func animateToState(state: InkDropState)
  func setHoverHighlightFadeDuration(miliseconds: Int)
  func useDefaultHoverHighlightFadeDuration()
  func snapToActivated()
  func snapToHidden()
  func addObserver(observer: InkDropObserver)
  func removeObserver(observer: InkDropObserver)
  func notifyInkDropAnimationStarted()
  func notifyInkDropRippleAnimationEnded(state: InkDropState)
}

public class InkDropImpl : InkDrop {

  public var autoHighlightMode: AutoHighlightMode {
    didSet {
      exitHighlightState()
      highlightStateFactory = HighlightStateFactory(highlightMode: autoHighlightMode, inkDrop: self)
      highlightState = highlightStateFactory.createStartState()
    }
  }

    public var targetInkDropState: InkDropState {
    guard let ripple = inkDropRipple else {
      return InkDropState.Hidden
    }
    return ripple.targetInkDropState
  }

  public var isHovered: Bool {
    didSet {
       highlightState!.onHoverChanged()
    }
  }
  
  public var isFocused: Bool {
    didSet {
       highlightState!.onFocusChanged()
    }
  }
   
  public var isHighlightFadingInOrVisible: Bool {
    return highlight != nil && highlight!.isFadingInOrVisible
  }

  public var showHighlightOnHover: Bool {
    get {
      return _showHighlightOnHover
    }
    set {
      _showHighlightOnHover = newValue
      highlightState!.showOnHoverChanged()
    }
  }

  public var showHighlightOnFocus: Bool {
    get {
      return _showHighlightOnFocus
    }    
    set {
      _showHighlightOnFocus = newValue
      highlightState!.showOnFocusChanged()
    }
  }

  public var hoverHighlightFadeDurationMs: Int?
  public private(set) var observers: [InkDropObserver]
  
  fileprivate var highlightState: HighlightState? {
    get {
      return _highlightState
    }
    set {
      exitHighlightState()
      _highlightState = newValue
      if let state = _highlightState {
         state.enter()
      }
    }
  }
  
  fileprivate var shouldHighlight: Bool {
    return shouldHighlightBasedOnFocus || (showHighlightOnHover && isHovered)
  }

  fileprivate var shouldHighlightBasedOnFocus: Bool {
     return showHighlightOnFocus && isFocused
  }
  
  fileprivate weak var inkDropHost: InkDropHost?
  fileprivate var rootLayer: Layer
  fileprivate var rootLayerAddedToHost: Bool
  fileprivate var highlight: InkDropHighlight?
  fileprivate var inkDropRipple: InkDropRipple?
  fileprivate var highlightStateFactory: HighlightStateFactory!
  fileprivate var exitingHighlightState: Bool
  fileprivate var _showHighlightOnHover: Bool
  fileprivate var _showHighlightOnFocus: Bool
  fileprivate var _highlightState: HighlightState?
  
  public init(inkDropHost: InkDropHost, hostSize: IntSize) {

    self.inkDropHost = inkDropHost
    rootLayer = try! Layer(type: .None)//.NotDrawn)
    rootLayerAddedToHost = false
    _showHighlightOnHover = true
    _showHighlightOnFocus = false
    isHovered = false
    isFocused = false
    exitingHighlightState = false
    rootLayer.bounds = IntRect(size: hostSize)
    autoHighlightMode = AutoHighlightMode.None
    rootLayer.name = "InkDropImpl:RootLayer"
    observers = []
    highlightStateFactory = HighlightStateFactory(highlightMode: AutoHighlightMode.None, inkDrop: self)
  }

  deinit {
    highlightState = DestroyingHighlightState()

    // Explicitly destroy the InkDropRipple so that this still exists if
    // views::InkDropRippleObserver methods are called on this.
    destroyInkDropRipple()
    destroyInkDropHighlight()
  }

  public func addObserver(observer: InkDropObserver) {
    observers.append(observer)
  }
  
  public func removeObserver(observer: InkDropObserver) {
    for (i, elem) in observers.enumerated() {
      if observer === elem {
        observers.remove(at: i)  
        break
      }
    }
  }
  
  public func notifyInkDropAnimationStarted() {
    for observer in observers {
      observer.inkDropAnimationStarted()
    }
  }
  
  public func notifyInkDropRippleAnimationEnded(state: InkDropState) {
    for observer in observers {
      observer.inkDropRippleAnimationEnded(state: state)
    }
  }

  public func hostSizeChanged(size newSize: IntSize) {
    rootLayer.bounds = IntRect(size: newSize)
    if let ripple = inkDropRipple {
      ripple.hostSizeChanged(size: newSize)
    }
  }
  
  public func animateToState(state inkDropState: InkDropState) {
    if inkDropState == InkDropState.Hidden &&
          targetInkDropState == InkDropState.Hidden {
      return
    }

    destroyHiddenTargetedAnimations()
    if inkDropRipple == nil {
      createInkDropRipple()
    }
    inkDropRipple!.animateToState(inkDropState)
  }
  
  public func setHoverHighlightFadeDuration(miliseconds: Int) {
    hoverHighlightFadeDurationMs = miliseconds
  }
  
  public func useDefaultHoverHighlightFadeDuration() {
    hoverHighlightFadeDurationMs = nil
  }
  
  public func snapToActivated() {
    destroyHiddenTargetedAnimations()
    if inkDropRipple == nil {
      createInkDropRipple()
    }
    inkDropRipple!.snapToActivated()
  }
  
  public func snapToHidden() {
    destroyHiddenTargetedAnimations()
    guard let ripple = inkDropRipple else {
      return
    }
    ripple.snapToHidden()
  }
   // Destroys |ink_drop_ripple_| if it's targeted to the HIDDEN state.
  fileprivate func destroyHiddenTargetedAnimations() {
    if let ripple = inkDropRipple  {
      if ripple.targetInkDropState == InkDropState.Hidden || 
        shouldAnimateToHidden(state: ripple.targetInkDropState) {
        destroyInkDropRipple()
      }
    }
  }

  // Creates a new InkDropRipple and sets it to |ink_drop_ripple_|. If
  // |ink_drop_ripple_| wasn't null then it will be destroyed using
  // DestroyInkDropRipple().
  fileprivate func createInkDropRipple() {
    destroyInkDropRipple()
    inkDropRipple = inkDropHost!.createInkDropRipple()
    inkDropRipple!.observer = self
    rootLayer.add(child: inkDropRipple!.rootLayer)
    addRootLayerToHostIfNeeded()
  }

  // Destroys the current |ink_drop_ripple_|.
  fileprivate func destroyInkDropRipple() {
    guard let ripple = inkDropRipple else {
      return
    }
    rootLayer.remove(child: ripple.rootLayer)
    inkDropRipple = nil
    removeRootLayerFromHostIfNeeded()
  }

  // Creates a new InkDropHighlight and assigns it to |highlight_|. If
  // |highlight_| wasn't null then it will be destroyed using
  // DestroyInkDropHighlight().
  fileprivate func createInkDropHighlight() {
    destroyInkDropHighlight()

    highlight = inkDropHost!.createInkDropHighlight()
    highlight!.observer = self
    rootLayer.add(child: highlight!.layer)
    addRootLayerToHostIfNeeded()
  }

  // Destroys the current |highlight_|.
  fileprivate func destroyInkDropHighlight() {
    guard let hl = highlight else {
      return
    }
    rootLayer.remove(child: hl.layer)
    hl.observer = nil
    highlight = nil
    removeRootLayerFromHostIfNeeded()
  }

  // Adds the |root_layer_| to the |ink_drop_host_| if it hasn't already been
  // added.
  fileprivate func addRootLayerToHostIfNeeded() {
    if !rootLayerAddedToHost {
      rootLayerAddedToHost  = true
      inkDropHost!.addInkDropLayer(layer: rootLayer)
    }
  }

  // Removes the |root_layer_| from the |ink_drop_host_| if no ink drop ripple
  // or highlight is active.
  fileprivate func removeRootLayerFromHostIfNeeded() {
    if rootLayerAddedToHost && highlight == nil && inkDropRipple == nil {
      rootLayerAddedToHost = false
      inkDropHost!.removeInkDropLayer(layer: rootLayer)
    }
  }


  // Enables or disables the highlight state based on |should_highlight| and if
  // an animation is triggered it will be scheduled to have the given
  // |animation_duration|. If |explode| is true the highlight will expand as it
  // fades out. |explode| is ignored when |should_higlight| is true.
  fileprivate func setHighlight(
                    shouldHighlight: Bool,
                    animationDuration: TimeDelta,
                    explode: Bool) {
    if isHighlightFadingInOrVisible == shouldHighlight {
      return
    }

    if shouldHighlight {
      createInkDropHighlight()
      highlight!.fadeIn(duration: animationDuration)
    } else {
      highlight!.fadeOut(duration: animationDuration, explode: explode)
    }
  }

  // Exits the current |highlight_state_| and sets it to null. Ensures state
  // transitions are not triggered during HighlightStatae::Exit() calls on debug
  // builds.
  fileprivate func exitHighlightState() {
    if let hs = highlightState {
      exitingHighlightState = true
      hs.exit()
    }
    highlightState = nil
    exitingHighlightState = false
  }
}

extension InkDropImpl : InkDropRippleObserver {
  
  public func animationStarted(inkDropState: InkDropState) {
    highlightState!.animationStarted(state: inkDropState)
    notifyInkDropAnimationStarted()
  }
  
  public func animationEnded(inkDropState: InkDropState,
                             reason: InkDropAnimationEndedReason) {
    
    highlightState!.animationEnded(state: inkDropState, reason: reason)
    notifyInkDropRippleAnimationEnded(state: inkDropState)
    
    if reason != InkDropAnimationEndedReason.Success {
      return
    }
    
    guard let ripple = inkDropRipple else {
      return
    }
   
    if shouldAnimateToHidden(state: inkDropState) {
      ripple.animateToState(InkDropState.Hidden)
    } else if inkDropState == InkDropState.Hidden {
      // TODO(bruthig): Investigate whether creating and destroying
      // InkDropRipples is expensive and consider creating an
      // InkDropRipplePool. See www.crbug.com/522175.
      destroyInkDropRipple()
    }
  }

}

extension InkDropImpl : InkDropHighlightObserver {
  
  public func animationStarted(animationType: InkDropHighlight.AnimationType) {
    notifyInkDropAnimationStarted()
  }
  
  public func animationEnded(animationType: InkDropHighlight.AnimationType, reason: InkDropAnimationEndedReason) {
    if animationType == InkDropHighlight.AnimationType.FadeOut && reason == InkDropAnimationEndedReason.Success {
      destroyInkDropHighlight()
    }
  }
}

fileprivate let kHighlightFadeInOnHoverChangeDurationMs: Int = 250
fileprivate let kHighlightFadeOutOnHoverChangeDurationMs: Int = 250

fileprivate let kHighlightFadeInOnFocusChangeDurationMs: Int = 0
fileprivate let kHighlightFadeOutOnFocusChangeDurationMs: Int = 0

fileprivate let kHighlightFadeInOnRippleHidingDurationMs: Int = 250
fileprivate let kHighlightFadeOutOnRippleShowingDurationMs: Int = 120

fileprivate let kHighlightFadeInOnRippleShowingDurationMs: Int = 250
fileprivate let kHighlightFadeOutOnRippleHidingDurationMs: Int = 120

fileprivate let kHoverFadeInAfterRippleDelayMs: Int = 1000

fileprivate func shouldAnimateToHidden(state: InkDropState) -> Bool {
  switch state {
    case .ActionTriggered, .AlternateActionTriggered, .Deactivated:
      return true
    default:
      return false
  }
}

internal protocol HighlightState {

  var stateFactory: HighlightStateFactory { get }
  var inkDrop: InkDropImpl? { get }

  func enter()
  func exit()
  func showOnHoverChanged()
  func onHoverChanged()
  func showOnFocusChanged()
  func onFocusChanged()
  func animationStarted(state: InkDropState)
  func animationEnded(state: InkDropState,
                      reason: InkDropAnimationEndedReason)
}

internal class DestroyingHighlightState : HighlightState {
  public var stateFactory: HighlightStateFactory { return HighlightStateFactory(highlightMode: .None, inkDrop: nil) }
  public var inkDrop: InkDropImpl? { return nil }

  init() {}
  public func enter() {}
  public func showOnHoverChanged() {}
  public func onHoverChanged() {}
  public func showOnFocusChanged() {}
  public func onFocusChanged() {}
  public func animationStarted(state: InkDropState) {}
  public func animationEnded(state: InkDropState,
                            reason: InkDropAnimationEndedReason) {}
}

internal class NoAutoHighlightHiddenState : HighlightState {

  public private(set) var stateFactory: HighlightStateFactory
  public private(set) var inkDrop: InkDropImpl? 
  var animationDuration: TimeDelta
  var explode: Bool

  init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {
    self.stateFactory = stateFactory
    self.animationDuration = animationDuration
    self.explode = explode
  }

  public func enter() {
    if let inkdrop = inkDrop {
      inkdrop.setHighlight(shouldHighlight: false, animationDuration: animationDuration, explode: explode)
    }
  }

  public func showOnHoverChanged() {
    if let milis = inkDrop?.hoverHighlightFadeDurationMs {
      handleHoverAndFocusChangeChanges(duration: milis)
    } else {
      handleHoverAndFocusChangeChanges(duration: kHighlightFadeInOnHoverChangeDurationMs)
    }
  }

  public func onHoverChanged() {
    if let milis = inkDrop?.hoverHighlightFadeDurationMs {
      handleHoverAndFocusChangeChanges(duration: milis)  
    } else {
      handleHoverAndFocusChangeChanges(duration: kHighlightFadeInOnHoverChangeDurationMs)
    }
  }

  public func showOnFocusChanged() {
    handleHoverAndFocusChangeChanges(duration: kHighlightFadeInOnFocusChangeDurationMs)
  }

  public func onFocusChanged() {
    handleHoverAndFocusChangeChanges(duration: kHighlightFadeInOnFocusChangeDurationMs)
  }

  public func animationStarted(state: InkDropState) {}
  public func animationEnded(state: InkDropState,
                            reason: InkDropAnimationEndedReason) {}

  func handleHoverAndFocusChangeChanges(duration animationDurationMs: Int) {
    if let inkdrop = inkDrop, inkdrop.shouldHighlight {
        inkdrop.highlightState = stateFactory.createVisibleState(
          animationDuration: TimeDelta.from(milliseconds: Int64(animationDurationMs)), 
          explode: false)
    }
  }
}

internal class NoAutoHighlightVisibleState : HighlightState {

  public private(set) var stateFactory: HighlightStateFactory
  public private(set) var inkDrop: InkDropImpl? 
  var animationDuration: TimeDelta
  var explode: Bool

  init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {
    self.stateFactory =  stateFactory
    self.animationDuration = animationDuration
    self.explode = explode
  }

  public func enter() {
    inkDrop!.setHighlight(shouldHighlight: true, animationDuration: animationDuration, explode: explode)
  }

  public func exit() {}
  public func showOnHoverChanged() {
    if let m = inkDrop?.hoverHighlightFadeDurationMs {
      handleHoverAndFocusChangeChanges(animationDurationMs: m)  
    } else {
      handleHoverAndFocusChangeChanges(animationDurationMs: kHighlightFadeOutOnHoverChangeDurationMs)
    }
  }
  public func onHoverChanged() {
    if let m = inkDrop?.hoverHighlightFadeDurationMs {
      handleHoverAndFocusChangeChanges(animationDurationMs: m)
    } else {
      handleHoverAndFocusChangeChanges(animationDurationMs: kHighlightFadeOutOnHoverChangeDurationMs)
    }
    
  }
  public func showOnFocusChanged() {
    handleHoverAndFocusChangeChanges(animationDurationMs: kHighlightFadeOutOnFocusChangeDurationMs)
  }

  public func onFocusChanged() {
    handleHoverAndFocusChangeChanges(animationDurationMs: kHighlightFadeOutOnFocusChangeDurationMs)
  }

  public func animationStarted(state: InkDropState) {}
  public func animationEnded(state: InkDropState,
                            reason: InkDropAnimationEndedReason) {}

  func handleHoverAndFocusChangeChanges(animationDurationMs: Int) {
    if inkDrop!.shouldHighlight {
        inkDrop!.highlightState = stateFactory.createHiddenState(
        animationDuration: TimeDelta.from(milliseconds: Int64(animationDurationMs)), explode: false)
    }
  }                           
}

internal class HideHighlightOnRippleHiddenState: NoAutoHighlightHiddenState {
  var highlightAfterRippleTimer: Timer?

  override init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {

    super.init(stateFactory: stateFactory,
              animationDuration: animationDuration,
              explode: explode)
  }

  public override func showOnHoverChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.showOnHoverChanged();
  }

  public override func onHoverChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.onHoverChanged();
  }

  public override func showOnFocusChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.showOnFocusChanged()
  }

  public override func onFocusChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.onFocusChanged()
  }

  public override func animationStarted(state inkDropState: InkDropState) {
    if inkDropState == InkDropState.Deactivated &&
        inkDrop!.shouldHighlightBasedOnFocus {
      if let ripple = inkDrop!.inkDropRipple {
        ripple.snapToHidden() 
      }
    
      inkDrop!.highlightState = stateFactory.createVisibleState(animationDuration: TimeDelta(), explode: false)
    }
  }

  public override func animationEnded(state inkDropState: InkDropState,
                            reason: InkDropAnimationEndedReason) {
    if inkDropState == InkDropState.Hidden {
      // Re-highlight, as necessary. For hover, there's a delay; for focus, jump
      // straight into the animation.
      if inkDrop!.shouldHighlightBasedOnFocus {
        inkDrop!.highlightState = 
          stateFactory.createVisibleState(animationDuration: TimeDelta(), explode:  false)
        return
      } else {
        startHighlightAfterRippleTimer()
      }
    }
  }

  func startHighlightAfterRippleTimer() {
    highlightAfterRippleTimer = OneShotTimer()
    highlightAfterRippleTimer!.start(
        delay: TimeDelta.from(milliseconds: Int64(kHoverFadeInAfterRippleDelayMs)),
        {
          self.highlightAfterRippleTimerFired()
        })
  }

  func highlightAfterRippleTimerFired() {
    highlightAfterRippleTimer = nil
    if inkDrop!.targetInkDropState == InkDropState.Hidden && inkDrop!.shouldHighlight {
      inkDrop!.highlightState = stateFactory.createVisibleState(
          animationDuration: TimeDelta.from(milliseconds:
             Int64(kHighlightFadeInOnRippleHidingDurationMs)),
          explode: true)
    }
  }
}

internal class HideHighlightOnRippleVisibleState : NoAutoHighlightVisibleState {

  override init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {

    super.init(stateFactory: stateFactory,
              animationDuration: animationDuration,
              explode: explode)     
  }

  public override func animationStarted(state inkDropState: InkDropState) {}
}

internal class ShowHighlightOnRippleHiddenState : NoAutoHighlightHiddenState {

  override init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {
    super.init(stateFactory: stateFactory,
              animationDuration: animationDuration,
              explode: explode)
  }

  public override func animationStarted(state inkDropState: InkDropState) {  
    if inkDropState != InkDropState.Hidden {
      inkDrop!.highlightState = stateFactory.createVisibleState(
          animationDuration: TimeDelta.from(milliseconds:
              Int64(kHighlightFadeInOnRippleShowingDurationMs)), explode:  false)
    }
  }
}

internal class ShowHighlightOnRippleVisibleState : NoAutoHighlightVisibleState {

  override init(stateFactory: HighlightStateFactory,
      animationDuration: TimeDelta,
      explode: Bool) {
    super.init(stateFactory: stateFactory,
              animationDuration: animationDuration,
              explode: explode)
  }

  public override func showOnHoverChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.showOnHoverChanged()
  }

  public override func onHoverChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.onHoverChanged()
  }

  public override func showOnFocusChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.showOnFocusChanged()
  }

  public override func onFocusChanged() {
    if inkDrop!.targetInkDropState != InkDropState.Hidden {
      return
    }
    super.onFocusChanged()
  }

  public override func animationStarted(state inkDropState: InkDropState) {
    if inkDropState == InkDropState.Hidden && !inkDrop!.shouldHighlight {
        inkDrop!.highlightState = stateFactory.createHiddenState(
          animationDuration: TimeDelta.from(milliseconds:
            Int64(kHighlightFadeOutOnRippleHidingDurationMs)), explode: false)
    }
  }
}

internal class HighlightStateFactory {

  public var highlightMode: AutoHighlightMode
  public weak var inkDrop: InkDropImpl?

  public init(highlightMode: AutoHighlightMode,
              inkDrop: InkDropImpl?) {
    self.highlightMode = highlightMode
    self.inkDrop = inkDrop
  }

  public func createStartState() -> HighlightState? {
    switch highlightMode {
      case AutoHighlightMode.None:
        return NoAutoHighlightHiddenState(
            stateFactory: self, animationDuration: TimeDelta(), explode: false)
      case AutoHighlightMode.HideOnRipple:
        return HideHighlightOnRippleHiddenState(
            stateFactory: self, animationDuration: TimeDelta(), explode: false)
      case AutoHighlightMode.ShowOnRipple:
        return ShowHighlightOnRippleHiddenState(
            stateFactory: self, animationDuration: TimeDelta(), explode: false)
    }
  }

  public func createHiddenState(
      animationDuration: TimeDelta,
      explode: Bool) -> HighlightState? {
    switch highlightMode {
      case AutoHighlightMode.None:
        return NoAutoHighlightHiddenState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
      case AutoHighlightMode.HideOnRipple:
        return HideHighlightOnRippleHiddenState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
      case AutoHighlightMode.ShowOnRipple:
        return ShowHighlightOnRippleHiddenState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
    }
  }

  public func createVisibleState(
      animationDuration: TimeDelta,
      explode: Bool) -> HighlightState? {
    switch highlightMode {
      case AutoHighlightMode.None:
        return NoAutoHighlightVisibleState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
      case AutoHighlightMode.HideOnRipple:
        return HideHighlightOnRippleVisibleState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
      case AutoHighlightMode.ShowOnRipple:
        return ShowHighlightOnRippleVisibleState(
          stateFactory: self, animationDuration: animationDuration, explode: explode)
    }
  }
}