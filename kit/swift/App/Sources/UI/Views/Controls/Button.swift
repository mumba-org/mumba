// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol ButtonListener {
  func buttonPressed(sender: Button, event: Event)
}

internal let hoverFadeDurationMs: Int = 150

public class Button : InkDropHostView {

  public enum State : Int {
    case Normal   = 0
    case Hovered  = 1
    case Pressed  = 2
    case Disabled = 3

    static let count: Int = 4
  }

  public enum Style {
    case Button
    case TextButton
  }

  public enum NotifyAction {
    case NotifyOnPress
    case NotifyOnRelease
  }

  public enum KeyClickAction {
    case ClickOnKeyPress
    case ClickOnKeyRelease
    case ClickNone
  }

  public override var className: String {
    return "Button"
  }

  public var state: State {
    get {
      return _state
    }
    set {

      guard newValue != _state else {
        return
      }

      if animateOnStateChange && (!isThrobbing || !hoverAnimation.isAnimating) {
        
        isThrobbing = false
        
        if newValue == .Hovered && newValue == .Normal {
          hoverAnimation.hide()
        } else if newValue != .Hovered {
          hoverAnimation.reset()
        } else if newValue == .Normal {
          hoverAnimation.show()
        } else {
          hoverAnimation.reset(value: 1)
        }
      }

      let oldState = _state
      _state = newValue
      stateChanged(oldState: oldState)
      schedulePaint()
    }
  }

  public var isHotTracked: Bool {
    get {
      return state == .Hovered
    }
    set {
      if state != .Disabled {
        state = newValue ? State.Hovered : State.Normal
      }

      // if newValue {
      //   notifyAccessibilityEvent(AXEvent.kHover, true)
      // }
    }
  }

  internal override var inkDropBaseColor: Color {
    return Colors.placeholderColor
  }

  internal var shouldUpdateInkDropOnClickCanceled: Bool {
    return true
  }
  
  internal var shouldEnterHoveredState: Bool {
    
    if !isVisible {
      return false
    }

    var checkMousePosition = true
    
    if let nativeWindow = widget?.window {//widget?.nativeWindow {
      let rootWindow = nativeWindow.rootWindow
      var captureWindow: Window?
      
      if let captureClient = rootWindow?.captureClient {//client.getCaptureClient(rootWindow) {
        captureWindow = captureClient.globalCaptureWindow
      }
      
      checkMousePosition = captureWindow == nil || captureWindow === rootWindow
    }
    
    return checkMousePosition && isMouseHovered
  }
  
  
  public var tag: Int
  public var triggerableEventFlags: EventFlags = EventFlags.LeftMouseButton
  public var listener: ButtonListener?
  public var requestFocusOnPress: Bool = false
  public var animateOnStateChange: Bool = false
  public var focusPainter: Painter?
  public var hideInkDropWhenShowingContextMenu: Bool = true
  public var hasInkDropActionOnClick: Bool = true
  public var accessibleName: String = String()
  //internal var focusBehavior: View.FocusBehavior 
  internal var hoverAnimation: ThrobAnimation!
  fileprivate var isThrobbing: Bool = false
  fileprivate var notifyAction: NotifyAction = NotifyAction.NotifyOnRelease
  fileprivate var _state: State
 
  var tooltipText: String
  
  public class func getButtonStateFrom(theme state: Theme.State) -> State {
    switch state {
      case .Disabled:  
        return State.Disabled
      case .Hovered:   
        return State.Hovered
      case .Normal:    
        return State.Normal
      case .Pressed:  
        return State.Pressed
    }
  }

  internal init(listener: ButtonListener?) {
    self.listener = listener
    tag = -1
    tooltipText = String()
    
    //setProperty(kIsButtonProperty, true)
     _state = State.Normal

    super.init()
    
    focusBehavior = FocusBehavior.accessibleOnly
    hoverAnimation = ThrobAnimation(target: self)
    hoverAnimation.slideDuration = hoverFadeDurationMs
  }

  public func setFocusForPlatform() {
    focusBehavior = FocusBehavior.always
  }

  public func startThrobbing(cyclesTilStop: Int) {
    if !animateOnStateChange {
      return
    }
    isThrobbing = true
    hoverAnimation.startThrobbing(cyclesTilStop: cyclesTilStop)
  }

  public func stopThrobbing() {
    if hoverAnimation.isAnimating {
      hoverAnimation.stop()
      schedulePaint()
    }
  }

  public func setAnimationDuration(duration: Int) {
    hoverAnimation.slideDuration = duration
  }

  open override func onEnabledChanged() {
    if isEnabled ? (state != .Disabled) : (state == .Disabled) {
      return
    }

    if isEnabled {
      state = shouldEnterHoveredState ? State.Hovered : State.Normal
      inkDrop!.isHovered = shouldEnterHoveredState
    } else {
      state = State.Disabled
      inkDrop!.isHovered = false
    }
  }
  
  open override func onMousePressed(event: MouseEvent) -> Bool {
    if state == .Disabled {
      return true
    }

    if state != .Pressed && shouldEnterPushedState(event: event) && hitTest(point:event.location) {
      state = .Pressed
      animateInkDrop(state: InkDropState.ActionPending, event: event)
    }
    
    requestFocusFromEvent()
    
    if isTriggerableEvent(event: event) && notifyAction == .NotifyOnPress {
      notifyClick(event: event)
      // NOTE: We may be deleted at this point (by the listener's notification
      // handler).
    }
    return true
  }

  open override func onMouseDragged(event: MouseEvent) -> Bool {
    if state != .Disabled  {
      let shouldEnterPushed = shouldEnterPushedState(event: event)
      let shouldShowPending =
          shouldEnterPushed && notifyAction == .NotifyOnRelease && !inDrag()
      if hitTest(point:event.location) {
        state = shouldEnterPushed ? .Pressed : .Hovered
        if shouldShowPending && inkDrop!.targetInkDropState == InkDropState.Hidden {
          animateInkDrop(state: InkDropState.ActionPending, event:  event)
        }
      } else {
        state = .Normal
        if shouldShowPending && inkDrop!.targetInkDropState == InkDropState.ActionPending {
          animateInkDrop(state: InkDropState.Hidden, event:  event)
        }
      }
    }
    return true
  }

  open override func onMouseReleased(event: MouseEvent) {
    if state != .Disabled  {
      if !hitTest(point:event.location) {
        state = .Normal
      } else {
        state = .Hovered
        if isTriggerableEvent(event: event) && notifyAction == .NotifyOnRelease {
          notifyClick(event: event)
          // NOTE: We may be deleted at this point (by the listener's notification
          // handler).
          return
        }
      }
    }
    if notifyAction == .NotifyOnRelease {
      onClickCanceled(event: event)
    }
  }

  open override func onMouseCaptureLost() {
    if state != .Disabled  {
      state = .Normal
    }
    animateInkDrop(state: InkDropState.Hidden, event: nil)
    inkDrop!.isHovered = false
    super.onMouseCaptureLost()
  }

  open override func onMouseMoved(event: MouseEvent) {
    if state != .Disabled {
      state = hitTest(point:event.location) ? .Hovered : .Normal
    }
  }

  open override func onMouseEntered(event: MouseEvent) {
    if state != .Disabled {
      state = .Hovered
    }
  }

  open override func onMouseExited(event: MouseEvent) {
    if state != .Disabled && !inDrag() {
      state = .Normal
    }
  }

  open override func onMouseWheel(event: MouseWheelEvent) -> Bool {
    return false
  }

  open override func onKeyPressed(event: KeyEvent) -> Bool {
    if state == .Disabled {
      return false
    }

    switch getKeyClickActionForEvent(event: event) {
      case KeyClickAction.ClickOnKeyRelease:
        state = .Pressed
        if inkDrop!.targetInkDropState != InkDropState.ActionPending {
          animateInkDrop(state: InkDropState.ActionPending, event: nil)
        }
        return true
      case KeyClickAction.ClickOnKeyPress:
        state = .Normal
        notifyClick(event: event)
        return true
      case KeyClickAction.ClickNone:
        return false
    }
  }

  open override func onKeyReleased(event: KeyEvent) -> Bool {
    let clickButton =
      state == .Pressed &&
      getKeyClickActionForEvent(event: event) == KeyClickAction.ClickOnKeyRelease
    
    if !clickButton {
      return false
    }

    state = .Normal
    notifyClick(event: event)
    return true
  }

  open override func onGestureEvent(event: inout GestureEvent) {
    
    if state == .Disabled {
      super.onGestureEvent(event: &event)
      return
    }

    if event.type == .GestureTap && isTriggerableEvent(event: event) {
      // Set the button state to hot and start the animation fully faded in. The
      // GESTURE_END event issued immediately after will set the state to
      // STATE_NORMAL beginning the fade out animation. See
      // http://crbug.com/131184.
      state = .Hovered
      hoverAnimation.reset(value: 1.0)
      notifyClick(event: event)
      event.stopPropagation()
    } else if event.type == .GestureTapDown && shouldEnterPushedState(event: event) {
      state = .Pressed
      requestFocusFromEvent()
      event.stopPropagation()
    } else if event.type == .GestureTapCancel || event.type == .GestureEnd {
      state = .Normal
    }

    if !event.handled {
      // super
      super.onGestureEvent(event: &event)
    }

  }

  open override func acceleratorPressed(accelerator: Accelerator) -> Bool {
    state = .Normal
    notifyClick(event: accelerator.toKeyEvent())
    return true
  }
  
  open override func skipDefaultKeyEventProcessing(event: KeyEvent) -> Bool {
    return getKeyClickActionForEvent(event: event) != KeyClickAction.ClickNone
  }
  
  public override func getTooltipText(p: IntPoint) -> String? {
    if tooltipText.count == 0 {
      return nil
    }

    return tooltipText
  }

  open override func showContextMenu(point p: IntPoint, sourceType: MenuSourceType) {
    if contextMenuController == nil {
      return
    }

    // We're about to show the context menu. Showing the context menu likely means
    // we won't get a mouse exited and reset state. Reset it now to be sure.
    if state != .Disabled {
      state = .Normal
    }
    
    if hideInkDropWhenShowingContextMenu {
      inkDrop!.isHovered = false
      animateInkDrop(state: InkDropState.Hidden, event: nil)
    }

    super.showContextMenu(point: p, sourceType: sourceType)
  }

  open override func onDragDone() {
    if state != .Disabled {
      state = .Normal
    }
    animateInkDrop(state: InkDropState.Hidden, event: nil)
  }
 
  open override func onPaint(canvas: Canvas) {
    super.onPaint(canvas: canvas)
    paintButtonContents(canvas: canvas)
    if let painter = focusPainter {
      PainterHelper.paintFocusPainter(view: self, canvas: canvas, focusPainter: painter)
    }
  }
  
  //override func getAccessibleNodeData(nodeData: AXNodeData) 
  
  open override func visibilityChanged(startingFrom: View, isVisible: Bool) {
    super.visibilityChanged(startingFrom: startingFrom, isVisible: isVisible)
    if state == .Disabled {
      return
    }
    state = isVisible && shouldEnterHoveredState ? .Hovered : .Normal
  }
  
  open override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if !details.isAdd && state != .Disabled && details.child === self {
      state = .Normal
    }
    super.viewHierarchyChanged(details: details)
  }

  open override func onFocus() {
    super.onFocus()
    if focusPainter != nil {
      schedulePaint()
    }
  }

  open override func onBlur() {
     // InkDropHostView.onBlur()
    if isHotTracked || state == .Pressed {
      state = .Normal
      if inkDrop!.targetInkDropState != InkDropState.Hidden {
        animateInkDrop(state: InkDropState.Hidden, event: nil)
      }
      // TODO(bruthig) : Fix Buttons to work well when multiple input
      // methods are interacting with a button. e.g. By animating to HIDDEN here
      // it is possible for a Mouse Release to trigger an action however there
      // would be no visual cue to the user that this will occur.
    }

    if focusPainter != nil {
      schedulePaint()
    }
  }

  public func setTooltipText(tooltipText: String) {
    self.tooltipText = tooltipText
    tooltipTextChanged()
  }

  public override func createInkDrop() -> InkDrop? {
    return nil
  }

  internal func getKeyClickActionForEvent(event: KeyEvent) -> KeyClickAction {
    if event.keyCode == .KeySpace {
      return PlatformStyle.keyClickActionOnSpace
    }
    
    if event.keyCode == .KeyReturn &&
      PlatformStyle.returnClicksFocusedControl {
      return .ClickOnKeyPress
    }
    
    return .ClickNone
  }

  internal func requestFocusFromEvent() {
    if requestFocusOnPress {
      requestFocus()
    }
  }

  internal func notifyClick(event: Event) {
    if hasInkDropActionOnClick {
      animateInkDrop(state: InkDropState.ActionTriggered,
                     event: LocatedEvent.fromIfValid(event))
    }
    
    if let l = listener {
      l.buttonPressed(sender: self, event: event)
    }
  }

  internal func onClickCanceled(event: Event) {
    if shouldUpdateInkDropOnClickCanceled {
      if inkDrop!.targetInkDropState == InkDropState.ActionPending ||
        inkDrop!.targetInkDropState == InkDropState.AlternateActionPending {
        animateInkDrop(state: InkDropState.Hidden,
                       event: LocatedEvent.fromIfValid(event))
      }
    }
  }

  internal func stateChanged(oldState: State) {}

  internal func isTriggerableEvent(event: Event) -> Bool {
     return event.type == .GestureTapDown ||
         event.type == .GestureTap ||
         (event.isMouseEvent && event.flags.contains(triggerableEventFlags))
  }

  internal func shouldEnterPushedState(event: Event) -> Bool {
     return isTriggerableEvent(event: event)
  }

  internal func paintButtonContents(canvas: Canvas) {}

}

extension Button : AnimationDelegate {
   
   public func animationProgressed(animation: Animation) {
     schedulePaint()
   }

}