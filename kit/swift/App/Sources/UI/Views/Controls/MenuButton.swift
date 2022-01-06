// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

// TODO: know who use this
public let defaultMenuOffsetX: Int = -2
public let defaultMenuOffsetY: Int = -4

// TODO: implement
fileprivate let IDR_MENU_DROPARROW = 1000

public protocol MenuButtonListener : ButtonListener {

  func onMenuButtonClicked(source: MenuButton,
                           point: IntPoint,
                           event: Graphics.Event)

}

public class MenuButton : LabelButton {
  
  public class PressedLock {
    
    public weak var button: MenuButton?
    
    public init(button: MenuButton?,
      isSiblingMenuShow: Bool,
      event: LocatedEvent?) {
      self.button = button
      if let b = self.button {
        b.incrementPressedLocked(snapInkDropToActivated: isSiblingMenuShow, event: event)
      }
    }

    public convenience init(button: MenuButton?) {
      self.init(button: button, isSiblingMenuShow: false, event: nil)
    }

    deinit {
      if let b = button {
        b.decrementPressedLocked()
      }
    }
  }

  public static let menuMarkerPaddingLeft: Int = 3
  public static let menuMarkerPaddingRight: Int = -1
  public static let minimumMsBetweenButtonClicks: Int = 100

  public override var className: String {
    return "MenuButton"
  }

  public override var childAreaBounds: IntRect {
    var s = size

    if showMenuMarker {
      s.width = s.width - Int(menuMarker!.width) - MenuButton.menuMarkerPaddingLeft - MenuButton.menuMarkerPaddingRight
    }

    return IntRect(size: s)
  }

  internal var maximumScreenXCoordinate: Int {
    guard let w = widget else {
      assert(false)
      return 0
    }

    let monitorBounds = w.workAreaBoundsInScreen
    return monitorBounds.right - 1
  }

  public var menuMarker: ImageSkia?
  public private(set) var showMenuMarker: Bool
  public var menuOffset: IntPoint
  
  fileprivate var pressedLockCount: Int = 0
  fileprivate var incrementPressedLockCalled: Bool?
  fileprivate var shouldDisableAfterPress: Bool = false
  fileprivate var menuClosedTime: TimeTicks

  public init(text: String,
              listener: MenuButtonListener?,
              showMenuMarker: Bool) {
    
    menuOffset = IntPoint(x: defaultMenuOffsetX, y: defaultMenuOffsetY)
    
    self.showMenuMarker = showMenuMarker
    
    menuMarker = ResourceBundle.getImage(IDR_MENU_DROPARROW)
    
    menuClosedTime = TimeTicks()
    
    super.init(listener: listener, text: text)
    
    horizontalAlignment = .AlignLeft
  }

  public func activate(event: Graphics.Event) -> Bool {
    if let l = listener as? MenuButtonListener {
      let lb = localBounds

      // The position of the menu depends on whether or not the locale is
      // right-to-left.
      var menuPosition = IntPoint(x: lb.right, y: lb.bottom)
      if i18n.isRTL() {
        menuPosition.x = lb.x
      }

      View.convertPointToScreen(src: self, point: &menuPosition)
      if i18n.isRTL() {
        menuPosition.offset(x: -menuOffset.x, y: menuOffset.y)
      } else {
        menuPosition.offset(x: menuOffset.x, y: menuOffset.y)
      }

      if maximumScreenXCoordinate <= menuPosition.x {
        menuPosition.x = maximumScreenXCoordinate - 1
      }   
      // We're about to show the menu from a mouse press. By showing from the
      // mouse press event we block RootView in mouse dispatching. This also
      // appears to cause RootView to get a mouse pressed BEFORE the mouse
      // release is seen, which means RootView sends us another mouse press no
      // matter where the user pressed. To force RootView to recalculate the
      // mouse target during the mouse press we explicitly set the mouse handler
      // to NULL.
      if let rootView = widget?.rootView {
        rootView.setMouseHandler(handler: nil)
      }
      //assert(incrementPressedLockCalled == nil)
      // Observe if IncrementPressedLocked() was called so we can trigger the
      // correct ink drop animations.
      let increment = false
      incrementPressedLockCalled = increment

      // We don't set our state here. It's handled in the MenuController code or
      // by our click listener.
      l.onMenuButtonClicked(source: self, point: menuPosition, event: event)

      incrementPressedLockCalled = nil

      if !increment && pressedLockCount == 0 {
        animateInkDrop(state: InkDropState.ActionTriggered, event: LocatedEvent.fromIfValid(event))
      }

      // We must return false here so that the RootView does not get stuck
      // sending all mouse pressed events to us instead of the appropriate
      // target.
      return false
    }

    animateInkDrop(state: InkDropState.Hidden, event: LocatedEvent.fromIfValid(event))
    
    return true
  }

  public func isTriggerableEventType(event: Graphics.Event) -> Bool  {
    if event.isMouseEvent {
      let mouseEvent = event as! MouseEvent
      // Active on left mouse button only, to prevent a menu from being activated
      // when a right-click would also activate a context menu.
      if !mouseEvent.onlyLeftMouseButton {
        return false
      }
      // If dragging is supported activate on release, otherwise activate on
      // pressed.
      let activeOn: EventType =
          getDragOperations(pressPoint: mouseEvent.location) == DragOperation.DragNone
              ? .MousePressed
              : .MouseReleased
      return event.type == activeOn
    }

    return event.type == .GestureTap
  }

  open override func calculatePreferredSize() -> IntSize {
    var prefsize = super.calculatePreferredSize()
    if showMenuMarker {
      prefsize.enlarge(width: Int(menuMarker!.width) + MenuButton.menuMarkerPaddingLeft + MenuButton.menuMarkerPaddingRight, height: 0)
    }
    return prefsize
  } 

  open override func onMousePressed(event: MouseEvent) -> Bool {
    if requestFocusOnPress {
      requestFocus()
    }
    
    if state != .Disabled && hitTest(point:event.location) &&
      isTriggerableEventType(event: event) {
    
      if isTriggerableEvent(event: event) {
        return activate(event: event)
      }
    }
    return true
  }

  open override func onMouseReleased(event: MouseEvent) {

    if state != .Disabled && isTriggerableEvent(event: event) &&
        hitTest(point:event.location) && !inDrag() {
      let _ = activate(event: event)
    } else {
      animateInkDrop(state: InkDropState.Hidden, event: event)
      super.onMouseReleased(event: event)
    }
  }

  open override func onMouseEntered(event: MouseEvent) {
    if pressedLockCount == 0 {  // Ignore mouse movement if state is locked.
      super.onMouseEntered(event: event)
    }
  }
  
  open override func onMouseExited(event: MouseEvent) {
    if pressedLockCount == 0 { // Ignore mouse movement if state is locked.
      super.onMouseExited(event: event)
    }
  }
  
  open override func onMouseMoved(event: MouseEvent) {
    if pressedLockCount == 0 {  // Ignore mouse movement if state is locked.
      super.onMouseMoved(event: event)
    }
  }
  
  open override func onGestureEvent(event: inout GestureEvent) {
    if state != .Disabled {
      if isTriggerableEvent(event: event) && !activate(event: event) {
        // When |Activate()| returns |false|, it means the click was handled by
        // a button listener and has handled the gesture event. So, there is no
        // need to further process the gesture event here. However, if the
        // listener didn't run menu code, we should make sure to reset our state.
        if state == .Hovered {
          state = .Normal
        }
        return
      }
      if event.type == .GestureTapDown {
        event.handled = true
        if pressedLockCount == 0 {
          state = .Hovered
        }
      } else if state == .Hovered &&
                (event.type == .GestureTapCancel || event.type == .GestureEnd) &&
                pressedLockCount == 0 {
        state = .Normal
      }
    }
    super.onGestureEvent(event: &event)
  }
 
  open override func onKeyPressed(event: KeyEvent) -> Bool {
    switch event.keyCode {
      case .KeySpace:
        // Alt-space on windows should show the window menu.
        if event.isAltDown {
          break
        }
        fallthrough
      case .KeyReturn:
        fallthrough
      case .KeyUp:
        fallthrough
      case .KeyDown:
        // WARNING: we may have been deleted by the time Activate returns.
        let _ = activate(event: event)
        // This is to prevent the keyboard event from being dispatched twice.  If
        // the keyboard event is not handled, we pass it to the default handler
        // which dispatches the event back to us causing the menu to get displayed
        // again. Return true to prevent this.
        return true
      default:
        break
    }
    return false
  }

  open override func onKeyReleased(event: KeyEvent) -> Bool {
    return false
  }

  // open override func getAccessibleNodeData(nodeData: AXNodeData) {
  // }

  internal override func isTriggerableEvent(event: Graphics.Event) -> Bool {
    if !isTriggerableEventType(event: event) {
      return false
    }

    let delta: TimeDelta = TimeTicks.now - menuClosedTime
    if Int(delta.milliseconds) < MenuButton.minimumMsBetweenButtonClicks {
      return false  // Not enough time since the menu closed.
    }

    return true
  }

  internal override func shouldEnterPushedState(event: Graphics.Event) -> Bool {
    return isTriggerableEventType(event: event)
  }

  internal override func stateChanged(oldState: State) {
     if pressedLockCount == 0 {
       // The button's state was changed while it was supposed to be locked in a
      // pressed state. This shouldn't happen, but conceivably could if a caller
      // tries to switch from enabled to disabled or vice versa while the button
      // is pressed.
      if state == .Normal {
        shouldDisableAfterPress = false
      } else if state == .Disabled {
        shouldDisableAfterPress = true
      }
    } else {
      super.stateChanged(oldState: oldState)
    }
  }

  internal override func notifyClick(event: Graphics.Event) {
    let _ = activate(event: event)
  }

  internal override func paintButtonContents(canvas: Canvas) {
    if showMenuMarker {
      paintMenuMarker(canvas: canvas)
    }
  }

  internal func paintMenuMarker(canvas: Canvas) {
    guard let marker = menuMarker else {
      return // should not happen
    }
    // Using the Views mirroring infrastructure incorrectly flips icon content.
    // Instead, manually mirror the position of the down arrow.
    var arrowBounds = IntRect(x: width - Int(insets.right) - Int(marker.width) - MenuButton.menuMarkerPaddingRight,
                              y: height / 2 - Int(marker.height / 2),
                              width: Int(marker.width),
                              height: Int(marker.height))
    arrowBounds.x = getMirroredXForRect(rect: arrowBounds)
    canvas.drawImageInt(image: marker, x: arrowBounds.x, y: arrowBounds.y)
  }

  internal func incrementPressedLocked(snapInkDropToActivated: Bool,
                                       event: LocatedEvent?) {
    pressedLockCount += 1
    if incrementPressedLockCalled != nil {
      incrementPressedLockCalled = true
    }
    shouldDisableAfterPress = state == .Disabled
    if state != .Pressed {
      if inkDrop != nil && snapInkDropToActivated {
        inkDrop!.snapToActivated()
      } else {
        animateInkDrop(state: .Activated, event: event)
      }
    }
    state = .Pressed
    if let inkdrop = inkDrop {
      inkdrop.isHovered = false
    }
  }
 
  internal func decrementPressedLocked() {
    pressedLockCount -= 1
    //DCHECK_GE(pressed_lock_count_, 0);

    // If this was the last lock, manually reset state to the desired state.
    if pressedLockCount == 0 {
      menuClosedTime = TimeTicks.now
      var desiredState = Button.State.Normal
      if shouldDisableAfterPress {
        desiredState = .Disabled
        shouldDisableAfterPress = false
      } else if shouldEnterHoveredState {
        desiredState = .Hovered
        if let inkdrop = inkDrop {
          inkdrop.isHovered = true
        }
      }
      
      state = desiredState
      // The widget may be null during shutdown. If so, it doesn't make sense to
      // try to add an ink drop effect.
      if widget != nil && state != .Pressed {
        animateInkDrop(state: InkDropState.Deactivated, event: nil)
      }
    }
  }
}