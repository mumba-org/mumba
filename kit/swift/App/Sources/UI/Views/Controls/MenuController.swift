// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Platform

internal let dropBetweenPixels = 5

internal let minimumMsPressedToActivate: Int = 200
fileprivate let centeredContextMenuYOffset: Int = -15
fileprivate let menuSelectionHoldTimeMs: Int = minimumMsPressedToActivate
fileprivate let bubbleTipSizeLeftRight: Int = 12
fileprivate let bubbleTipSizeTopBottom: Int = 11
fileprivate let closeOnExitTime: Int = 1200
fileprivate let maximumLengthMovedToActivate: Float = 4.0
fileprivate let scrollTimerMS: Int = 30

public enum NotifyType {
    case NotifyDelegate
    case DontNotifyDelegate
}

public protocol MenuControllerDelegate : class {

  func onMenuClosed(type: NotifyType,
                    menu: MenuItemView?,
                    mouseEventFlags: Int)

  func siblingMenuCreated(menu: MenuItemView)  
}

public class MenuController : UIWidgetObserver {
  
  public enum ExitType {
    // Don't exit.
    case None

    // All menus, including nested, should be exited.
    case All

    // Only the outermost menu should be exited.
    case Outermost

    // This is set if the menu is being closed as the result of one of the menus
    // being destroyed.
    case Destroyed
  }

  public class var activeInstance: MenuController? {
    return _activeInstance
  }

  // Get the anchor position wich is used to show this menu.
  public var anchorPosition: MenuAnchorPosition { 
    return state.anchor 
  }
  // Controls behavior differences between a combobox and other types of menu
  // (like a context menu).
  public var isCombobox: Bool = false

  // Whether to use the touchable layout.
  public var useTouchableLayout: Bool = false

  // Owner of child windows.
  // WARNING: this may be NULL.
  public private(set) var owner: UIWidget?

    // Indicates what to exit.
  public private(set) var exitType: ExitType = ExitType.None

     // The timestamp of the event which closed the menu - or 0 otherwise.
  public private(set) var closingEventTime: TimeTicks = TimeTicks()
  
  public var inNestedRun: Bool { 
    return !menuStack.isEmpty 
  }

  public var canProcessInputEvents: Bool {
    return true
  }

  // True when drag operation is in progress.
  public private(set) var dragInProgress: Bool = false

  // True when the drag operation in progress was initiated by the
  // MenuController for a child MenuItemView (as opposed to initiated separately
  // by a child View).
  public private(set) var didInitiateDrag: Bool = false

  // Whether the menu |owner_| needs gesture events. When set to true, the menu
  // will preserve the gesture events of the |owner_| and MenuController will
  // forward the gesture events to |owner_| until no |ET_GESTURE_END| event is
  // captured.
  public var sendGestureEventsToOwner: Bool = false

  // If true, Run blocks. If false, Run doesn't block and this is used for
  // drag and drop. Note that the semantics for drag and drop are slightly
  // different: cancel timer is kicked off any time the drag moves outside the
  // menu, mouse events do nothing...
  public private(set) var isBlockingRun: Bool

  // If true, we're showing.
  fileprivate var showing: Bool = false

  // Whether we did a capture. We do a capture only if we're blocking and
  // the mouse was down when Run.
  fileprivate var didCapture: Bool = false

  // As the user drags the mouse around pending_state_ changes immediately.
  // When the user stops moving/dragging the mouse (or clicks the mouse)
  // pending_state_ is committed to state_, potentially resulting in
  // opening or closing submenus. This gives a slight delayed effect to
  // submenus as the user moves the mouse around. This is done so that as the
  // user moves the mouse all submenus don't immediately pop.
  fileprivate var pendingState: State = State()
  fileprivate var state: State = State()

  // If the user accepted the selection, this is the result.
  fileprivate var result: MenuItemView?

  // The event flags when the user selected the menu.
  fileprivate var acceptEventFlags: Int = 0

  // If not empty, it means we're nested. When Run is invoked from within
  // Run, the current state (state_) is pushed onto menu_stack_. This allows
  // MenuController to restore the state when the nested run returns.
  fileprivate typealias NestedState = (State, MenuButton.PressedLock)
  // using NestedState =
  //     std::pair<State, std::unique_ptr<MenuButton::PressedLock>>
  
  fileprivate var menuStack: Array<NestedState> = Array<NestedState>()

  // When Run is invoked during an active Run, it may be called from a separate
  // MenuControllerDelegate. If not empty it means we are nested, and the
  // stacked delegates should be notified instead of |delegate_|.
  //std::list<internal::MenuControllerDelegate*> delegate_stack_
  fileprivate var delegateStack: Array<MenuControllerDelegate> = Array<MenuControllerDelegate>()

  // As the mouse moves around submenus are not opened immediately. Instead
  // they open after this timer fires.
  fileprivate var showTimer: OneShotTimer = OneShotTimer()

  // Used to invoke CancelAll(). This is used during drag and drop to hide the
  // menu after the mouse moves out of the of the menu. This is necessitated by
  // the lack of an ability to detect when the drag has completed from the drop
  // side.
  fileprivate var cancelAllTimer: OneShotTimer = OneShotTimer()

  // Drop target.
  fileprivate var dropTarget: MenuItemView?
  
  fileprivate var dropPosition: DropPosition = DropPosition.DropUnknown

  // Indicates a possible drag operation.
  fileprivate var possibleDrag: Bool = false

  // Location the mouse was pressed at. Used to detect d&d.
  fileprivate var pressPoint: IntPoint = IntPoint()

  // We get a slew of drag updated messages as the mouse is over us. To avoid
  // continually processing whether we can drop, we cache the coordinates.
  fileprivate var validDropCoordinates: Bool = false
  fileprivate var dropPoint: IntPoint = IntPoint()
  fileprivate var lastDropOperation: Int = DropPosition.DropUnknown.rawValue

  // If true, we're in the middle of invoking ShowAt on a submenu.
  fileprivate var showingSubmenu: Bool = false

  // Task for scrolling the menu. If non-null indicates a scroll is currently
  // underway.
  fileprivate var scrollTask: MenuScrollTask?

  // The lock to keep the menu button pressed while a menu is visible.
  fileprivate var pressedLock: MenuButton.PressedLock?

  // ViewTracker used to store the View mouse drag events are forwarded to. See
  // UpdateActiveMouseView() for details.
  fileprivate var activeMouseViewTracker: ViewTracker = ViewTracker()

  // Current hot tracked child button if any.
  fileprivate var hotButton: Button?

  // Time when the menu is first shown.
  fileprivate var menuStartTime: TimeTicks = TimeTicks()

  // If a mouse press triggered this menu, this will have its location (in
  // screen coordinates). Otherwise this will be (0, 0).
  fileprivate var menuStartMousePressLoc: IntPoint = IntPoint()

  // Set to true if the menu item was selected by touch.
  fileprivate var itemSelectedByTouch: Bool = false

  // During mouse event handling, this is the RootView to forward mouse events
  // to. We need this, because if we forward one event to it (e.g., mouse
  // pressed), subsequent events (like dragging) should also go to it, even if
  // the mouse is no longer over the view.
  fileprivate var currentMouseEventTarget: MenuHostRootView?

  // A mask of the EventFlags for the mouse buttons currently pressed.
  fileprivate var currentMousePressedState: Int = 0

  fileprivate var menuPreTargetHandler: MenuPreTargetHandler?

  fileprivate weak var delegate: MenuControllerDelegate? 

  // The active instance.
  fileprivate static var _activeInstance: MenuController?
  

  internal init(blocking: Bool,
                delegate: MenuControllerDelegate) {
    self.isBlockingRun = blocking
    self.delegate = delegate
    delegateStack.append(delegate)
    MenuController._activeInstance = self
  }

  deinit {
    if let own = owner {
      own.removeObserver(self)
    }
    if MenuController._activeInstance === self {
      MenuController._activeInstance = nil
    }
    stopShowTimer()
    stopCancelAllTimer()
  }

  public func run(parent: UIWidget?,
    button: MenuButton?,
    root: MenuItemView,
    bounds: IntRect,
    position: MenuAnchorPosition,
    contextMenu: Bool,
    isNestedDrag: Bool) {

    exitType = .None
    possibleDrag = false
    dragInProgress = false
    didInitiateDrag = false
    closingEventTime = TimeTicks()
    menuStartTime = TimeTicks.now
    menuStartMousePressLoc = IntPoint()

    if let rootView = parent?.rootView {
      if let event = rootView.currentEvent as? MouseEvent, event.type == .MousePressed {
          var screenLoc = event.location
          View.convertPointToScreen(src: event.target as! View, point: &screenLoc)
          menuStartMousePressLoc = screenLoc
      }
    }

    // If we are already showing, this new menu is being nested. Such as context
    // menus on top of normal menus.
    if showing {
      // Only support nesting of blocking_run menus, nesting of
      // blocking/non-blocking shouldn't be needed.
      //DCHECK(blocking_run_)

      state.hotButton = hotButton
      hotButton = nil
      // We're already showing, push the current state.
      menuStack.append((state, pressedLock!))

      // The context menu should be owned by the same parent.
      //DCHECK_EQ(owner_, parent)
    } else {
      showing = true

      if let own = owner {
        own.removeObserver(self)
      }

      owner = parent
      if let own = owner {
        own.addObserver(self)
      }

  //#if defined(USE_AURA)
      // Only create a MenuPreTargetHandler for non-nested menus. Nested menus
      // will use the existing one.
      menuPreTargetHandler = MenuPreTargetHandler(controller: self, owner: owner)
 // #endif
    }
    // Reset current state.
    pendingState = State()
    state = State()
    updateInitialLocation(bounds: bounds, position: position, contextMenu: contextMenu)

    // Set the selection, which opens the initial menu.
    setSelection(menuItem: root, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))

    if !isBlockingRun {
      if !isNestedDrag {
        // Start the timer to hide the menu. This is needed as we get no
        // notification when the drag has finished.
        startCancelAllTimer()
      }
      return
    }

    if let b = button {
      pressedLock = MenuButton.PressedLock(button: b)
    }

    // Make sure it doesn't attempt to shut down while the menu is showing.
    //ViewsDelegate.instance.addRef()
  }


  // Cancels the current Run. See ExitType for a description of what happens
  // with the various parameters.
  public func cancel(type: ExitType) {
      // If the menu has already been destroyed, no further cancellation is
    // needed.  We especially don't want to set the |exit_type_| to a lesser
    // value.
    if exitType == .Destroyed || exitType == type {
      return
    }

    if !showing {
      // This occurs if we're in the process of notifying the delegate for a drop
      // and the delegate cancels us. Or if the releasing of ViewsDelegate causes
      // an immediate shutdown.
      return
    }

    let selected = state.item
    exitType = type

    sendMouseCaptureLostToActiveView()

    // Hide windows immediately.
    setSelection(menuItem: nil, types: MenuController.SetSelectionTypes(rawValue: SetSelectionTypes.SelectionUpdateImmediately.rawValue | SetSelectionTypes.SelectionExit.rawValue))

    if let d = delegate {
      if !isBlockingRun {
        // If we didn't block the caller we need to notify the menu, which
        // triggers deleting us.
        //DCHECK(selected)
        showing = false
        d.onMenuClosed(type: NotifyType.NotifyDelegate,
                       menu: selected!.rootMenuItem, 
                       mouseEventFlags: acceptEventFlags)
        // WARNING: the call to MenuClosed deletes us.
        return
      }
    }

    // If |type| is EXIT_ALL we update the state of the menu to not showing. For
    // dragging this ensures that the correct visual state is reported until the
    // drag operation completes. For non-dragging cases it is possible that the
    // release of ViewsDelegate leads immediately to shutdown, which can trigger
    // nested calls to Cancel. We want to reject these to prevent attempting a
    // nested tear down of this and |delegate_|.
    if type == .All {
      showing = false
    }

    // On Windows and Linux the destruction of this menu's UIWidget leads to the
    // teardown of the platform specific drag-and-drop UIWidget. Do not shutdown
    // while dragging, leave the UIWidget hidden until drag-and-drop has completed,
    // at which point all menus will be destroyed.
    if !dragInProgress {
      exitMenu()
    }

  }

  // An alternative to Cancel(EXIT_ALL) that can be used with a OneShotTimer.
  public func cancelAll() { 
    cancel(type: .All) 
  }

  // When is_nested_run() this will add a delegate to the stack. The most recent
  // delegate will be notified. It will be removed upon the exiting of the
  // nested menu. Ownership is not taken.
  public func addNestedDelegate(delegate: MenuControllerDelegate) {
    delegateStack.append(delegate)
    self.delegate = delegate
  }

  // Various events, forwarded from the submenu.
  //
  // NOTE: the coordinates of the events are in that of the
  // MenuScrollViewContainer.
  public func onMousePressed(source: SubmenuView, event: inout MouseEvent) -> Bool {
      // We should either have no current_mouse_event_target_, or should have a
    // pressed state stored.
    //DCHECK(!current_mouse_event_target_ || current_mouse_pressed_state_)

    // Find the root view to check. If any buttons were previously pressed, this
    // is the same root view we've been forwarding to. Otherwise, it's the root
    // view of the target.
    let forwardToRoot =
        currentMousePressedState != 0 ? currentMouseEventTarget : getRootView(source: source, sourceLoc: event.location)

    currentMousePressedState |= event.changedButtonFlags

    if let forward = forwardToRoot {
      var eventForRoot = event as LocatedEvent
      // Reset hot-tracking if a different view is getting a mouse press.
      convertLocatedEventForRootView(source: source, dst: forward, event: &eventForRoot)
      let view = forward.getEventHandlerFor(point: eventForRoot.location)
      let button = view as! Button
      
      if hotButton !== button {
        setHotTrackedButton(hotButton: button)
      }

      // Empty menu items are always handled by the menu controller.
      if view == nil || view!.id != MenuItemView.emptyMenuItemViewID {
        let processed = forward.processMousePressed(event: eventForRoot as! MouseEvent)
        // If the event was processed, the root view becomes our current mouse
        // handler...
        if processed && currentMouseEventTarget == nil {
          currentMouseEventTarget = forward
        }

        // ...and we always return the result of the current handler.
        if currentMouseEventTarget != nil {
          return processed
        }
      }

    }
    // Otherwise, the menu handles this click directly.
    setSelectionOnPointerDown(source: source, event: event)
    return true
  }
  
  public func onMouseDragged(source: SubmenuView, event: MouseEvent) -> Bool {
    
    if let target = currentMouseEventTarget {
      var eventForRoot = event as LocatedEvent
      convertLocatedEventForRootView(source: source, dst: target, event: &eventForRoot)
      return target.processMouseDragged(event: eventForRoot as! MouseEvent)
    }

    var part = getMenuPart(source: source, sourceLoc: event.location)
    updateScrolling(part: part)

    if !isBlockingRun {
      return false
    }

    if possibleDrag {
      if View.exceededDragThreshold(delta: event.location - pressPoint) {
        startDrag(source: source, location: pressPoint)
      }
      return true
    }

    var mouseMenu: MenuItemView? = nil
    if part.type == MenuPartType.MenuItem {
      // If there is no menu target, but a submenu target, then we are interacting
      // with an empty menu item within a submenu. These cannot become selection
      // targets for mouse interaction, so do not attempt to update selection.
      if part.menu != nil || part.submenu == nil {
        if part.menu == nil {
          part.menu = source.menuItem
        } else {
          mouseMenu = part.menu
        }
        setSelection(menuItem: part.menu != nil ? part.menu! : state.item, types: SetSelectionTypes.SelectionOpenSubmenu)
      }
    } else if part.type == MenuPartType.None {
      // If there is a sibling menu, show it. Otherwise, if the user has selected
      // a menu item with no accompanying sibling menu or submenu, move selection
      // back to the parent menu item.
      if !showSiblingMenu(source: source, mouseLocation: event.location) {
        if !part.isScroll && pendingState.item != nil &&
            pendingState.item!.parentMenuItem != nil &&
            !pendingState.item!.submenuIsShowing {
          setSelection(menuItem: pendingState.item!.parentMenuItem, types: SetSelectionTypes.SelectionOpenSubmenu)
        }
      }
    }
    updateActiveMouseView(eventSource: source, event: event, targetMenu: mouseMenu)

    return true
  }
  
  public func onMouseReleased(source: SubmenuView, event: MouseEvent) {
    currentMousePressedState &= ~event.changedButtonFlags

    if let target = currentMouseEventTarget {
      // If this was the final mouse button, then remove the forwarding target.
      // We need to do this *before* dispatching the event to the root view
      // because there's a chance that the event will open a nested (and blocking)
      // menu, and we need to not have a forwarded root view.
      //MenuHostRootView* cached_event_target = current_mouse_event_target_
      
      if currentMousePressedState == 0 {
         currentMouseEventTarget = nil
      }

      var eventForRoot = event as LocatedEvent
      convertLocatedEventForRootView(source: source, dst: target, event: &eventForRoot)
      target.processMouseReleased(event: eventForRoot as! MouseEvent)
      return
    }

    if !isBlockingRun {
      return
    }

    //DCHECK(state_.item)
    possibleDrag = false
    //DCHECK(blocking_run_)
    let part = getMenuPart(source: source, sourceLoc: event.location)
    if event.isRightMouseButton && part.type == MenuPartType.MenuItem {
      var menu = part.menu
      // |menu| is NULL means this event is from an empty menu or a separator.
      // If it is from an empty menu, use parent context menu instead of that.
      if menu == nil &&
          part.submenu!.childCount == 1 &&
          part.submenu!.childAt(index: 0)!.id == MenuItemView.emptyMenuItemViewID {
        menu = part.parent
      }

      if menu != nil {
        var screenLocation = event.location
        View.convertPointToScreen(src: source.scrollViewContainer,
                                  point: &screenLocation)
        if showContextMenu(menuItem: menu!, screenLocation: screenLocation, sourceType: .Mouse) {
          return
        }
      }
    }

    // We can use Ctrl+click or the middle mouse button to recursively open urls
    // for selected folder menu items. If it's only a left click, show the
    // contents of the folder.
    if !part.isScroll && part.menu != nil && !(part.menu!.hasSubmenu && event.flags.contains(.LeftMouseButton)) {
      if activeMouseViewTracker.view != nil {
        sendMouseReleaseToActiveView(eventSource: source, event: event)
        return
      }
      // If a mouse release was received quickly after showing.
      let timeShown: TimeDelta = TimeTicks.now - menuStartTime
      if Int(timeShown.milliseconds) < menuSelectionHoldTimeMs {
        // And it wasn't far from the mouse press location.
        var screenLoc = event.location
        View.convertPointToScreen(src: source.scrollViewContainer, point: &screenLoc)
        let moved: IntVec2 = screenLoc - menuStartMousePressLoc
        if moved.length < maximumLengthMovedToActivate {
          // Ignore the mouse release as it was likely this menu was shown under
          // the mouse and the action was just a normal click.
          return
        }
      }
      if part.menu!.delegate!.shouldExecuteCommandWithoutClosingMenu(
              id: part.menu!.command, e: event) {
        let _ = part.menu!.delegate!.executeCommand(id: part.menu!.command, mouseEventFlags: event.flags.rawValue)
        return
      }
      if part.menu!.nonIconChildViewsCount == 0 &&
          part.menu!.delegate!.isTriggerableEvent(view: part.menu!, e: event) {
        let shownTime: TimeDelta = TimeTicks.now - menuStartTime
        if !state.contextMenu || !View.shouldShowContextMenuOnMousePress ||
            Int(shownTime.milliseconds) > menuSelectionHoldTimeMs {
          accept(item: part.menu, eventFlags: event.flags.rawValue)
        }
        return
      }
    } else if part.type == MenuPartType.MenuItem {
      // User either clicked on empty space, or a menu that has children.
      setSelection(menuItem: part.menu != nil ? part.menu! : state.item!,
                   types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
    }
    sendMouseCaptureLostToActiveView()
  }
  
  public func onMouseMoved(source: SubmenuView, event: MouseEvent) {
    
    if let target = currentMouseEventTarget {
      var eventForRoot = event as LocatedEvent//MouseEvent(event)
      convertLocatedEventForRootView(source: source, dst: target, event: &eventForRoot)
      target.processMouseMoved(event: eventForRoot as! MouseEvent)
      return
    }
 
    if let rootView = getRootView(source: source, sourceLoc: event.location) {
      rootView.processMouseMoved(event: event)

      // Update hot-tracked button when a button state is changed with a mouse
      // event. It is necessary to track it for accurate hot-tracking when both
      // mouse and keyboard are used to navigate the menu.
      var eventForRoot = event as LocatedEvent//MouseEvent(event)
      convertLocatedEventForRootView(source: source, dst: rootView, event: &eventForRoot)
      let view = rootView.getEventHandlerFor(point: eventForRoot.location)
      if let b = view as? Button {
        if b.isHotTracked {
          setHotTrackedButton(hotButton: b)
        }
      }
    }

    handleMouseLocation(source: source, mouseLocation: event.location)
  }
  
  public func onMouseEntered(source: SubmenuView, event: MouseEvent) {

  }
  
  public func onMouseWheel(source: SubmenuView, event: MouseWheelEvent) -> Bool {
    let part = getMenuPart(source: source, sourceLoc: event.location)
    return part.submenu != nil && part.submenu!.onMouseWheel(event: event)
  }
  
  public func onGestureEvent(source: SubmenuView, event: inout GestureEvent) {
     if let own = owner { 
       if sendGestureEventsToOwner {
  // #if defined(OS_MACOSX)
  //     NOTIMPLEMENTED()
  // #else   // !defined(OS_MACOSX)
        event.convertLocationToTarget(source: source.widget!.window,
                                      target: own.window)
  // #endif  // defined(OS_MACOSX)
        own.onGestureEvent(event: &event)
        // Reset |send_gesture_events_to_owner_| when the first gesture ends.
        if event.type == .GestureEnd {
          sendGestureEventsToOwner = false
        }
        return
       }
    }

    let rootView = getRootView(source: source, sourceLoc: event.location)
    if let rview = rootView {
      // Reset hot-tracking if a different view is getting a touch event.
      var eventForRoot = event as LocatedEvent
      convertLocatedEventForRootView(source: source, dst: rview, event: &eventForRoot)
      let view = rview.getEventHandlerFor(point: eventForRoot.location)
      let button = view as! Button
      if hotButton != nil && hotButton !== button {
        setHotTrackedButton(hotButton: nil)
      }
    }

    let part = getMenuPart(source: source, sourceLoc: event.location)
    if event.type == .GestureTapDown {
      setSelectionOnPointerDown(source: source, event: event)
      event.stopPropagation()
    } else if event.type == .GestureLongPress {
      if part.type == MenuPartType.MenuItem && part.menu != nil {
        var screenLocation = event.location
        View.convertPointToScreen(src: source.scrollViewContainer,
                                  point: &screenLocation)
        if showContextMenu(menuItem: part.menu!, screenLocation: screenLocation, sourceType: .Touch) {
          event.stopPropagation()
        }
      }
    } else if event.type == .GestureTap {
      if !part.isScroll && part.menu != nil && !part.menu!.hasSubmenu {
        if part.menu!.delegate!.isTriggerableEvent(view: part.menu!, e: event) {
          itemSelectedByTouch = true
          accept(item: part.menu, eventFlags: event.flags.rawValue)
        }
        event.stopPropagation()
      } else if part.type == MenuPartType.MenuItem {
        // User either tapped on empty space, or a menu that has children.
        setSelection(menuItem: part.menu != nil ? part.menu! : state.item, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
        event.stopPropagation()
      }
    } else if event.type == .GestureTapCancel &&
              part.menu != nil  &&
              part.type == MenuPartType.MenuItem {
      // Move the selection to the parent menu so that the selection in the
      // current menu is unset. Make sure the submenu remains open by sending the
      // appropriate SetSelectionTypes flags.
      setSelection(menuItem: part.menu!.parentMenuItem,
        types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
     
      event.stopPropagation()
    }

    if event.stoppedPropagation {
      return
    }

    if let sub = part.submenu {
      sub.onGestureEvent(event: &event)
    }
  }
  
  public func onTouchEvent(source: SubmenuView, event: TouchEvent) {
    if event.type == .TouchPressed {
      let part = getMenuPart(source: source, sourceLoc: event.location)
      if part.type == MenuPartType.None {
        repostEventAndCancel(source: source, event: event)
        event.handled = true
      }
    }
  }
  
  public func getTooltipHandlerForPoint(source: SubmenuView, point: IntPoint) -> View? {
    if let rootView = getRootView(source: source, sourceLoc: point) {
      return rootView.processGetTooltipHandlerFor(point: point)
    }
    return nil
  }
  
  public func viewHierarchyChanged(source: SubmenuView, details: ViewHierarchyChangedDetails) {
    if !details.isAdd {
    // If the current mouse handler is removed, remove it as the handler.
      if details.child === currentMouseEventTarget {
        currentMouseEventTarget = nil
        currentMousePressedState = 0
      }
      // Update |hot_button_| (both in |this| and in |menu_stack_| if it gets
      // removed while a menu is up.
      if details.child === hotButton {
        hotButton = nil
        for var nestedState in menuStack {
          if details.child === nestedState.0.hotButton {
            nestedState.0.hotButton = nil
          }
        }
      }
    }
  }

  public func getDropFormats(source: SubmenuView,
                             formats: inout Int,
                             formatTypes: inout [ClipboardFormatType]) -> Bool {
    return source.menuItem!.delegate!.getDropFormats(menu: source.menuItem!, formats: &formats, formatTypes: &formatTypes)
  }
  
  public func areDropTypesRequired(source: SubmenuView) -> Bool {
    return source.menuItem!.delegate!.areDropTypesRequired(menu: source.menuItem!)
  }

  public func canDrop(source: SubmenuView, data: OSExchangeData) -> Bool {
    return source.menuItem!.delegate!.canDrop(menu: source.menuItem!, data: data)
  }
  
  public func onDragEntered(source: SubmenuView, event: DropTargetEvent) {
    validDropCoordinates = false
  }
  
  public func onDragUpdated(source: SubmenuView, event: DropTargetEvent) -> DragOperation {
    stopCancelAllTimer()

    var screenLoc = event.location
    View.convertPointToScreen(src: source, point: &screenLoc)
    if validDropCoordinates && screenLoc == dropPoint {
      return DragOperation(rawValue: lastDropOperation)!
    }
    dropPoint = screenLoc
    validDropCoordinates = true

    var menuItem: MenuItemView? = getMenuItemAt(menu: source, x: Int(event.x), y: Int(event.y))
    var overEmptyMenu = false
    if menuItem == nil {
      // See if we're over an empty menu.
      menuItem = getEmptyMenuItemAt(source: source, x: Int(event.x), y: Int(event.y))
      if menuItem != nil {
        overEmptyMenu = true
      }
    }
    var dropPosition = DropPosition.DropNone
    var dropOperation = DragOperation.DragNone
    if let menu = menuItem {
      var menuItemLoc = event.location
      View.convertPointToTarget(source: source, target: menu, point: &menuItemLoc)
      var queryMenuItem: MenuItemView? = nil
      if !overEmptyMenu {
        let menuItemHeight = menu.height
        if menu.hasSubmenu &&
            (menuItemLoc.y > dropBetweenPixels &&
            menuItemLoc.y < (menuItemHeight - dropBetweenPixels)) {
          dropPosition = DropPosition.DropOn
        } else {
          dropPosition = (menuItemLoc.y < menuItemHeight / 2) ?
              DropPosition.DropBefore : DropPosition.DropAfter
        }
        queryMenuItem = menu
      } else {
        queryMenuItem = menu.parentMenuItem
        dropPosition = DropPosition.DropOn
      }
      dropOperation = DragOperation(rawValue: menu.delegate!.getDropOperation(
          item: queryMenuItem!, event: event, position: &dropPosition))!

      // If the menu has a submenu, schedule the submenu to open.
      setSelection(menuItem: menu, types: menu.hasSubmenu ? SetSelectionTypes.SelectionOpenSubmenu : SetSelectionTypes.SelectionDefault)

      if dropPosition == DropPosition.DropNone || dropOperation == DragOperation.DragNone {
        menuItem = nil
      }

    } else {
      setSelection(menuItem: source.menuItem, types: SetSelectionTypes.SelectionOpenSubmenu)
    }
    setDropMenuItem(target: menuItem, position: dropPosition)
    lastDropOperation = dropOperation.rawValue
    return dropOperation
  }

  public func onDragExited(source: SubmenuView) {
    startCancelAllTimer()

    if dropTarget != nil {
      stopShowTimer()
      setDropMenuItem(target: nil, position: DropPosition.DropNone)
    }
  }
  
  public func onPerformDrop(source: SubmenuView, event: DropTargetEvent) -> DragOperation {
    let item = state.item
    //DCHECK(item)
    var target: MenuItemView? = dropTarget
    let dropPos = dropPosition
    //MenuItemView* drop_target = drop_target_
    //MenuDelegate::DropPosition drop_position = drop_position_

    // Close all menus, including any nested menus.
    setSelection(menuItem: nil, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionUpdateImmediately.rawValue | SetSelectionTypes.SelectionExit.rawValue))
    closeAllNestedMenus()

    // Set state such that we exit.
    showing = false
    exitType = .All

    // If over an empty menu item, drop occurs on the parent.
    if target!.id == MenuItemView.emptyMenuItemViewID {
      target = target!.parentMenuItem
    }

    if !isBlockingRun {
      delegate!.onMenuClosed(
          type: NotifyType.DontNotifyDelegate, menu: item!.rootMenuItem, mouseEventFlags: acceptEventFlags)
    }

    // WARNING: the call to MenuClosed deletes us.

    return DragOperation(rawValue: target!.delegate!.onPerformDrop(
        menu: target!, position: dropPos, event: event))!
  }
  // Invoked from the scroll buttons of the MenuScrollViewContainer.
  public func onDragEnteredScrollButton(source: SubmenuView, isUp: Bool) {
    var part = MenuPart()
    part.type = isUp ? MenuPartType.ScrollUp : MenuPartType.ScrollDown
    part.submenu = source
    updateScrolling(part: part)

    // Do this to force the selection to hide.
    setDropMenuItem(target: source.getMenuItemAt(index: 0), position: DropPosition.DropNone)

    stopCancelAllTimer()    
  }
  
  public func onDragExitedScrollButton(source: SubmenuView) {
    startCancelAllTimer()
    setDropMenuItem(target: nil, position: DropPosition.DropNone)
    stopScrolling()
  }

  // Called by the UIWidget when a drag is about to start on a child view. This
  // could be initiated by one of our MenuItemViews, or could be through another
  // child View.
  public func onDragWillStart() {
    dragInProgress = true
  }

  // Called by the UIWidget when the drag has completed. |should_close|
  // corresponds to whether or not the menu should close.
  public func onDragComplete(shouldClose: Bool) {
    dragInProgress = false
    // During a drag, mouse events are processed directly by the widget, and not
    // sent to the MenuController. At drag completion, reset pressed state and
    // the event target.
    currentMousePressedState = 0
    currentMouseEventTarget = nil

    // Only attempt to close if the MenuHost said to.
    if shouldClose {
      if showing {
        // During a drag operation there are several ways in which this can be
        // canceled and deleted. Verify that this is still active before closing
        // the widgets.
        if MenuController.activeInstance === self {
          //base::WeakPtr<MenuController> this_ref = AsWeakPtr()
          closeAllNestedMenus()
          cancel(type: .All)
          // The above may have deleted us. If not perform a full shutdown.
          //if (!this_ref)
          //  return
          exitMenu()
        }
      } else if exitType == .All {
        // We may have been canceled during the drag. If so we still need to fully
        // shutdown.
        exitMenu()
      }
    }
  }

  // Called while dispatching messages to intercept key events.
  // Returns ui::POST_DISPATCH_NONE if the event was swallowed by the menu.
  public func onWillDispatchKeyEvent(event: KeyEvent) -> PostDispatchAction {
    if exitType == .All || exitType == .Destroyed {
      // If the event has arrived after the menu's exit type has changed but
      // before its Widgets have been destroyed, the event will continue its
      // normal propagation for the following reason:
      // If the user accepts a menu item in a nested menu, and the menu item
      // action starts a base::RunLoop IDC_BOOKMARK_BAR_OPEN_ALL sometimes opens
      // a modal dialog. The modal dialog starts a base::RunLoop and keeps the
      // base::RunLoop running for the duration of its lifetime.
      return PostDispatchAction.PerformDefault
    }

    event.stopPropagation()

    if event.type == .KeyPressed {
      //base::WeakPtr<MenuController> this_ref = AsWeakPtr()
      onKeyDown(keyCode: event.keyCode)
      // Key events can lead to this being deleted.
      //if (!this_ref)
      //  return ui::POST_DISPATCH_NONE

      // Do not check mnemonics if the Alt or Ctrl modifiers are pressed. For
      // example Ctrl+<T> is an accelerator, but <T> only is a mnemonic.
      let keyFlagsMask: Int = EventFlags.ControlDown.rawValue | EventFlags.AltDown.rawValue
      let flags = event.flags
      // TODO: check if is really flags.contains or !flags.contains
      if exitType == .None && !flags.contains(EventFlags(rawValue: keyFlagsMask)) { 
        let c = event.character
        selectByChar(key: Character(UnicodeScalar(c)!))
        // SelectByChar can lead to this being deleted.
        //if (!this_ref)
        //  return ui::POST_DISPATCH_NONE
      }
    }

    let accelerator = Accelerator(keycode: event.keyCode, modifiers: 0)
    let result =
        ViewsDelegate.instance.processAcceleratorWhileMenuShowing(accelerator)

    if result == ViewsDelegate.ProcessMenuAcceleratorResult.CloseMenu {
      cancelAll()
    }
    
    return PostDispatchAction.None
  }

  // Update the submenu's selection based on the current mouse location
  public func updateSubmenuSelection(source: SubmenuView) {
    if source.isShowing {
      var point = Screen.instance.cursorScreenPoint
      let rootSubmenu = source.menuItem!.rootMenuItem.submenu
      View.convertPointFromScreen(dst: rootSubmenu!.widget!.rootView!, point: &point)
      handleMouseLocation(source: source, mouseLocation: point)
    }
  }

  // UIWidgetObserver
  public func onWidgetDestroying(widget: UIWidget) {
    owner!.removeObserver(self)
    owner = nil
  }

  fileprivate class MenuScrollTask {
    
    var isScrollingUp: Bool = false
    var scrollingTimer: RepeatingTimer = RepeatingTimer(tickClock: nil)
    var startScrollTime: Time = Time()
    var pixelsPerSecond: Int
    var startY: Int = 0
    var submenu: SubmenuView?
    
    public init() {
      pixelsPerSecond = MenuItemView.prefMenuHeight * 20
    }

    public func update(part: MenuPart) {
      if !part.isScroll {
        stopScrolling()
        return
      }
      
      let newMenu = part.submenu
      let newIsUp = (part.type == MenuPartType.ScrollUp)
      if newMenu === submenu && isScrollingUp == newIsUp {
        return
      }

      startScrollTime = Time.now
      startY = part.submenu!.visibleBounds.y
      submenu = newMenu
      isScrollingUp = newIsUp

      if !scrollingTimer.isRunning {
        scrollingTimer.start(delay: TimeDelta.from(milliseconds: Int64(scrollTimerMS)), { self.run() })
      }
    }

    public func stopScrolling() {
      if scrollingTimer.isRunning {
        scrollingTimer.stop()
        submenu = nil
      }
    }

    private func run() {
      guard let menu = submenu else {
        return
      }
      var visRect: IntRect = menu.visibleBounds
      let deltaY = Int((Time.now - startScrollTime).milliseconds) * pixelsPerSecond / 1000
      visRect.y = isScrollingUp ? max(0, startY - deltaY) : min(submenu!.height - visRect.height, startY + deltaY)
      menu.scrollRectToVisible(rect: visRect)
    }

  }

  fileprivate struct SelectByCharDetails {
    var firstMatch: Int
    var hasMultiple: Bool
    var indexOfItem: Int
    var nextMatch: Int

    public init() {
      firstMatch = -1
      hasMultiple = false
      indexOfItem = -1
      nextMatch = -1
    }
  }

  // Values supplied to SetSelection.
  internal struct SetSelectionTypes : OptionSet {
    public static let SelectionDefault            = SetSelectionTypes(rawValue: 1 << 0)
    // If set submenus are opened immediately, otherwise submenus are only
    // openned after a timer fires.
    public static let SelectionUpdateImmediately  = SetSelectionTypes(rawValue: 1 << 1)
    // If set and the menu_item has a submenu, the submenu is shown.
    public static let SelectionOpenSubmenu        = SetSelectionTypes(rawValue: 1 << 2)
    // SetSelection is being invoked as the result exiting or cancelling the
    // menu. This is used for debugging.
    public static let SelectionExit               = SetSelectionTypes(rawValue: 1 << 3)

    public var rawValue: Int

    public init(rawValue: Int)  {
      self.rawValue = rawValue
    }
  }

  // Direction for IncrementSelection and FindInitialSelectableMenuItem.
  internal enum SelectionIncrementDirectionType {
    // Navigate the menu up.
    case IncrementSelectionUp
    // Navigate the menu down.
    case IncrementSelectionDown
  }

  // Tracks selection information.
  fileprivate struct State {
   
    // The selected menu item.
    var item: MenuItemView?

    // Used to capture a hot tracked child button when a nested menu is opened
    // and to restore the hot tracked state when exiting a nested menu.
    var hotButton: Button?

    // If item has a submenu this indicates if the submenu is showing.
    var submenuOpen: Bool

    // Bounds passed to the run menu. Used for positioning the first menu.
    var initialBounds: IntRect

    // Position of the initial menu.
    var anchor: MenuAnchorPosition

    // The direction child menus have opened in.
    var openLeading: Set<Bool>

    // Bounds for the monitor we're showing on.
    var monitorBounds: IntRect

    // Is the current menu a context menu.
    var contextMenu: Bool

    init() {
      submenuOpen = false
      anchor = .TopLeft
      initialBounds = IntRect()
      openLeading = Set<Bool>()
      monitorBounds = IntRect()
      contextMenu = false
    }
  }


  fileprivate enum MenuPartType {
    case None
    case MenuItem
    case ScrollUp
    case ScrollDown
  }

  // Used by GetMenuPart to indicate the menu part at a particular location.
  fileprivate struct MenuPart {
    // Type of part.
   
    // Convenience for testing type == SCROLL_DOWN or type == SCROLL_UP.
    public var isScroll: Bool { 
      return type == .ScrollDown || type == .ScrollUp 
    }

    // Type of part.
    public var type: MenuPartType

    // If type is MENU_ITEM, this is the menu item the mouse is over, otherwise
    // this is NULL.
    // NOTE: if type is MENU_ITEM and the mouse is not over a valid menu item
    //       but is over a menu (for example, the mouse is over a separator or
    //       empty menu), this is NULL and parent is the menu the mouse was
    //       clicked on.
    public var menu: MenuItemView?

    // If type is MENU_ITEM but the mouse is not over a menu item this is the
    // parent of the menu item the user clicked on. Otherwise this is NULL.
    public var parent: MenuItemView?

    // This is the submenu the mouse is over.
    public var submenu: SubmenuView?
  
    fileprivate init() {
      type = MenuPartType.None
    }

  }

  // Sets the selection to |menu_item|. A value of NULL unselects
  // everything. |types| is a bitmask of |SetSelectionTypes|.
  //
  // Internally this updates pending_state_ immediatley. state_ is only updated
  // immediately if SELECTION_UPDATE_IMMEDIATELY is set. If
  // SELECTION_UPDATE_IMMEDIATELY is not set CommitPendingSelection is invoked
  // to show/hide submenus and update state_.
  internal func setSelection(menuItem: MenuItemView?, types selectionTypes: SetSelectionTypes) {
    var pathsDifferAt = 0
    var currentPath: [MenuItemView] = []
    var newPath: [MenuItemView] = []
    
    buildPathsAndCalculateDiff(oldItem: pendingState.item!, newItem: menuItem!, oldPath: &currentPath, newPath: &newPath, firstDiffAt: &pathsDifferAt)

    let currentSize = currentPath.count
    let newSize = newPath.count

    let pendingItemChanged = pendingState.item != menuItem
    
    if pendingItemChanged && pendingState.item != nil {
      setHotTrackedButton(hotButton: nil)
    }

    // Notify the old path it isn't selected.
    var currentDelegate: MenuDelegate? = nil
    
    if let first = currentPath.first {
      currentDelegate = first.delegate
    }

    for i in pathsDifferAt..<currentSize {
      let elem = currentPath[i]

      if elem.type == .Submenu {
        if let d = currentDelegate {
          d.willHideMenu(menu: elem)
        }
      }

      elem.isSelected = false
    }

    // Notify the new path it is selected.
    for i in pathsDifferAt..<newSize {
      let item = newPath[i]
      item.scrollRectToVisible(rect: item.localBounds)
      item.isSelected = true
    }

    if let menuDelegate = menuItem?.delegate {
      menuDelegate.selectionChanged(menu: menuItem!)
    }

    //DCHECK(menu_item || (selection_types & SELECTION_EXIT) != 0)

    pendingState.item = menuItem
    pendingState.submenuOpen = selectionTypes.contains(SetSelectionTypes.SelectionOpenSubmenu)// (selectionTypes & SELECTION_OPEN_SUBMENU) != 0

    // Stop timers.
    stopCancelAllTimer()
    // Resets show timer only when pending menu item is changed.
    if pendingItemChanged {
      stopShowTimer()
    }

    if selectionTypes.contains(SetSelectionTypes.SelectionUpdateImmediately) {
      commitPendingSelection()
    } else if pendingItemChanged {
      startShowTimer()
    }

    // Notify an accessibility focus event on all menu items except for the root.
    // TODO: implement
    // if let menu = menuItem {
    //   if MenuController.menuDepth(menu) != 1 || menu.type != MenuItemViewType.Submenu {
    //     menu.notifyAccessibilityEvent(eventType: AXEvent.Selection, sendNativeEvent: true)
    //   }
    // }
  }

  fileprivate func setSelectionOnPointerDown(source: SubmenuView, event: LocatedEvent) {
    if !isBlockingRun {
      return
    }

    //CHECK(!active_mouse_view_tracker_->view())

    var part = getMenuPart(source: source, sourceLoc: event.location)
    if part.isScroll {
      return  // Ignore presses on scroll buttons.
    }

    // When this menu is opened through a touch event, a simulated right-click
    // is sent before the menu appears.  Ignore it.
    if event.flags.contains(EventFlags.RightMouseButton) && event.flags.contains(EventFlags.FromTouch) {
      return
    }

    if part.type == MenuPartType.None || (part.type == MenuPartType.MenuItem && part.menu != nil &&
        part.menu!.rootMenuItem !== state.item!.rootMenuItem) {
      // Remember the time stamp of the current (press down) event. The owner can
      // then use this to figure out if this menu was finished with the same click
      // which is sent to it thereafter.
      closingEventTime = event.timestamp
      // Event wasn't pressed over any menu, or the active menu, cancel.
      repostEventAndCancel( source: source, event: event)
      // Do not repost events for Linux Aura because this behavior is more
      // consistent with the behavior of other Linux apps.
      return
    }

    // On a press we immediately commit the selection, that way a submenu
    // pops up immediately rather than after a delay.
    var selectionTypes: Int = SetSelectionTypes.SelectionUpdateImmediately.rawValue
    if part.menu == nil {
      part.menu = part.parent
      selectionTypes |= SetSelectionTypes.SelectionOpenSubmenu.rawValue
    } else {
      if part.menu!.delegate!.canDrag(menu: part.menu!) {
        possibleDrag = true
        pressPoint = event.location
      }
      if part.menu!.hasSubmenu {
        selectionTypes |= SetSelectionTypes.SelectionOpenSubmenu.rawValue
      }
    }
    setSelection(menuItem: part.menu, types: SetSelectionTypes(rawValue: selectionTypes))
  }
  
  fileprivate func startDrag(source: SubmenuView, location: IntPoint) {
    guard let item = state.item else {
      return
    }
    //DCHECK(item)
    // Points are in the coordinates of the submenu, need to map to that of
    // the selected item. Additionally source may not be the parent of
    // the selected item, so need to map to screen first then to item.
    var pressLoc = location
    View.convertPointToScreen(src: source.scrollViewContainer, point: &pressLoc)
    View.convertPointFromScreen(dst: item, point: &pressLoc)
    var widgetLoc = pressLoc
    //View.convertPointToWidget(item, &widgetLoc)
    View.convertPointToWindow(src: item, point: &widgetLoc)

    let rasterScale = scaleFactorForDragFromWidget(source.widget)
    let canvas = Canvas(size: item.size, imageScale: rasterScale, isOpaque: false)
    item.paintButton(canvas: canvas, mode: MenuItemView.PaintButtonMode.ForDrag)
    //let image = ImageRepresentation(canvas.bitmap, rasterScale)
    let image = ImageSkia(bitmap: canvas.bitmap!, scale: rasterScale)

    let data = OSExchangeData()
    item.delegate!.writeDragData(sender: item, data: data)
    data.provider.setDragImage(image, cursorOffset: pressLoc.offsetFromOrigin)

    stopScrolling()
    let dragOps = item.delegate!.getDragOperations(sender: item)
    didInitiateDrag = true
    //base::WeakPtr<MenuController> this_ref = AsWeakPtr()
    // TODO(varunjain): Properly determine and send DRAG_EVENT_SOURCE below.
    item.widget!.runShellDrag(view: nil, data: data, location: widgetLoc, operation: DragOperation(rawValue: dragOps)!, source: DragEventSource.Mouse)
    // MenuController may have been deleted so check before accessing member
    // variables.
    //if (this_ref)
      //did_initiate_drag_ = false
    didInitiateDrag = false  
  }

  // Key processing.
  fileprivate func onKeyDown(keyCode: KeyboardCode) {
    // Do not process while performing drag-and-drop
    if !isBlockingRun {
      return
    }

    switch keyCode {
      case .KeyUp:
        incrementSelection(direction: .IncrementSelectionUp)
      case .KeyDown:
        incrementSelection(direction: .IncrementSelectionDown)

      // Handling of VK_RIGHT and VK_LEFT is different depending on the UI
      // layout.
      case .KeyRight:
        if i18n.isRTL() {
          closeSubmenu()
        } else {
          openSubmenuChangeSelectionIfCan()
        }
      case .KeyLeft:
        if i18n.isRTL() {
          openSubmenuChangeSelectionIfCan()
        } else {
          closeSubmenu()
        }
  // On Mac, treat space the same as return.
  //#if !os(macOS)
      case .KeySpace:
        let _ = sendAcceleratorToHotTrackedView()
  //#endif
      case .KeyF4:
        if !isCombobox {
          break
        }
        // Fallthrough to accept or dismiss combobox menus on F4, like windows.
        fallthrough
      case .KeyReturn:
 // #if os(macOS)
 //       fallthrough
 //     case .KeySpace:
 // #endif
        if let item = pendingState.item {
          if let menu = item.submenu {
            if keyCode == .KeyF4 && menu.isShowing {
              cancel(type: .All)
            } else {
              openSubmenuChangeSelectionIfCan()
            }
          } else {
            if !sendAcceleratorToHotTrackedView() && item.isEnabled {
              accept(item: item, eventFlags: 0)
            }
          }
        }
      case .KeyEscape:
        if state.item!.parentMenuItem == nil ||
            (state.item!.parentMenuItem!.parentMenuItem == nil && !state.item!.submenuIsShowing) {
          // User pressed escape and current menu has no submenus. If we are
          // nested, close the current menu on the stack. Otherwise fully exit the
          // menu.
          cancel(type: delegateStack.count > 1 ? .Outermost : .All)
          break
        }
        closeSubmenu()
      case .KeyApps: 
        if let hotView = getFirstHotTrackedView(view: pendingState.item) {
          hotView.showContextMenu(point: hotView.keyboardContextMenuLocation, sourceType: MenuSourceType.Keyboard)
        } else if pendingState.item!.isEnabled &&
                  pendingState.item!.rootMenuItem !== pendingState.item {
          // Show the context menu for the given menu item. We don't try to show
          // the menu for the (boundless) root menu item. This can happen, e.g.,
          // when the user hits the APPS key after opening the menu, when no item
          // is selected, but showing a context menu for an implicitly-selected
          // and invisible item doesn't make sense.
          let _ = showContextMenu(menuItem: pendingState.item!,
                          screenLocation: pendingState.item!.keyboardContextMenuLocation,
                          sourceType: MenuSourceType.Keyboard)
        }

  //#if os(Windows)
      // On Windows, pressing Alt and F10 keys should hide the menu to match the
      // OS behavior.
 //     case .KeyMenu:
 //       fallthrough
 //     case .KeyF10:
 //       cancel(.ExitAll)
 // #endif

      default:
        return
    }
  }

 
  // Runs the platform specific bits of the message loop.
  fileprivate func runMessageLoop() {
    assert(false)
    // TODO: implement
    //messageLoop.run(self, owner, nestedMenu)
  }

  // Invokes AcceleratorPressed() on the hot tracked view if there is one.
  // Returns true if AcceleratorPressed() was invoked.
  fileprivate func sendAcceleratorToHotTrackedView() -> Bool {
    guard let hotView = getFirstHotTrackedView(view: pendingState.item) else {
      return false
    }

    let accelerator = Accelerator(keycode: .KeyReturn, modifiers: 0)
    let _ = hotView.acceleratorPressed(accelerator: accelerator)
    //let button = hotView as! Button//CustomButton
    hotView.isHotTracked = true
    return true
  }

  fileprivate func updateInitialLocation(bounds: IntRect,
                                         position: MenuAnchorPosition,
                                         contextMenu: Bool) {
    pendingState.contextMenu = contextMenu
    pendingState.initialBounds = bounds
    if bounds.height > 1 {
      // Inset the bounds slightly, otherwise drag coordinates don't line up
      // nicely and menus close prematurely.
      pendingState.initialBounds.inset(horizontal: 0, vertical: 1)
    }

    // Reverse anchor position for RTL languages.
    if i18n.isRTL() && (position == .TopRight || position == .TopLeft) {
      pendingState.anchor = position == .TopRight
                                  ? .TopLeft
                                  : .TopRight
    } else {
      pendingState.anchor = position
    }

    // Calculate the bounds of the monitor we'll show menus on. Do this once to
    // avoid repeated system queries for the info.
    pendingState.monitorBounds = Screen.getDisplayNearestPoint(point: bounds.origin)!.workArea

    if !pendingState.monitorBounds.contains(rect: bounds) {
      // Use the monitor area if the work area doesn't contain the bounds. This
      // handles showing a menu from the launcher.
      let monitorArea = Screen.getDisplayNearestPoint(point: bounds.origin)!.bounds
      
      if monitorArea.contains(rect:  bounds) {
        pendingState.monitorBounds = monitorArea
      }
    }
  }

  // Invoked when the user accepts the selected item. This is only used
  // when blocking. This schedules the loop to quit.
  fileprivate func accept(item: MenuItemView?, eventFlags: Int) {
    result = item
    if item != nil && !menuStack.isEmpty && !item!.delegate!.shouldCloseAllMenusOnExecute(id: item!.command) {
      exitType = .Outermost
    } else {
      exitType = .All
    }
    acceptEventFlags = eventFlags
    exitMenu()
  }

  fileprivate func showSiblingMenu(source: SubmenuView, mouseLocation: IntPoint) -> Bool {
    if !menuStack.isEmpty || pressedLock == nil {
      return false
    }

    let sourceView = source.scrollViewContainer
    if mouseLocation.x >= 0 &&
       mouseLocation.x < sourceView.width &&
       mouseLocation.y >= 0 &&
       mouseLocation.y < sourceView.height {
      // The mouse is over the menu, no need to continue.
      return false
    }

    if let windowUnderMouse = (Screen.instance as? DesktopScreen)?.windowUnderCursor {
      if owner == nil || windowUnderMouse !== owner!.window { //owner.nativeWindow {
        return false
      }
    }
    
    // The user moved the mouse outside the menu and over the owning window. See
    // if there is a sibling menu we should show.
    var screenPoint = mouseLocation
    View.convertPointToScreen(src: sourceView, point: &screenPoint)
    var anchor = MenuAnchorPosition.TopLeft
    var hasMnemonics: Bool = false
    var button: MenuButton?
    let altMenu = source.menuItem!.delegate!.getSiblingMenu(
        menu: source.menuItem!.rootMenuItem,
        screenPoint: screenPoint, 
        anchor: &anchor, 
        hasMnemonics: &hasMnemonics, 
        button: &button)

    if altMenu == nil || state.item != nil && state.item!.rootMenuItem === altMenu {
      return false
    }

    delegate!.siblingMenuCreated(menu: altMenu!)

    guard let btn = button else {
      // If the delegate returns a menu, they must also return a button.
      // NOTREACHED()
      assert(false)
      return false
    }

    // There is a sibling menu, update the button state, hide the current menu
    // and show the new one.
    pressedLock = MenuButton.PressedLock(button: btn)

    // Need to reset capture when we show the menu again, otherwise we aren't
    // going to get any events.
    didCapture = false
    var screenMenuLoc = IntPoint()
    View.convertPointToScreen(src: btn, point: &screenMenuLoc)

    // It is currently not possible to show a submenu recursively in a bubble.
    //DCHECK(!MenuItemView::IsBubble(anchor))
    // Subtract 1 from the height to make the popup flush with the button border.
    updateInitialLocation(bounds: IntRect(x: screenMenuLoc.x, y: screenMenuLoc.y, width: btn.width, height: btn.height - 1),
                          position: anchor, contextMenu: state.contextMenu)
    altMenu!.prepareForRun(
        isFirstMenu: false, hasMnemonics: hasMnemonics,
        showMnemonics: source.menuItem!.rootMenuItem.showMnemonics)

    altMenu!.controller = self
    setSelection(menuItem: altMenu, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
    return true
  }

  // Shows a context menu for |menu_item| as a result of an event if
  // appropriate, using the given |screen_location|. This is invoked on long
  // press, releasing the right mouse button, and pressing the "app" key.
  // Returns whether a context menu was shown.
  fileprivate func showContextMenu(menuItem: MenuItemView, screenLocation: IntPoint, sourceType: MenuSourceType) -> Bool {
    var selectionTypes: Int = SetSelectionTypes.SelectionUpdateImmediately.rawValue
    if state.item === pendingState.item && state.submenuOpen {
      selectionTypes |= SetSelectionTypes.SelectionOpenSubmenu.rawValue
    }
    
    setSelection(menuItem: pendingState.item, types: SetSelectionTypes(rawValue: selectionTypes))

    if menuItem.delegate!.showContextMenu(
            source: menuItem, id: menuItem.command, p: screenLocation, sourceType: sourceType) {
      sendMouseCaptureLostToActiveView()
      return true
    }
    return false
  }

  // Closes all menus, including any menus of nested invocations of Run.
  fileprivate func closeAllNestedMenus() {
    for elem in menuStack {
    //for (std::list<NestedState>::iterator i = menu_stack_.begin()
    //    i != menu_stack_.end() ++i) {
      //State& state = i->first
      var state = elem.0
      var lastItem: MenuItemView? = state.item
      var item: MenuItemView? = lastItem
      while item != nil {
        closeMenu(item: item!)
        lastItem = item
        item = item!.parentMenuItem
      }
      state.submenuOpen = false
      state.item = lastItem
    }
  }

  // Gets the enabled menu item at the specified location.
  // If over_any_menu is non-null it is set to indicate whether the location
  // is over any menu. It is possible for this to return NULL, but
  // over_any_menu to be true. For example, the user clicked on a separator.
  fileprivate func getMenuItemAt(menu: View, x: Int, y: Int) -> MenuItemView? {
    var childUnderMouse = menu.getEventHandlerFor(point: IntPoint(x: x, y: y))
    
    while childUnderMouse != nil &&
          childUnderMouse!.id != MenuItemView.menuItemViewID {
      childUnderMouse = childUnderMouse!.parent
    }

    if let child = childUnderMouse, child.isEnabled &&
        child.id == MenuItemView.menuItemViewID {
      return child as? MenuItemView
    }

    return nil
  }

  // If there is an empty menu item at the specified location, it is returned.
  fileprivate func getEmptyMenuItemAt(source: View, x: Int, y: Int) -> MenuItemView? {
    if let childUnderMouse = source.getEventHandlerFor(point: IntPoint(x: x, y: y)) {
      if childUnderMouse.id == MenuItemView.emptyMenuItemViewID {
        return childUnderMouse as? MenuItemView
      }
    }
    return nil
  }

  // Returns true if the coordinate is over the scroll buttons of the
  // SubmenuView's MenuScrollViewContainer. If true is returned, part is set to
  // indicate which scroll button the coordinate is.
  fileprivate func isScrollButtonAt(source: SubmenuView,
                        x: Int,
                        y: Int,
                        part: inout MenuPartType) -> Bool {
    let scrollView = source.scrollViewContainer
    if let childUnderMouse = scrollView.getEventHandlerFor(point: IntPoint(x: x, y: y)) {
      if childUnderMouse.isEnabled {
        if childUnderMouse === scrollView.scrollUpButton {
          part = MenuPartType.ScrollUp
          return true
        }

        if childUnderMouse === scrollView.scrollDownButton {
          part = MenuPartType.ScrollDown
          return true
        }
      }
    }
    return false
  }

  // Returns the target for the mouse event. The coordinates are in terms of
  // source's scroll view container.
  fileprivate func getMenuPart(source: SubmenuView, sourceLoc: IntPoint) -> MenuPart {
    var screenLoc = sourceLoc
    View.convertPointToScreen(src: source.scrollViewContainer, point: &screenLoc)
    return getMenuPartByScreenCoordinateUsingMenu(item: state.item!, screenLoc: screenLoc)
  }

  // Returns the target for mouse events. The search is done through |item| and
  // all its parents.
  fileprivate func getMenuPartByScreenCoordinateUsingMenu(item: MenuItemView,
                                                          screenLoc: IntPoint) -> MenuPart {
    var part = MenuPart()
    var it = item.parentMenuItem
    while it != nil {
      if let menu = item.submenu, menu.isShowing && 
          getMenuPartByScreenCoordinateImpl(menu: menu, screenLoc: screenLoc, part: &part) {
        return part
      }
      it = item.parentMenuItem
    }
    return part
  }

  // Implementation of GetMenuPartByScreenCoordinate for a single menu. Returns
  // true if the supplied SubmenuView contains the location in terms of the
  // screen. If it does, part is set appropriately and true is returned.
  fileprivate func getMenuPartByScreenCoordinateImpl(menu: SubmenuView,
                                                     screenLoc: IntPoint,
                                                     part: inout MenuPart) -> Bool {
    var scrollViewLoc = screenLoc
    let scrollViewContainer = menu.scrollViewContainer
    View.convertPointFromScreen(dst: scrollViewContainer, point: &scrollViewLoc)
    if scrollViewLoc.x < 0 ||
       scrollViewLoc.x >= scrollViewContainer.width ||
       scrollViewLoc.y < 0 ||
       scrollViewLoc.y >= scrollViewContainer.height {
      // IntPoint isn't contained in menu.
      return false
    }

    if isScrollButtonAt(source: menu, x: scrollViewLoc.x, y: scrollViewLoc.y, part: &(part.type)) {
      part.submenu = menu
      return true
    }

    // Not over the scroll button. Check the actual menu.
    if doesSubmenuContainLocation(submenu: menu, screenLoc: screenLoc) {
      var menuLoc = screenLoc
      View.convertPointFromScreen(dst: menu, point: &menuLoc)
      part.menu = getMenuItemAt(menu: menu, x: menuLoc.x, y: menuLoc.y)
      part.type = MenuPartType.MenuItem
      part.submenu = menu
      if part.menu == nil {
        part.parent = menu.menuItem
      }
      return true
    }

    // While the mouse isn't over a menu item or the scroll buttons of menu, it
    // is contained by menu and so we return true. If we didn't return true other
    // menus would be searched, even though they are likely obscured by us.
    return true
  }

  // Returns the RootView of the target for the mouse event, if there is a
  // target at |source_loc|.
  fileprivate func getRootView(source: SubmenuView,
                               sourceLoc: IntPoint) -> MenuHostRootView? {
    let part = getMenuPart(source: source, sourceLoc: sourceLoc)
    if let widget = part.submenu?.widget {
      return widget.rootView as? MenuHostRootView
    }
    return nil
  }

  // Converts the located event from |source|'s geometry to |dst|'s geometry,
  // iff the root view of source and dst differ.
  fileprivate func convertLocatedEventForRootView(source: View,
                                                  dst: View,
                                                  event: inout LocatedEvent) {
    if source.widget!.rootView === dst {
      return
    }

    var newLocation = event.location
    View.convertPointToScreen(src: source, point: &newLocation)
    View.convertPointFromScreen(dst: dst, point: &newLocation)
    event.location = newLocation
  }

  // Returns true if the SubmenuView contains the specified location. This does
  // NOT included the scroll buttons, only the submenu view.
  fileprivate func doesSubmenuContainLocation(submenu: SubmenuView,
                                  screenLoc: IntPoint) -> Bool {
    var viewLoc = screenLoc
    View.convertPointFromScreen(dst: submenu, point: &viewLoc)
    let visRect = submenu.visibleBounds
    return visRect.contains(x: viewLoc.x, y: viewLoc.y)
  }

  // Opens/Closes the necessary menus such that state_ matches that of
  // pending_state_. This is invoked if submenus are not opened immediately,
  // but after a delay.
  fileprivate func commitPendingSelection() {
    stopShowTimer()

    var pathsDifferAt = 0
    var currentPath: [MenuItemView] = []
    var newPath: [MenuItemView] = []
    
    buildPathsAndCalculateDiff(oldItem: state.item!, newItem: pendingState.item!, oldPath: &currentPath, newPath: &newPath, firstDiffAt: &pathsDifferAt)

    // Hide the old menu.
    for i in pathsDifferAt..<currentPath.count {
      if let menu = currentPath[i].submenu {
        menu.hide()
      }
    }

    // Copy pending to state, making sure to preserve the direction menus were
    // opened.
    let pendingOpenDirection = state.openLeading
    state.openLeading = Set<Bool>()
    state = pendingState
    state.openLeading = pendingOpenDirection

    let depth = MenuController.menuDepth(item: state.item)
    if depth == 0 {
      state.openLeading.removeAll(keepingCapacity: true)
    } else {
      var cachedSize = state.openLeading.count
      //DCHECK_GE(menu_depth, 0)
      while cachedSize >= depth {
        //state.openLeading.popBack()
        let lastItem = state.openLeading.index(state.openLeading.endIndex, offsetBy: -1)
        state.openLeading.remove(at: lastItem)
        cachedSize -= 1
      }
    }

    if state.item == nil {
      // Nothing to select.
      stopScrolling()
      return
    }

    // Open all the submenus preceeding the last menu item (last menu item is
    // handled next).
    if newPath.count > 1 {
      for i in 0..<newPath.count - 1 {
        openMenu(item: newPath[i])
      }
    }

    if state.submenuOpen {
      // The submenu should be open, open the submenu if the item has a submenu.
      if state.item!.hasSubmenu {
        openMenu(item: state.item!)
      } else {
        state.submenuOpen = false
      }
    } else if let menu = state.item!.submenu {
      if menu.isShowing {
        menu.hide()
      }
    }

    if let menu = scrollTask?.submenu {
      // Stop the scrolling if none of the elements of the selection contain
      // the menu being scrolled.
      var found = false
      var menuItem = state.item
    
      while menuItem != nil && !found {
        found = (menuItem!.hasSubmenu && menuItem!.submenu!.isShowing && menuItem!.submenu === menu)
        menuItem = menuItem!.parentMenuItem
      }
    
      if !found {
        stopScrolling()
      }
    }
  }

  // If item has a submenu, it is closed. This does NOT update the selection
  // in anyway.
  fileprivate func closeMenu(item: MenuItemView) {
    guard let menu = item.submenu else {
      return
    }
    menu.hide()
  }

  // If item has a submenu, it is opened. This does NOT update the selection
  // in anyway.
  fileprivate func openMenu(item: MenuItemView) {
    if let menu = item.submenu {
      if menu.isShowing {
        return
      }
    }

    openMenuImpl(item: item, show: true)
    didCapture = true
  }

  // Implementation of OpenMenu. If |show| is true, this invokes show on the
  // menu, otherwise Reposition is invoked.
  fileprivate func openMenuImpl(item: MenuItemView, show: Bool) {
    if show {
      let oldCount = item.submenu!.childCount
      item.delegate!.willShowMenu(menu: item)
      if oldCount != item.submenu!.childCount {
        // If the number of children changed then we may need to add empty items.
        item.removeEmptyMenus()
        item.addEmptyMenus()
      }
    }
    let lastIndex = state.openLeading.index(state.openLeading.endIndex, offsetBy: -1)
    let preferLeading = 
      state.openLeading.isEmpty ? true : state.openLeading[lastIndex]
    var resultingDirection: Bool = false
    let bounds = MenuItemView.isBubble(anchor: state.anchor) ?
        calculateBubbleMenuBounds(item: item, preferLeading: preferLeading, isLeading: &resultingDirection) :
        calculateMenuBounds(item: item, preferLeading: preferLeading, isLeading: &resultingDirection)
    state.openLeading.insert(resultingDirection)
    let doCapture = (!didCapture && isBlockingRun)
    showingSubmenu = true
    if show {
      // Menus are the only place using kGroupingPropertyKey, so any value (other
      // than 0) is fine.
      //var groupingId = 1001
      //let groupingIdPtr = UnsafeRawPointer(&groupingId)
      item.submenu!.showAt(parent: owner!, bounds: bounds, doCapture: doCapture)
      //item.submenu!.widget.setNativeWindowProperty(TooltipManager.kGroupingPropertyKey, &groupingId)//groupingIdPtr)
      //item.submenu!.widget.setWindowProperty(TooltipManager.kGroupingPropertyKey, &groupingId)//groupingIdPtr)
    } else {
      item.submenu!.reposition(bounds: bounds)
    }
    showingSubmenu = false
  }

  // Invoked when the children of a menu change and the menu is showing.
  // This closes any submenus and resizes the submenu.
  internal func menuChildrenChanged(item: MenuItemView) {
    var ancestor: MenuItemView? = state.item
    
    while ancestor != nil && ancestor !== item {
      ancestor = ancestor!.parentMenuItem
    }

    if ancestor == nil {
      ancestor = pendingState.item
      
      while ancestor != nil && ancestor !== item {
        ancestor = ancestor!.parentMenuItem
      }

      if ancestor == nil {
        return
      }

    }
    
    setSelection(menuItem: item, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
    
    if item.hasSubmenu {
      openMenuImpl(item: item, show: false)
    }
  }

  // Builds the paths of the two menu items into the two paths, and
  // sets first_diff_at to the location of the first difference between the
  // two paths.
  fileprivate func buildPathsAndCalculateDiff(oldItem: MenuItemView,
                                              newItem: MenuItemView,
                                              oldPath: inout [MenuItemView],
                                              newPath: inout [MenuItemView],
                                              firstDiffAt: inout Int) {
    buildMenuItemPath(item: oldItem, path: &oldPath)
    buildMenuItemPath(item: newItem, path: &newPath)

    let commonSize = min(oldPath.count, newPath.count)

    // Find the first difference between the two paths, when the loop
    // returns, diff_i is the first index where the two paths differ.
    for i in 0..<commonSize {
      if oldPath[i] !== newPath[i] {
        firstDiffAt = i
        return
      }
    }

    firstDiffAt = commonSize
  }

  // Builds the path for the specified item.
  fileprivate func buildMenuItemPath(item: MenuItemView?, path: inout [MenuItemView]) {
    guard let menuItem = item else {
      return
    }
    
    buildMenuItemPath(item: menuItem.parentMenuItem, path: &path)
    path.append(menuItem)
  }

  // Starts/stops the timer that commits the pending state to state
  // (opens/closes submenus).
  fileprivate func startShowTimer() {
    //showTimer.start(TimeDelta.FromMilliseconds(MenuConfig.instance.showDelay),
    //  self, commitPendingSelection)
    // TODO: fix
    showTimer.start(delay: TimeDelta(milliseconds: Int64(MenuConfig.instance().showDelay)), {
      self.commitPendingSelection()
    })
  }

  fileprivate func stopShowTimer() {
    showTimer.stop()
  }

  // Starts/stops the timer cancel the menu. This is used during drag and
  // drop when the drop enters/exits the menu.
  fileprivate func startCancelAllTimer() {
    //cancelAllTimer.start(TimeDelta.FromMilliseconds(closeOnExitTime),
    //                     self, cancelAll)
    cancelAllTimer.start(delay: TimeDelta(milliseconds: Int64(closeOnExitTime)),
                         { self.cancelAll() })
  }
  
  fileprivate func stopCancelAllTimer() {
    cancelAllTimer.stop()
  }

  // Calculates the bounds of the menu to show. is_leading is set to match the
  // direction the menu opened in.
  internal func calculateMenuBounds(item: MenuItemView,
                                    preferLeading: Bool,
                                    isLeading: inout Bool) -> IntRect {
    guard let submenu = item.submenu else {
      // TODO: exception
      return IntRect()
    }
   
    //DCHECK(submenu)

    var pref = submenu.scrollViewContainer.preferredSize

    // For comboboxes, ensure the menu is at least as wide as the anchor.
    if isCombobox {
      pref.width = max(pref.width, state.initialBounds.width)
    }

    // Don't let the menu go too wide.
    pref.width = min(pref.width, item.delegate!.getMaxWidthForMenu(menu: item))

    if !state.monitorBounds.isEmpty {
      pref.width = min(pref.width, state.monitorBounds.width)
    }

    // Assume we can honor prefer_leading.
    isLeading = preferLeading

    var x: Int, y: Int

    let menuConfig = MenuConfig.instance()

    if item.parentMenuItem == nil {
      // First item, position relative to initial location.
      x = state.initialBounds.x

      // Offsets for context menu prevent menu items being selected by
      // simply opening the menu (bug 142992).
      if menuConfig.offsetContextMenus && state.contextMenu {
        x += 1
      }

      y = state.initialBounds.bottom
      if state.anchor == .TopRight {
        x = x + state.initialBounds.width - pref.width
        if menuConfig.offsetContextMenus && state.contextMenu {
          x -= 1
        }
      } else if state.anchor == .BottomCenter {
        x = x - (pref.width - state.initialBounds.width) / 2
        if pref.height > state.initialBounds.y + centeredContextMenuYOffset {
          // Menu does not fit above the anchor. We move it to below.
          y = state.initialBounds.y - centeredContextMenuYOffset
        } else {
          y = max(0, state.initialBounds.y - pref.height) + centeredContextMenuYOffset
        }
      }

      if !state.monitorBounds.isEmpty &&
          y + pref.height > state.monitorBounds.bottom {
        // The menu doesn't fit fully below the button on the screen. The menu
        // position with respect to the bounds will be preserved if it has
        // already been drawn. When the requested positioning is below the bounds
        // it will shrink the menu to make it fit below.
        // If the requested positioning is best fit, it will first try to fit the
        // menu below. If that does ;not fit it will try to place it above. If
        // that will not fit it will place it at the bottom of the work area and
        // moving it off the initial_bounds region to avoid overlap.
        // In all other requested position styles it will be flipped above and
        // the height will be shrunken to the usable height.
        if item.actualMenuPosition == MenuItemView.MenuPosition.BelowBounds {
          pref.height = min(pref.height,
                            state.monitorBounds.bottom - y)
        } else if item.actualMenuPosition ==
                  MenuItemView.MenuPosition.BestFit {
          var orientation = MenuItemView.MenuPosition.BelowBounds
          if state.monitorBounds.height < pref.height {
            // Handle very tall menus.
            pref.height = state.monitorBounds.height
            y = state.monitorBounds.y
          } else if state.monitorBounds.y + pref.height < state.initialBounds.y {
            // Flipping upwards if there is enough space.
            y = state.initialBounds.y - pref.height
            orientation = MenuItemView.MenuPosition.AboveBounds
          } else {
            // It is allowed to move the menu a bit around in order to get the
            // best fit and to avoid showing scroll elements.
            y = state.monitorBounds.bottom - pref.height
          }
          if orientation == MenuItemView.MenuPosition.BelowBounds {
            // The menu should never overlap the owning button. So move it.
            // We use the anchor view style to determine the preferred position
            // relative to the owning button.
            if state.anchor == .TopLeft {
              // The menu starts with the same x coordinate as the owning button.
              if x + state.initialBounds.width + pref.width >
                  state.monitorBounds.right {
                x -= pref.width  // Move the menu to the left of the button.
              } else {
                x += state.initialBounds.width // Move the menu right.
              }
            } else {
              // The menu should end with the same x coordinate as the owning
              // button.
              if state.monitorBounds.x >
                  state.initialBounds.x - pref.width {
                x = state.initialBounds.right  // Move right of the button.
              } else {
                x = state.initialBounds.x - pref.width // Move left.
              }
            }
          }
          item.actualMenuPosition = orientation
        } else {
          pref.height = min(pref.height, state.initialBounds.y - state.monitorBounds.y)
          y = state.initialBounds.y - pref.height
          item.actualMenuPosition = MenuItemView.MenuPosition.AboveBounds
        }
      } else if item.actualMenuPosition == MenuItemView.MenuPosition.AboveBounds {
        pref.height = min(pref.height, state.initialBounds.y - state.monitorBounds.y)
        y = state.initialBounds.y - pref.height
      } else {
        item.actualMenuPosition = MenuItemView.MenuPosition.BelowBounds
      }
      if state.monitorBounds.width != 0 &&
          menuConfig.offsetContextMenus && state.contextMenu {
        if x + pref.width > state.monitorBounds.right {
          x = state.initialBounds.x - pref.width - 1
        }
        if x < state.monitorBounds.x {
          x = state.monitorBounds.x
        }
      }
    } else {
      // Not the first menu position it relative to the bounds of the menu
      // item.
      var itemLoc = IntPoint()
      View.convertPointToScreen(src: item, point: &itemLoc)

      // We must make sure we take into account the UI layout. If the layout is
      // RTL, then a 'leading' menu is positioned to the left of the parent menu
      // item and not to the right.
      let layoutIsRtl = i18n.isRTL
      let createOnTheRight: Bool = (preferLeading && !layoutIsRtl()) ||
                                (!preferLeading && layoutIsRtl())
      let submenuHorizontalInset = menuConfig.submenuHorizontalInset

      if createOnTheRight {
        x = itemLoc.x + item.width - submenuHorizontalInset
        if state.monitorBounds.width != 0 &&
            x + pref.width > state.monitorBounds.right {
          if layoutIsRtl() {
            isLeading = true
          }
          else {
            isLeading = false
          }
          x = itemLoc.x - pref.width + submenuHorizontalInset
        }
      } else {
        x = itemLoc.x - pref.width + submenuHorizontalInset
        if state.monitorBounds.width != 0 && x < state.monitorBounds.x {
          if layoutIsRtl() {
            isLeading = false
          } else {
            isLeading = true
          }
          x = itemLoc.x + item.width - submenuHorizontalInset
        }
      }
      y = itemLoc.y - menuConfig.menuVerticalBorderSize
      if state.monitorBounds.width != 0 {
        pref.height = min(pref.height, state.monitorBounds.height)
        if y + pref.height > state.monitorBounds.bottom {
          y = state.monitorBounds.bottom - pref.height
        }
        if y < state.monitorBounds.y {
          y = state.monitorBounds.y
        }
      }
    }

    if state.monitorBounds.width != 0 {
      if x + pref.width > state.monitorBounds.right {
        x = state.monitorBounds.right - pref.width
      }
      if x < state.monitorBounds.x {
        x = state.monitorBounds.x
      }
    }
    return IntRect(x: x, y: y, width: pref.width, height: pref.height)
  }

  // Calculates the bubble bounds of the menu to show. is_leading is set to
  // match the direction the menu opened in.
  fileprivate func calculateBubbleMenuBounds(item: MenuItemView,
                                      preferLeading: Bool,
                                      isLeading: inout Bool) -> IntRect {
        // Assume we can honor prefer_leading.
    isLeading = preferLeading

    guard let submenu = item.submenu else {
      return IntRect()
    }

    var pref = submenu.scrollViewContainer.preferredSize
    let ownerBounds = pendingState.initialBounds

    // First the size gets reduced to the possible space.
    if !state.monitorBounds.isEmpty {
      var maxWidth = state.monitorBounds.width
      var maxHeight = state.monitorBounds.height
      // In case of bubbles, the maximum width is limited by the space
      // between the display corner and the target area + the tip size.
      if state.anchor == .BubbleLeft {
        maxWidth = ownerBounds.x - state.monitorBounds.x +
                    bubbleTipSizeLeftRight
      } else if state.anchor == .BubbleRight {
        maxWidth = state.monitorBounds.right - ownerBounds.right +
                    bubbleTipSizeLeftRight
      } else if state.anchor == .BubbleAbove {
        maxHeight = ownerBounds.y - state.monitorBounds.y +
                    bubbleTipSizeTopBottom
      } else if state.anchor == .BubbleBelow {
        maxHeight = state.monitorBounds.bottom - ownerBounds.bottom +
                    bubbleTipSizeTopBottom
      }
      // The space for the menu to cover should never get empty.
      //DCHECK_GE(max_width, kBubbleTipSizeLeftRight)
      //DCHECK_GE(max_height, kBubbleTipSizeTopBottom)
      pref.width = min(pref.width, maxWidth)
      pref.height = min(pref.height, maxHeight)
    }
    // Also make sure that the menu does not go too wide.
    pref.width = min(pref.width, item.delegate!.getMaxWidthForMenu(menu: item))

    var x: Int, y: Int
    if state.anchor == .BubbleAbove ||
        state.anchor == .BubbleBelow {
      if state.anchor == .BubbleAbove {
        y = ownerBounds.y - pref.height + bubbleTipSizeTopBottom
      } else {
        y = ownerBounds.bottom - bubbleTipSizeTopBottom
      }
      x = ownerBounds.centerPoint.x - pref.width / 2
      let xOld = x
      if x < state.monitorBounds.x {
        x = state.monitorBounds.x
      } else if x + pref.width > state.monitorBounds.right {
        x = state.monitorBounds.right - pref.width
      }
      submenu.scrollViewContainer.bubbleArrowOffset = 
        pref.width / 2 - x + xOld
    } else {
      if state.anchor == .BubbleRight {
        x = ownerBounds.right - bubbleTipSizeLeftRight
      } else {
        x = ownerBounds.x - pref.width + bubbleTipSizeLeftRight
      }

      y = ownerBounds.centerPoint.y - pref.height / 2
      let yOld = y
      if y < state.monitorBounds.y {
        y = state.monitorBounds.y
      } else if y + pref.height > state.monitorBounds.bottom {
        y = state.monitorBounds.bottom - pref.height
      }
      submenu.scrollViewContainer.bubbleArrowOffset =
          pref.height / 2 - y + yOld
    }
    return IntRect(x: x, y: y, width: pref.width, height: pref.height)
  }

  // Returns the depth of the menu.
  fileprivate class func menuDepth(item: MenuItemView?) -> Int {
     return item != nil ? (menuDepth(item: item!.parentMenuItem) + 1) : 0
  }

  // Selects the next or previous (depending on |direction|) menu item.
  fileprivate func incrementSelection(direction: SelectionIncrementDirectionType) {
    guard let item = pendingState.item else {
      return
    }
  
    if pendingState.submenuOpen && item.hasSubmenu && item.submenu!.isShowing {
      // A menu is selected and open, but none of its children are selected,
      // select the first menu item that is visible and enabled.
      if item.submenu!.menuItemCount > 0 {
        if let toSelect = findInitialSelectableMenuItem(parent: item, direction: direction) {
          setSelection(menuItem: toSelect, types: SetSelectionTypes.SelectionDefault)
        }
        return
      }
    }

    if item.hasChildren {
      if let button = getFirstHotTrackedView(view: item) {
        button.isHotTracked = false
        let toMakeHot = getNextFocusableView(
            ancestor: item, startAt: button, forward: direction == .IncrementSelectionDown)
        if let buttonHot = toMakeHot as? Button {//CustomButton {
          buttonHot.isHotTracked = true
          return
        }
      } else {
        let toMakeHot =
            getInitialFocusableView(start: item, forward: direction == .IncrementSelectionDown)
        
        if let buttonHot = toMakeHot as? Button {//CustomButton {
          buttonHot.isHotTracked = true
          return
        }
      }
    }

    if let parent = item.parentMenuItem {
      let parentCount = parent.submenu!.menuItemCount
      if parentCount > 1 {
        for i in 0..<parentCount {
          if parent.submenu!.getMenuItemAt(index: i) === item {
            guard let toSelect =
                findNextSelectableMenuItem(parent: parent, index: i, direction: direction) else {
              break
            }
            setSelection(menuItem: toSelect, types: SetSelectionTypes.SelectionDefault)
            let toMakeHot = getInitialFocusableView(start: toSelect, forward: direction == .IncrementSelectionDown)
            if let buttonHot = toMakeHot as? Button { //CustomButton {
              buttonHot.isHotTracked = true
            }
            break
          }
        }
      }
    }
  }

  // Returns the first (|direction| == NAVIGATE_SELECTION_DOWN) or the last
  // (|direction| == INCREMENT_SELECTION_UP) selectable child menu item of
  // |parent|. If there are no selectable items returns NULL.
  fileprivate func findInitialSelectableMenuItem(
      parent: MenuItemView,
      direction: SelectionIncrementDirectionType) -> MenuItemView? {
    return findNextSelectableMenuItem(
      parent: parent, index: direction == .IncrementSelectionDown ? -1 : 0, direction: direction)
  }

  // Returns the next or previous selectable child menu item of |parent|
  // starting at |index| and incrementing or decrementing index by 1 depending
  // on |direction|. If there are no more selectable items NULL is returned.
  fileprivate func findNextSelectableMenuItem(
      parent: MenuItemView,
      index: Int,
      direction: SelectionIncrementDirectionType) -> MenuItemView? {
    
    let parentCount = parent.submenu!.menuItemCount
    let stopIndex = (index + parentCount) % parentCount
    let includeAllItems =
        (index == -1 && direction == .IncrementSelectionDown) ||
        (index == 0 && direction == .IncrementSelectionUp)
    let delta = direction == .IncrementSelectionUp ? -1 : 1
    // Loop through the menu items skipping any invisible menus. The loop stops
    // when we wrap or find a visible and enabled child.
    var nindex: Int = index
    repeat {
      nindex = (index + delta + parentCount) % parentCount
      if nindex == stopIndex && !includeAllItems {
        return nil
      }
      if let child = parent.submenu!.getMenuItemAt(index: nindex) {
        if child.isVisible && child.isEnabled {
          return child
        }
      }
    } while (nindex != stopIndex)
    
    return nil
  }

  // If the selected item has a submenu and it isn't currently open, the
  // the selection is changed such that the menu opens immediately.
  fileprivate func openSubmenuChangeSelectionIfCan() {
    guard let item = pendingState.item else {
      return
    }
    
    if !item.hasSubmenu || !item.isEnabled {
      return
    }

    var toSelect: MenuItemView? = nil
    if item.submenu!.menuItemCount > 0 {
      toSelect = findInitialSelectableMenuItem(parent: item, direction: .IncrementSelectionDown)
    }
    if toSelect != nil {
      setSelection(menuItem: toSelect!, types: SetSelectionTypes.SelectionUpdateImmediately)
      return
    }
    // No menu items, just show the sub-menu.
    setSelection(menuItem: item, types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
  }

  // If possible, closes the submenu.
  fileprivate func closeSubmenu() {
    guard let item = state.item, let parentMenuItem = item.parentMenuItem else {
      return
    }

    if item.hasSubmenu && item.submenu!.isShowing {
      setSelection(menuItem: item, types: SetSelectionTypes.SelectionUpdateImmediately)
    } else if parentMenuItem.parentMenuItem != nil {
      setSelection(menuItem: parentMenuItem, types: SetSelectionTypes.SelectionUpdateImmediately)
    }
  }

  // Returns details about which menu items match the mnemonic |key|.
  // |match_function| is used to determine which menus match.
  fileprivate func findChildForMnemonic(
      parent: MenuItemView,
      key: Character,
      match matchFn: (_: MenuItemView, _: Character) -> Bool) -> SelectByCharDetails {

    var details = SelectByCharDetails()

    guard let submenu = parent.submenu else {
      return details
    }

    for i in 0..<submenu.menuItemCount {      
      let child = submenu.getMenuItemAt(index: i)!
      if child.isEnabled && child.isVisible {
        
        if child === pendingState.item {
          details.indexOfItem = i
        }

        if matchFn(child, key) {
          if details.firstMatch == -1 {
            details.firstMatch = i
          } else {
            details.hasMultiple = true
          }
         
          if details.nextMatch == -1 && details.indexOfItem != -1 && i > details.indexOfItem {
            details.nextMatch = i
          }
        }
      }
    }
    return details
  }

  // Selects or accepts the appropriate menu item based on |details|.
  fileprivate func acceptOrSelect(parent: MenuItemView, details: SelectByCharDetails) {
    guard let submenu = parent.submenu else {
      return
    }
    //DCHECK(submenu)
    if !details.hasMultiple {
      // There's only one match, activate it (or open if it has a submenu).
      if submenu.getMenuItemAt(index: details.firstMatch)!.hasSubmenu {
        setSelection(menuItem: submenu.getMenuItemAt(index: details.firstMatch),
          types: SetSelectionTypes(rawValue: SetSelectionTypes.SelectionOpenSubmenu.rawValue | SetSelectionTypes.SelectionUpdateImmediately.rawValue))
      } else {
        accept(item: submenu.getMenuItemAt(index: details.firstMatch), eventFlags: 0)
      }
    } else if details.indexOfItem == -1 || details.nextMatch == -1 {
      setSelection(menuItem: submenu.getMenuItemAt(index: details.firstMatch), types: SetSelectionTypes.SelectionDefault)
    } else {
      setSelection(menuItem: submenu.getMenuItemAt(index: details.nextMatch), types: SetSelectionTypes.SelectionDefault)
    }
  }

  // Selects by mnemonic, and if that doesn't work tries the first character of
  // the title.
  fileprivate func selectByChar(key character: Character) {
    // if !character {
    //   return
    // }

    //let charArray: [Character] = [character, Character("")]
    let charArray = String([character, Character("")])
    let key: Character = charArray.lowercased()[charArray.startIndex]//charArray[0].toLower()//i18n.toLower(charArray)[0]

    guard var item = pendingState.item else {
      return
    }
    
    if !item.hasSubmenu || !item.submenu!.isShowing {
      item = item.parentMenuItem!
    }
    //DCHECK(item)
    //DCHECK(item->HasSubmenu())
    //DCHECK(item->GetSubmenu())
    if item.submenu!.menuItemCount == 0 {
      return
    }

    // Look for matches based on mnemonic first.
    var details: SelectByCharDetails = findChildForMnemonic(parent: item, key: key, match: matchesMnemonic)
    if details.firstMatch != -1 {
      acceptOrSelect(parent: item, details: details)
      return
    }

    if isCombobox {
      item.submenu?.prefixSelector?.insertText(charArray)
    } else {
      // If no mnemonics found, look at first character of titles.
      details = findChildForMnemonic(parent: item, key: key, match: titleMatchesMnemonic)
      if details.firstMatch != -1 {
        acceptOrSelect(parent: item, details: details)
      }
    }
  }

  fileprivate func repostEvent(source: SubmenuView,
                               event: LocatedEvent,
                               screenLoc: IntPoint,
                               nativeView: Window?,//NativeView?,
                               window: Window?) {
    if !event.isMouseEvent && !event.isTouchEvent {
      // TODO(rbyers): Gesture event repost is tricky to get right
      // crbug.com/170987.
      //DCHECK(event->IsGestureEvent())
      return
    }

  #if os(Windows)
    if state.item == nil {
      // We some times get an event after closing all the menus. Ignore it. Make
      // sure the menu is in fact not visible. If the menu is visible, then
      // we're in a bad state where we think the menu isn't visibile but it is.
      //assert(!source.widget.visible)
      return
    }

    state.item.rootMenuItem.submenu.releaseCapture()
  #endif

    if nativeView == nil {
      return
    }

  // #if os(Windows)
  //   let screenLocPixels = win.DIPToScreenPoint(screenLoc)
  //   HWND targetWindow = ::WindowFromPoint(screenLocPixels.toPOINT())
  //   // If we don't find a native window for the HWND at the current location,
  //   // then attempt to find a native window from its parent if one exists.
  //   // There are HWNDs created outside views, which don't have associated
  //   // native windows.
  //   if window == nil {
  //     HWND parent = ::GetParent(targetWindow)
  //     if parent != nil {
  //       if let host = WindowTreeHost.getForAcceleratedWidget(parent) {
  //         targetWindow = parent
  //         window = host.window
  //       }
  //     }
  //   }
  //   // Convert screen_loc to pixels for the Win32 API's like WindowFromPoint,
  //   // PostMessage/SendMessage to work correctly. These API's expect the
  //   // coordinates to be in pixels.
  //   if event.isMouseEvent {
  //     let sourceWindow: HWND = HWNDForNativeView(nativeView)
  //     if targetWindow == nil || sourceWindow == nil ||
  //         GetWindowThreadProcessId(sourceWindow, nil) !=
  //         GetWindowThreadProcessId(targetWindow, nil) {
  //       // Even though we have mouse capture, windows generates a mouse event if
  //       // the other window is in a separate thread. Only repost an event if
  //       // |target_window| and |source_window| were created on the same thread,
  //       // else double events can occur and lead to bad behavior.
  //       return
  //     }

  //     // Determine whether the click was in the client area or not.
  //     // NOTE: WM_NCHITTEST coordinates are relative to the screen.
  //     let coords: LPARAM = MAKELPARAM(screenLocPixels.x, screenLocPixels.y)
  //     let ncHitResult: LRESULT = SendMessage(target_window, WM_NCHITTEST, 0, coords)
  //     let clientArea: Bool = ncHitResult == HTCLIENT

  //     // TODO(sky): this isn't right. The event to generate should correspond with
  //     // the event we just got. MouseEvent only tells us what is down, which may
  //     // differ. Need to add ability to get changed button from MouseEvent.
  //     var eventType: Int
  //     let flags = event.flags
  //     if flags.contains(.LeftMouseButton) {
  //       eventType = clientArea ? WM_LBUTTONDOWN : WM_NCLBUTTONDOWN
  //     } else if flags.contains(.MiddleMouseButton) {
  //       eventType = clientArea ? WM_MBUTTONDOWN : WM_NCMBUTTONDOWN
  //     } else if flags.contains(.RightMouseButton) {
  //       eventType = clientArea ? WM_RBUTTONDOWN : WM_NCRBUTTONDOWN
  //     } else {
  //       assert(false)
  //       return
  //     }

  //     let windowX = screenLocPixels.x
  //     let windowY = screenLocPixels.y
  //     if clientArea {
  //       let pt: POINT(windowX, windowY)
  //       screenToClient(targetWindow, &pt)
  //       windowX = pt.x
  //       windowY = pt.y
  //     }

  //     let target: WPARAM = clientArea ? event.nativeEvent.wParam : ncHitResult
  //     let windowCoords: LPARAM = MAKELPARAM(windowX, windowY)
  //     postMessage(targetWindow, eventType, target, windowCoords)
  //     return
  //   }
  // #endif
    // Non Aura window.
    if window == nil {
      return
    }

    assert(false)
    // TODO: implement
    // MenuMessageLoop.repostEventToWindow(event, window, screenLoc)
  }


  // For Windows and Aura we repost an event which dismisses the |source| menu.
  // The menu may also be canceled depending on the target of the event. |event|
  // is then processed without the menu present. On non-aura Windows, a new
  // mouse event is generated and posted to the window (if there is one) at the
  // location of the event. On aura, the event is reposted on the RootWindow.
  fileprivate func repostEventAndCancel(source: SubmenuView, event: LocatedEvent) {
    var screenLoc = event.location
    View.convertPointToScreen(src: source.scrollViewContainer, point: &screenLoc)

  #if os(Windows)
    let nativeView = source.widget.nativeView
    var window: NativeWindow? = nil
    if nativeView != nil {
      let screen = Screen.instance
      window = screen.getWindowAtScreenPoint(screenLoc)
    }
    // We're going to close and we own the event capture. We need to repost the
    // event, otherwise the window the user clicked on won't get the event.
    repostEvent(source, event, screenLoc, nativeView, window)
  #endif

    // Determine target to see if a complete or partial close of the menu should
    // occur.
    var exitType = ExitType.All
    if !menuStack.isEmpty {
      // We're running nested menus. Only exit all if the mouse wasn't over one
      // of the menus from the last run.
      let lastPart = getMenuPartByScreenCoordinateUsingMenu(
        item: menuStack.last!.0.item!, screenLoc: screenLoc)
      if lastPart.type != MenuPartType.None {
        exitType = .Outermost
      }
    }
    cancel(type: exitType)

  //#if defined(OS_HROMEOS)
    // We're going to exit the menu and want to repost the event so that is
    // is handled normally after the context menu has exited. We call
    // RepostEvent after Cancel so that event capture has been released so
    // that finding the event target is unaffected by the current capture.
    //repostEvent(source, event, screen_loc, native_view, window)
   //#endif
  }

  // Sets the drop target to new_item.
  fileprivate func setDropMenuItem(target newTarget: MenuItemView?, position newPosition: DropPosition) {
    if newTarget === dropTarget && newPosition == dropPosition {
      return
    }

    if let menuItem = dropTarget?.parentMenuItem {
      menuItem.submenu!.setDropMenuItem(item: nil, position: .DropNone)
    }

    dropTarget = newTarget
    dropPosition = newPosition
    if let menuItem = dropTarget?.parentMenuItem {
      menuItem.submenu!.setDropMenuItem(item: newTarget, position: dropPosition)
    }
  }

  // Starts/stops scrolling as appropriate. part gives the part the mouse is
  // over.
  fileprivate func updateScrolling(part: MenuPart) {
    if !part.isScroll && scrollTask == nil {
      return
    }

    if scrollTask == nil {
      scrollTask = MenuScrollTask()
    }

    scrollTask!.update(part: part)
  }

  // Stops scrolling.
  fileprivate func stopScrolling() {
    scrollTask = nil
  }

  // Updates active mouse view from the location of the event and sends it
  // the appropriate events. This is used to send mouse events to child views so
  // that they react to click-drag-release as if the user clicked on the view
  // itself.
  fileprivate func updateActiveMouseView(eventSource: SubmenuView,
    event: MouseEvent,
    targetMenu: View?) {

    var target: View? = nil
    var targetMenuLoc = event.location
    if let menu = targetMenu {
      if menu.hasChildren {
        // Locate the deepest child view to send events to.  This code assumes we
        // don't have to walk up the tree to find a view interested in events. This
        // is currently true for the cases we are embedding views, but if we embed
        // more complex hierarchies it'll need to change.
        View.convertPointToScreen(src: eventSource.scrollViewContainer, point: &targetMenuLoc)
        View.convertPointFromScreen(dst: menu, point: &targetMenuLoc)
        target = menu.getEventHandlerFor(point: targetMenuLoc)
        if target === targetMenu || !target!.isEnabled {
          target = nil
        }
      }
    }
    
    var activeMouseView = activeMouseViewTracker.view
    
    if target !== activeMouseView {
      sendMouseCaptureLostToActiveView()
      activeMouseView = target
      if let mouseView = activeMouseView {
        var targetPoint = targetMenuLoc
        View.convertPointToTarget(
            source: targetMenu!, target: mouseView, point: &targetPoint)

        let mouseEnteredEvent = MouseEvent(type: .MouseEntered,
          location: targetPoint,
          rootLocation: targetPoint, 
          timestamp: Int64(TimeTicks.now.microseconds), 
          flags: EventFlags(rawValue: 0), 
          changedButtonFlags: 0)
        
        mouseView.onMouseEntered(event: mouseEnteredEvent)
      
        let mousePressedEvent = MouseEvent(
            type: .MousePressed, 
            location: targetPoint, 
            rootLocation: targetPoint,
            timestamp: Int64(TimeTicks.now.microseconds), 
            flags: event.flags, 
            changedButtonFlags: event.changedButtonFlags)
        let _ = mouseView.onMousePressed(event: mousePressedEvent)
      }
    }

    if let mouseView = activeMouseView {
      var targetPoint = targetMenuLoc
      View.convertPointToTarget(source: targetMenu!, target: mouseView, point: &targetPoint)
      
      let mouseDraggedEvent = MouseEvent(
          type: .MouseDragged, 
          location: targetPoint, 
          rootLocation: targetPoint, 
          timestamp: Int64(TimeTicks.now.microseconds),
          flags: event.flags, 
          changedButtonFlags: event.changedButtonFlags)
      let _ = mouseView.onMouseDragged(event: mouseDraggedEvent)
    }
  }

  // Sends a mouse release event to the current active mouse view and sets
  // it to null.
  fileprivate func sendMouseReleaseToActiveView(eventSource: SubmenuView, event: MouseEvent) {
    guard let activeMouseView = activeMouseViewTracker.view else {
      return  
    }

    var targetLoc = event.location
    View.convertPointToScreen(src: eventSource.scrollViewContainer,
                              point: &targetLoc)
    View.convertPointFromScreen(dst: activeMouseView, point: &targetLoc)
    let releaseEvent = MouseEvent(type: .MouseReleased, location: targetLoc, rootLocation: targetLoc,
                                  timestamp: Int64(TimeTicks.now.microseconds), flags: event.flags,
                                  changedButtonFlags: event.changedButtonFlags)
    // Reset active mouse view before sending mouse released. That way if it calls
    // back to us, we aren't in a weird state.
    activeMouseViewTracker.clear()
    activeMouseView.onMouseReleased(event: releaseEvent)
  }
  // Sends a mouse capture lost event to the current active mouse view and sets
  // it to null.
  fileprivate func sendMouseCaptureLostToActiveView() {
    guard let activeMouseView = activeMouseViewTracker.view else {
      return  
    }
    // Reset the active_mouse_view_ before sending mouse capture lost. That way if
    // it calls back to us, we aren't in a weird state.
    activeMouseViewTracker.clear()
    activeMouseView.onMouseCaptureLost()
  }

  // Performs the teardown of menus. This will notifiy the |delegate_|. If
  // |exit_type_| is EXIT_ALL all nested runs will be exited.
  fileprivate func exitMenu() {

  }

  // Performs the teardown of the menu launched by Run(). The selected item is
  // returned.
  fileprivate func exitTopMostMenu() -> MenuItemView? {
    return nil
  }

  // Handles the mouse location event on the submenu |source|.
  fileprivate func handleMouseLocation(source: SubmenuView,
                                       mouseLocation: IntPoint) {
    if showingSubmenu {
      return
    }

    // Ignore mouse events if we're closing the menu.
    if exitType != .None {
      return
    }

    let part = getMenuPart(source: source, sourceLoc: mouseLocation)
    updateScrolling(part: part)

    if !isBlockingRun {
      return
    }

    if part.type == MenuPartType.None && showSiblingMenu(source: source, mouseLocation: mouseLocation) {
      return
    }

    if part.type == MenuPartType.MenuItem && part.menu != nil {
      setSelection(menuItem: part.menu, types: SetSelectionTypes.SelectionOpenSubmenu)
    } else if !part.isScroll && pendingState.item?.parentMenuItem != nil &&
              (!pendingState.item!.hasSubmenu ||
                !pendingState.item!.submenu!.isShowing) {
      // On exit if the user hasn't selected an item with a submenu, move the
      // selection back to the parent menu item.
      setSelection(menuItem: pendingState.item!.parentMenuItem!, types: SetSelectionTypes.SelectionOpenSubmenu)
    }
  }

  // Sets hot-tracked state to the first focusable descendant view of |item|.
  fileprivate func setInitialHotTrackedView(item: MenuItemView,
                                            direction: SelectionIncrementDirectionType) {

  }

  // Updates the current |hot_button_| and its hot tracked state.
  fileprivate func setHotTrackedButton(hotButton: Button?) {

  }

}

fileprivate func matchesMnemonic(menu: MenuItemView, key: Character) -> Bool {
  return key != Character("") && menu.mnemonic == key
}

// Returns true if |menu| doesn't have a mnemonic and first character of the its
// title is |key|.
fileprivate func titleMatchesMnemonic(menu: MenuItemView, key: Character) -> Bool {
  if menu.mnemonic != Character("") {
    return false
  }

  let lowerTitle = menu.title.lowercased()//i18n.toLower(menu.title)
  return !lowerTitle.isEmpty && lowerTitle[lowerTitle.startIndex] == key
}

// Returns the first descendant of |view| that is hot tracked.
func getFirstHotTrackedView(view inputView: View?) -> Button? {
  
  guard let view = inputView else {
    return nil
  }

  if let button = view as? Button {
    if button.isHotTracked {
      return button
    }
  }
  
  for i in 0..<view.childCount {
    if let hotView = getFirstHotTrackedView(view: view.childAt(index: i)) {
      return hotView
    }
  }
  return nil
}

// Recurses through the child views of |view| returning the first view starting
// at |start| that is focusable. A value of -1 for |start| indicates to start at
// the first view (if |forward| is false, iterating starts at the last view). If
// |forward| is true the children are considered first to last, otherwise last
// to first.
func getFirstFocusableView(view: View, start: Int, forward: Bool) -> View? {
  if forward {
    let begin = start == -1 ? 0 : start
    for i in begin..<view.childCount {
      if let deepest = getFirstFocusableView(view: view.childAt(index: i)!, start: -1, forward: forward) {
        return deepest
      }
    }
  } else {
    let begin = (start == -1 ? view.childCount - 1 : start)
    for i in (0...begin).reversed() {
      if let deepest = getFirstFocusableView(view: view.childAt(index: i)!, start: -1, forward: forward) {
        return deepest  
      }
    }
  }
  return view.focusable ? view : nil
}

// Returns the first child of |start| that is focusable.
func getInitialFocusableView(start: View, forward: Bool) -> View? {
  return getFirstFocusableView(view: start, start: -1, forward: forward)
}

// Returns the next view after |start_at| that is focusable. Returns NULL if
// there are no focusable children of |ancestor| after |start_at|.
func getNextFocusableView(ancestor: View, startAt: View, forward: Bool) -> View? {
  var parent = startAt
  repeat {
    guard let newParent = parent.parent else {
      return nil
    }
    var index = newParent.getIndexOf(view: parent)
    index += forward ? 1 : -1
    if forward || index != -1 {
      if let next = getFirstFocusableView(view: newParent, start: index, forward: forward) {
        return next
      }
    }
    parent = newParent
  } while parent !== ancestor
  return nil
}

internal func scaleFactorForDragFromWidget(_ widget: UIWidget?) -> Float {
  var deviceScale: Float = 1.0
  if let window = widget?.window {
    deviceScale = UI.getScaleFactorForWindow(window: window)
  }
  return deviceScale
}

//extension MenuController.NestedState : Hashable {
  // TODO: implement
//  public var hashValue: Int { return -1 }
//}