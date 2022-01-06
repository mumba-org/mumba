// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform

class MouseEnterExitEvent : MouseEvent {
  init(event: MouseEvent, eventType: EventType) {
    super.init(model: event, type: eventType)
  }
}

class PreEventDispatchHandler : EventHandler {

  weak var owner: View?

  init(owner: View) {
    self.owner = owner
  }

  func onKeyEvent(event: inout KeyEvent) {

  }

  // Not implemented
  func onEvent(event: inout Event) {}
  func onMouseEvent(event: inout MouseEvent) {}
  func onScrollEvent(event: inout ScrollEvent) {}
  func onTouchEvent(event: inout TouchEvent) {}
  func onGestureEvent(event: inout GestureEvent) {}
  func onCancelMode(event: inout CancelModeEvent) {}

}

class PostEventDispatchHandler : EventHandler {

  init() {}

  func onGestureEvent(event: inout GestureEvent) {

  }

  // Not implemented
  func onEvent(event: inout Event) {}
  func onKeyEvent(event: inout KeyEvent) {}
  func onMouseEvent(event: inout MouseEvent) {}
  func onScrollEvent(event: inout ScrollEvent) {}
  func onTouchEvent(event: inout TouchEvent) {}
  func onCancelMode(event: inout CancelModeEvent) {}

}

public class RootView : View,
                        EventProcessor,
                        FocusTraversable {

  public override var widget: UIWidget? {
    return _widget
  }

  public override var isDrawn: Bool {
    return isVisible
  }

  override public var dragInfo: ViewDragInfo? {
    return _dragInfo
  }

  public var contentsView: View? {

    get {
      if childCount > 0 {
        return childAt(index: 0)
      }
      return nil
    }

    set (view) {

      guard view != nil else {
        return
      }

      layoutManager = FillLayout()

      if hasChildren {
        removeAllChildren(deleteChildren: true)
      }

      addChild(view: view!)
      layout()
    }

  }

  public override var className: String {
    return "RootView"
  }

  public var rootTarget: EventTarget? {
    return self
  }

  public var currentEvent: Event? {
    return nil
  }

  public var focusSearch: FocusSearch? {
    return _focusSearch
  }

  public var focusTraversableParent: FocusTraversable? {
    get {
      return _focusTraversableParent
    }
    set {
      _focusTraversableParent = newValue
    }
  }

  public var focusTraversableParentView: View? {
    get {
      return _focusTraversableParentView
    }
    set {
      _focusTraversableParentView = newValue
    }
  }

  var mousePressedHandler: View?

  var mouseMoveHandler: View?

  var lastClickHandler: View?

  var explicitMouseHandler: Bool

  var lastMouseEventFlags: Int

  var lastMouseEventX: Int

  var lastMouseEventY: Int

  var gestureHandler: View?

  var gestureHandlerSetBeforeProcessing: Bool

  var preDispatchHandler: PreEventDispatchHandler?

  var postDispatchHandler: PostEventDispatchHandler?

  var eventDispatchTarget: View?

  var oldDispatchTarget: View?

  // the RootView owner window
  weak var _widget: UIWidget?

  var _focusSearch: FocusSearch?

  var _focusTraversableParent: FocusTraversable?

  var _focusTraversableParentView: View?

  var _dragInfo: ViewDragInfo

  public init(widget: UIWidget) {
    _widget = widget
    explicitMouseHandler = false
    lastMouseEventFlags = 0
    lastMouseEventX = -1
    lastMouseEventY = -1
    gestureHandlerSetBeforeProcessing = false
    _dragInfo = ViewDragInfo()
    super.init()
    postDispatchHandler = PostEventDispatchHandler()
    preDispatchHandler = PreEventDispatchHandler(owner: self)
    _focusSearch = FocusSearch(root: self, cycle: false, accessibilityMode: false)
    addPreTargetHandler(handler: preDispatchHandler!)
    addPostTargetHandler(handler: postDispatchHandler!)
    let _ = setEventTargeter(targeter: RootViewTargeter(delegate: self, rootView: self))
  }

  deinit {
    if hasChildren {
      removeAllChildren(deleteChildren: true)
    }
  }

  public func notifyNativeViewHierarchyChanged() {
    propagateNativeViewHierarchyChanged()
  }

  public func localeChanged() {
    propagateLocaleChanged()
  }

  public func deviceScaleFactorChanged(deviceScaleFactor: Float) {
    propagateDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
  }

  //public override func layout() {
  //  super.layout()
  //  widget!.onRootViewLayout()
  //}

  public override func schedulePaintInRect(rect: IntRect) {
    if let l = layer {
      let _ = l.schedulePaint(invalidRect: rect)
    } else {
      // PROVAVEL FONTE DO ERRO invalidRect.empty NUNCA É VAZIA!!
      // olhar: xrect = convertRectToParent, localBounds e invalidRect = intersectRects
      let xrect = convertRectToParent(rect: rect)
      let invalidRect = IntRect.intersectRects(a: localBounds, b: xrect)
      ////print("localBounds: \(localBounds) xrect: \(xrect) invalidRect: \(invalidRect)")
      // Quando da o erro:
      // local: 300, 300  xrect: 300, 300 -> volta invalidRect: 300, 300
      // esta correto!!
      // O Problema na verdade nao é esse:
      // Alguem esta mandando a RootView fazer um schedulePaint indevido!!
      // e como xrec e localBounds sempre acabam batendo.. entra no loop
      // e alguem manda pro schedule da RootView novamente sem dever
      if !invalidRect.isEmpty {
        if let w = widget {
          w.schedulePaintInRect(rect: invalidRect)
        }
      }
    }
  }

  public override func onMousePressed(event: MouseEvent) -> Bool {
    updateCursor(event: event)
    setMouseLocationAndFlags(event: event)

    if let handler = mousePressedHandler {
      let mousePressedEvent = MouseEvent(model: event, source: self, target: handler)
      _dragInfo.reset()
      let dispatchDetails = dispatchEvent(target: handler, event: mousePressedEvent)
      if dispatchDetails.dispatcherDestroyed {
        return true
      }
      return true
    }

    assert(!explicitMouseHandler)

    var hitDisabledView = false

    mousePressedHandler = getEventHandlerFor(point: event.location)

    while mousePressedHandler != nil && mousePressedHandler !== self {
      //DVLOG(1) << "OnMousePressed testing "
      //    << mouse_pressed_handler_->GetClassName();
      if !mousePressedHandler!.isEnabled {
        // Disabled views should eat events instead of propagating them upwards.
        hitDisabledView = true
        break
      }

      let mousePressedEvent = MouseEvent(model: event, source: self, target: mousePressedHandler!)

      if mousePressedHandler !== lastClickHandler {
        mousePressedEvent.flags = EventFlags(rawValue: event.flags.rawValue & ~EventFlags.IsDoubleClick.rawValue)
      }

      _dragInfo.reset()

      let dispatchDetails = dispatchEvent(target: mousePressedHandler!, event: mousePressedEvent)

      if dispatchDetails.dispatcherDestroyed {
        return mousePressedEvent.handled
      }

      if mousePressedHandler == nil {
        break
      }

      if mousePressedEvent.handled {
        lastClickHandler = mousePressedHandler
        //DVLOG(1) << "OnMousePressed handled by "
        //    << mousePressedHandler.className
        return true
      }
      mousePressedHandler = mousePressedHandler!.parent
    }
    // Reset mouse_pressed_handler_ to indicate that no processing is occurring.
    mousePressedHandler = nil

    // In the event that a double-click is not handled after traversing the
    // entire hierarchy (even as a single-click when sent to a different view),
    // it must be marked as handled to avoid anything happening from default
    // processing if it the first click-part was handled by us.
    if lastClickHandler != nil && (event.flags.rawValue & EventFlags.IsDoubleClick.rawValue) != 0 {
      hitDisabledView = true
    }

    lastClickHandler = nil
    return hitDisabledView
  }

  public override func onMouseDragged(event: MouseEvent) -> Bool {
    if let mouseHandler = mousePressedHandler {
      setMouseLocationAndFlags(event: event)

      let mouseEvent = MouseEvent(model: event, source: self, target: mouseHandler)

      let dispatchDetails = dispatchEvent(target: mouseHandler, event: mouseEvent)

      if dispatchDetails.dispatcherDestroyed {
        return false
      }
    }
    return false
  }

  public override func onMouseReleased(event: MouseEvent) {
    updateCursor(event: event)

    if let mouseHandler = mousePressedHandler {
      let mouseReleased = MouseEvent(model: event, source: self, target: mouseHandler)
      setMouseHandler(handler: nil)
      let dispatchDetails = dispatchEvent(target: mouseHandler, event: mouseReleased)
      if dispatchDetails.dispatcherDestroyed {
        return
      }
    }
  }

  public override func onMouseCaptureLost() {
    if mousePressedHandler != nil || gestureHandler != nil {
      if mousePressedHandler != nil {
        let lastPoint = IntPoint(x: lastMouseEventX, y: lastMouseEventY)
        let releaseEvent = MouseEvent(type: EventType.MouseReleased, location: lastPoint,
                                      //lastPoint, EventTimeForNow(),
                                      rootLocation: lastPoint, timestamp: 0,
                                      flags: EventFlags(rawValue: lastMouseEventFlags), changedButtonFlags: 0)
        updateCursor(event: releaseEvent)
      }
      setMouseHandler(handler: nil)
      if let mouseHandler = mousePressedHandler {
        mouseHandler.onMouseCaptureLost()
      } else if let ghandler = gestureHandler {
        ghandler.onMouseCaptureLost()
      }
    }
  }

  public override func onMouseMoved(event: MouseEvent) {
    var v = getEventHandlerFor(point: event.location)

    while v != nil && !v!.isEnabled && v !== mouseMoveHandler {
      v = v!.parent
    }

    if v != nil && v !== self {
      if v !== mouseMoveHandler {
        if let mouseHandler = mouseMoveHandler {
           if !mouseHandler.notifyEnterExitOnChild || !mouseHandler.contains(view: v!) {
            let exit = MouseEnterExitEvent(event: event, eventType: EventType.MouseExited)
            exit.convertLocationToTarget(source: self, target: mouseHandler)
            var dispatchDetails = dispatchEvent(target: mouseHandler, event: exit)
            if dispatchDetails.dispatcherDestroyed {
              return
            }

            if !dispatchDetails.targetDestroyed {
              dispatchDetails = notifyEnterExitOfDescendant(event: event, type: EventType.MouseExited, view: mouseHandler, sibling: v)
              if dispatchDetails.dispatcherDestroyed {
                return
              }
            }
          }
        }
        let oldHandler = mouseMoveHandler
        mouseMoveHandler = v
        if let mouseHandler = mouseMoveHandler {
          if !mouseHandler.notifyEnterExitOnChild || !mouseHandler.contains(view: oldHandler!) {
            let entered = MouseEnterExitEvent(event: event, eventType: EventType.MouseEntered)
            entered.convertLocationToTarget(source: self, target: mouseHandler)
            var dispatchDetails = dispatchEvent(target: mouseHandler, event: entered)
            if dispatchDetails.dispatcherDestroyed || dispatchDetails.targetDestroyed {
              return
            }

            dispatchDetails = notifyEnterExitOfDescendant(
              event: event,
              type: EventType.MouseEntered,
              view: mouseHandler,
              sibling: oldHandler)

            if dispatchDetails.dispatcherDestroyed || dispatchDetails.targetDestroyed {
              return
            }
          }
        }
      } // if v !== mouseMoveHandler
      let movedEvent = MouseEvent(model: event, source: self, target: mouseMoveHandler!)
      mouseMoveHandler!.onMouseMoved(event: movedEvent)
      if (movedEvent.flags.rawValue & EventFlags.IsNonClient.rawValue) == 0 {
        widget!.setCursor(cursor: mouseMoveHandler!.getCursor(event: movedEvent))
      }
    } else if let mouseHandler = mouseMoveHandler {
      let exited = MouseEnterExitEvent(event: event, eventType: EventType.MouseExited)
      var dispatchDetails = dispatchEvent(target: mouseHandler, event: exited)
      if dispatchDetails.dispatcherDestroyed {
        return
      }

      if !dispatchDetails.targetDestroyed {
        dispatchDetails = notifyEnterExitOfDescendant(event: event,
                                                      type: EventType.MouseExited,
                                                      view: mouseHandler, sibling: v)
        if dispatchDetails.dispatcherDestroyed {
         return
        }
      }

      if (event.flags.rawValue & EventFlags.IsNonClient.rawValue) == 0 {
        widget!.setCursor(cursor: PlatformCursorNil)
      }
      mouseMoveHandler = nil
    } // else if mouseMoveHandler != nil
  }

  public override func onMouseExited(event: MouseEvent) {
    if let mouseHandler = mouseMoveHandler {
      let exited = MouseEnterExitEvent(event: event, eventType: EventType.MouseExited)
      var dispatchDetails = dispatchEvent(target: mouseHandler, event: exited)
      if dispatchDetails.dispatcherDestroyed {
        return
      }
      // The mouse_move_handler_ could have been destroyed in the context of the
      // mouse exit event.
      if !dispatchDetails.targetDestroyed {
        dispatchDetails = notifyEnterExitOfDescendant(event: event, type: EventType.MouseExited, view: mouseHandler, sibling: nil)
        if dispatchDetails.dispatcherDestroyed {
          return
        }
      }
      mouseMoveHandler = nil
    }
  }

  public override func onMouseWheel(event: MouseWheelEvent) -> Bool {
    var v = getEventHandlerFor(point: event.location)
    while v != nil && v !== self && !event.handled {
      let dispatchDetails = dispatchEvent(target: v!, event: event)
      if dispatchDetails.dispatcherDestroyed || dispatchDetails.targetDestroyed {
        return event.handled
      }
      v = v!.parent
    }
    return event.handled
  }

  public override func setMouseHandler(handler: View?) {
    explicitMouseHandler = (handler != nil)
    mousePressedHandler = handler
    gestureHandler = handler
    _dragInfo.reset()
  }

  public override func getAccessibleState(state: inout AXViewState) {

  }

  public override func updateParentLayer() {
    if layer != nil {
      reparentLayer(offset: IntVec2(x: mirroredX, y: y), parentLayer: widget!.layer)
    }
  }

  public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    widget!.viewHierarchyChanged(details: details)

    if !details.isAdd {
      if !explicitMouseHandler && mousePressedHandler === details.child {
        mousePressedHandler = nil
      }
      if mouseMoveHandler === details.child {
        mouseMoveHandler = nil
      }
      if gestureHandler === details.child {
        gestureHandler = nil
      }
      if eventDispatchTarget === details.child {
        eventDispatchTarget = nil
      }
      if oldDispatchTarget === details.child {
        oldDispatchTarget = nil
      }
    }
  }

  public override func visibilityChanged(startingFrom: View, isVisible: Bool) {
    if !isVisible {
      // When the root view is being hidden (e.g. when widget is minimized)
      // handlers are reset, so that after it is reshown, events are not captured
      // by old handlers.
      explicitMouseHandler = false
      mousePressedHandler = nil
      mouseMoveHandler = nil
      gestureHandler = nil
      eventDispatchTarget = nil
      oldDispatchTarget = nil
    }
  }

  public override func onPaint(canvas: Canvas) {
    if layer == nil || !layer!.fillsBoundsOpaquely {
      canvas.drawColor(color: Color.Black, mode: BlendMode.Clear)
    }
    super.onPaint(canvas: canvas)
  }

  override func calculateOffsetToAncestorWithLayer(layerParent: inout Layer?) -> IntVec2 {
    let offset = super.calculateOffsetToAncestorWithLayer(layerParent: &layerParent)
    //if layer == nil && layerParent != nil {   // before
    if layer == nil && layerParent == nil {   // now
      layerParent = widget!.layer
    }
    return offset
  }

  public func onEventFromSource(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func onEventProcessingStarted(event: Event) {
    guard event.isGestureEvent else{
      return
    }

    let gestureEvent = event as! GestureEvent

    if gestureEvent.type == EventType.GestureBegin {
      event.handled = true
      return
    }

    if gestureEvent.type == EventType.GestureEnd && gestureEvent.details.touchPoints > 1 || gestureHandler == nil {
      event.handled = true
      return
    }

    if gestureHandler == nil &&
      (gestureEvent.type == EventType.GestureScrollUpdate ||
       gestureEvent.type == EventType.GestureScrollEnd ||
       gestureEvent.type == EventType.ScrollFlingStart) {
      event.handled = true
      return
    }

    gestureHandlerSetBeforeProcessing = gestureHandler != nil
  }

  public func onEventProcessingFinished(event: Event) {
    if event.isGestureEvent && !event.handled && !gestureHandlerSetBeforeProcessing {
      gestureHandler = nil
    }
  }

  public func sendEventToProcessor(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func canDispatchToTarget(target: EventTarget) -> Bool {
    return eventDispatchTarget === target
  }

  public func dispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func preDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
    let view = target as! View
    if event.isGestureEvent {
      gestureHandler = view

      if !view.isEnabled {
        event.handled = true
      }
    }

    oldDispatchTarget = eventDispatchTarget
    eventDispatchTarget = view
    return EventDispatchDetails()
  }

  public func postDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {

    if event.type == EventType.GestureEnd {
      if gestureHandler != nil && gestureHandler === mousePressedHandler {
        setMouseHandler(handler: nil)
      } else {
        gestureHandler = nil
      }
    }

    var details = EventDispatchDetails()
    if target !== eventDispatchTarget {
      details.targetDestroyed = true
    }

    eventDispatchTarget = oldDispatchTarget
    oldDispatchTarget = nil

    return details
  }

  public func dispatchEventToTarget(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  //override func getDragInfo() -> ViewDragInfo {
  //  return dragInfo
  //}

  func updateCursor(event: MouseEvent) {
    if (event.flags.rawValue & EventFlags.IsNonClient.rawValue) == 0 {
      let v = getEventHandlerFor(point: event.location)
      let me = MouseEvent(model: event, source: self, target: v!)
      widget!.setCursor(cursor: v!.getCursor(event: me))
    }
  }

  func setMouseLocationAndFlags(event: MouseEvent) {
    lastMouseEventFlags = event.flags.rawValue
    lastMouseEventX = Int(event.x)
    lastMouseEventY = Int(event.y)
  }

  func notifyEnterExitOfDescendant(
      event: MouseEvent,
      type: EventType,
      view: View,
      sibling: View?) -> EventDispatchDetails {

   var p = view.parent

   while p != nil {
      if !p!.notifyEnterExitOnChild {
        continue
      }
      if let s = sibling {
        if p!.contains(view: s) {
          break
        }
      }

      let notifyEvent = MouseEnterExitEvent(event: event, eventType: type)
      let dispatchDetails = dispatchEvent(target: p!, event: notifyEvent)
      if dispatchDetails.dispatcherDestroyed || dispatchDetails.targetDestroyed {
        return dispatchDetails
      }
      p = p!.parent
    }
    return EventDispatchDetails()
  }
}

//extension RootView : ViewTargeterDelegate {}

// extension RootView : FocusTraversable {

//   public var focusSearch: FocusSearch? {
//     return _focusSearch
//   }

//   public var focusTraversableParent: FocusTraversable? {
//     get {
//       return _focusTraversableParent
//     }
//     set {
//       _focusTraversableParent = newValue
//     }
//   }

//   public var focusTraversableParentView: View? {
//     get {
//       return _focusTraversableParentView
//     }
//     set {
//       _focusTraversableParentView = newValue
//     }
//   }

// }

// extension RootView : EventProcessor {

//   public var rootTarget: EventTarget? {
//     return self
//   }

//   public var currentEvent: Event? {
//     return nil
//   }

//   public func onEventFromSource(event: Event) -> EventDispatchDetails {
//     return EventDispatchDetails()
//   }

//   public func onEventProcessingStarted(event: Event) {
//     guard event.isGestureEvent else{
//       return
//     }

//     let gestureEvent = event as! GestureEvent

//     if gestureEvent.type == EventType.GestureBegin {
//       event.handled = true
//       return
//     }

//     if gestureEvent.type == EventType.GestureEnd && gestureEvent.details.touchPoints > 1 || gestureHandler == nil {
//       event.handled = true
//       return
//     }

//     if gestureHandler == nil &&
//       (gestureEvent.type == EventType.GestureScrollUpdate ||
//        gestureEvent.type == EventType.GestureScrollEnd ||
//        gestureEvent.type == EventType.ScrollFlingStart) {
//       event.handled = true
//       return
//     }

//     gestureHandlerSetBeforeProcessing = gestureHandler != nil
//   }

//   public func onEventProcessingFinished(event: Event) {
//     if event.isGestureEvent && !event.handled && !gestureHandlerSetBeforeProcessing {
//       gestureHandler = nil
//     }
//   }

//   public func sendEventToProcessor(event: Event) -> EventDispatchDetails {
//     return EventDispatchDetails()
//   }

//   public func canDispatchToTarget(target: EventTarget) -> Bool {
//     return eventDispatchTarget === target
//   }

//   public func dispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
//     return EventDispatchDetails()
//   }

//   public func preDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
//     let view = target as! View
//     if event.isGestureEvent {
//       gestureHandler = view

//       if !view.enabled {
//         event.handled = true
//       }
//     }

//     oldDispatchTarget = eventDispatchTarget
//     eventDispatchTarget = view
//     return EventDispatchDetails()
//   }

//   public func postDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {

//     if event.type == EventType.GestureEnd {
//       if gestureHandler != nil && gestureHandler === mousePressedHandler {
//         setMouseHandler(handler: nil)
//       } else {
//         gestureHandler = nil
//       }
//     }

//     var details = EventDispatchDetails()
//     if target !== eventDispatchTarget {
//       details.targetDestroyed = true
//     }

//     eventDispatchTarget = oldDispatchTarget
//     oldDispatchTarget = nil

//     return details
//   }

//   public func dispatchEventToTarget(target: EventTarget, event: Event) -> EventDispatchDetails {
//     return EventDispatchDetails()
//   }
// }
