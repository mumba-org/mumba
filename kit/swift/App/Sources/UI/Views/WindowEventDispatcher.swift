// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class WindowEventDispatcher {

  enum WindowHiddenReason {
    case WindowDestroyed
    case WindowHidden
    case WindowMoving
  }

  private(set) public var mousePressedHandler: Window?

  private(set) public var mouseMovedHandler: Window?

  public var lastMouseLocationInRoot: IntPoint {
    return IntPoint()
  }

  public var skipIme: Bool = true

  private var host: WindowTreeHost
  private var eventDispatchTarget: Window?
  private var oldDispatchTarget: Window?
  private var heldMoveEvent: LocatedEvent?
  private var heldRepostableEvent: LocatedEvent?
  private var dispatchingHeldEvent: LocatedEvent?
  private var synthesizeMouseMove: Bool
  private var moveHoldCount: Int

  init(_ host: WindowTreeHost) {
    self.host = host
    synthesizeMouseMove = false
    moveHoldCount = 0
  }

  public func repostEvent(event: LocatedEvent) {

  }

  public func onMouseEventsEnableStateChanged(enabled: Bool) {

  }

  public func dispatchCancelModeEvent() {

  }

  public func dispatchMouseExitAtPoint(target: Window?, point: IntPoint) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func processedTouchEvent(uniqueEventId: UInt32, window: Window, result: EventResult) {

  }

  public func holdPointerMoves() {

  }

  public func releasePointerMoves() {

  }

  public func getLastMouseLocationInRoot() -> IntPoint {
    return IntPoint()
  }

  public func onHostLostMouseGrab() {

  }

  public func onCursorMovedToRootLocation(rootLocation: IntPoint) {

  }

  public func onPostNotifiedWindowDestroying(window: Window) {

  }

  func transformEventForDeviceScaleFactor(event: LocatedEvent) {

  }

  // Dispatches OnMouseExited to the |window| which is hiding if necessary.
  func dispatchMouseExitToHidingWindow(window: Window) {

  }

  func dispatchMouseEnterOrExit(target: Window, event: MouseEvent, type: EventType) {

  }

  func processGestures(gestures: GestureRecognizer.Gestures) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  func onWindowHidden(invisible: Window, reason: WindowHiddenReason) {

  }

  // Returns a target window for the given gesture event.
  func getGestureTarget(event: GestureEvent) -> Window? {
    return nil
  }

  func isDispatchedHeldEvent(event: Event) -> Bool {
    return false
  }


  // GestureEventHelper
  func canDispatchToConsumer(consumer: GestureConsumer) -> Bool {
    return false
  }

  func dispatchGestureEvent(event: GestureEvent) {

  }

  func dispatchCancelTouchEvent(event: TouchEvent) {

  }

  // We hold and aggregate mouse drags and touch moves as a way of throttling
  // resizes when HoldMouseMoves() is called. The following methods are used to
  // dispatch held and newly incoming mouse and touch events, typically when an
  // event other than one of these needs dispatching or a matching
  // ReleaseMouseMoves()/ReleaseTouchMoves() is called.  NOTE: because these
  // methods dispatch events from WindowTreeHost the coordinates are in terms of
  // the root.
  func dispatchHeldEvents() -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  // Posts a task to send synthesized mouse move event if there is no a pending
  // task.
  func postSynthesizeMouseMove() {

  }

  // Creates and dispatches synthesized mouse move event using the current mouse
  // location.
  func synthesizeMouseMoveEvent() -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  // Calls SynthesizeMouseMove() if |window| is currently visible and contains
  // the mouse cursor.
  func synthesizeMouseMoveAfterChangeToWindow(window: Window) {

  }

  func preDispatchLocatedEvent(target: Window, event: LocatedEvent) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  func preDispatchMouseEvent(target: Window, event: MouseEvent) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  func preDispatchTouchEvent(target: Window, event: TouchEvent) -> EventDispatchDetails {
    return EventDispatchDetails()
  }
}


extension WindowEventDispatcher: WindowObserver {

  public func onWindowDestroying(window: Window) {

  }

  public func onWindowDestroyed(window: Window) {

  }

  public func onWindowAddedToRootWindow(window: Window) {

  }

  public func onWindowRemovingFromRootWindow(window: Window, newRoot: Window) {

  }

  public func onWindowVisibilityChanging(window: Window, visible: Bool) {

  }

  public func onWindowVisibilityChanged(window: Window, visible: Bool) {

  }

  public func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect) {

  }

  public func onWindowTransforming(window: Window) {

  }

  public func onWindowTransformed(window: Window) {

  }

  public func onWindowTitleChanged(window: Window) {

  }

}

extension WindowEventDispatcher : UIObserver {

  public func onWindowInitialized(window: Window) {

  }

  public func onHostInitialized(host: WindowTreeHost) {

  }

  public func onHostActivated(host: WindowTreeHost) {

  }

  public func onBeforeDestroy() {

  }
}

extension WindowEventDispatcher: EventProcessor {

  public var rootTarget: EventTarget? {
    return nil
  }

  public func onEventFromSource(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func onEventProcessingStarted(event: Event) {

  }

  public func onEventProcessingFinished(event: Event) {

  }

  public func sendEventToProcessor(event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }
}

extension WindowEventDispatcher: EventDispatcherDelegate {

  public var currentEvent: Event? {
    return nil
  }

  public func canDispatchToTarget(target: EventTarget) -> Bool {
    return false
  }

  public func preDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func postDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func dispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

  public func dispatchEventToTarget(target: EventTarget, event: Event) -> EventDispatchDetails {
    return EventDispatchDetails()
  }

}

extension WindowEventDispatcher : CaptureDelegate {

  public func updateCapture(oldCapture: Window, newCapture: Window) {

  }

  public func onOtherRootGotCapture() {

  }

  public func setNativeCapture() {

  }

  public func releaseNativeCapture() {

  }

}

extension WindowEventDispatcher : GestureEventHelper {}
