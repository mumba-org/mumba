// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

open class EventTargetIterator<T: EventTarget> {
  public init() {}
  public init(elems: [T]) {}
}

open class EventTarget : EventHandler {

  open var parentTarget: EventTarget? {
    return nil
  }

  open var eventTargeter: EventTargeter? {
    get { return nil }
    set {}
  }

  open var targetHandler: EventHandler? {
    get { return nil }
    set {}
  }

  open var isPreTargetListEmpty: Bool {
    get {
      return false
    }

    set {

    }
  }

  open var childIterator: EventTargetIterator<EventTarget> {
    return EventTargetIterator<EventTarget>()
  }

  public init() {
    isPreTargetListEmpty = true
  }

  open class func convertPointToTarget(source: EventTarget,
                                         target: EventTarget,
                                         point: inout IntPoint) {
  }

  open func canAcceptEvent(event: Event) -> Bool {
    return false
  }

  open func convertEventToTarget(target: EventTarget, event: LocatedEvent) {

  }

  open func addPreTargetHandler(handler: EventHandler) {

  }

  open func prependPreTargetHandler(handler: EventHandler) {

  }

  open func removePreTargetHandler(handler: EventHandler) {

  }

  open func addPostTargetHandler(handler: EventHandler) {

  }

  open func removePostTargetHandler(handler: EventHandler) {

  }

  // EventHandler
  open func onEvent(event: inout Event) {}
  open func onKeyEvent(event: inout KeyEvent) {}
  open func onMouseEvent(event: inout MouseEvent) {}
  open func onScrollEvent(event: inout ScrollEvent) {}
  open func onTouchEvent(event: inout TouchEvent) {}
  open func onGestureEvent(event: inout GestureEvent) {}
  open func onCancelMode(event: inout CancelModeEvent) {}

}
