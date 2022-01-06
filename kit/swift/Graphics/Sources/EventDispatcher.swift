// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public typealias EventHandlerList = [EventHandler]

public struct EventDispatchDetails {

  public init() {
    dispatcherDestroyed = false
    targetDestroyed = false
  }

  public var dispatcherDestroyed: Bool
  public var targetDestroyed: Bool
}

public protocol EventDispatcherDelegate {

  var currentEvent: Event? { get }

  func canDispatchToTarget(target: EventTarget) -> Bool
  func dispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails
  func preDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails
  func postDispatchEvent(target: EventTarget, event: Event) -> EventDispatchDetails
  func dispatchEventToTarget(target: EventTarget, event: Event) -> EventDispatchDetails
}

// Dispatches events to appropriate targets.
public class EventDispatcher {

  private(set) public var currentEvent: Event?
  private var handlerList: EventHandlerList
  private var delegate: EventDispatcherDelegate?

  public var delegateDestroyed: Bool {
    return delegate == nil
  }

  init(delegate: EventDispatcherDelegate) {
    self.delegate = delegate
    handlerList = EventHandlerList()
  }

  public func processEvent(target: EventTarget, event: Event) {

  }

  public func onHandlerDestroyed(handler: EventHandler) {

  }

  public func onDispatcherDelegateDestroyed() {

  }

  public func dispatchEventToEventHandlers(list: EventHandlerList, event: Event) {

  }

  public func dispatchEvent(handler: EventHandler, event: Event) {

  }
}
