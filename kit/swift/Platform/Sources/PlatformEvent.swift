// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public typealias ScopedEventDispatcher = Int

public enum PostDispatchAction : UInt32 {
  case None = 0x0
  case PerformDefault = 0x1
  case StopPropagation = 0x2
}

public protocol PlatformEventDispatcher : class {
  func canDispatchEvent(event: inout PlatformEvent) -> Bool
  func dispatchEvent(event: inout PlatformEvent) -> PostDispatchAction
}

public protocol PlatformEventObserver : class {
  func willProcessEvent(event: PlatformEvent)
  func didProcessEvent(event: PlatformEvent)
}

// TODO: implement!!!
open class PlatformEventSource {

    //open class func createDefault() -> PlatformEventSource? { return nil }

    //public class func instance() -> PlatformEventSource? {
    //  return PlatformEventSource._instance
    //}

    public init() {
      _overriddenDispatcherRestored = false
      _dispatchers = [PlatformEventDispatcher]()
      _observers = [PlatformEventObserver]()
      //PlatformEventSource._instance = self
    }

    deinit {
      //PlatformEventSource._instance = nil
    }

    public func dispatchEvent(platformEvent: inout PlatformEvent) -> UInt32 {
      var action = PostDispatchAction.PerformDefault

      for observer in _observers {
        observer.willProcessEvent(event: platformEvent)
      }

      if let overridden = _overriddenDispatcher {
        action = overridden.dispatchEvent(event: &platformEvent)
      }

      if (action.rawValue & PostDispatchAction.PerformDefault.rawValue) > 0 && _dispatchers.count > 0 {
        for dispatcher in _dispatchers {
          if dispatcher.canDispatchEvent(event: &platformEvent) {
            action = dispatcher.dispatchEvent(event: &platformEvent)
            if (action.rawValue & PostDispatchAction.StopPropagation.rawValue) > 0 {
              break
            }
          }
        }
      }

      for observer in _observers {
        observer.didProcessEvent(event: platformEvent)
      }

      if _overriddenDispatcherRestored {
        stopCurrentEventStream()
      }

      _overriddenDispatcherRestored = false
      return action.rawValue
    }

    public func addPlatformEventDispatcher(dispatcher: PlatformEventDispatcher) {
      _dispatchers.append(dispatcher)
      onDispatcherListChanged()
    }

    public func removePlatformEventDispatcher(dispatcher: PlatformEventDispatcher) {
      for (index, item) in _dispatchers.enumerated() {
        if dispatcher === item {
          _dispatchers.remove(at: index)
          break
        }
      }
      onDispatcherListChanged()
    }

    public func overrideDispatcher(dispatcher: PlatformEventDispatcher) -> ScopedEventDispatcher {
      return 0
    }

    public func stopCurrentEventStream() {

    }

    public func addPlatformEventObserver(observer: PlatformEventObserver) {
      _observers.append(observer)
    }

    public func removePlatformEventObserver(observer: PlatformEventObserver) {
      for (index, item) in _observers.enumerated() {
        if observer === item {
          _observers.remove(at: index)
          return
        }
      }
    }

    func onDispatcherListChanged() {

    }

    var _dispatchers: [PlatformEventDispatcher]
    var _observers: [PlatformEventObserver]
    var _overriddenDispatcher: PlatformEventDispatcher?
    var _overriddenDispatcherRestored: Bool
    //public static var _instance: PlatformEventSource?
}
