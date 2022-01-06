// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Libevent

public struct EventFlags {

  public static let none = EventFlags(rawValue: 0)
  public static let timeout = EventFlags(rawValue: 0x01)
  public static let read = EventFlags(rawValue: 0x02)
  public static let write = EventFlags(rawValue: 0x04)
  public static let signal = EventFlags(rawValue: 0x08)
  public static let persist = EventFlags(rawValue: 0x10)
  
  var rawValue: Int

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
}

public struct EventLoopFlags {
  
  public static let none = EventFlags(rawValue: 0)
  public static let once = EventLoopFlags(rawValue: 0x01)
  public static let nonblock = EventLoopFlags(rawValue: 0x02)

  var rawValue: Int

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }

}

public struct EventTimer {
  var seconds: Int64 = 0
  var microseconds: Int64 = 0
}

public class Event {

  internal var handle: CEvent
  var disposed: Bool = false
  var added: Bool = false

  internal var fd: CInt {
    return _LibeventEventGetFD(handle)
  }

  internal var events: CInt {
    return _LibeventEventGetEvents(handle)
  }

  public init() {
    handle = _LibeventEventAlloc()
  }

  internal init(handle: CEvent) {
    self.handle = handle
  }

  deinit {
    if !disposed {
      dispose()
    }
  }

  public func dispose() {
    guard !disposed else {
      return
    }

    delete()
    _LibeventEventDestroy(handle)
    
    disposed = true
  }

  @discardableResult
  public func add() -> Int {
    let rv = _LibeventEventAdd(handle)
    added = true
    return Int(rv)
  }

  @discardableResult
  public func add(timeout: EventTimer) -> Int {
    let rv = _LibeventEventAddWithTimeout(handle, timeout.seconds, timeout.microseconds)
    added = true
    return Int(rv)
  }

  public func set(pipe: WakeupPipe?, flags: EventFlags, callback: @escaping CEventSetCallback, context: UnsafeMutableRawPointer) {
    if let p = pipe {
      _LibeventEventSet(handle, p.descriptor, Int16(flags.rawValue), callback, context)
    } else {
      _LibeventEventSet(handle, -1, Int16(flags.rawValue), callback, context) 
    }
  }

  public func set(fd: FileDescriptor, flags: EventFlags, callback: @escaping CEventSetCallback, context: UnsafeMutableRawPointer) {
    _LibeventEventSet(handle, fd, Int16(flags.rawValue), callback, context)
  }

  @discardableResult
  public func delete() -> Int {
    guard added else {
      return -1
    }
    let rc = _LibeventEventDel(handle)
    added = false
    return Int(rc)
  }

}

/// Helper to automate handle destruction from the heap
internal class ScopedEvent {
  
  internal var event: Event?

  internal var fd: CInt? {
    return event?.fd
  }

  internal var events: CInt? {
    return event?.events
  }

  static func new() -> ScopedEvent {
    return ScopedEvent(event: Event())
  }

  init() {}

  init(event: Event) {
    self.event = event
  }
  
  deinit {
    if let ev = event {
      ev.dispose()
      event = nil
    }
  }

  @discardableResult
  public func add() -> Int {
    var rc = 0
    if let ev = event {
      rc = ev.add()
    }
    return rc
  }

  @discardableResult
  public func add(timeout: EventTimer) -> Int {
    var rc = 0

    if let ev = event {
      rc = ev.add(timeout: timeout)
    }
    
    return rc
  }

  public func set(pipe: WakeupPipe?, flags: EventFlags, callback: @escaping CEventSetCallback, context: UnsafeMutableRawPointer) {
    if let ev = event {
      ev.set(pipe: pipe, flags: flags, callback: callback, context: context)
    }
  }

  public func set(fd: CInt, flags: EventFlags, callback: @escaping CEventSetCallback, context: UnsafeMutableRawPointer) {
    if let ev = event {
      ev.set(fd: fd, flags: flags, callback: callback, context: context)
    }
  }

  @discardableResult
  public func delete() -> Int {
    var rc = 0
    if let ev = event {
      rc = ev.delete()
    }
    return rc
  }

  public func release() -> Event {
    let ev = event!
    event = nil
    return ev
  }
}

public class EventLoop {
  
  private var handle: CEventBase
  private var eventBaseLock: Lock = Lock()
  private var disposed: Bool = false

  public init() {
    handle = _LibeventEventBaseAlloc()
  }

  deinit {
    if !disposed {
      dispose()
    }
  }
  
  //@inline(never)
  public func dispose() {
    _LibeventEventBaseDestroy(handle)
    disposed = true
  }

  //@inline(never)
  public func loop(flags: EventLoopFlags) {
    eventBaseLock.withLockVoid {
      _LibeventEventBaseLoop(handle, CInt(flags.rawValue))
    }
  }

  @discardableResult
  //@inline(never)
  public func set(event: Event) -> Int {
    return Int(_LibeventEventBaseSet(handle, event.handle))
  }

  //@inline(never)
  public func loopbreak() {
    _LibeventEventBaseLoopbreak(handle)
  }

}