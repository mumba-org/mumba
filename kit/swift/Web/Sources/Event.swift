// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public enum EventPhase : Int {
  case None = 0
  case CapturingPhase = 1
  case AtTarget = 2
  case BubblingPhase = 3
}

public class Event {    

  public var type: String {
    var len: CInt = 0
    guard let ref = _WebEventGetType(reference, &len) else {
      return String()
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!

  }

  public var target: WebNode? {
    guard let ref = _WebEventGetTarget(reference) else {
      return nil
    }
    return WebNode(reference: ref)
  }

  public var currentTarget: WebNode? {
    guard let ref = _WebEventGetCurrentTarget(reference) else {
      return nil
    }
    return WebNode(reference: ref)
  }

  public var srcElement: WebNode? {
    guard let ref = _WebEventGetSrcElement(reference) else {
      return nil
    }
    return WebNode(reference: ref)
  }
      
  public var eventPhase: EventPhase {
    return EventPhase(rawValue: Int(_WebEventGetEventPhase(reference)))!
  }

  public var bubbles: Bool {
    return _WebEventBubbles(reference) != 0
  }

  public var cancelable: Bool {
    return _WebEventIsCancelable(reference) != 0
  }

  public var defaultPrevented: Bool {
    return _WebEventDefaultPrevented(reference) != 0
  }

  public var composed: Bool {
    return _WebEventIsComposed(reference) != 0
  }

  public var isTrusted: Bool {
    return _WebEventIsTrusted(reference) != 0 
  }

  public var timestamp: TimeTicks {
    return TimeTicks(microseconds: _WebEventGetTimestamp(reference))
  }

  public var isUIEvent: Bool {
    return _WebEventIsUIEvent(reference) != 0
  }
  
  public var isMouseEvent: Bool {
    return _WebEventIsMouseEvent(reference) != 0
  }
  
  public var isFocusEvent: Bool {
    return _WebEventIsFocusEvent(reference) != 0
  }
  
  public var isKeyboardEvent: Bool {
    return _WebEventIsKeyboardEvent(reference) != 0
  }
  
  public var isTouchEvent: Bool {
    return _WebEventIsTouchEvent(reference) != 0
  }
  
  public var isGestureEvent: Bool {
    return _WebEventIsGestureEvent(reference) != 0
  }
  
  public var isWheelEvent: Bool {
    return _WebEventIsWheelEvent(reference) != 0
  }
  
  public var isRelatedEvent: Bool {
    return _WebEventIsRelatedEvent(reference) != 0
  }
  
  public var isPointerEvent: Bool {
    return _WebEventIsPointerEvent(reference) != 0
  }
  
  public var isInputEvent: Bool {
    return _WebEventIsInputEvent(reference) != 0
  }
  
  public var isDragEvent: Bool {
    return _WebEventIsDragEvent(reference) != 0
  }
  
  public var isClipboardEvent: Bool {
    return _WebEventIsClipboardEvent(reference) != 0
  }
  
  public var isBeforeTextInsertedEvent: Bool { 
    return _WebEventIsBeforeTextInsertedEvent(reference) != 0
  }
  
  public var isBeforeUnloadEvent: Bool {
    return _WebEventIsBeforeUnloadEvent(reference) != 0
  }

  public static func create() -> Event {
    return Event()
  }

  public static func create(type: String) -> Event {
    return Event(type: type, bubbles: false, cancelable: false)
  }
  
  public static func createCancelable(type: String) -> Event  {
    return Event(type: type, bubbles: false, cancelable: true)
  }

  public static func createBubble(type: String) -> Event  {
    return Event(type: type, bubbles: true, cancelable: false)
  }

  public static func createCancelableBubble(type: String) -> Event {
    return Event(type: type, bubbles: true, cancelable: true)
  }
  
  var reference: WebEventRef!
  
  public init() {
    reference = _WebEventCreateEmpty()
  }

  public init(type: String, bubbles: Bool, cancelable: Bool) {
    var cstr: UnsafePointer<Int8>?
    type.withCString { cstr = $0 }
    reference = _WebEventCreate(cstr, bubbles ? 1 : 0, cancelable ? 1 : 0)
  }

  public init(reference: WebEventRef) {
    self.reference = reference
  }
  
  public func stopPropagation() {
    _WebEventStopPropagation(reference)
  }

  public func stopImmediatePropagation() {
    _WebEventStopImmediatePropagation(reference)
  }

  public func preventDefault() {
    _WebEventPreventDefault(reference)
  }

  public func initEvent(type: String, bubbles: Bool = false, cancelable: Bool = false) {
    type.withCString {
      _WebEventInitEvent(reference, $0, bubbles ? 1 : 0, cancelable ? 1 : 0)
    }
  } 
}

public class AnimationEvent : Event {}

public class MouseEvent : Event {}
  
public class FocusEvent : Event {}

public class KeyboardEvent : Event {}
  
public class TouchEvent : Event {}

public class GestureEvent : Event {}

public class WheelEvent : Event {}
  
public class PointerEvent: Event {}
  
public class InputEvent : Event {}
  
public class DragEvent : Event {}
  
public class ClipboardEvent: Event {}
  
public class BeforeTextInsertedEvent : Event {}
  
public class BeforeUnloadEvent : Event {}