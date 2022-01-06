// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public struct WebTouchAction : OptionSet {
  
  public let rawValue: Int
  
  static let None = WebTouchAction(rawValue: 0x0)
  static let PanLeft = WebTouchAction(rawValue: 0x1)
  static let PanRight = WebTouchAction(rawValue: 0x2)
  static let PanX = WebTouchAction(rawValue: WebTouchAction.PanLeft.rawValue | WebTouchAction.PanRight.rawValue)
  static let PanUp = WebTouchAction(rawValue: 0x4)
  static let PanDown = WebTouchAction(rawValue: 0x8)
  static let PanY = WebTouchAction(rawValue: WebTouchAction.PanUp.rawValue | WebTouchAction.PanDown.rawValue)
  static let Pan = WebTouchAction(rawValue: WebTouchAction.PanX.rawValue | WebTouchAction.PanY.rawValue)
  static let PinchZoom = WebTouchAction(rawValue: 0x10)
  static let Manipulation = WebTouchAction(rawValue: WebTouchAction.Pan.rawValue | WebTouchAction.PinchZoom.rawValue)
  static let DoubleTapZoom = WebTouchAction(rawValue: 0x20)
  static let ActionAuto = WebTouchAction(rawValue: WebTouchAction.Manipulation.rawValue | WebTouchAction.DoubleTapZoom.rawValue)

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }

}

public enum WebEventType : Int {
  case Undefined = -1
  // WebMouseEvent
  case MouseDown = 0
  case MouseUp = 1
  case MouseMove = 2
  case MouseEnter = 3
  case MouseLeave = 4
  case ContextMenu = 5

  // WebMouseWheelEvent
  case MouseWheel = 6

  // WebKeyboardEvent
  case RawKeyDown = 7
  case KeyDown = 8
  case KeyUp = 9
  case Char = 10

  // WebGestureEvent
  case GestureScrollBegin = 11
  case GestureScrollEnd = 12
  case GestureScrollUpdate = 13
  case GestureFlingStart = 14
  case GestureFlingCancel = 15
  case GesturePinchBegin = 16
  case GesturePinchEnd = 17
  case GesturePinchUpdate = 18
  case GestureTapDown = 19
  case GestureShowPress = 20
  case GestureTap = 21
  case GestureTapCancel = 22
  case GestureLongPress = 23
  case GestureLongTap = 24
  case GestureTwoFingerTap = 25
  case GestureTapUnconfirmed = 26
  case GestureDoubleTap = 27
  
  // WebTouchEvent
  case TouchStart = 28
  case TouchMove = 29
  case TouchEnd = 30
  case TouchCancel = 31
  case TouchScrollStarted = 32


  // WebPointerEvent
  case PointerDown = 33
  case PointerUp = 34
  case PointerMove = 35
  case PointerCancel = 36
  case PointerCausedUaAction = 37
}

// NOTE: while Event is the core Events that DOM deals with
// this are from the WebFrame/WebView points of view

// TODO: transform those in structs and just copy the bits around
//       giving the 'Event' family are the real ones to be mapped

// WebInputEvent family just need proper serialization
public class WebInputEvent {

    public struct Modifiers : OptionSet {
        // modifiers for all events:
        public static let ShiftKey         = Modifiers(rawValue: 1 << 0)
        public static let ControlKey       = Modifiers(rawValue: 1 << 1)
        public static let AltKey           = Modifiers(rawValue: 1 << 2)
        public static let MetaKey          = Modifiers(rawValue: 1 << 3)

        // modifiers for keyboard events:
        public static let IsKeyPad         = Modifiers(rawValue: 1 << 4)
        public static let IsAutoRepeat     = Modifiers(rawValue: 1 << 5)

        // modifiers for mouse events:
        public static let LeftButtonDown   = Modifiers(rawValue: 1 << 6)
        public static let MiddleButtonDown = Modifiers(rawValue: 1 << 7)
        public static let RightButtonDown  = Modifiers(rawValue: 1 << 8)

        // Toggle modifers for all events.
        public static let CapsLockOn       = Modifiers(rawValue: 1 << 9)
        public static let NumLockOn        = Modifiers(rawValue: 1 << 10)

        public static let IsLeft           = Modifiers(rawValue: 1 << 11)
        public static let IsRight          = Modifiers(rawValue: 1 << 12)

        // Indicates that an event was generated on the touch screen while
        // touch accessibility is enabled, so the event should be handled
        // by accessibility code first before normal input event processing.
        public static let IsTouchAccessibility = Modifiers(rawValue: 1 << 13)

        public static let IsComposing      = Modifiers(rawValue: 1 << 14)
        public static let AltGrKey         = Modifiers(rawValue: 1 << 15)
        public static let OSKey            = Modifiers(rawValue: 1 << 16)
        public static let FnKey            = Modifiers(rawValue: 1 << 17)
        public static let SymbolKey        = Modifiers(rawValue: 1 << 18)

        public static let ScrollLockOn     = Modifiers(rawValue: 1 << 19)

        public var rawValue: Int

        public init(rawValue: Int) {
          self.rawValue = rawValue
        }

    }

    public enum RailsMode : Int {
        case RailsModeFree       = 0
        case RailsModeHorizontal = 1
        case RailsModeVertical   = 2
    }

    public enum Result : Int {
        case notHandled = 0
        case handledSuppressed = 1
        case handledApplication = 2
        case handledSystem = 3
    }

    static let InputModifiers = Modifiers(rawValue: Modifiers.ShiftKey.rawValue | Modifiers.ControlKey.rawValue | Modifiers.AltKey.rawValue | Modifiers.MetaKey.rawValue)

    //public var timeStampSeconds: Double = 0.0
    //public var size: Int = 0
    //public var type: EventType = .Undefined
    // shift key?
    //public var modifiers: Modifiers = Modifiers(rawValue: 0)

    public var frameScale: Float {
      get {
        return _WebInputEventGetFrameScale(reference)
      }
      set {
        _WebInputEventSetFrameScale(reference, newValue)
      }
    }
    
    public var frameTranslate: FloatPoint {
      get {
        var x: Float = 0
        var y: Float = 0
        _WebInputEventGetFrameTranslate(reference, &x, &y)
        return FloatPoint(x: x, y: y)
      }
      set {
        _WebInputEventSetFrameTranslate(reference, newValue.x, newValue.y)
      }
    }

    public var type: WebEventType {
      get {
        return WebEventType(rawValue: Int(_WebInputEventGetType(reference)))!
      }
      set {
        _WebInputEventSetType(reference, CInt(newValue.rawValue))
      }
    }

    public var modifiers: Modifiers {
      get {
        return Modifiers(rawValue: Int(_WebInputEventGetModifiers(reference)))
      } 
      set {
        _WebInputEventSetModifiers(reference, CInt(newValue.rawValue))
      }
    }
    
    public var timestamp: TimeTicks {
      get {
        return TimeTicks(microseconds: _WebInputEventGetTimestamp(reference))
      }
      set {
        _WebInputEventSetTimestamp(reference, newValue.microseconds)
      }
    }

    public var size: Int {
      return Int(_WebInputEventGetSize(reference))
    }

    public var isMouseEvent: Bool {
      return _WebInputEventIsMouseEvent(reference) != 0
    }

    public var isKeyboardEvent: Bool {
      return _WebInputEventIsKeyboardEvent(reference) != 0
    }

    public var isTouchEvent: Bool { 
      return _WebInputEventIsTouchEvent(reference) != 0
    }

    public var isGestureEvent: Bool {
      return _WebInputEventIsGestureEvent(reference) != 0
    }

    public var isPointerEvent: Bool {
      return _WebInputEventIsPointerEvent(reference) != 0
    }

    var reference: WebInputEventRef?

    public init(reference: WebInputEventRef) {
      self.reference = reference
    }

    init() {
      self.reference = nil 
    }

    public func asMouseEvent() -> WebMouseEvent {
      return WebMouseEvent(reference: self.reference!)
    }

    public func asKeyboardEvent() -> WebKeyboardEvent {
      return WebKeyboardEvent(reference: self.reference!)
    }

    public func asGestureEvent() -> WebGestureEvent {
      return WebGestureEvent(reference: self.reference!)
    }
}

public struct WebMouseButtons : OptionSet {
  public let rawValue: Int
  
  public static let NoButton = EventResult(rawValue: 0)
  public static let Left     = EventResult(rawValue: 1 << 0)
  public static let Right    = EventResult(rawValue: 1 << 1)
  public static let Middle   = EventResult(rawValue: 1 << 2)
  public static let Back     = EventResult(rawValue: 1 << 3)
  public static let Forward  = EventResult(rawValue: 1 << 4)
  public static let Eraser   = EventResult(rawValue: 1 << 5)
 
  public init(rawValue: Int) { self.rawValue = rawValue }
}

public class WebMouseEvent : WebInputEvent {

  public var positionInWidget: FloatPoint {
    get {
      var x: Float = 0.0
      var y: Float = 0.0
      _WebMouseEventGetPositionInWidget(reference, &x, &y)
      return FloatPoint(x: x, y: y)
    }
    set {
      _WebMouseEventSetPositionInWidget(reference, newValue.x, newValue.y)
    }
  }

  public var positionInScreen: FloatPoint {
    get {
      var x: Float = 0.0
      var y: Float = 0.0
      _WebMouseEventGetPositionInScreen(reference, &x, &y)
      return FloatPoint(x: x, y: y)
    }
    set {
      _WebMouseEventSetPositionInScreen(reference, newValue.x, newValue.y)
    }
  }

  public var id: Int32 {
    return _WebMouseEventGetId(reference)
  }

  public var force: Float {
    return _WebMouseEventGetForce(reference)
  }

  public var button: WebMouseButtons {
    return WebMouseButtons(rawValue: Int(_WebMouseEventGetButton(reference)))
  }

  public var movementX: Int {
    return Int(_WebMouseEventGetMovementX(reference))
  }

  public var movementY: Int {
    return Int(_WebMouseEventGetMovementY(reference))
  }

  public var clickCount: Int {
    return Int(_WebMouseEventGetClickCount(reference))  
  }

}

public class WebGestureEvent : WebInputEvent {
  //public var x: Int = 0
  //public var y: Int = 0
  //public var globalX: Int = 0
  //public var globalY: Int = 0
  //public var sourceDevice: WebGestureDevice = .Uninitialized

  public var positionInWidget: FloatPoint {
    get {
      var x: Float = 0.0
      var y: Float = 0.0
      _WebGestureEventGetPositionInWidget(reference, &x, &y)
      return FloatPoint(x: x, y: y)
    }
    set {
      _WebGestureEventSetPositionInWidget(reference, newValue.x, newValue.y)
    }
  }

  public var positionInScreen: FloatPoint {
    get {
      var x: Float = 0.0
      var y: Float = 0.0
      _WebGestureEventGetPositionInScreen(reference, &x, &y)
      return FloatPoint(x: x, y: y)
    }
    set {
      _WebGestureEventSetPositionInScreen(reference, newValue.x, newValue.y)
    }
  }

}

public class WebMouseWheelEvent : WebInputEvent {

}

public class WebKeyboardEvent : WebInputEvent {
  
  public var windowsKeyCode: Int {
    get {
      return Int(_WebKeyboardEventGetWindowsKeyCode(reference))
    }
    set {
      _WebKeyboardEventSetWindowsKeyCode(reference, CInt(newValue))
    }
  }
  
  public var nativeKeyCode: Int {
    get {
      return Int(_WebKeyboardEventGetNativeKeyCode(reference))
    }
    set {
      _WebKeyboardEventSetNativeKeyCode(reference, CInt(newValue))
    }
  }
  
  public var domCode: Int {
    get {
      return Int(_WebKeyboardEventGetDomCode(reference))
    }
    set {
      _WebKeyboardEventSetDomCode(reference, CInt(newValue))
    }
  }
  
  public var domKey: Int {
    get {
      return Int(_WebKeyboardEventGetDomKey(reference))
    }
    set {
      _WebKeyboardEventSetDomKey(reference, CInt(newValue))
    }
  }

  public var isSystemKey: Bool {
    get {
      return _WebKeyboardEventIsSystemKey(reference) != 0
    }
    set {
      _WebKeyboardEventSetIsSystemKey(reference, newValue ? 1 : 0)
    } 
  }
  
  public var isBrowserShortcut: Bool {
    get {
      return _WebKeyboardEventIsBrowserShortcut(reference) != 0
    }
    set {
      _WebKeyboardEventSetIsBrowserShortcut(reference, newValue ? 1 : 0)
    }
  }
  
  public var text: String {
    get {
      let holder = StringHolder() 
      let ptr = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _WebKeyboardEventGetText(reference, ptr, { (ptr: UnsafeMutableRawPointer?, data: UnsafePointer<UInt16>?) in 
        let instance = unsafeBitCast(ptr, to: StringHolder.self)
        instance.string = String(utf16CodeUnits: data!, count: 4)
      })
      return holder.string
    }
    set {
      newValue.withCString {
        _WebKeyboardEventSetText(reference, $0, CInt(newValue.count))
      }
    }
  }
  
  public var unmodifiedText: String {
    get {
      let holder = StringHolder() 
      let ptr = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _WebKeyboardEventGetUnmodifiedText(reference, ptr, { (ptr: UnsafeMutableRawPointer?, data: UnsafePointer<UInt16>?) in 
        let instance = unsafeBitCast(ptr, to: StringHolder.self)
        instance.string = String(utf16CodeUnits: data!, count: 4)
      })
      return holder.string
    }
    set {
      newValue.withCString {
        _WebKeyboardEventSetUnmodifiedText(reference, $0, CInt(newValue.count))
      }
    }
  }
}

class StringHolder {
  public var string: String = String()
  public init() {}
}

public struct WebDOMMessageEvent {
  var reference: WebDOMMessageEventRef

  init(reference: WebDOMMessageEventRef) {
    self.reference = reference
  }
}

public struct ProgressEvent {
  public var isLengthComputable: Bool = false  
  public var loaded: UInt64 = 0
  public var total: UInt64 = 0
}