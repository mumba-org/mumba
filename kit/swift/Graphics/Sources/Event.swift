// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Foundation

#if os(Linux)
import MumbaShims
public typealias PlatformEvent = XEvent
#else
public typealias PlatformEvent = Int
#endif

public enum EventType {
  case Unknown
  case MousePressed
  case MouseDragged
  case MouseReleased
  case MouseMoved
  case MouseEntered
  case MouseExited
  case KeyPressed
  case KeyReleased
  case MouseWheel
  case MouseCaptureChanged  // Event has no location.
  case TouchReleased
  case TouchPressed
  case TouchMoved
  case TouchCancelled
  case DropTargetEvent

  // PointerEvents
  case PointerDown
  case PointerMoved
  case PointerUp
  case PointerCancelled
  case PointerEntered
  case PointerExited
  case PointerWheelChanged
  case PointerCaptureChanged

  // GestureEvent types
  case GestureScrollBegin
  //case GestureTypeStart = EventType.GestureScrollBegin.rawValue
  case GestureScrollEnd
  case GestureScrollUpdate
  case GestureTap
  case GestureTapDown
  case GestureTapCancel
  case GestureTapUnconfirmed // User tapped, but the tap delay hasn't expired.
  case GestureDoubleTap
  case GestureBegin  // The first event sent when each finger is pressed.
  case GestureEnd    // Sent for each released finger.
  case GestureTwoFingerTap
  case GesturePinchBegin
  case GesturePinchEnd
  case GesturePinchUpdate
  case GestureLongPress
  case GestureLongTap
  // A SWIPE gesture can happen at the end of a touch sequence involving one or
  // more fingers if the finger velocity was high enough when the first finger
  // was released.
  case GestureSwipe
  case GestureShowPress

  // Sent by Win8+ metro when the user swipes from the bottom or top.
  case GestureWin8EdgeSwipe

  // Scroll support.
  case Scroll
  case ScrollFlingStart
  case ScrollFlingCancel
  //case GestureTypeEnd = .ScrollFlingCancel.rawValue
  case UMAData
  // Sent by the system to indicate any modal type operations, such as drag and
  // drop or menus, should stop.
  case CancelMode
}

public struct EventFlags : OptionSet {
  public let rawValue: Int

  public static let None                 = EventFlags(rawValue: 0)
  public static let CapsLockDown         = EventFlags(rawValue: 1 << 0)
  public static let ShiftDown            = EventFlags(rawValue: 1 << 1)
  public static let ControlDown          = EventFlags(rawValue: 1 << 2)
  public static let AltDown              = EventFlags(rawValue: 1 << 3)
  public static let LeftMouseButton      = EventFlags(rawValue: 1 << 4)
  public static let MiddleMouseButton    = EventFlags(rawValue: 1 << 5)
  public static let RightMouseButton     = EventFlags(rawValue: 1 << 6)
  public static let CommandDown          = EventFlags(rawValue: 1 << 7)
  public static let Extended             = EventFlags(rawValue: 1 << 8)
  public static let IsSynthesized        = EventFlags(rawValue: 1 << 9)
  public static let AltgrDown            = EventFlags(rawValue: 1 << 10)
  public static let Mod3Down             = EventFlags(rawValue: 1 << 11)
  public static let BackMouseButton      = EventFlags(rawValue: 1 << 12)
  public static let ForwardMouseButton   = EventFlags(rawValue: 1 << 13)
  public static let NumLockDown          = EventFlags(rawValue: 1 << 14)
  public static let ScrollLockDown       = EventFlags(rawValue: 1 << 15)
  // key events
  public static let ImeFabricatedKey     = EventFlags(rawValue: 1 << 16)  // Key event fabricated by the underlying
                                    // IME without a user action.
                                    // (Linux X11 only)
  public static let IsRepeat             = EventFlags(rawValue: 1 << 17)
  public static let Final                = EventFlags(rawValue: 1 << 18)  // Do not remap; the event was created with
                                    // the desired final values.
  // mouse events
  public static let IsDoubleClick        = EventFlags(rawValue: 1 << 19)
  public static let IsTripleClick        = EventFlags(rawValue: 1 << 20)
  public static let IsNonClient          = EventFlags(rawValue: 1 << 21)
  public static let FromTouch            = EventFlags(rawValue: 1 << 22)  // Indicates this mouse event is generated
  public static let TouchAccessibility   = EventFlags(rawValue: 1 << 23)  // Indicates this event was generated from
                                                                       // touch accessibility mode.

  public init(rawValue: Int) { self.rawValue = rawValue }
}

public struct EventResult: OptionSet {
  public let rawValue: Int

  public static let Unhandled           = EventResult(rawValue: 0)        // The event hasn't been handled. The event can be
                                     // propagated to other handlers.
  public static let Handled             = EventResult(rawValue: 1 << 0)   // The event has already been handled, but it can
                                     // still be propagated to other handlers.
  public static let Consumed            = EventResult(rawValue: 1 << 1)   // The event has been handled, and it should not be
                                     // propagated to other handlers.
  public static let DisableSyncHandling = EventResult(rawValue: 1 << 2)
                                     // The event shouldn't be handled synchronously. This
                                     // happens if the event is being handled
                                     // asynchronously, or if the event is invalid and
                                     // shouldn't be handled at all.

  public init(rawValue: Int) { self.rawValue = rawValue }
}

public enum EventPhase {
  case Predispatch
  case Pretarget
  case Target
  case PostTarget
  case PostDispatch
}

// Device ID for Touch and Key Events.
public enum EventDeviceId : Int {
  case UnknownDevice = -1
}

// Pointing device type.
public enum EventPointerType : Int {
  case PointerTypeUnknown = 0
  case PointerTypeMouse
  case PointerTypePen
  case PointerTypeTouch
}

open class Event {

  public static func fromIfValid(_ event: Event) -> LocatedEvent? {
    return event.isLocatedEvent ? (event as! LocatedEvent) : nil
  }

  public var type: EventType

  private (set) public var name: String

  public var platformEvent: PlatformEvent?

  private(set) public var timestamp: TimeTicks

  public var flags: EventFlags

  private(set) public var target: EventTarget?

  private(set) public var phase: EventPhase

  private(set) public var result: EventResult

  public var latency: LatencyInfo

  public var handled: Bool {
    get {
      return !result.contains(.Unhandled)
    }
    set {
      result = EventResult(rawValue: result.rawValue | EventResult.Handled.rawValue)
    }
  }

  public var sourceDeviceId: Int

  private(set) public var cancelable: Bool

  public var isShiftDown: Bool {
    return flags.contains(.ShiftDown)
  }

  public var isControlDown: Bool {
    return flags.contains(.ControlDown)
  }

  public var isCapsLockDown: Bool {
    return flags.contains(.CapsLockDown)
  }

  public var isAltDown: Bool {
    return flags.contains(.AltDown)
  }

  public var isAltGrDown: Bool {
    return flags.contains(.AltgrDown)
  }

  public var isCommandDown: Bool {
    return flags.contains(.CommandDown)
  }

  public var isRepeat: Bool {
    return flags.contains(.IsRepeat)
  }

  public var isKeyEvent: Bool {
    return type == .KeyPressed || type == .KeyReleased
  }

  public var isMouseEvent: Bool {
    return type == .MousePressed ||
           type == .MouseDragged ||
           type == .MouseReleased ||
           type == .MouseMoved ||
           type == .MouseEntered ||
           type == .MouseExited ||
           type == .MouseWheel ||
           type == .MouseCaptureChanged
  }

  public var isTouchEvent: Bool {
    return type == .TouchReleased ||
           type == .TouchPressed ||
           type == .TouchMoved ||
           type == .TouchCancelled
  }

  public var isGestureEvent: Bool {
    switch type {
      case .GestureScrollBegin,
           .GestureScrollEnd,
           .GestureScrollUpdate,
           .GestureTap,
           .GestureTapCancel,
           .GestureTapDown,
           .GestureBegin,
           .GestureEnd,
           .GestureTwoFingerTap,
           .GesturePinchBegin,
           .GesturePinchEnd,
           .GesturePinchUpdate,
           .GestureLongPress,
           .GestureLongTap,
           .GestureSwipe,
           .GestureShowPress,
           .GestureWin8EdgeSwipe:
           return true
      case .ScrollFlingCancel,
           .ScrollFlingStart:
           return flags.contains(.FromTouch)
      default:
           return false
      }
  }

  // An ending event is paired with the event which started it. Setting capture
  // should not prevent ending events from getting to their initial target.
  public var isEndingEvent: Bool {
    switch type {
      case .TouchCancelled,
           .GestureTapCancel,
           .GestureEnd,
           .GestureScrollEnd,
           .GesturePinchEnd:
        return true
      default:
          return false
    }
  }

  public var isScrollEvent: Bool {
    // Flings can be GestureEvents too. EF_FROM_TOUCH determins if they're
    // Gesture or Scroll events.
    return type == .Scroll ||
           ((type == .ScrollFlingStart ||
           type == .ScrollFlingCancel) &&
           !flags.contains(.FromTouch))
  }

  public var isScrollGestureEvent: Bool {
    return type == .GestureScrollBegin ||
           type == .GestureScrollUpdate ||
           type == .GestureScrollEnd
  }

  public var isFlingScrollEvent: Bool {
    return type == .ScrollFlingCancel ||
           type == .ScrollFlingStart
  }

  public var isMouseWheelEvent: Bool {
    return type == .MouseWheel
  }

  public var isLocatedEvent: Bool {
    return isMouseEvent || isScrollEvent || isTouchEvent || isGestureEvent
  }

  public var isPointerEvent: Bool {
    return type == .PointerDown ||
           type == .PointerMoved ||
           type == .PointerUp ||
           type == .PointerCancelled ||
           type == .PointerEntered ||
           type == .PointerExited ||
           type == .PointerWheelChanged ||
           type == .PointerCaptureChanged
  }

  public var stoppedPropagation: Bool {
    return !result.contains(.Consumed)
  }

  public static func clone(_ event: Event) -> Event {
    if event.isKeyEvent {
      return KeyEvent(copy: event as! KeyEvent)
    } else if event.isMouseEvent {
      if event.isMouseWheelEvent {
        return MouseWheelEvent(copy: event as! MouseWheelEvent)
      }
      return MouseEvent(copy: event as! MouseEvent)
    } else if event.isTouchEvent {
      return TouchEvent(copy: event as! TouchEvent)
    } else if event.isGestureEvent {
      return GestureEvent(copy: event as! GestureEvent)
    } else if event.isPointerEvent {
      return PointerEvent(copy: event as! PointerEvent)
    } else if event.isScrollEvent {
      return ScrollEvent(copy: event as! ScrollEvent)
    }
    return Event(copy: event)
  }

  init() {
    name = ""
    type = .Unknown
    cancelable = false
    latency = LatencyInfo()
    result = .Unhandled
    phase = .Predispatch
    timestamp = TimeTicks()
    flags = .None
    sourceDeviceId = 0
  }

  public init(_ event: PlatformEvent) {
    name = ""
    type = .Unknown
    cancelable = false
    latency = LatencyInfo()
    result = .Unhandled
    phase = .Predispatch
    timestamp = TimeTicks()
    flags = .None
    platformEvent = event
    sourceDeviceId = 0
  }

  public init(copy: Event) {
    name = copy.name
    type = copy.type
    cancelable = false
    latency = copy.latency
    result = .Unhandled
    phase = copy.phase
    timestamp = copy.timestamp
    flags = copy.flags
    platformEvent = copy.platformEvent
    sourceDeviceId = copy.sourceDeviceId
  }

  public func stopPropagation() {

  }

}

open class CancelModeEvent : Event {
  public override init() { super.init() }
  public override init(_ event: PlatformEvent) {
    super.init(event)
  }
}

open class LocatedEvent : Event {

  public var x: Float {
    return locationf.x
  }

  public var y: Float {
    return locationf.y
  }

  public var location: IntPoint {
    get {
      return IntPoint.toFloored(point: locationf)
    }
    set {
      locationf = FloatPoint(newValue)
    }
  }

  public var locationf: FloatPoint

  public var rootLocation: FloatPoint

  public override init(){
    locationf = FloatPoint()
    rootLocation = FloatPoint()
    super.init()
  }

  public override init(_ event: PlatformEvent) {
    locationf = FloatPoint()
    rootLocation = FloatPoint()
    super.init(event)
  }

  public init(copy: LocatedEvent) {
    locationf = FloatPoint()
    rootLocation = FloatPoint()
    super.init(copy: copy)
  }

  public init<T: EventTarget>(model: LocatedEvent, source: T, target: T?) {
    locationf = model.locationf
    rootLocation = model.rootLocation

    assert(target != nil && target !== source)

    var offset = IntPoint.toFloored(point: locationf)
    EventTarget.convertPointToTarget(source: source, target: target!, point: &offset);
    let diff: IntVec2 = IntPoint.toFloored(point: locationf) - offset
    locationf = locationf - diff
    super.init(copy: model)
  }

  public func convertLocationToTarget<T: EventTarget>(source: T, target: T) {
    assert(target !== source)

    var offset = IntPoint.toFloored(point: locationf)
    EventTarget.convertPointToTarget(source: source, target: target, point: &offset);
    let diff: IntVec2 = IntPoint.toFloored(point: locationf) - offset
    locationf = locationf - diff
  }
}

open class MouseEvent : LocatedEvent {

  public var onlyRightMouseButton: Bool {
    return false
  }

  public var onlyLeftMouseButton: Bool {
    return false
  }

  public var isRightMouseButton: Bool {
    return false
  }

  public var onlyMiddleMouseButton: Bool {
    return false
  }

  public var isAnyButton: Bool {
    return false
  }

  public var changedButtonFlags: Int = 0

  public override init(){ super.init() }

  public override init(_ event: PlatformEvent) {
    super.init(event)
  }

  public init(copy: MouseEvent) {
    super.init(copy: copy)
  }

  public init(model: MouseEvent, type: EventType) {
    super.init()
    self.type = type
  }

  public init(type etype: EventType,
              location: IntPoint,
              rootLocation: IntPoint,
              timestamp: Int64, // TODO: fixit
              flags: EventFlags,
              changedButtonFlags: Int) {
    super.init()
  }

  public override init<T: EventTarget>(model: LocatedEvent, source: T, target: T?) {
    super.init(model: model, source: source, target: target)
  }

}

public class MouseWheelEvent : MouseEvent {

#if os(Windows)
  public static let wheelDelta: Int = 120
#else
  public static let wheelDelta: Int = 53
#endif

  
  public var xOffset: Int {
    return offset.x
  }

  public var yOffset: Int {
    return offset.y
  }

  public private(set) var offset: IntVec2
 
  public override init(){
    offset = IntVec2()
    super.init() 
  }
 
  public override init(_ event: PlatformEvent) {
    offset = IntVec2()
    super.init(event)
  }
 
  public init(copy: MouseWheelEvent) {
    offset = IntVec2()
    super.init(copy: copy)
  }
 
  public init(event: ScrollEvent) {
    offset = IntVec2()
    super.init()
  }

  public init(event: MouseEvent, x: Int, y: Int) {
    offset = IntVec2(x: x, y: y)
    super.init(copy: event)
  }
}

public class TouchEvent : LocatedEvent {
  public override init(){ super.init() }
  public override init(_ event: PlatformEvent) {
    super.init(event)
  }

  public init(copy: TouchEvent) {
   super.init(copy: copy)
  }
}

public class PointerEvent : LocatedEvent {
  public init(copy: PointerEvent) {
    super.init(copy: copy)
  }
}

public class KeyEvent : Event {

  public var character: Int// {
  //  get {
  //    return "\0"
  //  }
  //  set {
  //
  //  }
  //}

  public var text: Character {
    return "\0"
  }

  public var unmodifiedText: Character {
    return "\0"
  }

  public var keyCode: KeyboardCode

  private (set) public var isChar: Bool

  private (set) public var code: DomCode

  public var locatedWindowsKeyboardCode: KeyboardCode {
    return .KeyUnknown
  }

  public var conflatedWindowsKeyCode: UInt16 {
    return 0
  }

  public var isUnicodeKeyCode: Bool {
    return false
  }

  public var domKey: DomKey {
    return key
  }

  public var codeString: String {
    return ""
  }

  private var key: DomKey

  public override init(){
    character = 0
    key = DomKey()
    isChar = false
    code = DomCode.None
    keyCode = .KeyUnknown
    super.init()
  }
  public override init(_ event: PlatformEvent) {
    character = 0
    key = DomKey()
    isChar = false
    code = DomCode.None
    keyCode = .KeyUnknown
    super.init(event)
  }

  public init(copy: KeyEvent) {
    character = 0
    key = DomKey()
    isChar = false
    code = DomCode.None
    keyCode = .KeyUnknown
    super.init(copy: copy)
  }

  public func normalizeFlags() {

  }

}

open class ScrollEvent: MouseEvent {
  public override init(){ super.init() }
  public override init(_ event: PlatformEvent) {
    super.init(event)
  }

  public init(copy: ScrollEvent) {
   super.init(copy: copy)
  }
}

open class GestureEvent : LocatedEvent {
  private (set) public var details: GestureEventDetails

  public override init() {
    details = GestureEventDetails()
    super.init()
  }
  public override init(_ event: PlatformEvent) {
    details = GestureEventDetails()
    super.init(event)
  }

  public init(copy: GestureEvent) {
    details = GestureEventDetails()
    super.init(copy: copy)
  }
}

open class DropTargetEvent : LocatedEvent {

  public var data: OSExchangeData

  public var sourceOperations: Int

  public init(data: OSExchangeData,
              location: IntPoint,
              rootLocation: IntPoint,
              sourceOperations: Int){
   self.data = data
   self.sourceOperations = sourceOperations
   super.init()
  }

  public override init(_ event: PlatformEvent) {
   data = OSExchangeData()
   sourceOperations = 0

   super.init(event)
  }
}
