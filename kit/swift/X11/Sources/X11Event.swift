// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base
import MumbaShims

// Scroll amount for each wheelscroll event. 53 is also the value used for GTK+.
let WheelScrollAmount: Int = 53
let MinWheelButton: Int = 4
let MaxWheelButton: Int = 7


func _XIMaskIsSet(mask: UnsafeMutablePointer<UInt8>, _ event: Int) -> Bool {
  let index = Int(event >> 3)
  return mask[index] & UInt8(1 << (event & 7)) != 0
}

// Detects if a touch event is a driver-generated 'special event'.
// A 'special event' is a touch event with maximum radius and pressure at
// location (0, 0).
// This needs to be done in a cleaner way: http://crbug.com/169256
func touchEventIsGeneratedHack(nativeEvent: PlatformEvent) -> Bool {
  // XIDeviceEvent* event =
  //     static_cast<XIDeviceEvent*>(native_event->xcookie.data);
  // CHECK(event->evtype == XI_TouchBegin ||
  //       event->evtype == XI_TouchUpdate ||
  //       event->evtype == XI_TouchEnd);
  //
  // // Force is normalized to [0, 1].
  // if (ui::GetTouchForce(native_event) < 1.0f)
  //   return false;
  //
  // if (ui::EventLocationFromNative(native_event) != gfx::IntPoint())
  //   return false;
  //
  // // Radius is in pixels, and the valuator is the diameter in pixels.
  // double radius = ui::GetTouchRadiusX(native_event), min, max;
  // unsigned int deviceid =
  //     static_cast<XIDeviceEvent*>(native_event->xcookie.data)->sourceid;
  // if (!ui::DeviceDataManagerX11::GetInstance()->GetDataRange(
  //     deviceid, ui::DeviceDataManagerX11::DT_TOUCH_MAJOR, &min, &max)) {
  //   return false;
  // }
  //
  // return radius * 2 == max
  return false
}

func getFlingData(nativeEvent: PlatformEvent,
                  vx: inout Float,
                  vy: inout Float,
                  vxOrdinal: inout Float,
                  vyOrdinal: inout Float,
                  isCancel: inout Bool) -> Bool {
  //if (!DeviceDataManagerX11::GetInstance()->IsFlingEvent(native_event))
  //  return false;

  //float vx_, vy_;
  //float vx_ordinal_, vy_ordinal_;
  //bool is_cancel_;
  //if (!vx)
  //  vx = &vx_;
  //if (!vy)
  //  vy = &vy_;
  //if (!vx_ordinal)
  //  vx_ordinal = &vx_ordinal_;
  //if (!vy_ordinal)
  //  vy_ordinal = &vy_ordinal_;
  //if (!is_cancel)
  //  is_cancel = &is_cancel_;

  //DeviceDataManagerX11::GetInstance()->GetFlingData(
  //    native_event, vx, vy, vx_ordinal, vy_ordinal, is_cancel);
  //return true;
  return true
}

func getEventFlagsForButton(button: Int) -> Int {
  switch button {
    case 1:
      return EventFlags.LeftMouseButton.rawValue
    case 2:
      return EventFlags.MiddleMouseButton.rawValue
    case 3:
      return EventFlags.RightMouseButton.rawValue
    case 8:
      return EventFlags.BackMouseButton.rawValue
    case 9:
      return EventFlags.ForwardMouseButton.rawValue
    default:
      return 0
  }
}

func getButtonMaskForX2Event(xievent: XIDeviceEvent) -> Int {
  var buttonflags: Int = 0
  for i in 0...8 * Int(xievent.buttons.mask_len) {
    if _XIMaskIsSet(mask: xievent.buttons.mask, i) {
      let button: Int = (xievent.sourceid == xievent.deviceid) ?
          X11DeviceDataManager.instance()!.getMappedButton(button: i) : i
      buttonflags |= getEventFlagsForButton(button: button)
    }
  }
  return buttonflags
}

func getTouchEventType(nativeEvent: PlatformEvent) -> EventType {

  let event = unsafeBitCast(nativeEvent.xcookie.data, to: XIDeviceEvent.self)
  switch event.evtype {
    case XI_TouchBegin:
      return touchEventIsGeneratedHack(nativeEvent: nativeEvent) ? .Unknown :
                                                      .TouchPressed
    case XI_TouchUpdate:
      return touchEventIsGeneratedHack(nativeEvent: nativeEvent) ? .Unknown :
                                                      .TouchMoved
    case XI_TouchEnd:
      return touchEventIsGeneratedHack(nativeEvent: nativeEvent) ? .TouchCancelled :
                                                      .TouchReleased
    case XI_ButtonPress:
      return .TouchPressed
    case XI_ButtonRelease:
      return .TouchReleased
    case XI_Motion:
      // Should not convert any emulated Motion event from touch device to
      // touch event.
      if (event.flags & XIPointerEmulated) == 0 &&
          getButtonMaskForX2Event(xievent: event) != 0 {
        return .TouchMoved
      }
      return .Unknown
    default:
      break
      //NOTREACHED();
  }
  return .Unknown
}

func eventButtonFromNative(nativeEvent: PlatformEvent) -> Int {
  assert(GenericEvent == nativeEvent.type)
  let xievent = unsafeBitCast(nativeEvent.xcookie.data, to: XIDeviceEvent.self)
  let button: Int = Int(xievent.detail)

  return (xievent.sourceid == xievent.deviceid) ?
         X11DeviceDataManager.instance()!.getMappedButton(button: button) : button
}

public func eventTypeFromNative(nativeEvent: PlatformEvent) -> EventType {

  if let deviceManager = X11DeviceDataManager.instance() {
    if deviceManager.isEventBlocked(event: nativeEvent) {
      return .Unknown
    }
  }

  switch nativeEvent.type {

    case KeyPress:
      return .KeyPressed
    case KeyRelease:
      return .KeyReleased
    case ButtonPress:
      if Int(nativeEvent.xbutton.button) >= MinWheelButton &&
          Int(nativeEvent.xbutton.button) <= MaxWheelButton {
        return .MouseWheel
      }
      return .MousePressed
    case ButtonRelease:
      // Drop wheel events; we should've already scrolled on the press.
      if Int(nativeEvent.xbutton.button) >= MinWheelButton &&
          Int(nativeEvent.xbutton.button) <= MaxWheelButton {
        return .Unknown
      }
      return .MouseReleased
    case MotionNotify:
      if nativeEvent.xmotion.state & UInt32(Button1Mask | Button2Mask | Button3Mask) != 0 {
        return .MouseDragged
      }
      return .MouseMoved
    case EnterNotify:
      // The standard on Windows is to send a MouseMove event when the mouse
      // first enters a window instead of sending a special mouse enter event.
      // To be consistent we follow the same style.
      return .MouseMoved
    case LeaveNotify:
      return .MouseExited
    case GenericEvent:
      if let touchFactory = X11TouchFactory.instance() {
      
        if !touchFactory.shouldProcessXI2Event(xev: nativeEvent) {
          return .Unknown
        }

        let xievent = unsafeBitCast(nativeEvent.xcookie.data, to: XIDeviceEvent.self)

        // This check works only for master and floating slave devices. That is
        // why it is necessary to check for the XI_Touch* events in the following
        // switch statement to account for attached-slave touchscreens.
        if touchFactory.isTouchDevice(device: Int(xievent.sourceid)) {
          return getTouchEventType(nativeEvent: nativeEvent)
        }

        switch xievent.evtype {
          case XI_TouchBegin:
            return .TouchPressed
          case XI_TouchUpdate:
            return .TouchMoved
          case XI_TouchEnd:
            return .TouchReleased
          case XI_ButtonPress:
            let button = eventButtonFromNative(nativeEvent: nativeEvent)
            if button >= MinWheelButton && button <= MaxWheelButton {
              return .MouseWheel
            }
            return .MousePressed
          case XI_ButtonRelease:
            let button = eventButtonFromNative(nativeEvent: nativeEvent)
            // Drop wheel events; we should've already scrolled on the press.
            if button >= MinWheelButton && button <= MaxWheelButton {
              return .Unknown
            }
            return .MouseReleased
          case XI_Motion:
            var isCancel: Bool = false
            let devices = X11DeviceDataManager.instance()!
            var fa: Float = 0.0, fb: Float = 0.0, fc: Float = 0.0, fd: Float = 0.0
            if getFlingData(nativeEvent: nativeEvent, vx: &fa,  vy: &fb, vxOrdinal: &fc, vyOrdinal: &fd, isCancel: &isCancel) {
              return isCancel ? .ScrollFlingCancel : .ScrollFlingStart
            }
            if devices.isScrollEvent(event: nativeEvent) {
              return devices.isTouchpadXInputEvent(event: nativeEvent) ? .Scroll : .MouseWheel
            }
            if devices.isCMTMetricsEvent(event: nativeEvent) {
              return .UMAData
            }
            if getButtonMaskForX2Event(xievent: xievent) != 0 {
              return .MouseDragged
            }
            if devices.hasEventData(
                  xiev: xievent, type: X11DeviceDataManager.DataType.CMTScrollX) ||
              devices.hasEventData(
                  xiev: xievent, type: X11DeviceDataManager.DataType.CMTScrollY) {
            // Don't produce mouse move events for mousewheel scrolls.
              return .Unknown
            }
            return .MouseMoved
          case XI_KeyPress:
            return .KeyPressed
          case XI_KeyRelease:
            return .KeyReleased
          default:
            break
        }
    }
    default:
      break
  }
  return .Unknown
}

public func eventTimeFromNative(nativeEvent: PlatformEvent) -> TimeDelta {

  switch nativeEvent.type {
    case KeyPress, KeyRelease:
      return TimeDelta.from(milliseconds: Int64(nativeEvent.xkey.time))
    case ButtonPress, ButtonRelease:
      return TimeDelta.from(milliseconds: Int64(nativeEvent.xbutton.time))
    case MotionNotify:
      return TimeDelta.from(milliseconds: Int64(nativeEvent.xmotion.time))
    case EnterNotify, LeaveNotify:
      return TimeDelta.from(milliseconds: Int64(nativeEvent.xcrossing.time))
    case GenericEvent:
      var start: Int64 = 0, end: Int64 = 0
      var touchTimestamp: Int64 = 0
      if getGestureTimes(nativeEvent: nativeEvent, startTime: &start, endTime: &end) {
        // If the driver supports gesture times, use them.
        return TimeDelta.from(milliseconds: end * 1000000)
      } else if X11DeviceDataManager.instance()!.getEventData(
          xev: nativeEvent,
          type: X11DeviceDataManager.DataType.TouchRawTimestamp,
          value: &touchTimestamp) {
        return TimeDelta.from(milliseconds: touchTimestamp * 1000000)
      } else {
        let xide = unsafeBitCast(nativeEvent.xcookie.data, to: XIDeviceEvent.self)
        return TimeDelta.from(milliseconds: Int64(xide.time))
      }
      default:
        break
  }
  return TimeDelta()
}

func getGestureTimes(nativeEvent: PlatformEvent,
                     startTime: inout Int64,
                     endTime: inout Int64) -> Bool {
  // if (!ui::DeviceDataManagerX11::GetInstance()->HasGestureTimes(native_event))
  //   return false;
  //
  // double start_time_, end_time_;
  // if (!start_time)
  //   start_time = &start_time_;
  // if (!end_time)
  //   end_time = &end_time_;
  //
  // ui::DeviceDataManagerX11::GetInstance()->GetGestureTimes(
  //     native_event, start_time, end_time);
  // return true;
  return false
}
