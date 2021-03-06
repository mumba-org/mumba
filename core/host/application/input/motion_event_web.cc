// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/motion_event_web.h"

#include "base/logging.h"
#include "base/numerics/math_constants.h"
#include "core/shared/common/input/web_touch_event_traits.h"
#include "ui/events/blink/blink_event_util.h"
#include "ui/gfx/geometry/angle_conversions.h"

using blink::WebInputEvent;
using blink::WebPointerProperties;
using blink::WebTouchEvent;
using blink::WebTouchPoint;

namespace host {
namespace {

ui::MotionEvent::Action GetActionFrom(const WebTouchEvent& event) {
  DCHECK(event.touches_length);
  switch (event.GetType()) {
    case WebInputEvent::kTouchStart:
      if (common::WebTouchEventTraits::AllTouchPointsHaveState(
              event, WebTouchPoint::kStatePressed))
        return ui::MotionEvent::Action::DOWN;
      else
        return ui::MotionEvent::Action::POINTER_DOWN;
    case WebInputEvent::kTouchEnd:
      if (common::WebTouchEventTraits::AllTouchPointsHaveState(
              event, WebTouchPoint::kStateReleased))
        return ui::MotionEvent::Action::UP;
      else
        return ui::MotionEvent::Action::POINTER_UP;
    case WebInputEvent::kTouchCancel:
      DCHECK(common::WebTouchEventTraits::AllTouchPointsHaveState(
          event, WebTouchPoint::kStateCancelled));
      return ui::MotionEvent::Action::CANCEL;
    case WebInputEvent::kTouchMove:
      return ui::MotionEvent::Action::MOVE;
    default:
      break;
  };
  NOTREACHED()
      << "Unable to derive a valid MotionEvent::Action from the WebTouchEvent.";
  return ui::MotionEvent::Action::CANCEL;
}

int GetActionIndexFrom(const WebTouchEvent& event) {
  for (size_t i = 0; i < event.touches_length; ++i) {
    if (event.touches[i].state != WebTouchPoint::kStateUndefined &&
        event.touches[i].state != WebTouchPoint::kStateStationary)
      return i;
  }
  return -1;
}

}  // namespace

MotionEventWeb::MotionEventWeb(const WebTouchEvent& event)
    : event_(event),
      cached_action_(GetActionFrom(event)),
      cached_action_index_(GetActionIndexFrom(event)),
      unique_event_id_(event.unique_touch_event_id) {
  DCHECK_GT(GetPointerCount(), 0U);
}

MotionEventWeb::~MotionEventWeb() {}

uint32_t MotionEventWeb::GetUniqueEventId() const {
  return unique_event_id_;
}

MotionEventWeb::Action MotionEventWeb::GetAction() const {
  return cached_action_;
}

int MotionEventWeb::GetActionIndex() const {
  DCHECK(cached_action_ == Action::POINTER_UP ||
         cached_action_ == Action::POINTER_DOWN)
      << "Invalid action for GetActionIndex(): " << cached_action_;
  DCHECK_GE(cached_action_index_, 0);
  DCHECK_LT(cached_action_index_, static_cast<int>(event_.touches_length));
  return cached_action_index_;
}

size_t MotionEventWeb::GetPointerCount() const {
  return event_.touches_length;
}

int MotionEventWeb::GetPointerId(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return event_.touches[pointer_index].id;
}

float MotionEventWeb::GetX(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return event_.touches[pointer_index].PositionInWidget().x;
}

float MotionEventWeb::GetY(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return event_.touches[pointer_index].PositionInWidget().y;
}

float MotionEventWeb::GetRawX(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return event_.touches[pointer_index].PositionInScreen().x;
}

float MotionEventWeb::GetRawY(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return event_.touches[pointer_index].PositionInScreen().y;
}

float MotionEventWeb::GetTouchMajor(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return 2.f * std::max(event_.touches[pointer_index].radius_x,
                        event_.touches[pointer_index].radius_y);
}

float MotionEventWeb::GetTouchMinor(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());
  return 2.f * std::min(event_.touches[pointer_index].radius_x,
                        event_.touches[pointer_index].radius_y);
}

float MotionEventWeb::GetOrientation(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());

  float orientation_rad =
      gfx::DegToRad(event_.touches[pointer_index].rotation_angle);
  DCHECK(0 <= orientation_rad && orientation_rad <= base::kPiFloat / 2)
      << "Unexpected touch rotation angle";

  if (GetToolType(pointer_index) == ToolType::STYLUS) {
    const WebPointerProperties& pointer = event_.touches[pointer_index];

    if (pointer.tilt_y <= 0 && pointer.tilt_x < 0) {
      // Stylus is tilted to the left away from the user or straight
      // to the left thus the orientation should be within [pi/2,pi).
      orientation_rad += base::kPiFloat / 2;
    } else if (pointer.tilt_y < 0 && pointer.tilt_x >= 0) {
      // Stylus is tilted to the right away from the user or straight away
      // from the user thus the orientation should be within [-pi,-pi/2).
      orientation_rad -= base::kPiFloat;
    } else if (pointer.tilt_y >= 0 && pointer.tilt_x > 0) {
      // Stylus is tilted to the right towards the user or straight
      // to the right thus the orientation should be within [-pi/2,0).
      orientation_rad -= base::kPiFloat / 2;
    }
  } else if (event_.touches[pointer_index].radius_x >
             event_.touches[pointer_index].radius_y) {
    // The case radiusX == radiusY is omitted from here on purpose: for circles,
    // we want to pass the angle (which could be any value in such cases but
    // always seems to be set to zero) unchanged.
    orientation_rad -= base::kPiFloat / 2;
  }

  return orientation_rad;
}

float MotionEventWeb::GetPressure(size_t pointer_index) const {
  return 0.f;
}

float MotionEventWeb::GetTiltX(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());

  if (GetToolType(pointer_index) != ToolType::STYLUS)
    return 0.f;

  return event_.touches[pointer_index].tilt_x;
}

float MotionEventWeb::GetTiltY(size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());

  if (GetToolType(pointer_index) != ToolType::STYLUS)
    return 0.f;

  return event_.touches[pointer_index].tilt_y;
}

base::TimeTicks MotionEventWeb::GetEventTime() const {
  return event_.TimeStamp();
}

ui::MotionEvent::ToolType MotionEventWeb::GetToolType(
    size_t pointer_index) const {
  DCHECK_LT(pointer_index, GetPointerCount());

  const WebPointerProperties& pointer = event_.touches[pointer_index];

  switch (pointer.pointer_type) {
    case WebPointerProperties::PointerType::kUnknown:
      return ToolType::UNKNOWN;
    case WebPointerProperties::PointerType::kMouse:
      return ToolType::MOUSE;
    case WebPointerProperties::PointerType::kPen:
      return ToolType::STYLUS;
    case WebPointerProperties::PointerType::kEraser:
      return ToolType::ERASER;
    case WebPointerProperties::PointerType::kTouch:
      return ToolType::FINGER;
  }
  NOTREACHED() << "Unexpected pointerType";
  return ToolType::UNKNOWN;
}

int MotionEventWeb::GetButtonState() const {
  return 0;
}

int MotionEventWeb::GetFlags() const {
  return ui::WebEventModifiersToEventFlags(event_.GetModifiers());
}

}  // namespace host
