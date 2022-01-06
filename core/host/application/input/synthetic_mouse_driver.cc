// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/synthetic_mouse_driver.h"

#include "core/host/application/input/synthetic_gesture_target.h"

namespace host {

SyntheticMouseDriver::SyntheticMouseDriver() : last_modifiers_(0) {
  mouse_event_.pointer_type = blink::WebPointerProperties::PointerType::kMouse;
}

SyntheticMouseDriver::~SyntheticMouseDriver() {}

void SyntheticMouseDriver::DispatchEvent(SyntheticGestureTarget* target,
                                         const base::TimeTicks& timestamp) {
  mouse_event_.SetTimeStamp(timestamp);
  if (mouse_event_.GetType() != blink::WebInputEvent::kUndefined) {
    target->DispatchInputEventToPlatform(mouse_event_);
    mouse_event_.SetType(blink::WebInputEvent::kUndefined);
  }
}

void SyntheticMouseDriver::Press(float x,
                                 float y,
                                 int index,
                                 common::SyntheticPointerActionParams::Button button) {
  DCHECK_EQ(index, 0);
  int modifiers =
      common::SyntheticPointerActionParams::GetWebMouseEventModifier(button);
  mouse_event_ = common::SyntheticWebMouseEventBuilder::Build(
      blink::WebInputEvent::kMouseDown, x, y, modifiers | last_modifiers_,
      mouse_event_.pointer_type);
  mouse_event_.click_count = 1;
  mouse_event_.button =
      common::SyntheticPointerActionParams::GetWebMouseEventButton(button);
  last_modifiers_ = modifiers | last_modifiers_;
}

void SyntheticMouseDriver::Move(float x, float y, int index) {
  DCHECK_EQ(index, 0);
  blink::WebMouseEvent::Button button = mouse_event_.button;
  int click_count = mouse_event_.click_count;
  mouse_event_ = common::SyntheticWebMouseEventBuilder::Build(
      blink::WebInputEvent::kMouseMove, x, y, last_modifiers_,
      mouse_event_.pointer_type);
  mouse_event_.button = button;
  mouse_event_.click_count = click_count;
}

void SyntheticMouseDriver::Release(
    int index,
    common::SyntheticPointerActionParams::Button button) {
  DCHECK_EQ(index, 0);
  mouse_event_ = common::SyntheticWebMouseEventBuilder::Build(
      blink::WebInputEvent::kMouseUp, mouse_event_.PositionInWidget().x,
      mouse_event_.PositionInWidget().y, last_modifiers_,
      mouse_event_.pointer_type);
  mouse_event_.click_count = 1;
  mouse_event_.button =
      common::SyntheticPointerActionParams::GetWebMouseEventButton(button);
  last_modifiers_ =
      last_modifiers_ &
      (~common::SyntheticPointerActionParams::GetWebMouseEventModifier(button));
}

bool SyntheticMouseDriver::UserInputCheck(
    const common::SyntheticPointerActionParams& params) const {
  if (params.index() != 0)
    return false;

  if (params.pointer_action_type() ==
      common::SyntheticPointerActionParams::PointerActionType::NOT_INITIALIZED) {
    return false;
  }

  if (params.pointer_action_type() ==
      common::SyntheticPointerActionParams::PointerActionType::PRESS) {
    int modifiers =
        common::SyntheticPointerActionParams::GetWebMouseEventModifier(params.button());
    if (last_modifiers_ & modifiers)
      return false;
  }

  if (params.pointer_action_type() ==
          common::SyntheticPointerActionParams::PointerActionType::RELEASE &&
      mouse_event_.click_count <= 0) {
    return false;
  }

  return true;
}

}  // namespace host
