// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_MOCK_INPUT_DISPOSITION_HANDLER_H_
#define MUMBA_HOST_APPLICATION_INPUT_MOCK_INPUT_DISPOSITION_HANDLER_H_

#include <stddef.h>

#include <memory>
#include <utility>

#include "core/host/application/input/input_disposition_handler.h"

namespace host {

class InputRouter;

class MockInputDispositionHandler : public InputDispositionHandler {
 public:
  MockInputDispositionHandler();
  ~MockInputDispositionHandler() override;

  // InputDispositionHandler
  void OnKeyboardEventAck(const NativeWebKeyboardEventWithLatencyInfo& event,
                          common::InputEventAckSource ack_source,
                          common::InputEventAckState ack_result) override;
  void OnMouseEventAck(const common::MouseEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnWheelEventAck(const common::MouseWheelEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                         common::InputEventAckSource ack_source,
                         common::InputEventAckState ack_result) override;
  void OnUnexpectedEventAck(UnexpectedEventAckType type) override;

  size_t GetAndResetAckCount();

  void set_input_router(InputRouter* input_router) {
    input_router_ = input_router;
  }

  void set_followup_touch_event(
      std::unique_ptr<common::GestureEventWithLatencyInfo> event) {
    gesture_followup_event_ = std::move(event);
  }

  void set_followup_touch_event(
      std::unique_ptr<common::TouchEventWithLatencyInfo> event) {
    touch_followup_event_ = std::move(event);
  }

  bool unexpected_event_ack_called() const {
    return unexpected_event_ack_called_;
  }
  common::InputEventAckState ack_state() const { return ack_state_; }

  common::InputEventAckState acked_wheel_event_state() const {
    return acked_wheel_event_state_;
  }

  blink::WebInputEvent::Type ack_event_type() const { return ack_event_type_; }

  const NativeWebKeyboardEvent& acked_keyboard_event() const {
    return *acked_key_event_;
  }
  const blink::WebMouseWheelEvent& acked_wheel_event() const {
    return acked_wheel_event_;
  }
  const common::TouchEventWithLatencyInfo& acked_touch_event() const {
    return acked_touch_event_;
  }
  const blink::WebGestureEvent& acked_gesture_event() const {
    return acked_gesture_event_;
  }

 private:
  void RecordAckCalled(blink::WebInputEvent::Type eventType,
                       common::InputEventAckState ack_result);

  InputRouter* input_router_;

  size_t ack_count_;
  bool unexpected_event_ack_called_;
  blink::WebInputEvent::Type ack_event_type_;
  common::InputEventAckState ack_state_;
  common::InputEventAckState acked_wheel_event_state_;
  std::unique_ptr<NativeWebKeyboardEvent> acked_key_event_;
  blink::WebMouseWheelEvent acked_wheel_event_;
  common::TouchEventWithLatencyInfo acked_touch_event_;
  blink::WebGestureEvent acked_gesture_event_;
  blink::WebMouseEvent acked_mouse_event_;

  std::unique_ptr<common::GestureEventWithLatencyInfo> gesture_followup_event_;
  std::unique_ptr<common::TouchEventWithLatencyInfo> touch_followup_event_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_MOCK_INPUT_DISPOSITION_HANDLER_H_
