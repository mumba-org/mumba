// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_INPUT_DISPOSITION_HANDLER_H_
#define MUMBA_HOST_APPLICATION_INPUT_INPUT_DISPOSITION_HANDLER_H_

#include "core/host/application/event_with_latency_info.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/common/input_event_ack_source.h"
#include "core/common/input_event_ack_state.h"
#include "third_party/blink/public/platform/web_input_event.h"

namespace host {

// Provided customized disposition response for input events.
class CONTENT_EXPORT InputDispositionHandler {
 public:
  virtual ~InputDispositionHandler() {}

  // Called upon event ack receipt from the renderer.
  virtual void OnKeyboardEventAck(
      const NativeWebKeyboardEventWithLatencyInfo& event,
      common::InputEventAckSource ack_source,
      common::InputEventAckState ack_result) = 0;
  virtual void OnMouseEventAck(const common::MouseEventWithLatencyInfo& event,
                               common::InputEventAckSource ack_source,
                               common::InputEventAckState ack_result) = 0;
  virtual void OnWheelEventAck(const common::MouseWheelEventWithLatencyInfo& event,
                               common::InputEventAckSource ack_source,
                               common::InputEventAckState ack_result) = 0;
  virtual void OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                               common::InputEventAckSource ack_source,
                               common::InputEventAckState ack_result) = 0;
  virtual void OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                                 common::InputEventAckSource ack_source,
                                 common::InputEventAckState ack_result) = 0;

  enum UnexpectedEventAckType {
    UNEXPECTED_ACK,
    UNEXPECTED_EVENT_TYPE,
    BAD_ACK_MESSAGE
  };
  virtual void OnUnexpectedEventAck(UnexpectedEventAckType type) = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_INPUT_DISPOSITION_HANDLER_H_
