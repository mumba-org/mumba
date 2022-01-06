// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_COMMON_INPUT_EVENT_ACK_STATE_H_
#define CONTENT_PUBLIC_COMMON_INPUT_EVENT_ACK_STATE_H_

#include "core/shared/common/content_export.h"

namespace common {

// Describes the state of the input event ACK coming back to the browser side.
enum InputEventAckState : int {
  INPUT_EVENT_ACK_STATE_UNKNOWN = 0,
  INPUT_EVENT_ACK_STATE_CONSUMED = 1,
  INPUT_EVENT_ACK_STATE_NOT_CONSUMED = 2,
  INPUT_EVENT_ACK_STATE_CONSUMED_SHOULD_BUBBLE = 3,
  INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS = 4,
  INPUT_EVENT_ACK_STATE_IGNORED = 5,
  INPUT_EVENT_ACK_STATE_SET_NON_BLOCKING = 6,
  INPUT_EVENT_ACK_STATE_SET_NON_BLOCKING_DUE_TO_FLING = 7,
  INPUT_EVENT_ACK_STATE_MAX =
      INPUT_EVENT_ACK_STATE_SET_NON_BLOCKING_DUE_TO_FLING
};

CONTENT_EXPORT const char* InputEventAckStateToString(InputEventAckState ack_state);

}  // namespace content

#endif  // CONTENT_PUBLIC_COMMON_INPUT_EVENT_ACK_STATE_H_
