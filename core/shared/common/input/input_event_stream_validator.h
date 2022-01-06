// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_INPUT_INPUT_EVENT_STREAM_VALIDATOR_H_
#define CONTENT_COMMON_INPUT_INPUT_EVENT_STREAM_VALIDATOR_H_

#include <string>

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/gesture_event_stream_validator.h"
#include "core/shared/common/input/touch_event_stream_validator.h"

namespace blink {
class WebInputEvent;
}

namespace common {

// DCHECKs that the stream of WebInputEvents passed to OnEvent is
// valid. Currently only validates touch and touchscreen gesture events.
class CONTENT_EXPORT InputEventStreamValidator {
 public:
  InputEventStreamValidator();
  ~InputEventStreamValidator();

  void Validate(const blink::WebInputEvent&,
                const bool fling_cancellation_is_deferred = false);

 private:
  bool ValidateImpl(const blink::WebInputEvent&,
                    const bool fling_cancellation_is_deferred,
                    std::string* error_msg);

  GestureEventStreamValidator gesture_validator_;
  TouchEventStreamValidator touch_validator_;
  std::string error_msg_;
  const bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(InputEventStreamValidator);
};

}  // namespace common

#endif  // CONTENT_COMMON_INPUT_INPUT_EVENT_STREAM_VALIDATOR_H_
