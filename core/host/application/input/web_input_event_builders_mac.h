// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_
#define MUMBA_HOST_APPLICATION_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_

#include "core/shared/common/content_export.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/platform/web_keyboard_event.h"
#include "third_party/blink/public/platform/web_mouse_wheel_event.h"

@class NSEvent;
@class NSView;

namespace host {

class CONTENT_EXPORT WebKeyboardEventBuilder {
 public:
  static blink::WebKeyboardEvent Build(NSEvent* event);
};

class CONTENT_EXPORT WebMouseEventBuilder {
 public:
  static blink::WebMouseEvent Build(
      NSEvent* event,
      NSView* view,
      blink::WebPointerProperties::PointerType pointerType =
          blink::WebPointerProperties::PointerType::kMouse);
};

class CONTENT_EXPORT WebMouseWheelEventBuilder {
 public:
  static blink::WebMouseWheelEvent Build(NSEvent* event,
                                         NSView* view);
};

class CONTENT_EXPORT WebGestureEventBuilder {
 public:
  static blink::WebGestureEvent Build(NSEvent*, NSView*);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_
