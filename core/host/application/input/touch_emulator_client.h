// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_TOUCH_EMULATOR_CLIENT_H_
#define MUMBA_HOST_APPLICATION_INPUT_TOUCH_EMULATOR_CLIENT_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/cursors/webcursor.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/blink/public/platform/web_touch_event.h"
#include "ui/base/ui_base_types.h"

namespace host {

// Emulates touch input with mouse and keyboard.
class CONTENT_EXPORT TouchEmulatorClient {
 public:
  virtual ~TouchEmulatorClient() {}

  virtual void ForwardEmulatedGestureEvent(
      const blink::WebGestureEvent& event) = 0;
  virtual void ForwardEmulatedTouchEvent(const blink::WebTouchEvent& event) = 0;
  virtual void SetCursor(const common::WebCursor& cursor) = 0;
  virtual void ShowContextMenuAtPoint(const gfx::Point& point,
                                      const ui::MenuSourceType source_type) = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_TOUCH_EMULATOR_CLIENT_H_
