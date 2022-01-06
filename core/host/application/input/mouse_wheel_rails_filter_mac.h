// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_MOUSE_WHEEL_RAILS_FILTER_MAC_H_
#define MUMBA_HOST_APPLICATION_INPUT_MOUSE_WHEEL_RAILS_FILTER_MAC_H_

#include "core/shared/common/content_export.h"
#include "third_party/blink/public/platform/web_mouse_wheel_event.h"
#include "ui/gfx/geometry/vector2d_f.h"

namespace host {

class CONTENT_EXPORT MouseWheelRailsFilterMac {
 public:
  MouseWheelRailsFilterMac();
  ~MouseWheelRailsFilterMac();
  blink::WebInputEvent::RailsMode UpdateRailsMode(
      const blink::WebMouseWheelEvent& event);

 private:
  gfx::Vector2dF decayed_delta_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_MOUSE_WHEEL_RAILS_FILTER_MAC_H_
