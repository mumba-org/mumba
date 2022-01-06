// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_UI_EVENTS_HELPER_H_
#define MUMBA_HOST_APPLICATION_UI_EVENTS_HELPER_H_

#include <memory>
#include <vector>

#include "core/host/application/event_with_latency_info.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input_event_ack_state.h"

namespace ui {
class TouchEvent;
}

namespace host {

enum TouchEventCoordinateSystem {
  SCREEN_COORDINATES,
  LOCAL_COORDINATES
};

// Creates a list of ui::TouchEvents out of a single WebTouchEvent.
// A WebTouchEvent can contain information about a number of WebTouchPoints,
// whereas a ui::TouchEvent contains information about a single touch-point. So
// it is possible to create more than one ui::TouchEvents out of a single
// WebTouchEvent. All the ui::TouchEvent in the list will carry the same
// LatencyInfo the WebTouchEvent carries.
// |coordinate_system| specifies which fields to use for the co-ordinates,
// WebTouchPoint.position or WebTouchPoint.screenPosition.  Is's up to the
// caller to do any co-ordinate system mapping (typically to get them into
// the Aura EventDispatcher co-ordinate system).
CONTENT_EXPORT bool MakeUITouchEventsFromWebTouchEvents(
    const common::TouchEventWithLatencyInfo& touch,
    std::vector<std::unique_ptr<ui::TouchEvent>>* list,
    TouchEventCoordinateSystem coordinate_system);

// Utility to map the event ack state from the renderer, returns true if the
// event could be handled non-blocking.
bool InputEventAckStateIsSetNonBlocking(common::InputEventAckState);

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_UI_EVENTS_HELPER_H_
