// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_APPLICATION_WINDOW_HOST_LATENCY_TRACKER_H_
#define MUMBA_HOST_APPLICATION_INPUT_APPLICATION_WINDOW_HOST_LATENCY_TRACKER_H_

#include <stdint.h>

#include <vector>

#include "base/macros.h"
#include "core/host/application/event_with_latency_info.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input_event_ack_state.h"
#include "ui/latency/latency_info.h"
#include "ui/latency/latency_tracker.h"

namespace host {

class ApplicationWindowHostDelegate;

// Utility class for tracking the latency of events passing through
// a given ApplicationWindowHost.
class CONTENT_EXPORT ApplicationWindowHostLatencyTracker
    : public ui::LatencyTracker {
 public:
  ApplicationWindowHostLatencyTracker(bool metric_sampling,
                                 ApplicationWindowHostDelegate* delegate);
  virtual ~ApplicationWindowHostLatencyTracker();

  // Associates the latency tracker with a given route and process.
  // Called once after the ApplicationWindowHost is fully initialized.
  void Initialize(int routing_id, int process_id);

  void ComputeInputLatencyHistograms(blink::WebInputEvent::Type type,
                                     int64_t latency_component_id,
                                     const ui::LatencyInfo& latency,
                                     common::InputEventAckState ack_result);

  // Populates the LatencyInfo with relevant entries for latency tracking.
  // Called when an event is received by the ApplicationWindowHost, prior to
  // that event being forwarded to the renderer (via the InputRouter).
  void OnInputEvent(const blink::WebInputEvent& event,
                    ui::LatencyInfo* latency);

  // Populates the LatencyInfo with relevant entries for latency tracking, also
  // terminating latency tracking for events that did not trigger rendering and
  // performing relevant UMA latency reporting. Called when an event is ack'ed
  // to the ApplicationWindowHost (from the InputRouter).
  void OnInputEventAck(const blink::WebInputEvent& event,
                       ui::LatencyInfo* latency,
                       common::InputEventAckState ack_result);

  void reset_delegate() { application_window_host_delegate_ = nullptr; }

  // Returns the ID that uniquely describes this component to the latency
  // subsystem.
  int64_t latency_component_id() const { return latency_component_id_; }

 private:
  int64_t last_event_id_;
  int64_t latency_component_id_;
  bool has_seen_first_gesture_scroll_update_;
  //bool set_url_for_ukm_ = false;
  // Whether the current stream of touch events includes more than one active
  // touch point. This is set in OnInputEvent, and cleared in OnInputEventAck.
  bool active_multi_finger_gesture_;
  // Whether the touch start for the current stream of touch events had its
  // default action prevented. Only valid for single finger gestures.
  bool touch_start_default_prevented_;

  ApplicationWindowHostDelegate* application_window_host_delegate_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHostLatencyTracker);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_RENDER_WIDGET_HOST_LATENCY_TRACKER_H_
