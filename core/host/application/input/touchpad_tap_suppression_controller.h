// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_TOUCHPAD_TAP_SUPPRESSION_CONTROLLER_H_
#define MUMBA_HOST_APPLICATION_INPUT_TOUCHPAD_TAP_SUPPRESSION_CONTROLLER_H_

#include "base/macros.h"
#include "core/host/application/event_with_latency_info.h"
#include "core/host/application/input/tap_suppression_controller.h"
#include "core/host/application/input/tap_suppression_controller_client.h"
#include "core/shared/common/content_export.h"
#include "third_party/blink/public/platform/web_input_event.h"

namespace host {

class TapSuppressionController;

class CONTENT_EXPORT TouchpadTapSuppressionControllerClient {
 public:
  virtual ~TouchpadTapSuppressionControllerClient() {}
  virtual void SendMouseEventImmediately(
      const common::MouseEventWithLatencyInfo& event) = 0;
};

// Controls the suppression of touchpad taps immediately following the dispatch
// of a GestureFlingCancel event.
class TouchpadTapSuppressionController : public TapSuppressionControllerClient {
 public:
  // The |client| must outlive the TouchpadTapSupressionController.
  TouchpadTapSuppressionController(
      TouchpadTapSuppressionControllerClient* client,
      const TapSuppressionController::Config& config);
  ~TouchpadTapSuppressionController() override;

  // Should be called on arrival of GestureFlingCancel events.
  void GestureFlingCancel();

  // Should be called on arrival of ACK for a GestureFlingCancel event.
  // |processed| is true if the GestureFlingCancel successfully stopped a fling.
  void GestureFlingCancelAck(bool processed);

  // Should be called on arrival of MouseDown events. Returns true if the caller
  // should stop normal handling of the MouseDown. In this case, the caller is
  // responsible for saving the event for later use, if needed.
  bool ShouldDeferMouseDown(const common::MouseEventWithLatencyInfo& event);

  // Should be called on arrival of MouseUp events. Returns true if the caller
  // should stop normal handling of the MouseUp.
  bool ShouldSuppressMouseUp();

 private:
  friend class MockApplicationWindowHost;

  // TapSuppressionControllerClient implementation.
  void DropStashedTapDown() override;
  void ForwardStashedGestureEvents() override;
  void ForwardStashedTapDown() override;

  TouchpadTapSuppressionControllerClient* client_;
  common::MouseEventWithLatencyInfo stashed_mouse_down_;

  // The core controller of tap suppression.
  TapSuppressionController controller_;

  DISALLOW_COPY_AND_ASSIGN(TouchpadTapSuppressionController);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_TOUCHPAD_TAP_SUPPRESSION_CONTROLLER_H_
