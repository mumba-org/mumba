// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_AURA_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_AURA_H_

#include "base/macros.h"
#include "base/time/time.h"
#include "core/host/application/input/synthetic_gesture_target_base.h"
#include "core/shared/common/input/synthetic_gesture_params.h"

namespace aura {
class Window;
}  // namespace aura

namespace host {

// SyntheticGestureTarget implementation for aura
class SyntheticGestureTargetAura : public SyntheticGestureTargetBase {
 public:
  explicit SyntheticGestureTargetAura(ApplicationWindowHost* host);

  // SyntheticGestureTargetBase:
  void DispatchWebTouchEventToPlatform(
      const blink::WebTouchEvent& web_touch,
      const ui::LatencyInfo& latency_info) override;
  void DispatchWebMouseWheelEventToPlatform(
      const blink::WebMouseWheelEvent& web_wheel,
      const ui::LatencyInfo& latency_info) override;
  void DispatchWebMouseEventToPlatform(
      const blink::WebMouseEvent& web_mouse,
      const ui::LatencyInfo& latency_info) override;

  // SyntheticGestureTarget:
  common::SyntheticGestureParams::GestureSourceType
  GetDefaultSyntheticGestureSourceType() const override;

  float GetTouchSlopInDips() const override;

  float GetMinScalingSpanInDips() const override;

 private:
  aura::Window* GetWindow() const;

  // Synthetic located event's location and touch event's radius are in DIP and
  // aura event dispatcher assumes input event is in device pixel and will apply
  // device scale factor to convert the input to DIP. So we need to use
  // device_scale_factor to convert the input event from DIP to device pixel
  // before dispatching it into platform.
  float device_scale_factor_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticGestureTargetAura);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_AURA_H_
