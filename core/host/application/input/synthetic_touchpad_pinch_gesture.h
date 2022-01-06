// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_TOUCHPAD_PINCH_GESTURE_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_TOUCHPAD_PINCH_GESTURE_H_

#include "base/macros.h"
#include "base/time/time.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_gesture_target.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_pinch_gesture_params.h"
#include "core/shared/common/input/synthetic_web_input_event_builders.h"
#include "third_party/blink/public/platform/web_input_event.h"

namespace host {

class CONTENT_EXPORT SyntheticTouchpadPinchGesture : public SyntheticGesture {
 public:
  explicit SyntheticTouchpadPinchGesture(
      const common::SyntheticPinchGestureParams& params);
  ~SyntheticTouchpadPinchGesture() override;

  SyntheticGesture::Result ForwardInputEvents(
      const base::TimeTicks& timestamp,
      SyntheticGestureTarget* target) override;

 private:
  enum GestureState { SETUP, STARTED, IN_PROGRESS, DONE };

  void ForwardGestureEvents(const base::TimeTicks& timestamp,
                            SyntheticGestureTarget* target);

  void UpdateTouchPoints(const base::TimeTicks& timestamp);

  void CalculateEndTime(SyntheticGestureTarget* target);
  float CalculateTargetScale(const base::TimeTicks& timestamp) const;
  base::TimeTicks ClampTimestamp(const base::TimeTicks& timestamp) const;
  bool HasReachedTarget(const base::TimeTicks& timestamp) const;

  common::SyntheticPinchGestureParams params_;
  common::SyntheticGestureParams::GestureSourceType gesture_source_type_;
  GestureState state_;
  base::TimeTicks start_time_;
  base::TimeTicks stop_time_;
  float current_scale_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SyntheticTouchpadPinchGesture);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_TOUCHPAD_PINCH_GESTURE_H_
