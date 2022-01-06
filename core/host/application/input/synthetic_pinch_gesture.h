// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PINCH_GESTURE_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PINCH_GESTURE_H_

#include "base/macros.h"
#include "base/time/time.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_gesture_target.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_pinch_gesture_params.h"

namespace host {

// SyntheticPinchGesture is a thin wrapper around either
// SyntheticTouchscreenPinchGesture or SyntheticTouchpadPinchGesture, depending
// on the SyntheticGestureParam's |input_type| and the default input type of the
// target.
class CONTENT_EXPORT SyntheticPinchGesture : public SyntheticGesture {
 public:
  explicit SyntheticPinchGesture(const common::SyntheticPinchGestureParams& params);
  ~SyntheticPinchGesture() override;

  SyntheticGesture::Result ForwardInputEvents(
      const base::TimeTicks& timestamp,
      SyntheticGestureTarget* target) override;

 private:
  common::SyntheticPinchGestureParams params_;
  std::unique_ptr<SyntheticGesture> lazy_gesture_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticPinchGesture);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PINCH_GESTURE_H_
