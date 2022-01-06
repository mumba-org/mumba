// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_SMOOTH_SCROLL_GESTURE_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_SMOOTH_SCROLL_GESTURE_H_

#include "core/host/application/input/synthetic_smooth_move_gesture.h"

#include "core/shared/common/input/synthetic_smooth_scroll_gesture_params.h"

namespace host {
class CONTENT_EXPORT SyntheticSmoothScrollGesture : public SyntheticGesture {
 public:
  explicit SyntheticSmoothScrollGesture(
      const common::SyntheticSmoothScrollGestureParams& params);
  ~SyntheticSmoothScrollGesture() override;

  // SyntheticGesture implementation:
  SyntheticGesture::Result ForwardInputEvents(
      const base::TimeTicks& timestamp,
      SyntheticGestureTarget* target) override;

 private:
  static SyntheticSmoothMoveGestureParams::InputType GetInputSourceType(
      common::SyntheticGestureParams::GestureSourceType gesture_source_type);

  bool InitializeMoveGesture(
      common::SyntheticGestureParams::GestureSourceType gesture_type,
      SyntheticGestureTarget* target);

  std::unique_ptr<SyntheticSmoothMoveGesture> move_gesture_;
  common::SyntheticSmoothScrollGestureParams params_;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_SMOOTH_SCROLL_GESTURE_H_
