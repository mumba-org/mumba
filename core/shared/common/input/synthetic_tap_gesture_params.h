// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_INPUT_SYNTHETIC_TAP_GESTURE_PARAMS_H_
#define CONTENT_COMMON_INPUT_SYNTHETIC_TAP_GESTURE_PARAMS_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_gesture_params.h"
#include "ui/gfx/geometry/point_f.h"

namespace common {

struct CONTENT_EXPORT SyntheticTapGestureParams
    : public SyntheticGestureParams {
 public:
  SyntheticTapGestureParams();
  SyntheticTapGestureParams(const SyntheticTapGestureParams& other);
  ~SyntheticTapGestureParams() override;

  GestureType GetGestureType() const override;

  gfx::PointF position;
  float duration_ms;

  static const SyntheticTapGestureParams* Cast(
      const SyntheticGestureParams* gesture_params);
};

}  // namespace common

#endif  // CONTENT_COMMON_INPUT_SYNTHETIC_TAP_GESTURE_PARAMS_H_
