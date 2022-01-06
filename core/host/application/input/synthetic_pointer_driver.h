// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_DRIVER_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_DRIVER_H_

#include <memory>

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_gesture_params.h"
#include "core/shared/common/input/synthetic_pointer_action_params.h"
#include "core/shared/common/input/synthetic_web_input_event_builders.h"

namespace host {

class SyntheticGestureTarget;

class CONTENT_EXPORT SyntheticPointerDriver {
 public:
  SyntheticPointerDriver();
  virtual ~SyntheticPointerDriver();

  static std::unique_ptr<SyntheticPointerDriver> Create(
      common::SyntheticGestureParams::GestureSourceType gesture_source_type);

  virtual void DispatchEvent(SyntheticGestureTarget* target,
                             const base::TimeTicks& timestamp) = 0;

  virtual void Press(float x,
                     float y,
                     int index = 0,
                     common::SyntheticPointerActionParams::Button button =
                         common::SyntheticPointerActionParams::Button::LEFT) = 0;
  virtual void Move(float x, float y, int index = 0) = 0;
  virtual void Release(int index = 0,
                       common::SyntheticPointerActionParams::Button button =
                           common::SyntheticPointerActionParams::Button::LEFT) = 0;

  // Check if the user inputs in the SyntheticPointerActionParams can generate
  // a valid sequence of pointer actions.
  virtual bool UserInputCheck(
      const common::SyntheticPointerActionParams& params) const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(SyntheticPointerDriver);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_DRIVER_H_
