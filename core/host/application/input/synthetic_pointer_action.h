// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_ACTION_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_ACTION_H_

#include "base/macros.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_gesture_target.h"
#include "core/host/application/input/synthetic_pointer_driver.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_pointer_action_list_params.h"
#include "core/shared/common/input/synthetic_pointer_action_params.h"

namespace host {

class CONTENT_EXPORT SyntheticPointerAction : public SyntheticGesture {
 public:
  explicit SyntheticPointerAction(
      const common::SyntheticPointerActionListParams& params);
  ~SyntheticPointerAction() override;

  SyntheticGesture::Result ForwardInputEvents(
      const base::TimeTicks& timestamp,
      SyntheticGestureTarget* target) override;

 private:
  enum GestureState { UNINITIALIZED, RUNNING, INVALID, DONE };

  GestureState ForwardTouchOrMouseInputEvents(const base::TimeTicks& timestamp,
                                              SyntheticGestureTarget* target);

  // params_ contains a list of lists of pointer actions, that each list of
  // pointer actions will be dispatched together.
  common::SyntheticPointerActionListParams params_;
  std::unique_ptr<SyntheticPointerDriver> synthetic_pointer_driver_;
  common::SyntheticGestureParams::GestureSourceType gesture_source_type_;
  GestureState state_;
  size_t num_actions_dispatched_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticPointerAction);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_POINTER_ACTION_H_
