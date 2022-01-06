// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_TOUCH_DRIVER_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_TOUCH_DRIVER_H_

#include <array>
#include "base/macros.h"
#include "core/host/application/input/synthetic_pointer_driver.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_web_input_event_builders.h"

namespace host {

class CONTENT_EXPORT SyntheticTouchDriver : public SyntheticPointerDriver {
 public:
  SyntheticTouchDriver();
  explicit SyntheticTouchDriver(common::SyntheticWebTouchEvent touch_event);
  ~SyntheticTouchDriver() override;

  void DispatchEvent(SyntheticGestureTarget* target,
                     const base::TimeTicks& timestamp) override;

  void Press(float x,
             float y,
             int index,
             common::SyntheticPointerActionParams::Button button =
                 common::SyntheticPointerActionParams::Button::LEFT) override;
  void Move(float x, float y, int index) override;
  void Release(int index,
               common::SyntheticPointerActionParams::Button button =
                   common::SyntheticPointerActionParams::Button::LEFT) override;

  bool UserInputCheck(
      const common::SyntheticPointerActionParams& params) const override;

 private:
  using IndexMap = std::array<int, blink::WebTouchEvent::kTouchesLengthCap>;

  common::SyntheticWebTouchEvent touch_event_;
  IndexMap index_map_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticTouchDriver);
};

}  // namespace host

#endif  // CONTENT_COMMON_INPUT_SYNTHETIC_TOUCH_DRIVER_H_
