// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_MOUSE_DRIVER_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_MOUSE_DRIVER_H_

#include "base/macros.h"
#include "core/host/application/input/synthetic_pointer_driver.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_web_input_event_builders.h"

namespace host {

class CONTENT_EXPORT SyntheticMouseDriver : public SyntheticPointerDriver {
 public:
  SyntheticMouseDriver();
  ~SyntheticMouseDriver() override;

  void DispatchEvent(SyntheticGestureTarget* target,
                     const base::TimeTicks& timestamp) override;

  void Press(float x,
             float y,
             int index = 0,
             common::SyntheticPointerActionParams::Button button =
                 common::SyntheticPointerActionParams::Button::LEFT) override;
  void Move(float x, float y, int index = 0) override;
  void Release(int index = 0,
               common::SyntheticPointerActionParams::Button button =
                   common::SyntheticPointerActionParams::Button::LEFT) override;

  bool UserInputCheck(
      const common::SyntheticPointerActionParams& params) const override;

 protected:
  blink::WebMouseEvent mouse_event_;

 private:
  unsigned last_modifiers_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticMouseDriver);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_MOUSE_DRIVER_H_
