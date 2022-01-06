// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/synthetic_pointer_driver.h"

#include "core/host/application/input/synthetic_mouse_driver.h"
#include "core/host/application/input/synthetic_pen_driver.h"
#include "core/host/application/input/synthetic_touch_driver.h"

namespace host {

SyntheticPointerDriver::SyntheticPointerDriver() {}
SyntheticPointerDriver::~SyntheticPointerDriver() {}

// static
std::unique_ptr<SyntheticPointerDriver> SyntheticPointerDriver::Create(
    common::SyntheticGestureParams::GestureSourceType gesture_source_type) {
  switch (gesture_source_type) {
    case common::SyntheticGestureParams::TOUCH_INPUT:
      return std::make_unique<SyntheticTouchDriver>();
    case common::SyntheticGestureParams::MOUSE_INPUT:
      return std::make_unique<SyntheticMouseDriver>();
    case common::SyntheticGestureParams::PEN_INPUT:
      return std::make_unique<SyntheticPenDriver>();
    case common::SyntheticGestureParams::DEFAULT_INPUT:
      return std::unique_ptr<SyntheticPointerDriver>();
  }
  NOTREACHED();
  return std::unique_ptr<SyntheticPointerDriver>();
}

}  // namespace host
