// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/synthetic_pen_driver.h"

namespace host {

SyntheticPenDriver::SyntheticPenDriver() : SyntheticMouseDriver() {
  mouse_event_.pointer_type = blink::WebPointerProperties::PointerType::kPen;
}

SyntheticPenDriver::~SyntheticPenDriver() {}

}  // namespace host
