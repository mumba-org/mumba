// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PEN_DRIVER_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PEN_DRIVER_H_

#include "base/macros.h"
#include "core/host/application/input/synthetic_mouse_driver.h"
#include "core/shared/common/content_export.h"

namespace host {

class CONTENT_EXPORT SyntheticPenDriver : public SyntheticMouseDriver {
 public:
  SyntheticPenDriver();
  ~SyntheticPenDriver() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(SyntheticPenDriver);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_PEN_DRIVER_H_
