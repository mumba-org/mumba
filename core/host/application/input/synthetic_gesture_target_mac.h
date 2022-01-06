// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_MAC_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_MAC_H_

#include "base/macros.h"
#include "core/host/application/input/synthetic_gesture_target_base.h"
#include "core/host/application/application_window_host_view_mac.h"
#include "core/common/input/synthetic_gesture_params.h"

namespace host {

// SyntheticGestureTarget implementation for mac
class SyntheticGestureTargetMac : public SyntheticGestureTargetBase {
 public:
  SyntheticGestureTargetMac(ApplicationWindowHost* host,
                            ApplicationWindowHostViewCocoa* cocoa_view);

  // SyntheticGestureTarget:
  void DispatchInputEventToPlatform(const blink::WebInputEvent& event) override;

 private:
  ApplicationWindowHostViewCocoa* cocoa_view_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticGestureTargetMac);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_MAC_H_
