// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_H_

#include "base/time/time.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_gesture_params.h"

namespace blink {
class WebInputEvent;
}

namespace host {

// Interface between the synthetic gesture controller and the ApplicationWindowHost.
class CONTENT_EXPORT SyntheticGestureTarget {
 public:
  SyntheticGestureTarget() {}
  virtual ~SyntheticGestureTarget() {}

  // Allows synthetic gestures to insert input events in the highest level of
  // input processing on the target platform (e.g. Java on Android), so that
  // the event traverses the entire input processing stack.
  virtual void DispatchInputEventToPlatform(
      const blink::WebInputEvent& event) = 0;

  // Returns the default gesture source type for the target.
  virtual common::SyntheticGestureParams::GestureSourceType
      GetDefaultSyntheticGestureSourceType() const = 0;

  // After how much time of inaction does the target assume that a pointer has
  // stopped moving.
  virtual base::TimeDelta PointerAssumedStoppedTime() const = 0;

  // Returns the maximum number of DIPs a touch pointer can move without being
  // considered moving by the platform.
  virtual float GetTouchSlopInDips() const = 0;

  // Returns the minimum number of DIPs two touch pointers have to be apart
  // to perform a pinch-zoom.
  virtual float GetMinScalingSpanInDips() const = 0;

  // If mouse wheels can only specify the number of ticks of some static
  // multiplier constant, this method returns that constant (in DIPs). If mouse
  // wheels can specify an arbitrary delta this returns 0.
  virtual int GetMouseWheelMinimumGranularity() const = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_H_
