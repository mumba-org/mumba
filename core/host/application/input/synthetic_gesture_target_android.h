// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_ANDROID_H_
#define MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_ANDROID_H_

#include "base/android/jni_android.h"
#include "base/android/scoped_java_ref.h"
#include "core/host/application/input/synthetic_gesture_target_base.h"
#include "core/host/android/motion_event_action.h"

namespace ui {
class LatencyInfo;
class ViewAndroid;
}  // namespace ui

namespace host {

// Owned by |SyntheticGestureController|. Keeps a strong pointer to Java object,
// which get destroyed together with the controller.
class SyntheticGestureTargetAndroid : public SyntheticGestureTargetBase {
 public:
  SyntheticGestureTargetAndroid(ApplicationWindowHost* host,
                                ui::ViewAndroid* view);
  ~SyntheticGestureTargetAndroid() override;

  // SyntheticGestureTargetBase:
  void DispatchWebTouchEventToPlatform(
      const blink::WebTouchEvent& web_touch,
      const ui::LatencyInfo& latency_info) override;
  void DispatchWebMouseWheelEventToPlatform(
      const blink::WebMouseWheelEvent& web_wheel,
      const ui::LatencyInfo& latency_info) override;
  void DispatchWebMouseEventToPlatform(
      const blink::WebMouseEvent& web_mouse,
      const ui::LatencyInfo& latency_info) override;

  // SyntheticGestureTarget:
  SyntheticGestureParams::GestureSourceType
  GetDefaultSyntheticGestureSourceType() const override;
  float GetTouchSlopInDips() const override;
  float GetMinScalingSpanInDips() const override;

 private:
  void TouchSetPointer(int index, int x, int y, int id);
  void TouchSetScrollDeltas(int x, int y, int dx, int dy);
  void TouchInject(MotionEventAction action,
                   int pointer_count,
                   base::TimeTicks time);

  ui::ViewAndroid* const view_;
  base::android::ScopedJavaGlobalRef<jobject> java_ref_;

  DISALLOW_COPY_AND_ASSIGN(SyntheticGestureTargetAndroid);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_SYNTHETIC_GESTURE_TARGET_ANDROID_H_
