// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/events/android/event_handler_android.h"

namespace ui {

bool EventHandlerAndroid::OnTouchEvent(const MotionEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnMouseEvent(const MotionEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnMouseWheelEvent(const MotionEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnDragEvent(const DragEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnGestureEvent(const GestureEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnGenericMotionEvent(
    const MotionEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::OnKeyUp(const KeyEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::DispatchKeyEvent(const KeyEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::ScrollBy(const GestureEventAndroid& event) {
  return false;
}

bool EventHandlerAndroid::ScrollTo(const GestureEventAndroid& event) {
  return false;
}

void EventHandlerAndroid::OnSizeChanged() {}

void EventHandlerAndroid::OnPhysicalBackingSizeChanged() {}

}  // namespace ui
