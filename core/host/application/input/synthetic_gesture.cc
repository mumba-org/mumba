// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/input/synthetic_gesture.h"

#include "base/logging.h"
#include "core/host/application/input/synthetic_gesture_target.h"
#include "core/host/application/input/synthetic_pinch_gesture.h"
#include "core/host/application/input/synthetic_pointer_action.h"
#include "core/host/application/input/synthetic_smooth_drag_gesture.h"
#include "core/host/application/input/synthetic_smooth_scroll_gesture.h"
#include "core/host/application/input/synthetic_tap_gesture.h"

namespace host {
namespace {

template <typename GestureType, typename GestureParamsType>
static std::unique_ptr<SyntheticGesture> CreateGesture(
    const common::SyntheticGestureParams& gesture_params) {
  return std::unique_ptr<SyntheticGesture>(
      new GestureType(*GestureParamsType::Cast(&gesture_params)));
}

}  // namespace

SyntheticGesture::SyntheticGesture() {}

SyntheticGesture::~SyntheticGesture() {}

std::unique_ptr<SyntheticGesture> SyntheticGesture::Create(
    const common::SyntheticGestureParams& gesture_params) {
  switch (gesture_params.GetGestureType()) {
    case common::SyntheticGestureParams::SMOOTH_SCROLL_GESTURE:
      return CreateGesture<SyntheticSmoothScrollGesture,
                           common::SyntheticSmoothScrollGestureParams>(gesture_params);
    case common::SyntheticGestureParams::SMOOTH_DRAG_GESTURE:
      return CreateGesture<SyntheticSmoothDragGesture,
                           common::SyntheticSmoothDragGestureParams>(gesture_params);
    case common::SyntheticGestureParams::PINCH_GESTURE:
      return CreateGesture<SyntheticPinchGesture,
                           common::SyntheticPinchGestureParams>(gesture_params);
    case common::SyntheticGestureParams::TAP_GESTURE:
      return CreateGesture<SyntheticTapGesture,
                           common::SyntheticTapGestureParams>(gesture_params);
    case common::SyntheticGestureParams::POINTER_ACTION_LIST:
      return CreateGesture<SyntheticPointerAction,
                           common::SyntheticPointerActionListParams>(gesture_params);
    default:
      NOTREACHED() << "Invalid synthetic gesture type";
      return nullptr;
  }
}

}  // namespace host
