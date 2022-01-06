// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_INPUT_SYNTHETIC_POINTER_ACTION_LIST_PARAMS_H_
#define CONTENT_COMMON_INPUT_SYNTHETIC_POINTER_ACTION_LIST_PARAMS_H_

#include <vector>
#include "core/shared/common/content_export.h"
#include "core/shared/common/input/synthetic_gesture_params.h"
#include "core/shared/common/input/synthetic_pointer_action_params.h"

namespace common {

struct CONTENT_EXPORT SyntheticPointerActionListParams
    : public SyntheticGestureParams {
 public:
  using ParamList = std::vector<SyntheticPointerActionParams>;

  SyntheticPointerActionListParams();
  SyntheticPointerActionListParams(const ParamList& param_list);
  SyntheticPointerActionListParams(
      const SyntheticPointerActionListParams& other);
  ~SyntheticPointerActionListParams() override;

  GestureType GetGestureType() const override;

  void PushPointerActionParams(const SyntheticPointerActionParams& param);
  void PushPointerActionParamsList(const ParamList& param_list);

  std::vector<ParamList> params;

  static const SyntheticPointerActionListParams* Cast(
      const SyntheticGestureParams* gesture_params);
};

}  // namespace common

#endif  // CONTENT_COMMON_INPUT_SYNTHETIC_POINTER_ACTION_LIST_PARAMS_H_
