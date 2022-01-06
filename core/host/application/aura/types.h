// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_AURA_TYPES_H_
#define MUMBA_HOST_APPLICATION_AURA_TYPES_H_

#include "core/host/application/overscroll_controller.h"

namespace host {

enum class NavigationDirection {
  NONE,
  FORWARD,
  BACK,
  RELOAD,
  NAVIGATION_COUNT,
};

// Note that this enum is used to back an UMA histogram, so it should be
// treated as append-only.
enum UmaNavigationType {
  NAVIGATION_TYPE_NONE,
  FORWARD_TOUCHPAD,
  BACK_TOUCHPAD,
  FORWARD_TOUCHSCREEN,
  BACK_TOUCHSCREEN,
  RELOAD_TOUCHPAD,
  RELOAD_TOUCHSCREEN,
  NAVIGATION_TYPE_COUNT,
};

UmaNavigationType GetUmaNavigationType(NavigationDirection direction,
                                       OverscrollSource source);

}  // namespace host

#endif  // CONTENT_BROWSER_WEB_CONTENTS_AURA_TYPES_H_
