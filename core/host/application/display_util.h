// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DISPLAY_UTIL_H_
#define MUMBA_HOST_APPLICATION_DISPLAY_UTIL_H_

#include "core/shared/common/content_export.h"
#include "core/common/screen_info.h"
#include "ui/display/display.h"
#include "ui/gfx/native_widget_types.h"

namespace host {

class CONTENT_EXPORT DisplayUtil {
 public:
  static void DisplayToScreenInfo(common::ScreenInfo* screen_info,
                                  const display::Display& display);

  static void GetNativeViewScreenInfo(common::ScreenInfo* screen_info,
                                      gfx::NativeView native_view);

  static void GetDefaultScreenInfo(common::ScreenInfo* screen_info);

  // Compute the orientation type of the display assuming it is a mobile device.
  static common::ScreenOrientationValues GetOrientationTypeForMobile(
      const display::Display& display);

  // Compute the orientation type of the display assuming it is a desktop.
  static common::ScreenOrientationValues GetOrientationTypeForDesktop(
      const display::Display& display);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_DISPLAY_UTIL_H_
