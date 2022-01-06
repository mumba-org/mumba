// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/dip_util.h"

#include "core/host/application/display_util.h"
#include "core/host/application/application_window_host_view.h"
#include "ui/base/layout.h"
#include "ui/gfx/geometry/dip_util.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_conversions.h"

namespace host {

float GetScaleFactorForView(const ApplicationWindowHostView* view) {
  if (view)
    return view->GetDeviceScaleFactor();
  common::ScreenInfo screen_info;
  DisplayUtil::GetDefaultScreenInfo(&screen_info);
  return screen_info.device_scale_factor;
}

gfx::Point ConvertViewPointToDIP(const ApplicationWindowHostView* view,
                                 const gfx::Point& point_in_pixel) {
  return gfx::ConvertPointToDIP(GetScaleFactorForView(view), point_in_pixel);
}

gfx::Size ConvertViewSizeToPixel(const ApplicationWindowHostView* view,
                                 const gfx::Size& size_in_dip) {
  return gfx::ConvertSizeToPixel(GetScaleFactorForView(view), size_in_dip);
}

gfx::Rect ConvertViewRectToPixel(const ApplicationWindowHostView* view,
                                 const gfx::Rect& rect_in_dip) {
  return gfx::ConvertRectToPixel(GetScaleFactorForView(view), rect_in_dip);
}

}  // namespace host
