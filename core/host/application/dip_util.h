// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DIP_UTIL_H_
#define MUMBA_HOST_APPLICATION_DIP_UTIL_H_

#include "core/shared/common/content_export.h"

namespace gfx {
class Point;
class Rect;
class Size;
}  // namespace gfx

namespace host {
class ApplicationWindowHostView;

// This is the same as view->GetDeviceScaleFactor(), but will return a best
// guess when |view| is nullptr.
CONTENT_EXPORT float GetScaleFactorForView(const ApplicationWindowHostView* view);

// Utility functions that convert point/size/rect between DIP and pixel
// coordinate system.
CONTENT_EXPORT gfx::Point ConvertViewPointToDIP(
    const ApplicationWindowHostView* view, const gfx::Point& point_in_pixel);
CONTENT_EXPORT gfx::Size ConvertViewSizeToPixel(
    const ApplicationWindowHostView* view, const gfx::Size& size_in_dip);
CONTENT_EXPORT gfx::Rect ConvertViewRectToPixel(
    const ApplicationWindowHostView* view, const gfx::Rect& rect_in_dip);

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_DIP_UTIL_H_
