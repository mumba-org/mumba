// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_APPLICATION_WINDOW_SURFACE_PROPERTIES_H_
#define CONTENT_COMMON_APPLICATION_WINDOW_SURFACE_PROPERTIES_H_

#include "components/viz/common/quads/compositor_frame.h"
#include "core/shared/common/content_export.h"

namespace common {

// This struct contains the properties that are constant among all
// CompositorFrames that the renderer submits to the same surface.
struct CONTENT_EXPORT ApplicationWindowSurfaceProperties {
  static ApplicationWindowSurfaceProperties FromCompositorFrame(
      const viz::CompositorFrame& frame);

  ApplicationWindowSurfaceProperties();
  ApplicationWindowSurfaceProperties(const ApplicationWindowSurfaceProperties& other);
  ~ApplicationWindowSurfaceProperties();

  ApplicationWindowSurfaceProperties& operator=(
      const ApplicationWindowSurfaceProperties& other);

  bool operator==(const ApplicationWindowSurfaceProperties& other) const;
  bool operator!=(const ApplicationWindowSurfaceProperties& other) const;

  std::string ToDiffString(const ApplicationWindowSurfaceProperties& other) const;

  gfx::Size size;
  float device_scale_factor = 0;
#ifdef OS_ANDROID
  float top_controls_height = 0;
  float top_controls_shown_ratio = 0;
  float bottom_controls_height = 0;
  float bottom_controls_shown_ratio = 0;
  viz::Selection<gfx::SelectionBound> selection;
  bool has_transparent_background = false;
#endif
};

}  // namespace content

#endif  // CONTENT_COMMON_RENDER_WIDGET_SURFACE_PROPERTIES_H_
