// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/zoom/page_zoom.h"

#include <stddef.h>

#include <algorithm>
#include <cmath>

#include "base/metrics/user_metrics.h"
#include "components/prefs/pref_service.h"
#include "components/zoom/page_zoom_constants.h"
#include "components/zoom/zoom_controller.h"
#include "core/host/application/host_zoom_map.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/page_zoom.h"
#include "core/shared/common/renderer_preferences.h"

using base::UserMetricsAction;

namespace {

enum PageZoomValueType {
  PAGE_ZOOM_VALUE_TYPE_FACTOR,
  PAGE_ZOOM_VALUE_TYPE_LEVEL,
};

std::vector<double> PresetZoomValues(PageZoomValueType value_type,
                                     double custom_value) {
  // Generate a vector of zoom values from an array of known preset
  // factors. The values in content::kPresetZoomFactors will already be in
  // sorted order.
  std::vector<double> zoom_values;
  bool found_custom = false;
  for (size_t i = 0; i < zoom::kPresetZoomFactorsSize; i++) {
    double zoom_value = zoom::kPresetZoomFactors[i];
    if (value_type == PAGE_ZOOM_VALUE_TYPE_LEVEL)
      zoom_value = common::ZoomFactorToZoomLevel(zoom_value);
    if (common::ZoomValuesEqual(zoom_value, custom_value))
      found_custom = true;
    zoom_values.push_back(zoom_value);
  }
  // If the preset array did not contain the custom value, append it to the
  // vector and then sort.
  double min = value_type == PAGE_ZOOM_VALUE_TYPE_LEVEL
                   ? common::ZoomFactorToZoomLevel(common::kMinimumZoomFactor)
                   : common::kMinimumZoomFactor;
  double max = value_type == PAGE_ZOOM_VALUE_TYPE_LEVEL
                   ? common::ZoomFactorToZoomLevel(common::kMaximumZoomFactor)
                   : common::kMaximumZoomFactor;
  if (!found_custom && custom_value > min && custom_value < max) {
    zoom_values.push_back(custom_value);
    std::sort(zoom_values.begin(), zoom_values.end());
  }
  return zoom_values;
}

}  // namespace anonymous

namespace zoom {

// static
std::vector<double> PageZoom::PresetZoomFactors(double custom_factor) {
  return PresetZoomValues(PAGE_ZOOM_VALUE_TYPE_FACTOR, custom_factor);
}

// static
std::vector<double> PageZoom::PresetZoomLevels(double custom_level) {
  return PresetZoomValues(PAGE_ZOOM_VALUE_TYPE_LEVEL, custom_level);
}

// static
void PageZoom::Zoom(host::ApplicationContents* app_contents,
                    common::PageZoom zoom) {
  zoom::ZoomController* zoom_controller =
      zoom::ZoomController::FromApplicationContents(app_contents);
  if (!zoom_controller)
    return;

  double current_zoom_level = zoom_controller->GetZoomLevel();
  double default_zoom_level = zoom_controller->GetDefaultZoomLevel();

  if (zoom == common::PAGE_ZOOM_RESET) {
    zoom_controller->SetZoomLevel(default_zoom_level);
    app_contents->SetPageScale(1.f);
    base::RecordAction(UserMetricsAction("ZoomNormal"));
    return;
  }

  // Generate a vector of zoom levels from an array of known presets along with
  // the default level added if necessary.
  std::vector<double> zoom_levels = PresetZoomLevels(default_zoom_level);

  if (zoom == common::PAGE_ZOOM_OUT) {
    // Iterate through the zoom levels in reverse order to find the next
    // lower level based on the current zoom level for this page.
    for (std::vector<double>::reverse_iterator i = zoom_levels.rbegin();
         i != zoom_levels.rend(); ++i) {
      double zoom_level = *i;
      if (common::ZoomValuesEqual(zoom_level, current_zoom_level))
        continue;
      if (zoom_level < current_zoom_level) {
        zoom_controller->SetZoomLevel(zoom_level);
        base::RecordAction(UserMetricsAction("ZoomMinus"));
        return;
      }
    }
    base::RecordAction(UserMetricsAction("ZoomMinus_AtMinimum"));
  } else {
    // Iterate through the zoom levels in normal order to find the next
    // higher level based on the current zoom level for this page.
    for (std::vector<double>::const_iterator i = zoom_levels.begin();
         i != zoom_levels.end(); ++i) {
      double zoom_level = *i;
      if (common::ZoomValuesEqual(zoom_level, current_zoom_level))
        continue;
      if (zoom_level > current_zoom_level) {
        zoom_controller->SetZoomLevel(zoom_level);
        base::RecordAction(UserMetricsAction("ZoomPlus"));
        return;
      }
    }
    base::RecordAction(UserMetricsAction("ZoomPlus_AtMaximum"));
  }
}

}  // namespace zoom
