// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/overscroll_configuration.h"

#include "base/command_line.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"

namespace {

bool g_is_history_navigation_mode_initialized = false;
host::OverscrollConfig::HistoryNavigationMode g_history_navigation_mode =
    host::OverscrollConfig::HistoryNavigationMode::kSimpleUi;

bool g_is_ptr_mode_initialized = false;
host::OverscrollConfig::PullToRefreshMode g_ptr_mode =
    host::OverscrollConfig::PullToRefreshMode::kDisabled;

const float kThresholdCompleteTouchpad = 0.3f;
const float kThresholdCompleteTouchscreen = 0.25f;

const float kThresholdStartTouchpad = 60.f;
const float kThresholdStartTouchscreen = 50.f;

bool g_is_touchpad_overscroll_history_navigation_enabled_initialized = false;
bool g_touchpad_overscroll_history_navigation_enabled = false;

float GetStartThresholdMultiplier() {
  //base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  //if (!cmd->HasSwitch(switches::kOverscrollStartThreshold))
  //  return 1.f;

  //std::string string_value =
  //    cmd->GetSwitchValueASCII(switches::kOverscrollStartThreshold);
  //int percentage;
  //if (base::StringToInt(string_value, &percentage) && percentage > 0)
  //  return percentage / 100.f;

  //DLOG(WARNING) << "Failed to parse switch "
  //              << switches::kOverscrollStartThreshold << ": " << string_value;
  return 1.f;
}

}  // namespace

namespace host {

// static
OverscrollConfig::HistoryNavigationMode
OverscrollConfig::GetHistoryNavigationMode() {
  if (g_is_history_navigation_mode_initialized)
    return g_history_navigation_mode;

  //const std::string mode =
  //    base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
  //        switches::kOverscrollHistoryNavigation);
  //if (mode == "0")
    g_history_navigation_mode = HistoryNavigationMode::kDisabled;
  //else if (mode == "1")
  //  g_history_navigation_mode = HistoryNavigationMode::kParallaxUi;
  g_is_history_navigation_mode_initialized = true;
  return g_history_navigation_mode;
}

// static
OverscrollConfig::PullToRefreshMode OverscrollConfig::GetPullToRefreshMode() {
  if (g_is_ptr_mode_initialized)
    return g_ptr_mode;

  //const std::string mode =
  //    base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
  //        switches::kPullToRefresh);
  //if (mode == "1")
    g_ptr_mode = PullToRefreshMode::kEnabled;
  //else if (mode == "2")
  //  g_ptr_mode = PullToRefreshMode::kEnabledTouchschreen;
  g_is_ptr_mode_initialized = true;
  return g_ptr_mode;
}

// static
float OverscrollConfig::GetThreshold(Threshold threshold) {
  switch (threshold) {
    case Threshold::kCompleteTouchpad:
      return kThresholdCompleteTouchpad;

    case Threshold::kCompleteTouchscreen:
      return kThresholdCompleteTouchscreen;

    case Threshold::kStartTouchpad:
      static const float threshold_start_touchpad =
          GetStartThresholdMultiplier() * kThresholdStartTouchpad;
      return threshold_start_touchpad;

    case Threshold::kStartTouchscreen:
      static const float threshold_start_touchscreen =
          GetStartThresholdMultiplier() * kThresholdStartTouchscreen;
      return threshold_start_touchscreen;
  }

  NOTREACHED();
  return -1.f;
}

// static
void OverscrollConfig::SetHistoryNavigationMode(HistoryNavigationMode mode) {
  g_history_navigation_mode = mode;
  g_is_history_navigation_mode_initialized = true;
}

// static
void OverscrollConfig::ResetHistoryNavigationMode() {
  g_is_history_navigation_mode_initialized = false;
  g_history_navigation_mode =
      OverscrollConfig::HistoryNavigationMode::kSimpleUi;
}

// static
void OverscrollConfig::SetPullToRefreshMode(PullToRefreshMode mode) {
  g_ptr_mode = mode;
  g_is_ptr_mode_initialized = true;
}

// static
void OverscrollConfig::ResetPullToRefreshMode() {
  g_is_ptr_mode_initialized = false;
  g_ptr_mode = OverscrollConfig::PullToRefreshMode::kDisabled;
}

// static
bool OverscrollConfig::TouchpadOverscrollHistoryNavigationEnabled() {
  if (!g_is_touchpad_overscroll_history_navigation_enabled_initialized) {
    g_is_touchpad_overscroll_history_navigation_enabled_initialized = true;
    g_touchpad_overscroll_history_navigation_enabled =
        base::FeatureList::IsEnabled(
            features::kTouchpadOverscrollHistoryNavigation);
  }

  return g_touchpad_overscroll_history_navigation_enabled;
}

// static
void OverscrollConfig::ResetTouchpadOverscrollHistoryNavigationEnabled() {
  g_is_touchpad_overscroll_history_navigation_enabled_initialized = false;
}

}  // namespace host
