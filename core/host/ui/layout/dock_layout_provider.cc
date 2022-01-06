// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/layout/dock_layout_provider.h"

#include <algorithm>

#include "base/logging.h"
#include "core/host/ui/layout/dock_typography.h"
//#include "core/host/ui/layout/harmony_layout_provider.h"
//#include "core/host/ui/layout/material_refresh_layout_provider.h"
#include "ui/base/material_design/material_design_controller.h"

namespace host {

namespace {

DockLayoutProvider* g_chrome_layout_provider = nullptr;

}  // namespace

DockLayoutProvider::DockLayoutProvider() {
  DCHECK_EQ(nullptr, g_chrome_layout_provider);
  g_chrome_layout_provider = this;
}

DockLayoutProvider::~DockLayoutProvider() {
  DCHECK_EQ(this, g_chrome_layout_provider);
  g_chrome_layout_provider = nullptr;
}

// static
DockLayoutProvider* DockLayoutProvider::Get() {
  // Check to avoid downcasting a base LayoutProvider.
  DCHECK_EQ(g_chrome_layout_provider, views::LayoutProvider::Get());
  return static_cast<DockLayoutProvider*>(views::LayoutProvider::Get());
}

// static
std::unique_ptr<views::LayoutProvider>
DockLayoutProvider::CreateLayoutProvider() {
  //if (ui::MaterialDesignController::GetMode() ==
  //    ui::MaterialDesignController::MATERIAL_REFRESH)
  //  return std::make_unique<MaterialRefreshLayoutProvider>();
  //return ui::MaterialDesignController::IsSecondaryUiMaterial()
         //    ? std::make_unique<HarmonyLayoutProvider>()
         //    : std::make_unique<DockLayoutProvider>();
  return std::make_unique<DockLayoutProvider>();
}

gfx::Insets DockLayoutProvider::GetInsetsMetric(int metric) const {
  switch (metric) {
    case DockInsetsMetric::INSETS_OMNIBOX:
      return gfx::Insets(3);
    case DockInsetsMetric::INSETS_TOAST:
      return gfx::Insets(0, 8);
    default:
      return views::LayoutProvider::GetInsetsMetric(metric);
  }
}

int DockLayoutProvider::GetDistanceMetric(int metric) const {
  switch (metric) {
    case DISTANCE_BUTTON_MINIMUM_WIDTH:
      return 48;
    case DISTANCE_CONTENT_LIST_VERTICAL_SINGLE:
      return 4;
    case DISTANCE_CONTENT_LIST_VERTICAL_MULTI:
      return 8;
    case DISTANCE_CONTROL_LIST_VERTICAL:
      return GetDistanceMetric(views::DISTANCE_RELATED_CONTROL_VERTICAL);
    case DISTANCE_RELATED_CONTROL_HORIZONTAL_SMALL:
      return 8;
    case DISTANCE_RELATED_CONTROL_VERTICAL_SMALL:
      return 4;
    case DISTANCE_RELATED_LABEL_HORIZONTAL_LIST:
      return 8;
    case DISTANCE_SUBSECTION_HORIZONTAL_INDENT:
      return 10;
    case DISTANCE_UNRELATED_CONTROL_HORIZONTAL:
      return 12;
    case DISTANCE_UNRELATED_CONTROL_HORIZONTAL_LARGE:
      return 20;
    case DISTANCE_UNRELATED_CONTROL_VERTICAL_LARGE:
      return 30;
    case DISTANCE_TOAST_CONTROL_VERTICAL:
      return 8;
    case DISTANCE_TOAST_LABEL_VERTICAL:
      return 12;
    case DISTANCE_MODAL_DIALOG_PREFERRED_WIDTH:
      return 400;
    case DISTANCE_BUBBLE_PREFERRED_WIDTH:
      return 320;
    default:
      return views::LayoutProvider::GetDistanceMetric(metric);
  }
}

const views::TypographyProvider& DockLayoutProvider::GetTypographyProvider()
    const {
  // This is not a data member because then HarmonyLayoutProvider would inherit
  // it, even when it provides its own.
  CR_DEFINE_STATIC_LOCAL(LegacyTypographyProvider, legacy_provider, ());
  return legacy_provider;
}

views::GridLayout::Alignment
DockLayoutProvider::GetControlLabelGridAlignment() const {
  return views::GridLayout::TRAILING;
}

bool DockLayoutProvider::UseExtraDialogPadding() const {
  return true;
}

bool DockLayoutProvider::ShouldShowWindowIcon() const {
  return true;
}

bool DockLayoutProvider::IsHarmonyMode() const {
  return false;
}

int DockLayoutProvider::GetCornerRadiusMetric(
    DockEmphasisMetric emphasis_metric,
    const gfx::Size& size) const {
  // Use the current fixed value for non-EMPHASIS_HIGH.
  return emphasis_metric == EMPHASIS_HIGH
             ? std::min(size.width(), size.height()) / 2
             : 4;
}

int DockLayoutProvider::GetShadowElevationMetric(
    DockEmphasisMetric emphasis_metric) const {
  // Just return a value for now.
  return 2;
}

}