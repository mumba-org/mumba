// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/themes/theme_service_custom.h"

#include "base/bind.h"
#include "base/macros.h"
#include "core/host/workspace/workspace.h"
#include "core/host/themes/theme_properties.h"
#include "core/host/themes/custom_theme_supplier.h"
#include "ui/gfx/image/image.h"
#include "ui/native_theme/native_theme_aura.h"
#include "ui/views/linux_ui/linux_ui.h"

namespace host {

CustomThemeService::CustomTheme::CustomTheme()//PrefService* pref_service)
    : CustomThemeSupplier(NATIVE_X11),
      linux_ui_(views::LinuxUI::instance()) {
}

void CustomThemeService::CustomTheme::StartUsingTheme() {
  //pref_service_->SetBoolean(prefs::kUsesSystemTheme, true);
  // Have the former theme notify its observers of change.
  ui::NativeTheme::GetInstanceForNativeUi()->NotifyObservers();
}

void CustomThemeService::CustomTheme::StopUsingTheme() {
  //pref_service_->SetBoolean(prefs::kUsesSystemTheme, false);
  // Have the former theme notify its observers of change.
  if (linux_ui_)
    linux_ui_->GetNativeTheme(NULL)->NotifyObservers();
}

bool CustomThemeService::CustomTheme::GetTint(int id, color_utils::HSL* hsl) const {
  return linux_ui_ && linux_ui_->GetTint(id, hsl);
}

bool CustomThemeService::CustomTheme::GetColor(int id, SkColor* color) const {
  auto custom_color = color_map_.find(id);
  if (custom_color != color_map_.end()) {
    SkColor rcolor = custom_color->second;
    *color = rcolor;
    return true;
  }
  return linux_ui_ && linux_ui_->GetColor(id, color);
}

void CustomThemeService::CustomTheme::SetColor(int id, SkColor color) {
  color_map_.emplace(std::make_pair(id, color));
}

gfx::Image CustomThemeService::CustomTheme::GetImageNamed(int id) {
  return gfx::Image();
}

bool CustomThemeService::CustomTheme::HasCustomImage(int id) const {
  return false;
}

CustomThemeService::CustomTheme::~CustomTheme() {}

CustomThemeService::CustomThemeService() {
  theme_ = new CustomThemeService::CustomTheme();
  SetCustomDefaultTheme(theme_);
}

CustomThemeService::~CustomThemeService() {}

bool CustomThemeService::ShouldInitWithSystemTheme() const {
  return false;//profile()->GetPrefs()->GetBoolean(prefs::kUsesSystemTheme);
}

void CustomThemeService::UseSystemTheme() {
  // theme_ = new CustomThemeService::CustomTheme();
  // SetCustomDefaultTheme(theme_);
}

void CustomThemeService::SetColor(int id, SkColor color) {
  theme_->SetColor(id, color);
}

bool CustomThemeService::IsSystemThemeDistinctFromDefaultTheme() const {
  return false;
}

bool CustomThemeService::UsingDefaultTheme() const {
  return ThemeService::UsingDefaultTheme() && !UsingSystemTheme();
}

bool CustomThemeService::UsingSystemTheme() const {
  // const CustomThemeSupplier* theme_supplier = get_theme_supplier();
  // return theme_supplier &&
  //        theme_supplier->get_theme_type() == CustomThemeSupplier::NATIVE_X11;
  return true;
}

void CustomThemeService::FixInconsistentPreferencesIfNeeded() {
  
}

}