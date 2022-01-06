// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_THEMES_THEME_SERVICE_CUSTOM_H_
#define CORE_HOST_THEMES_THEME_SERVICE_CUSTOM_H_

#include <map>

#include "base/macros.h"
#include "core/host/themes/theme_service.h"
#include "core/host/themes/custom_theme_supplier.h"
#include "ui/views/linux_ui/linux_ui.h"

namespace host {
// A subclass of ThemeService that manages the CustomThemeSupplier which
// provides a changing theme according to pages presented
class CustomThemeService : public ThemeService {
 public:
  CustomThemeService();
  ~CustomThemeService() override;

  // Overridden from ThemeService:
  bool ShouldInitWithSystemTheme() const override;
  void UseSystemTheme() override;
  bool IsSystemThemeDistinctFromDefaultTheme() const override;
  bool UsingDefaultTheme() const override;
  bool UsingSystemTheme() const override;
  void FixInconsistentPreferencesIfNeeded() override;

  void SetColor(int id, SkColor color);

 private:
  class CustomTheme : public CustomThemeSupplier {
  public:
    explicit CustomTheme();

    // Overridden from CustomThemeSupplier:
    void StartUsingTheme() override;
    void StopUsingTheme() override;
    bool GetTint(int id, color_utils::HSL* hsl) const override;
    bool GetColor(int id, SkColor* color) const override;
    gfx::Image GetImageNamed(int id) override;
    bool HasCustomImage(int id) const override;

    void SetColor(int id, SkColor color);

  private:
    ~CustomTheme() override;
    // These pointers are not owned by us.
    views::LinuxUI* const linux_ui_;
    std::map<int, SkColor> color_map_;
    //PrefService* const pref_service_;
    DISALLOW_COPY_AND_ASSIGN(CustomTheme);
  };

  CustomTheme* theme_; 

  DISALLOW_COPY_AND_ASSIGN(CustomThemeService);
};

}

#endif  // CHROME_BROWSER_THEMES_THEME_SERVICE_CUSTOM_H_
