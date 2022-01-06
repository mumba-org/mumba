// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_views_delegate.h"

#include "base/environment.h"
#include "base/nix/xdg_util.h"
#include "core/host/ui/native_widget_factory.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/views/linux_ui/linux_ui.h"

namespace host {

namespace {

bool IsDesktopEnvironmentUnity() {
  std::unique_ptr<base::Environment> env(base::Environment::Create());
  base::nix::DesktopEnvironment desktop_env =
      base::nix::GetDesktopEnvironment(env.get());
  return desktop_env == base::nix::DESKTOP_ENVIRONMENT_UNITY;
}

int GetWindowIconResourceId() {
  return IDR_PRODUCT_LOGO_128;
}

}  // namespace

views::NativeWidget* DockViewsDelegate::CreateNativeWidget(
    views::Widget::InitParams* params,
    views::internal::NativeWidgetDelegate* delegate) {
  NativeWidgetType native_widget_type =
      (params->parent && params->type != views::Widget::InitParams::TYPE_MENU &&
       params->type != views::Widget::InitParams::TYPE_TOOLTIP)
          ? NativeWidgetType::NATIVE_WIDGET_AURA
          : NativeWidgetType::DESKTOP_NATIVE_WIDGET_AURA;
  return host::CreateNativeWidget(native_widget_type, params, delegate);
}

gfx::ImageSkia* DockViewsDelegate::GetDefaultWindowIcon() const {
  ui::ResourceBundle& rb = ui::ResourceBundle::GetSharedInstance();
  return rb.GetImageSkiaNamed(GetWindowIconResourceId());
}

bool DockViewsDelegate::WindowManagerProvidesTitleBar(bool maximized) {
  // On Ubuntu Unity, the system always provides a title bar for
  // maximized windows.
  //
  // TODO(thomasanderson,crbug.com/784010): Consider using the
  // _UNITY_HOST wm hint when support for Ubuntu Trusty is dropped.
  if (!maximized)
    return false;
  static bool is_desktop_environment_unity = IsDesktopEnvironmentUnity();
  return is_desktop_environment_unity;
}

}