// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame_mus.h"

#include <stdint.h>

#include <memory>

#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "services/ui/public/cpp/property_type_converters.h"
#include "services/ui/public/interfaces/window_tree.mojom.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/mus/window_tree_host_mus_init_params.h"
#include "ui/views/mus/desktop_window_tree_host_mus.h"
#include "ui/views/mus/mus_client.h"
#include "ui/views/mus/window_manager_frame_values.h"

#if defined(OS_CHROMEOS)
#include "ash/public/cpp/config.h"
#include "ash/public/cpp/shelf_types.h"
#include "ash/public/cpp/window_properties.h"
#include "ash/public/cpp/window_state_type.h"
#include "ash/public/interfaces/window_properties.mojom.h"
#include "ash/public/interfaces/window_style.mojom.h"
#include "core/host/chromeos/ash_config.h"
#include "services/ui/public/interfaces/window_manager.mojom.h"
#endif

namespace host {

DockFrameMus::DockFrameMus(DockFrame* dock_frame,
                           DockWindow* dock_window)
    : views::DesktopNativeWidgetAura(dock_frame),
      dock_frame_(dock_frame),
      dock_window_(dock_window) {
#if defined(OS_CHROMEOS)
  // Not used with Mus on Chrome OS.
  DCHECK_EQ(chromeos::GetAshConfig(), ash::Config::MASH);
#endif
}

DockFrameMus::~DockFrameMus() {}

views::Widget::InitParams DockFrameMus::GetWidgetParams() {
  views::Widget::InitParams params;
  params.name = "DockFrame";
  params.native_widget = this;
  params.bounds = gfx::Rect(10, 10, 640, 480);
  params.delegate = dock_window_;
  std::map<std::string, std::vector<uint8_t>> properties =
      views::MusClient::ConfigurePropertiesFromParams(params);
//  const std::string chrome_app_id(extension_misc::kChromeAppId);
  std::string chrome_app_id;    
  // Indicates mash shouldn't handle immersive, rather we will.
  properties[ui::mojom::WindowManager::kDisableImmersive_InitProperty] =
      mojo::ConvertTo<std::vector<uint8_t>>(true);
#if defined(OS_CHROMEOS)
  properties[ash::mojom::kAshWindowStyle_InitProperty] =
      mojo::ConvertTo<std::vector<uint8_t>>(
          static_cast<int32_t>(ash::mojom::WindowStyle::BROWSER));
  // ChromeLauncherController manages the dock shortcut shelf item; set the
  // window's shelf item type property to be ignored by ash::ShelfWindowWatcher.
  properties[ui::mojom::WindowManager::kShelfItemType_Property] =
      mojo::ConvertTo<std::vector<uint8_t>>(
          static_cast<int64_t>(ash::TYPE_BROWSER_SHORTCUT));
  properties[ash::mojom::kWindowPositionManaged_Property] =
      mojo::ConvertTo<std::vector<uint8_t>>(
          static_cast<int64_t>(dock_window_->dock()->is_type_popup()));
  properties[ash::mojom::kCanConsumeSystemKeys_Property] =
      mojo::ConvertTo<std::vector<uint8_t>>(
          static_cast<int64_t>(dock_window_->dock()->is_app()));
#endif
  aura::WindowTreeHostMusInitParams window_tree_host_init_params =
      aura::CreateInitParamsForTopLevel(
          views::MusClient::Get()->window_tree_client(), std::move(properties));
  std::unique_ptr<views::DesktopWindowTreeHostMus> desktop_window_tree_host =
      std::make_unique<views::DesktopWindowTreeHostMus>(
          std::move(window_tree_host_init_params), dock_frame_, this);
  // DockNonClientFrameViewMus::OnBoundsChanged() takes care of updating
  // the insets.
  desktop_window_tree_host->set_auto_update_client_area(false);
  SetDesktopWindowTreeHost(std::move(desktop_window_tree_host));
  return params;
}

bool DockFrameMus::UseCustomFrame() const {
  return true;
}

bool DockFrameMus::UsesNativeSystemMenu() const {
  return false;
}

bool DockFrameMus::ShouldSaveWindowPlacement() const {
#if defined(OS_CHROMEOS)
  return nullptr == GetWidget()->GetNativeWindow()->GetProperty(
                        ash::kRestoreBoundsOverrideKey);
#else
  return true;
#endif
}

void DockFrameMus::GetWindowPlacement(
    gfx::Rect* bounds, ui::WindowShowState* show_state) const {
  DesktopNativeWidgetAura::GetWindowPlacement(bounds, show_state);
#if defined(OS_CHROMEOS)
  gfx::Rect* override_bounds = GetWidget()->GetNativeWindow()->GetProperty(
      ash::kRestoreBoundsOverrideKey);
  if (override_bounds && !override_bounds->IsEmpty()) {
    *bounds = *override_bounds;
    *show_state =
        ash::ToWindowShowState(GetWidget()->GetNativeWindow()->GetProperty(
            ash::kRestoreWindowStateTypeOverrideKey));
  }
#endif

  // Session restore might be unable to correctly restore other states.
  // For the record, https://crbug.com/396272
  if (*show_state != ui::SHOW_STATE_MAXIMIZED &&
      *show_state != ui::SHOW_STATE_MINIMIZED) {
    *show_state = ui::SHOW_STATE_NORMAL;
  }
}

bool DockFrameMus::PreHandleKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  return false;
}

bool DockFrameMus::HandleKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  return false;
}

int DockFrameMus::GetMinimizeButtonOffset() const {
  return 0;
}

}