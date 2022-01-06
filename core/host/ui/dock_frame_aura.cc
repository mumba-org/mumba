// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame_aura.h"

//#include "chrome/app/chrome_command_ids.h"
#include "core/host/ui/dock_desktop_window_tree_host.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_frame.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/window.h"
#include "ui/aura/window_event_dispatcher.h"
#include "ui/aura/window_observer.h"
#include "ui/base/hit_test.h"
#include "ui/base/models/simple_menu_model.h"
#include "ui/gfx/font.h"
#include "ui/views/view.h"
#include "ui/views/widget/widget.h"
#include "ui/wm/core/visibility_controller.h"

using aura::Window;

namespace host {

DockFrameAura::DockFrameAura(
    DockFrame* dock_frame,
    DockWindow* dock_window): 
      views::DesktopNativeWidgetAura(dock_frame),
      dock_window_(dock_window),
      dock_frame_(dock_frame),
      desktop_window_tree_host_(nullptr) {

  GetNativeWindow()->SetName("DockFrameAura");
}

DockFrameAura::~DockFrameAura() {

}

void DockFrameAura::OnHostClosed() {
  aura::client::SetVisibilityClient(GetNativeView()->GetRootWindow(), nullptr);
  DesktopNativeWidgetAura::OnHostClosed();
}

void DockFrameAura::InitNativeWidget(const views::Widget::InitParams& params) {
  desktop_window_tree_host_ =
      DockDesktopWindowTreeHost::CreateDockDesktopWindowTreeHost(
          dock_frame_,
          this,
          dock_window_,
          dock_frame_);
  views::Widget::InitParams modified_params = params;
  modified_params.desktop_window_tree_host =
      desktop_window_tree_host_->AsDesktopWindowTreeHost();
  DesktopNativeWidgetAura::InitNativeWidget(modified_params);

  visibility_controller_.reset(new wm::VisibilityController);
  aura::client::SetVisibilityClient(GetNativeView()->GetRootWindow(),
                                    visibility_controller_.get());
  wm::SetChildWindowVisibilityChangesAnimated(
      GetNativeView()->GetRootWindow());
}

views::Widget::InitParams DockFrameAura::GetWidgetParams() {
  views::Widget::InitParams params;
  params.native_widget = this;
  return params;
}

bool DockFrameAura::UseCustomFrame() const {
  //return false;
  return true;
}

bool DockFrameAura::UsesNativeSystemMenu() const {
  return desktop_window_tree_host_->UsesNativeSystemMenu();
}

int DockFrameAura::GetMinimizeButtonOffset() const {
  return desktop_window_tree_host_->GetMinimizeButtonOffset();
}

bool DockFrameAura::ShouldSaveWindowPlacement() const {
  return true;
}

void DockFrameAura::GetWindowPlacement(
  gfx::Rect* bounds,
  ui::WindowShowState* show_state) const {

  *bounds = GetWidget()->GetRestoredBounds();
  if (IsMaximized())
    *show_state = ui::SHOW_STATE_MAXIMIZED;
  else if (IsMinimized())
    *show_state = ui::SHOW_STATE_MINIMIZED;
  else
    *show_state = ui::SHOW_STATE_NORMAL;
}

bool DockFrameAura::PreHandleKeyboardEvent(
  const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "DockFrameAura::PreHandleKeyboardEvent";
  return false;
}

bool DockFrameAura::HandleKeyboardEvent(
  const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "DockFrameAura::HandleKeyboardEvent";
  return false;
}

}
