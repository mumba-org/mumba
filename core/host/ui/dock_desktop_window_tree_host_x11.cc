// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_desktop_window_tree_host_x11.h"

#include <utility>

#include "base/macros.h"
//#include "core/host/themes/theme_service.h"
//#include "core/host/themes/theme_service_factory.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"

namespace host {

////////////////////////////////////////////////////////////////////////////////
// DockDesktopWindowTreeHostX11, public:

DockDesktopWindowTreeHostX11::DockDesktopWindowTreeHostX11(
    views::internal::NativeWidgetDelegate* native_widget_delegate,
    views::DesktopNativeWidgetAura* desktop_native_widget_aura,
    DockWindow* dock_window,
    DockFrame* dock_frame)
    : views::DesktopWindowTreeHostX11(native_widget_delegate,
                                      desktop_native_widget_aura),
      dock_window_(dock_window) {
  dock_frame->set_frame_type(
      dock_frame->UseCustomFrame() ? views::Widget::FRAME_TYPE_FORCE_CUSTOM
                                          : views::Widget::FRAME_TYPE_FORCE_NATIVE);
}

DockDesktopWindowTreeHostX11::~DockDesktopWindowTreeHostX11() {
}

////////////////////////////////////////////////////////////////////////////////
// DockDesktopWindowTreeHostX11,
//     BrowserDesktopWindowTreeHost implementation:

views::DesktopWindowTreeHost*
    DockDesktopWindowTreeHostX11::AsDesktopWindowTreeHost() {
  return this;
}

int DockDesktopWindowTreeHostX11::GetMinimizeButtonOffset() const {
  return 0;
}

bool DockDesktopWindowTreeHostX11::UsesNativeSystemMenu() const {
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// DockDesktopWindowTreeHostX11,
//     views::DockDesktopWindowTreeHostX11 implementation:

void DockDesktopWindowTreeHostX11::Init(
    const views::Widget::InitParams& params) {
  views::DesktopWindowTreeHostX11::Init(params);

  // We have now created our backing X11 window. We now need to (possibly)
  // alert Unity that there's a menu bar attached to it.
  global_menu_bar_x11_.reset(new GlobalMenuBarX11(dock_window_, this));
}

void DockDesktopWindowTreeHostX11::CloseNow() {
  global_menu_bar_x11_.reset();
  views::DesktopWindowTreeHostX11::CloseNow();
}

void DockDesktopWindowTreeHostX11::OnMaximizedStateChanged() {
  dock_window_->frame()->GetFrameView()->OnMaximizedStateChanged();
}

void DockDesktopWindowTreeHostX11::OnFullscreenStateChanged() {
  dock_window_->frame()->GetFrameView()->OnFullscreenStateChanged();
}

////////////////////////////////////////////////////////////////////////////////
// DesktopWindowTreeHost, public:

// static
DockDesktopWindowTreeHost* DockDesktopWindowTreeHost::CreateDockDesktopWindowTreeHost(
        views::internal::NativeWidgetDelegate* native_widget_delegate,
        views::DesktopNativeWidgetAura* desktop_native_widget_aura,
        DockWindow* dock_window,
        DockFrame* dock_frame) {
  return new DockDesktopWindowTreeHostX11(native_widget_delegate,
                                   desktop_native_widget_aura,
                                   dock_window,
                                   dock_frame);
}

}
