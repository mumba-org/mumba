// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_X11_H_
#define MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_X11_H_

#include "base/macros.h"
#include "core/host/ui/dock_desktop_window_tree_host.h"
#include "core/host/ui/global_menu_bar_x11.h"
#include "ui/views/widget/desktop_aura/desktop_window_tree_host_x11.h"

namespace views {
class DesktopNativeWidgetAura;
}

namespace host {
class DockFrame;
class DockWindow;

class DockDesktopWindowTreeHostX11
    : public DockDesktopWindowTreeHost,
      public views::DesktopWindowTreeHostX11 {
 public:
  DockDesktopWindowTreeHostX11(
      views::internal::NativeWidgetDelegate* native_widget_delegate,
      views::DesktopNativeWidgetAura* desktop_native_widget_aura,
      DockWindow* dock_window,
      DockFrame* dock_frame);
  ~DockDesktopWindowTreeHostX11() override;

 private:
  // Overridden from BrowserDesktopWindowTreeHost:
  DesktopWindowTreeHost* AsDesktopWindowTreeHost() override;
  int GetMinimizeButtonOffset() const override;
  bool UsesNativeSystemMenu() const override;

  // Overridden from views::DesktopWindowTreeHostX11:
  void Init(const views::Widget::InitParams& params) override;
  void CloseNow() override;
  void OnMaximizedStateChanged() override;
  void OnFullscreenStateChanged() override;

  DockWindow* dock_window_;

  // Each browser frame maintains its own menu bar object because the lower
  // level dbus protocol associates a xid to a menu bar; we can't map multiple
  // xids to the same menu bar.
  std::unique_ptr<GlobalMenuBarX11> global_menu_bar_x11_;

  DISALLOW_COPY_AND_ASSIGN(DockDesktopWindowTreeHostX11);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_DESKTOP_WINDOW_TREE_HOST_X11_H_
