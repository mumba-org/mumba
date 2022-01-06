// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_WIN_H_
#define MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_WIN_H_

#include <windows.h>
#include <uxtheme.h>

#include "base/macros.h"
#include "core/host/ui/desktop_window_tree_host.h"
#include "core/host/ui/minimize_button_metrics_win.h"
#include "ui/views/widget/desktop_aura/desktop_window_tree_host_win.h"

namespace views {
class DesktopNativeWidgetAura;
class NativeMenuWin;
}

namespace host {
class DockFrame;
class DockWindow;
class WindowPropertyManager;

class DockDesktopWindowTreeHostWin : public DockDesktopWindowTreeHost,
                                     public views::DesktopWindowTreeHostWin {
 public:
  DockDesktopWindowTreeHostWin(
      views::internal::NativeWidgetDelegate* native_widget_delegate,
      views::DesktopNativeWidgetAura* desktop_native_widget_aura,
      DockWindow* dock_window,
      DockFrame* dock_frame);
  ~DockDesktopWindowTreeHostWin() override;

 private:
  views::NativeMenuWin* GetSystemMenu();

  // Overridden from BrowserDesktopWindowTreeHost:
  DesktopWindowTreeHost* AsDesktopWindowTreeHost() override;
  int GetMinimizeButtonOffset() const override;
  bool UsesNativeSystemMenu() const override;

  // Overridden from DesktopWindowTreeHostWin:
  int GetInitialShowState() const override;
  bool GetClientAreaInsets(gfx::Insets* insets) const override;
  void HandleCreate() override;
  void HandleDestroying() override;
  void HandleFrameChanged() override;
  void HandleWindowScaleFactorChanged(float window_scale_factor) override;
  bool PreHandleMSG(UINT message,
                    WPARAM w_param,
                    LPARAM l_param,
                    LRESULT* result) override;
  void PostHandleMSG(UINT message, WPARAM w_param, LPARAM l_param) override;
  views::FrameMode GetFrameMode() const override;
  bool ShouldUseNativeFrame() const override;
  bool ShouldWindowContentsBeTransparent() const override;
  void FrameTypeChanged() override;

  void UpdateDWMFrame();
  gfx::Insets GetClientEdgeThicknesses() const;
  MARGINS GetDWMFrameMargins() const;

  DockWindow* dock_window_;
  DockFrame* dock_frame_;

  MinimizeButtonMetrics minimize_button_metrics_;

  std::unique_ptr<WindowPropertyManager>
      window_property_manager_;

  // The wrapped system menu itself.
  std::unique_ptr<views::NativeMenuWin> system_menu_;

  // Necessary to avoid corruption on NC paint in Aero mode.
  bool did_gdi_clear_;

  DISALLOW_COPY_AND_ASSIGN(DockDesktopWindowTreeHostWin);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_DESKTOP_WINDOW_TREE_HOST_WIN_H_
