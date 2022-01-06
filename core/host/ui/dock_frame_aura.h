// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_FRAME_AURA_H_
#define MUMBA_HOST_UI_WINDOW_HOST_FRAME_AURA_H_

#include <memory>

#include "base/macros.h"
#include "core/host/ui/native_dock_frame.h"
#include "ui/views/context_menu_controller.h"
#include "ui/views/widget/desktop_aura/desktop_native_widget_aura.h"

namespace wm {
class VisibilityController;
}

namespace host {
class DockDesktopWindowTreeHost;
class DockFrame;
class DockWindow;

// DesktopBrowserFrameAura
class DockFrameAura : public views::DesktopNativeWidgetAura,
                      public NativeDockFrame {
public:
  
  DockFrameAura(DockFrame* dock_frame,
                DockWindow* dock_window);

  DockWindow* dock_window() const { return dock_window_; }
  DockFrame* dock_frame() const { return dock_frame_; }

 protected:

  ~DockFrameAura() override;

  // Overridden from views::DesktopNativeWidgetAura:
  void OnHostClosed() override;
  void InitNativeWidget(const views::Widget::InitParams& params) override;

  // Overridden from NativeBrowserFrame:
  views::Widget::InitParams GetWidgetParams() override;
  bool UseCustomFrame() const override;
  bool UsesNativeSystemMenu() const override;
  int GetMinimizeButtonOffset() const override;
  bool ShouldSaveWindowPlacement() const override;
  void GetWindowPlacement(gfx::Rect* bounds,
                          ui::WindowShowState* show_state) const override;
  bool PreHandleKeyboardEvent(
      const NativeWebKeyboardEvent& event) override;
  bool HandleKeyboardEvent(
      const NativeWebKeyboardEvent& event) override;

 private:
  // The BrowserView is our ClientView. This is a pointer to it.
  DockWindow* dock_window_;
  DockFrame* dock_frame_;

  // Owned by the RootWindow.
  DockDesktopWindowTreeHost* desktop_window_tree_host_;

  std::unique_ptr<wm::VisibilityController> visibility_controller_;
  
  DISALLOW_COPY_AND_ASSIGN(DockFrameAura);
};


}

#endif