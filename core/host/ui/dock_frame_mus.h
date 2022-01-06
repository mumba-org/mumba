// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_FRAME_MUS_H_
#define CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_FRAME_MUS_H_

#include "base/macros.h"
#include "core/host/ui/native_dock_frame.h"
#include "ui/views/widget/desktop_aura/desktop_native_widget_aura.h"

namespace host {

class DockFrame;
class DockWindow;

class DockFrameMus : public NativeDockFrame,
                     public views::DesktopNativeWidgetAura {
 public:
  DockFrameMus(DockFrame* dock_frame, DockWindow* dock_window);
  ~DockFrameMus() override;

 private:
  // Overridden from NativeDockFrame:
  views::Widget::InitParams GetWidgetParams() override;
  bool UseCustomFrame() const override;
  bool UsesNativeSystemMenu() const override;
  bool ShouldSaveWindowPlacement() const override;
  void GetWindowPlacement(gfx::Rect* bounds,
                          ui::WindowShowState* show_state) const override;
  bool PreHandleKeyboardEvent(
      const NativeWebKeyboardEvent& event) override;
  bool HandleKeyboardEvent(
      const NativeWebKeyboardEvent& event) override;
  int GetMinimizeButtonOffset() const override;

  DockFrame* dock_frame_;
  DockWindow* dock_window_;

  DISALLOW_COPY_AND_ASSIGN(DockFrameMus);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_FRAME_MUS_H_
