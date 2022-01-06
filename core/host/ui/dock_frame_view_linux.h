// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_OPAQUE_BROWSER_FRAME_VIEW_LINUX_H_
#define MUMBA_HOST_UI_OPAQUE_BROWSER_FRAME_VIEW_LINUX_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "core/host/ui/dock_frame_view_platform_specific.h"
#include "ui/views/linux_ui/window_button_order_observer.h"

namespace host {
class ThemeService;
// Plumbs button change events from views::LinuxUI to
// DockFrameViewLayout.
class DockFrameViewLinux
    : public DockFrameViewPlatformSpecific,
      public views::WindowButtonOrderObserver {
 public:
  DockFrameViewLinux(DockFrameView* view,
                     DockFrameViewLayout* layout,
                     ThemeService* theme_service);
  ~DockFrameViewLinux() override;

  // Overridden from DockFrameViewPlatformSpecific:
  bool IsUsingSystemTheme() override;

  // Overridden from views::WindowButtonOrderObserver:
  void OnWindowButtonOrderingChange(
      const std::vector<views::FrameButton>& leading_buttons,
      const std::vector<views::FrameButton>& trailing_buttons) override;

 private:
  DockFrameView* view_;
  DockFrameViewLayout* layout_;
  ThemeService* theme_service_;

  DISALLOW_COPY_AND_ASSIGN(DockFrameViewLinux);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_OPAQUE_BROWSER_FRAME_VIEW_LINUX_H_
