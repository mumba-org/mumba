// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame_view_linux.h"

#include "core/host/ui/dock_frame_view.h"
#include "core/host/ui/dock_frame_view_layout.h"
#include "core/host/themes/theme_service.h"
#include "ui/views/linux_ui/linux_ui.h"

namespace host {

///////////////////////////////////////////////////////////////////////////////
// DockFrameViewLinux, public:

DockFrameViewLinux::DockFrameViewLinux(
    DockFrameView* view,
    DockFrameViewLayout* layout,
    ThemeService* theme_service)
    : view_(view),
      layout_(layout),
      theme_service_(theme_service) {
  views::LinuxUI* ui = views::LinuxUI::instance();
  if (ui)
    ui->AddWindowButtonOrderObserver(this);
}

DockFrameViewLinux::~DockFrameViewLinux() {
  views::LinuxUI* ui = views::LinuxUI::instance();
  if (ui)
    ui->RemoveWindowButtonOrderObserver(this);
}

bool DockFrameViewLinux::IsUsingSystemTheme() {
  // On X11, this does the correct thing. On Windows, UsingSystemTheme() will
  // return true when using the default blue theme too.
  return theme_service_->UsingSystemTheme();
}

///////////////////////////////////////////////////////////////////////////////
// DockFrameViewLinux,
//     views::WindowButtonOrderObserver implementation:

void DockFrameViewLinux::OnWindowButtonOrderingChange(
    const std::vector<views::FrameButton>& leading_buttons,
    const std::vector<views::FrameButton>& trailing_buttons) {
  layout_->SetButtonOrdering(leading_buttons, trailing_buttons);

  // We can receive OnWindowButtonOrderingChange events before we've been added
  // to a Widget. We need a Widget because layout crashes due to dependencies
  // on a ui::ThemeProvider().
  if (view_->GetWidget()) {
    // A relayout on |view_| is insufficient because it would neglect
    // a relayout of the tabstrip.  Do a full relayout to handle the
    // frame buttons as well as open tabs.
    views::View* root_view = view_->GetWidget()->GetRootView();
    root_view->Layout();
    root_view->SchedulePaint();
  }
}

///////////////////////////////////////////////////////////////////////////////
// DockFrameViewObserver:

// static
DockFrameViewPlatformSpecific*
DockFrameViewPlatformSpecific::Create(
    DockFrameView* view,
    DockFrameViewLayout* layout,
    ThemeService* theme_service) {
  return new DockFrameViewLinux(view, layout, theme_service);
}

}
