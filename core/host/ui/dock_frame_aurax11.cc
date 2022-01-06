// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame_aurax11.h"

#include "base/command_line.h"
#include "core/host/shell_integration_linux.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/shared/common/switches.h"
#include "ui/views/widget/widget.h"

namespace host {

DockFrameAuraX11::DockFrameAuraX11(
    DockFrame* dock_frame,
    DockWindow* dock_window)
    : DockFrameAura(dock_frame, dock_window) {
  
}

DockFrameAuraX11::~DockFrameAuraX11() {

}

views::Widget::InitParams DockFrameAuraX11::GetWidgetParams() {
  views::Widget::InitParams params;
  params.native_widget = this;

  // Set up a custom WM_CLASS for some sorts of window types. This allows
  // task switchers in X11 environments to distinguish between main browser
  // windows and e.g app windows.
  params.wm_class_name = shell_integration_linux::GetProgramClassName();
  params.wm_class_class = shell_integration_linux::GetProgramClassClass();
  const char kX11WindowRoleApp[] = "app";
  //const char kX11WindowRolePopup[] = "pop-up";
  params.wm_role_name = std::string(kX11WindowRoleApp);
  //params.wm_role_name = std::string(kX11WindowRoleApp);//browser_view()->browser()->is_type_tabbed()
                        //    ? std::string(kX11WindowRoleBrowser)
                        //    : std::string(kX11WindowRolePopup);
  params.remove_standard_frame = UseCustomFrame();

  return params;
}

bool DockFrameAuraX11::UseCustomFrame() const {
  //return true;
  return false;
}


}
