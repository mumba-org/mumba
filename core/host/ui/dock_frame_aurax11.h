// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_FRAME_AURAX11_H_
#define MUMBA_HOST_UI_WINDOW_HOST_FRAME_AURAX11_H_

#include "base/macros.h"
#include "core/host/ui/dock_frame_aura.h"

namespace host {

// DesktopBrowserFrameAuraX11
class DockFrameAuraX11 : public DockFrameAura {
public:
  DockFrameAuraX11(DockFrame* dock_frame,
                         DockWindow* dock_window);

 protected:
  ~DockFrameAuraX11() override;

  // Overridden from NativeBrowserFrame:
  views::Widget::InitParams GetWidgetParams() override;
  bool UseCustomFrame() const override;

 private:

  DISALLOW_COPY_AND_ASSIGN(DockFrameAuraX11);
};


}

#endif