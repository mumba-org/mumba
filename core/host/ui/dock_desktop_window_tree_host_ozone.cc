// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "core/host/ui/dock_desktop_window_tree_host.h"

namespace host {
////////////////////////////////////////////////////////////////////////////////
// BrowserDesktopWindowTreeHost, public:

// static
DockDesktopWindowTreeHost* DockDesktopWindowTreeHost::CreateDockDesktopWindowTreeHost(
    views::internal::NativeWidgetDelegate* native_widget_delegate,
    views::DesktopNativeWidgetAura* desktop_native_widget_aura,
    DockWindow* dock_window,
    DockFrame* dock_frame) {
  NOTREACHED();
  return nullptr;
}

}