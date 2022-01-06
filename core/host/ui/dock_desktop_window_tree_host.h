// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_H_
#define MUMBA_HOST_UI_DOCK_WINDOW_TREE_HOST_H_

namespace views {
class DesktopNativeWidgetAura;
class DesktopWindowTreeHost;
namespace internal {
class NativeWidgetDelegate;
}
}

namespace host {
class DockFrame;
class DockWindow;

// Interface to a platform specific browser frame implementation. The object
// implementing this interface will also implement views::DesktopWindowTreeHost.
class DockDesktopWindowTreeHost {
 public:
  // BDRWH is owned by the RootWindow.
  static DockDesktopWindowTreeHost* CreateDockDesktopWindowTreeHost(
      views::internal::NativeWidgetDelegate* native_widget_delegate,
      views::DesktopNativeWidgetAura* desktop_native_widget_aura,
      DockWindow* dock_window,
      DockFrame* dock_frame);

  virtual views::DesktopWindowTreeHost* AsDesktopWindowTreeHost() = 0;

  virtual int GetMinimizeButtonOffset() const = 0;

  // Returns true if the OS takes care of showing the system menu. Returning
  // false means BrowserFrame handles showing the system menu.
  virtual bool UsesNativeSystemMenu() const = 0;
};

}

#endif  // MUMBA_HOST_UI_DESKTOP_WINDOW_TREE_HOST_H_
