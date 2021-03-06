// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "build/build_config.h"
//#include "core/host/themes/theme_service.h"
//#include "core/host/themes/theme_service_factory.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_frame_view.h"
#include "core/host/ui/dock_frame_view_layout.h"

#if defined(USE_AURA)
#include "core/host/ui/dock_non_client_frame_view_mus.h"
#include "ui/aura/env.h"
#endif

#if defined(OS_WIN)
#include "core/host/ui/glass_dock_frame_view.h"
#endif

#if defined(OS_LINUX) && !defined(OS_CHROMEOS)
#include "ui/views/linux_ui/linux_ui.h"
#endif

//#if BUILDFLAG(ENABLE_NATIVE_WINDOW_NAV_BUTTONS)
//#include "chrome/browser/ui/views/frame/desktop_linux_browser_frame_view.h"
//#include "chrome/browser/ui/views/frame/desktop_linux_browser_frame_view_layout.h"
//#include "chrome/browser/ui/views/nav_button_provider.h"
//#endif

namespace host {

DockNonClientFrameView* CreateDockNonClientFrameView(
    DockFrame* frame,
    DockWindow* dock_window) {
#if defined(USE_AURA)
  if (aura::Env::GetInstance()->mode() == aura::Env::Mode::MUS) {
    DockNonClientFrameViewMus* frame_view =
        new DockNonClientFrameViewMus(frame, dock_window);
    frame_view->Init();
    return frame_view;
  }
#endif
#if defined(OS_WIN)
  if (frame->ShouldUseNativeFrame())
    return new GlassDockFrameView(frame, dock_window);
#endif
// #if BUILDFLAG(ENABLE_NATIVE_WINDOW_NAV_BUTTONS)
//   std::unique_ptr<views::NavButtonProvider> nav_button_provider;
// #if defined(OS_LINUX) && !defined(OS_CHROMEOS)
//   if (ThemeServiceFactory::GetForProfile(dock_window->browser()->profile())
//           ->UsingSystemTheme() &&
//       views::LinuxUI::instance()) {
//     nav_button_provider = views::LinuxUI::instance()->CreateNavButtonProvider();
//   }
// #endif
//   if (nav_button_provider) {
//     return new DesktopLinuxDockFrameView(
//         frame, dock_window,
//         new DesktopLinuxDockFrameViewLayout(nav_button_provider.get()),
//         std::move(nav_button_provider));
//   }
// #endif
  return new DockFrameView(frame, dock_window, new DockFrameViewLayout());
}

}  // namespace host
