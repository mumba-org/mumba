// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_desktop_window_tree_host_win.h"

#include <dwmapi.h>

#include "base/macros.h"
#include "base/process/process_handle.h"
#include "base/win/windows_version.h"
#include "chrome/browser/lifetime/application_lifetime.h"
#include "chrome/browser/themes/theme_service.h"
#include "chrome/browser/themes/theme_service_factory.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/browser_window_property_manager_win.h"
#include "core/host/ui/system_menu_insertion_delegate_win.h"
//#include "chrome/browser/ui/views/tabs/tab_strip.h"
//#include "chrome/browser/win/titlebar_config.h"
#include "core/common/constants.h"
#include "ui/base/material_design/material_design_controller.h"
#include "ui/base/theme_provider.h"
#include "ui/display/win/screen_win.h"
#include "ui/gfx/geometry/point.h"
#include "ui/views/controls/menu/native_menu_win.h"
#include "ui/views/resources/grit/views_resources.h"

namespace host {

////////////////////////////////////////////////////////////////////////////////
// BrowserDesktopWindowTreeHostWin, public:

DockDesktopWindowTreeHostWin::DockDesktopWindowTreeHostWin(
    views::internal::NativeWidgetDelegate* native_widget_delegate,
    views::DesktopNativeWidgetAura* desktop_native_widget_aura,
    DockWindow* dock_window,
    DockFrame* dock_frame)
    : views::DesktopWindowTreeHostWin(native_widget_delegate,
                                      desktop_native_widget_aura),
      dock_window_(dock_window),
      dock_frame_(dock_frame),
      did_gdi_clear_(false) {
}

DockDesktopWindowTreeHostWin::~DockDesktopWindowTreeHostWin() {
}

views::NativeMenuWin* DockDesktopWindowTreeHostWin::GetSystemMenu() {
  if (!system_menu_.get()) {
    SystemMenuInsertionDelegateWin insertion_delegate;
    system_menu_.reset(
        new views::NativeMenuWin(dock_frame_->GetSystemMenuModel(),
                                 GetHWND()));
    system_menu_->Rebuild(&insertion_delegate);
  }
  return system_menu_.get();
}

////////////////////////////////////////////////////////////////////////////////
// BrowserDockDesktopWindowTreeHostWin, BrowserDesktopWindowTreeHost implementation:

views::DesktopWindowTreeHost* DockDesktopWindowTreeHostWin::AsDesktopWindowTreeHost() {
  return this;
}

int DockDesktopWindowTreeHostWin::GetMinimizeButtonOffset() const {
  return minimize_button_metrics_.GetMinimizeButtonOffsetX();
}

bool DockDesktopWindowTreeHostWin::UsesNativeSystemMenu() const {
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// BrowserDockDesktopWindowTreeHostWin, views::DockDesktopWindowTreeHostWin overrides:

int DockDesktopWindowTreeHostWin::GetInitialShowState() const {
  STARTUPINFO si = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  GetStartupInfo(&si);
  return si.wShowWindow;
}

bool DockDesktopWindowTreeHostWin::GetClientAreaInsets(
    gfx::Insets* insets) const {
  // Always use default insets for opaque frame.
  if (!ShouldUseNativeFrame())
    return false;

  // Use default insets for popups and apps, unless we are custom drawing the
  // titlebar.
  if (!ShouldCustomDrawSystemTitlebar() &&
      !dock_window_->IsBrowserTypeNormal())
    return false;

  if (GetWidget()->IsFullscreen()) {
    // In fullscreen mode there is no frame.
    *insets = gfx::Insets();
  } else {
    const int frame_thickness =
        display::win::ScreenWin::GetSystemMetricsForHwnd(
            GetHWND(), SM_CXSIZEFRAME);
    // Reduce the Windows non-client border size because we extend the border
    // into our client area in UpdateDWMFrame(). The top inset must be 0 or
    // else Windows will draw a full native titlebar outside the client area.
    *insets = gfx::Insets(0, frame_thickness, frame_thickness,
                          frame_thickness) - GetClientEdgeThicknesses();
  }
  return true;
}

void DockDesktopWindowTreeHostWin::HandleCreate() {
  views::DesktopWindowTreeHostWin::HandleCreate();
  browser_window_property_manager_ =
      BrowserWindowPropertyManager::CreateBrowserWindowPropertyManager(
          dock_window_, GetHWND());
}

void DockDesktopWindowTreeHostWin::HandleDestroying() {
  browser_window_property_manager_.reset();
  views::DesktopWindowTreeHostWin::HandleDestroying();
}

void DockDesktopWindowTreeHostWin::HandleFrameChanged() {
  // Reinitialize the status bubble, since it needs to be initialized
  // differently depending on whether or not DWM composition is enabled
  dock_window_->InitStatusBubble();

  // We need to update the glass region on or off before the base class adjusts
  // the window region.
  UpdateDWMFrame();
  views::DesktopWindowTreeHostWin::HandleFrameChanged();
}

void DockDesktopWindowTreeHostWin::HandleWindowScaleFactorChanged(
    float window_scale_factor) {
  views::DesktopWindowTreeHostWin::HandleWindowScaleFactorChanged(window_scale_factor);
  minimize_button_metrics_.OnDpiChanged();
}

bool DockDesktopWindowTreeHostWin::PreHandleMSG(UINT message,
                                            WPARAM w_param,
                                            LPARAM l_param,
                                            LRESULT* result) {
  switch (message) {
    case WM_ACTIVATE:
      if (LOWORD(w_param) != WA_INACTIVE)
        minimize_button_metrics_.OnHWNDActivated();
      return false;
    case WM_ENDSESSION:
      chrome::SessionEnding();
      return true;
    case WM_INITMENUPOPUP:
      GetSystemMenu()->UpdateStates();
      return true;
  }
  return views::DesktopWindowTreeHostWin::PreHandleMSG(
      message, w_param, l_param, result);
}

void DockDesktopWindowTreeHostWin::PostHandleMSG(UINT message,
                                             WPARAM w_param,
                                             LPARAM l_param) {
  HWND hwnd = GetHWND();
  switch (message) {
    case WM_CREATE:
      minimize_button_metrics_.Init(hwnd);
      break;
    case WM_WINDOWPOSCHANGED: {
      UpdateDWMFrame();

      // Windows lies to us about the position of the minimize button before a
      // window is visible. We use this position to portal the incognito avatar
      // in RTL mode, so when the window is shown, we need to re-layout and
      // schedule a paint for the non-client frame view so that the icon top has
      // the correct position when the window becomes visible. This fixes bugs
      // where the icon appears to overlay the minimize button. Note that we
      // will call Layout every time SetWindowPos is called with SWP_SHOWWINDOW,
      // however callers typically are careful about not specifying this flag
      // unless necessary to avoid flicker. This may be invoked during creation
      // on XP and before the non_client_view has been created.
      WINDOWPOS* window_pos = reinterpret_cast<WINDOWPOS*>(l_param);
      views::NonClientView* non_client_view = GetWidget()->non_client_view();
      if (window_pos->flags & SWP_SHOWWINDOW && non_client_view) {
        non_client_view->Layout();
        non_client_view->SchedulePaint();
      }
      break;
    }
    case WM_ERASEBKGND: {
      gfx::Insets insets;
      if (!did_gdi_clear_ && GetClientAreaInsets(&insets)) {
        // This is necessary to avoid white flashing in the titlebar area around
        // the minimize/maximize/close buttons.
        DCHECK_EQ(0, insets.top());
        HDC dc = GetDC(hwnd);
        MARGINS margins = GetDWMFrameMargins();
        RECT client_rect;
        GetClientRect(hwnd, &client_rect);
        HBRUSH brush = CreateSolidBrush(0);
        RECT rect = {0, 0, client_rect.right, margins.cyTopHeight};
        FillRect(dc, &rect, brush);
        DeleteObject(brush);
        ReleaseDC(hwnd, dc);
        did_gdi_clear_ = true;
      }
      break;
    }
    case WM_DWMCOLORIZATIONCOLORCHANGED: {
      // The activation border may have changed color.
      views::NonClientView* non_client_view = GetWidget()->non_client_view();
      if (non_client_view)
        non_client_view->SchedulePaint();
      break;
    }
  }
}

views::FrameMode DockDesktopWindowTreeHostWin::GetFrameMode() const {
  const views::FrameMode system_frame_mode =
      ShouldCustomDrawSystemTitlebar()
          ? views::FrameMode::SYSTEM_DRAWN_NO_CONTROLS
          : views::FrameMode::SYSTEM_DRAWN;

  // We don't theme popup or app windows, so regardless of whether or not a
  // theme is active for normal browser windows, we don't want to use the custom
  // frame for popups/apps.
  if (!dock_window_->IsBrowserTypeNormal() &&
      views::DesktopWindowTreeHostWin::GetFrameMode() ==
          views::FrameMode::SYSTEM_DRAWN) {
    return system_frame_mode;
  }

  // Otherwise, we use the native frame when we're told we should by the theme
  // provider (e.g. no custom theme is active).
  return GetWidget()->GetThemeProvider()->ShouldUseNativeFrame()
             ? system_frame_mode
             : views::FrameMode::CUSTOM_DRAWN;
}

bool DockDesktopWindowTreeHostWin::ShouldUseNativeFrame() const {
  if (!views::DesktopWindowTreeHostWin::ShouldUseNativeFrame())
    return false;
  // This function can get called when the Browser window is closed i.e. in the
  // context of the DockWindow destructor.
  if (!dock_window_->browser())
    return false;
  // We don't theme popup or app windows, so regardless of whether or not a
  // theme is active for normal browser windows, we don't want to use the custom
  // frame for popups/apps.
  if (!dock_window_->IsBrowserTypeNormal())
    return true;
  // Otherwise, we use the native frame when we're told we should by the theme
  // provider (e.g. no custom theme is active).
  return GetWidget()->GetThemeProvider()->ShouldUseNativeFrame();
}

bool DockDesktopWindowTreeHostWin::ShouldWindowContentsBeTransparent()
    const {
  return !ShouldCustomDrawSystemTitlebar() &&
         views::DesktopWindowTreeHostWin::ShouldWindowContentsBeTransparent();
}

void DockDesktopWindowTreeHostWin::FrameTypeChanged() {
  views::DesktopWindowTreeHostWin::FrameTypeChanged();
  did_gdi_clear_ = false;
}

////////////////////////////////////////////////////////////////////////////////
// BrowserDesktopWindowTreeHostWin, private:

void DockDesktopWindowTreeHostWin::UpdateDWMFrame() {
  // For "normal" windows on Aero, we always need to reset the glass area
  // correctly, even if we're not currently showing the native frame (e.g.
  // because a theme is showing), so we explicitly check for that case rather
  // than checking dock_frame_->ShouldUseNativeFrame() here.  Using that here
  // would mean we wouldn't reset the glass area to zero when moving from the
  // native frame to an opaque frame, leading to graphical glitches behind the
  // opaque frame.  Instead, we use that function below to tell us whether the
  // frame is currently native or opaque.
  if (!GetWidget()->client_view() || !dock_window_->IsBrowserTypeNormal() ||
      !views::DesktopWindowTreeHostWin::ShouldUseNativeFrame())
    return;

  MARGINS margins = GetDWMFrameMargins();

  DwmExtendFrameIntoClientArea(GetHWND(), &margins);
}

gfx::Insets DockDesktopWindowTreeHostWin::GetClientEdgeThicknesses() const {
  // Maximized windows have no visible client edge; the content goes to
  // the edge of the screen.  Restored windows on Windows 10 don't paint
  // the full 3D client edge, but paint content right to the edge of the
  // client area.
  if (IsMaximized() ||
      (base::win::GetVersion() >= base::win::VERSION_WIN10))
    return gfx::Insets();

  const ui::ThemeProvider* const tp = GetWidget()->GetThemeProvider();
    return gfx::Insets(
        0, tp->GetImageSkiaNamed(IDR_CONTENT_LEFT_SIDE)->width(),
        tp->GetImageSkiaNamed(IDR_CONTENT_BOTTOM_CENTER)->height(),
        tp->GetImageSkiaNamed(IDR_CONTENT_RIGHT_SIDE)->width());
}

MARGINS DockDesktopWindowTreeHostWin::GetDWMFrameMargins() const {
  // Don't extend the glass in at all if it won't be visible.
  if (!ShouldUseNativeFrame() || GetWidget()->IsFullscreen() ||
      ShouldCustomDrawSystemTitlebar())
    return MARGINS{0};

  // The glass should extend to the bottom of the tabstrip.
  HWND hwnd = GetHWND();
  gfx::Rect tabstrip_bounds(
      dock_frame_->GetBoundsForTabStrip(dock_window_->tabstrip()));
  tabstrip_bounds =
      display::win::ScreenWin::DIPToClientRect(hwnd, tabstrip_bounds);

  // Extend inwards far enough to go under the semitransparent client edges.
  const gfx::Insets thicknesses = GetClientEdgeThicknesses();
  gfx::Point left_top = display::win::ScreenWin::DIPToClientPoint(
      hwnd, gfx::Point(thicknesses.left(), thicknesses.top()));
  gfx::Point right_bottom = display::win::ScreenWin::DIPToClientPoint(
      hwnd, gfx::Point(thicknesses.right(), thicknesses.bottom()));

  if (base::win::GetVersion() < base::win::VERSION_WIN8) {
    // The 2 px (not DIP) at the inner edges of the glass are a light and
    // dark line, so we must inset further to account for those.
    constexpr gfx::Vector2d kDWMEdgeThickness(2, 2);
    left_top += kDWMEdgeThickness;
    right_bottom += kDWMEdgeThickness;
  }

  return MARGINS{left_top.x(), right_bottom.x(),
                 tabstrip_bounds.bottom() + left_top.y(), right_bottom.y()};
}

////////////////////////////////////////////////////////////////////////////////
// BrowserDesktopWindowTreeHost, public:

// static
DockDesktopWindowTreeHost* DockDesktopWindowTreeHost::CreateDockDesktopWindowTreeHost(
        views::internal::NativeWidgetDelegate* native_widget_delegate,
        views::DesktopNativeWidgetAura* desktop_native_widget_aura,
        DockWindow* dock_window,
        DockFrame* dock_frame) {
  return new DockDesktopWindowTreeHostWin(native_widget_delegate,
                                   desktop_native_widget_aura,
                                   dock_window,
                                   dock_frame);
}

}