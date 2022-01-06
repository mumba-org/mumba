// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_window_non_client_frame_view_mac.h"

//#include "chrome/browser/themes/theme_properties.h"
#include "core/host/ui/layout_constants.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock_window_layout.h"
//#include "chrome/browser/ui/views/tabs/tab_strip.h"
#include "ui/base/hit_test.h"
#include "ui/base/theme_provider.h"
#include "ui/gfx/canvas.h"

namespace host {

namespace {

// How far to inset the tabstrip from the sides of the window.
const int kTablistTopInset = 8;
const int kTablistLeftInset = 70;  // Make room for window control buttons.
constexpr int kTablistRightInset = 4;  // Margin for profile switcher.
constexpr const gfx::Size kMinTabbedWindowSize(400, 272);
constexpr const gfx::Size kMinPopupWindowSize(100, 122);

}  // namespace

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, public:

DockNonClientFrameViewMac::DockNonClientFrameViewMac(
    DockFrame* frame,
    DockWindow* browser_view)
    : DockNonClientFrameView(frame, browser_view) {}

DockNonClientFrameViewMac::~DockNonClientFrameViewMac() {
}

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, BrowserNonClientFrameView implementation:

bool DockNonClientFrameViewMac::CaptionButtonsOnLeadingEdge() const {
  return true;
}

gfx::Rect DockNonClientFrameViewMac::GetBoundsForTabStrip(
    views::View* tabstrip) const {
  DCHECK(tabstrip);
  gfx::Rect bounds = gfx::Rect(0, kTablistTopInset, width(),
                               tabstrip->GetPreferredSize().height());
  bounds.Inset(GetTabStripLeftInset(), 0, GetTabStripRightInset(), 0);
  return bounds;
}

int DockNonClientFrameViewMac::GetTopInset(bool restored) const {
  return dock_window()->IsTabStripVisible() ? kTablistTopInset : 0;
}

int DockNonClientFrameViewMac::GetTabStripRightInset() const {
  int inset = kTablistRightInset;
  views::View* profile_switcher_view = GetProfileSwitcherButton();
  if (profile_switcher_view) {
    inset += profile_switcher_view->GetPreferredSize().width();
  } else if (profile_indicator_icon()) {
    inset +=
        profile_indicator_icon()->bounds().width() + GetAvatarIconPadding();
  }
  return inset;
}

int DockNonClientFrameViewMac::GetThemeBackgroundXInset() const {
  return 0;
}

void DockNonClientFrameViewMac::UpdateThrobber(bool running) {
}

int DockNonClientFrameViewMac::GetTabStripLeftInset() const {
  return kTablistLeftInset;
}

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, views::NonClientFrameView implementation:

gfx::Rect DockNonClientFrameViewMac::GetBoundsForClientView() const {
  return bounds();
}

gfx::Rect DockNonClientFrameViewMac::GetWindowBoundsForClientBounds(
    const gfx::Rect& client_bounds) const {
  return client_bounds;
}

int DockNonClientFrameViewMac::NonClientHitTest(const gfx::Point& point) {
  views::View* profile_switcher_view = GetProfileSwitcherButton();
  if (profile_switcher_view) {
    gfx::Point point_in_switcher(point);
    views::View::ConvertPointToTarget(this, profile_switcher_view,
                                      &point_in_switcher);
    if (profile_switcher_view->HitTestPoint(point_in_switcher)) {
      return HTCLIENT;
    }
  }
  int component = frame()->client_view()->NonClientHitTest(point);

  // DockWindow::NonClientHitTest will return HTNOWHERE for points that hit
  // the native title bar. On Mac, we need to explicitly return HTCAPTION for
  // those points.
  if (component == HTNOWHERE && bounds().Contains(point))
    return HTCAPTION;

  return component;
}

void DockNonClientFrameViewMac::GetWindowMask(const gfx::Size& size,
                                                 gfx::Path* window_mask) {
}

void DockNonClientFrameViewMac::ResetWindowControls() {
}

void DockNonClientFrameViewMac::UpdateWindowIcon() {
}

void DockNonClientFrameViewMac::UpdateWindowTitle() {
}

void DockNonClientFrameViewMac::SizeConstraintsChanged() {
}

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, views::View implementation:

gfx::Size DockNonClientFrameViewMac::GetMinimumSize() const {
  gfx::Size size = dock_window()->GetMinimumSize();
  size.SetToMax(dock_window()->browser()->is_type_tabbed()
                    ? kMinTabbedWindowSize
                    : kMinPopupWindowSize);
  return size;
}

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, protected:

// views::View:

void DockNonClientFrameViewMac::Layout() {
  DCHECK(dock_window());
  views::View* profile_switcher_view = GetProfileSwitcherButton();
  if (profile_indicator_icon() && dock_window()->IsTabStripVisible()) {
    LayoutIncognitoButton();
    // Mac lays out the incognito icon on the right, as the stoplight
    // buttons live in its Windows/Linux location.
    profile_indicator_icon()->SetX(width() - GetTabStripRightInset());
  } else if (profile_switcher_view != nullptr) {
    gfx::Size button_size = profile_switcher_view->GetPreferredSize();
    int button_x = width() - GetTabStripRightInset();
    int button_y = 0;
    TabStrip* tabstrip = dock_window()->tabstrip();
    if (tabstrip && dock_window()->IsTabStripVisible()) {
      int new_tab_button_bottom =
          tabstrip->bounds().y() + tabstrip->GetNewTabButtonBounds().height();
      // Align the switcher's bottom to bottom of the new tab button;
      button_y = new_tab_button_bottom - button_size.height();
    }
    profile_switcher_view->SetBounds(button_x, button_y, button_size.width(),
                                     button_size.height());
  }
  BrowserNonClientFrameView::Layout();
}

void DockNonClientFrameViewMac::OnPaint(gfx::Canvas* canvas) {
  if (!dock_window()->IsBrowserTypeNormal())
    return;

  canvas->DrawColor(GetFrameColor());

  if (!GetThemeProvider()->UsingSystemTheme())
    PaintThemedFrame(canvas);

  if (dock_window()->IsToolbarVisible())
    PaintToolbarBackground(canvas);
}

// BrowserNonClientFrameView:
//AvatarButtonStyle DockNonClientFrameViewMac::GetAvatarButtonStyle() const {
//  return AvatarButtonStyle::NATIVE;
//}

///////////////////////////////////////////////////////////////////////////////
// DockNonClientFrameViewMac, private:

void DockNonClientFrameViewMac::PaintThemedFrame(gfx::Canvas* canvas) {
  gfx::ImageSkia image = GetFrameImage();
  canvas->TileImageInt(image, 0, 0, width(), image.height());
  gfx::ImageSkia overlay = GetFrameOverlayImage();
  canvas->DrawImageInt(overlay, 0, 0);
}

}