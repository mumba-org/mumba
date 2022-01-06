// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_non_client_frame_view.h"

#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "mumba/app/vector_icons/vector_icons.h"
#include "core/host/host.h"
#include "core/host/themes/theme_properties.h"
#include "core/host/ui/layout_constants.h"
#include "core/host/ui/view_ids.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/tablist/tablist.h"
#include "chrome/grit/theme_resources.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/base/material_design/material_design_controller.h"
#include "ui/base/theme_provider.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/color_palette.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/paint_vector_icon.h"
#include "ui/gfx/scoped_canvas.h"
#include "ui/views/background.h"

#if defined(OS_WIN)
#include "core/host/ui/taskbar_decorator_win.h"
#endif

namespace host {

DockNonClientFrameView::DockNonClientFrameView(
  DockFrame* frame,
  DockWindow* dock_window)
    : frame_(frame),
      dock_window_(dock_window) {

}

DockNonClientFrameView::~DockNonClientFrameView() {

}

void DockNonClientFrameView::OnDockWindowInitViewsComplete() {
  UpdateMinimumSize();
}

void DockNonClientFrameView::OnMaximizedStateChanged() {}

void DockNonClientFrameView::OnFullscreenStateChanged() {}

bool DockNonClientFrameView::CaptionButtonsOnLeadingEdge() const {
  return false;
}

SkColor DockNonClientFrameView::GetToolbarTopSeparatorColor() const {
 const auto color_id =
     ShouldPaintAsActive()
         ? ThemeProperties::COLOR_TOOLBAR_TOP_SEPARATOR
         : ThemeProperties::COLOR_TOOLBAR_TOP_SEPARATOR_INACTIVE;
  ui::ThemeProvider* tp = dock_window_->GetThemeServiceForActiveTab()->GetThemeProvider();
  return tp->GetColor(color_id);
}

void DockNonClientFrameView::UpdateClientArea() {}

void DockNonClientFrameView::UpdateMinimumSize() {}

void DockNonClientFrameView::ChildPreferredSizeChanged(views::View* child) {
  //if (child == GetProfileSwitcherButton()) {
    // Perform a re-layout if the avatar button has changed, since that can
    // affect the size of the tabs.
  //  frame()->GetRootView()->Layout();
  //}
}

void DockNonClientFrameView::VisibilityChanged(
  views::View* starting_from,
  bool is_visible) {
  // UpdateTaskbarDecoration() calls DrawTaskbarDecoration(), but that does
  // nothing if the window is not visible.  So even if we've already gotten the
  // up-to-date decoration, we need to run the update procedure again here when
  // the window becomes visible.
  //if (is_visible)
  //  OnProfileAvatarChanged(base::FilePath());
}

bool DockNonClientFrameView::ShouldPaintAsThemed() const {
  return true;//dock_window_->IsBrowserTypeNormal();
}

SkColor DockNonClientFrameView::GetFrameColor(bool active) const {
  ThemeProperties::OverwritableByUserThemeProperty color_id =
      active ? ThemeProperties::COLOR_FRAME
             : ThemeProperties::COLOR_FRAME_INACTIVE;
  //return ShouldPaintAsThemed()
         //    ? GetThemeProviderForProfile()->GetColor(color_id)
         //    : ThemeProperties::GetDefaultColor(color_id,
         //                                       false);
  const ui::ThemeProvider* tp = frame_->GetThemeProvider();
  if (dock_window_->GetThemeServiceForActiveTab()) {
    tp = dock_window_->GetThemeServiceForActiveTab()->GetThemeProvider();
  }
  return tp->GetColor(color_id);
}

gfx::ImageSkia DockNonClientFrameView::GetFrameImage(bool active) const {
  const ui::ThemeProvider* tp = frame_->GetThemeProvider();
  int frame_image_id = active ? IDR_THEME_FRAME : IDR_THEME_FRAME_INACTIVE;
  return ShouldPaintAsThemed() && (tp->HasCustomImage(frame_image_id) ||
                                   tp->HasCustomImage(IDR_THEME_FRAME))
             ? *tp->GetImageSkiaNamed(frame_image_id)
             : gfx::ImageSkia();
}

gfx::ImageSkia DockNonClientFrameView::GetFrameOverlayImage(
    bool active) const {
  if (!dock_window_->IsDockTypeNormal())
    return gfx::ImageSkia();

  const ui::ThemeProvider* tp = frame_->GetThemeProvider();
  int frame_overlay_image_id =
      active ? IDR_THEME_FRAME_OVERLAY : IDR_THEME_FRAME_OVERLAY_INACTIVE;
  return tp->HasCustomImage(frame_overlay_image_id)
             ? *tp->GetImageSkiaNamed(frame_overlay_image_id)
             : gfx::ImageSkia();
}

SkColor DockNonClientFrameView::GetFrameColor() const {
  return GetFrameColor(ShouldPaintAsActive());
}

gfx::ImageSkia DockNonClientFrameView::GetFrameImage() const {
  return GetFrameImage(ShouldPaintAsActive());
}

gfx::ImageSkia DockNonClientFrameView::GetFrameOverlayImage() const {
  return GetFrameOverlayImage(ShouldPaintAsActive());
}

void DockNonClientFrameView::PaintToolbarBackground(
    gfx::Canvas* canvas) const {
  gfx::Rect toolbar_bounds(dock_window()->GetToolbarBounds());
  if (toolbar_bounds.IsEmpty())
    return;
  gfx::Point toolbar_origin(toolbar_bounds.origin());
  ConvertPointToTarget(dock_window(), this, &toolbar_origin);
  toolbar_bounds.set_origin(toolbar_origin);

  const ui::ThemeProvider* tp = dock_window_->GetThemeServiceForActiveTab()->GetThemeProvider();
  const int x = toolbar_bounds.x();
  const int y = toolbar_bounds.y();
  const int w = toolbar_bounds.width();

  // Background.
  if (tp->HasCustomImage(IDR_THEME_TOOLBAR)) {
    canvas->TileImageInt(*tp->GetImageSkiaNamed(IDR_THEME_TOOLBAR),
                         x + GetThemeBackgroundXInset(),
                         y - GetTopInset(false) - GetLayoutInsets(TAB).top(), x,
                         y, w, toolbar_bounds.height());
  } else {
    canvas->FillRect(toolbar_bounds,
                     tp->GetColor(ThemeProperties::COLOR_TOOLBAR));
  }

  gfx::ScopedCanvas scoped_canvas(canvas);
  if (Tablist::ShouldDrawStrokes()) {
    // Top stroke.
    gfx::Rect tablist_bounds =
        GetMirroredRect(GetBoundsForTablist(dock_window()->tablist()));
    canvas->ClipRect(tablist_bounds, SkClipOp::kDifference);
    gfx::Rect separator_rect(x, y, w, 0);
    separator_rect.set_y(tablist_bounds.bottom());
    DockWindow::Paint1pxHorizontalLine(canvas, GetToolbarTopSeparatorColor(),
                                           separator_rect, true);
  }
  // Toolbar/content separator.
  DockWindow::Paint1pxHorizontalLine(
      canvas, tp->GetColor(ThemeProperties::COLOR_TOOLBAR_BOTTOM_SEPARATOR),
      toolbar_bounds, true);
}

void DockNonClientFrameView::ViewHierarchyChanged(
    const ViewHierarchyChangedDetails& details) {
  //if (details.is_add && details.child == this)
  //  UpdateProfileIcons();
}

int DockNonClientFrameView::GetTablistLeftInset() const {
  return 4;
  //return 8;
}

void DockNonClientFrameView::ActivationChanged(bool active) {
  // On Windows, while deactivating the widget, this is called before the
  // active HWND has actually been changed.  Since we want the avatar state to
  // reflect that the window is inactive, we force NonClientFrameView to see the
  // "correct" state as an override.
  set_active_state_override(&active);
  //UpdateProfileIcons();
  set_active_state_override(nullptr);

  // Changing the activation state may change the toolbar top separator color
  // that's used as the stroke around tabs/the new tab button.
  dock_window_->tablist()->SchedulePaint();

  // Changing the activation state may change the visible frame color.
  SchedulePaint();
}

bool DockNonClientFrameView::DoesIntersectRect(const views::View* target,
                                                  const gfx::Rect& rect) const {
  DCHECK_EQ(target, this);
  if (!views::ViewTargeterDelegate::DoesIntersectRect(this, rect)) {
    // |rect| is outside the frame's bounds.
    return false;
  }

  if (!dock_window()->IsTablistVisible()) {
    // Claim |rect| if it is above the top of the topmost client area view.
    return rect.y() < GetTopInset(false);
  }

  // If the rect is outside the bounds of the client area, claim it.
  gfx::RectF rect_in_client_view_coords_f(rect);
  View::ConvertRectToTarget(this, frame()->client_view(),
                            &rect_in_client_view_coords_f);
  gfx::Rect rect_in_client_view_coords =
      gfx::ToEnclosingRect(rect_in_client_view_coords_f);
  if (!frame()->client_view()->HitTestRect(rect_in_client_view_coords))
    return true;

  // Otherwise, claim |rect| only if it is above the bottom of the tablist in
  // a non-tab portion.
  Tablist* tablist = dock_window()->tablist();
  if (!tablist || !dock_window()->IsTablistVisible())
    return false;

  gfx::RectF rect_in_tablist_coords_f(rect);
  View::ConvertRectToTarget(this, tablist, &rect_in_tablist_coords_f);
  gfx::Rect rect_in_tablist_coords =
      gfx::ToEnclosingRect(rect_in_tablist_coords_f);
  if (rect_in_tablist_coords.y() >= tablist->GetLocalBounds().bottom()) {
    // |rect| is below the tablist.
    return false;
  }

  if (tablist->HitTestRect(rect_in_tablist_coords)) {
    // Claim |rect| if it is in a non-tab portion of the tablist.
    return tablist->IsRectInWindowCaption(rect_in_tablist_coords);
  }

  // We claim |rect| because it is above the bottom of the tablist, but
  // not in the tablist itself. In particular, the avatar label/button is left
  // of the tablist and the window controls are right of the tablist.
  return true;
}

void DockNonClientFrameView::UpdateTaskbarDecoration() {
  LOG(INFO) << "DockNonClientFrameView::UpdateTaskbarDecoration() called, but we commented on windows. see if we really need this";
// #if defined(OS_WIN)
//   // For popups and panels which don't have the avatar button, we still
//   // need to draw the taskbar decoration. Even though we have an icon on the
//   // window's relaunch details, we draw over it because the user may have
//   // pinned the badge-less Chrome shortcut which will cause Windows to ignore
//   // the relaunch details.
//   // TODO(calamity): ideally this should not be necessary but due to issues
//   // with the default shortcut being pinned, we add the runtime badge for
//   // safety. See crbug.com/313800.
//   gfx::Image decoration;
//   AvatarMenu::ImageLoadStatus status = AvatarMenu::GetImageForMenuButton(
//       dock_window()->dock()->workspace()->GetPath(), &decoration);

//   UMA_HISTOGRAM_ENUMERATION(
//       "Profile.AvatarLoadStatus", status,
//       static_cast<int>(AvatarMenu::ImageLoadStatus::MAX) + 1);

//   // If the user is using a Gaia picture and the picture is still being loaded,
//   // wait until the load finishes. This taskbar decoration will be triggered
//   // again upon the finish of the picture load.
//   if (status == AvatarMenu::ImageLoadStatus::LOADING ||
//       status == AvatarMenu::ImageLoadStatus::PROFILE_DELETED) {
//     return;
//   }

//   //chrome::DrawTaskbarDecoration(frame_->GetNativeWindow(), &decoration);
//   DrawTaskbarDecoration(frame_->GetNativeWindow(), &decoration);
// #endif
}

}
