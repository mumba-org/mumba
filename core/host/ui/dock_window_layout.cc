// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_window_layout.h"

#include "base/macros.h"
#include "base/observer_list.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
//#include "core/host/ui/dock_finder.h"
#include "core/host/ui/dock_window.h"
//#include "core/host/ui/find_bar/find_bar.h"
//#include "core/host/ui/find_bar/find_bar_controller.h"
//#include "core/host/ui/views/bookmarks/bookmark_bar_view.h"
//#include "core/host/ui/views/download/download_shelf_view.h"
#include "core/host/ui/exclusive_access_bubble_views.h"
#include "core/host/ui/dock_window_layout_delegate.h"
#include "core/host/ui/contents_layout_manager.h"
//#include "core/host/ui/views/frame/immersive_mode_controller.h"
#include "core/host/ui/top_container_view.h"
//#include "core/host/ui/views/infobars/infobar_container_view.h"
//#include "core/host/ui/views/location_bar/location_bar_view.h"
#include "core/host/ui/tablist/tablist.h"
//#include "core/host/ui/views/toolbar/toolbar_view.h"
//#include "components/web_modal/web_contents_modal_dialog_host.h"
#include "ui/base/hit_test.h"
#include "ui/base/material_design/material_design_controller.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/scrollbar_size.h"
#include "core/host/ui/application_view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/window/client_view.h"

using views::View;
//using web_modal::WebContentsModalDialogHost;
//using web_modal::ModalDialogHostObserver;

namespace host {

namespace {

// The visible height of the shadow above the tabs. Clicks in this area are
// treated as clicks to the frame, rather than clicks to the tab.
const int kTabShadowSize = 2;
// The number of pixels the constrained window should overlap the bottom
// of the omnibox.
//const int kConstrainedWindowOverlap = 3;

// Combines View::ConvertPointToTarget and View::HitTest for a given |point|.
// Converts |point| from |src| to |dst| and hit tests it against |dst|. The
// converted |point| can then be retrieved and used for additional tests.
bool ConvertedHitTest(views::View* src, views::View* dst, gfx::Point* point) {
  DCHECK(src);
  DCHECK(dst);
  DCHECK(point);
  views::View::ConvertPointToTarget(src, dst, point);
  return dst->HitTestPoint(*point);
}

}  // namespace

// class DockWindowLayout::WebContentsModalDialogHostViews
//     : public WebContentsModalDialogHost {
//  public:
//   explicit WebContentsModalDialogHostViews(
//       DockWindowLayout* dock_window_layout)
//           : dock_window_layout_(dock_window_layout) {
//   }

//   ~WebContentsModalDialogHostViews() override {
//     for (ModalDialogHostObserver& observer : observer_list_)
//       observer.OnHostDestroying();
//   }

//   void NotifyPositionRequiresUpdate() {
//     for (ModalDialogHostObserver& observer : observer_list_)
//       observer.OnPositionRequiresUpdate();
//   }

//   gfx::Point GetDialogPosition(const gfx::Size& size) override {
//     views::View* view = dock_window_layout_->contents_container_;
//     gfx::Rect content_area = view->ConvertRectToWidget(view->GetLocalBounds());
//     const int middle_x = content_area.x() + content_area.width() / 2;
//     const int top = dock_window_layout_->web_contents_modal_dialog_top_y_;
//     return gfx::Point(middle_x - size.width() / 2, top);
//   }

//   bool ShouldActivateDialog() const override {
//     return chrome::FindLastActive() == dock_window_layout_->dock_;
//   }

//   gfx::Size GetMaximumDialogSize() override {
//     views::View* view = dock_window_layout_->contents_container_;
//     gfx::Rect content_area = view->ConvertRectToWidget(view->GetLocalBounds());
//     const int top = dock_window_layout_->web_contents_modal_dialog_top_y_;
//     return gfx::Size(content_area.width(), content_area.bottom() - top);
//   }

//  private:
//   gfx::NativeView GetHostView() const override {
//     gfx::NativeWindow window =
//         dock_window_layout_->dock()->window()->GetNativeWindow();
//     return views::Widget::GetWidgetForNativeWindow(window)->GetNativeView();
//   }

//   // Add/remove observer.
//   void AddObserver(ModalDialogHostObserver* observer) override {
//     observer_list_.AddObserver(observer);
//   }
//   void RemoveObserver(ModalDialogHostObserver* observer) override {
//     observer_list_.RemoveObserver(observer);
//   }

//   DockWindowLayout* const dock_window_layout_;

//   base::ObserverList<ModalDialogHostObserver> observer_list_;

//   DISALLOW_COPY_AND_ASSIGN(WebContentsModalDialogHostViews);
// };

////////////////////////////////////////////////////////////////////////////////
// DockWindowLayout, public:

DockWindowLayout::DockWindowLayout()
    : dock_(nullptr),
      dock_window_(nullptr),
      top_container_(nullptr),
      tablist_(nullptr),
      //toolbar_(nullptr),
      //bookmark_bar_(nullptr),
      //infobar_container_(nullptr),
      contents_container_(nullptr),
      contents_layout_manager_(nullptr) {}//,
      //download_shelf_(nullptr),
      //immersive_mode_controller_(nullptr),
      //dialog_host_(new WebContentsModalDialogHostViews(this)),
      //web_contents_modal_dialog_top_y_(-1) {} 

DockWindowLayout::~DockWindowLayout() {
}

void DockWindowLayout::Init(
    DockWindowLayoutDelegate* delegate,
    Dock* dock,
    views::ClientView* dock_view,
    views::View* top_container,
    Tablist* tablist,
    //views::View* toolbar,
    //InfoBarContainerView* infobar_container,
    views::View* contents_container,
    ContentsLayoutManager* contents_layout_manager) {//,
    //ImmersiveModeController* immersive_mode_controller) {
  delegate_.reset(delegate);
  dock_ = dock;
  dock_window_ = dock_view;
  top_container_ = top_container;
  tablist_ = tablist;
  //toolbar_ = toolbar;
  //infobar_container_ = infobar_container;
  contents_container_ = contents_container;
  contents_layout_manager_ = contents_layout_manager;
  //immersive_mode_controller_ = immersive_mode_controller;
}

//WebContentsModalDialogHost*
//    DockWindowLayout::GetWebContentsModalDialogHost() {
//  return dialog_host_.get();
//}

gfx::Size DockWindowLayout::GetMinimumSize() {
  gfx::Size tablist_size(
      //dock()->SupportsWindowFeature(Dock::FEATURE_TABSTRIP) ?
      tablist_->GetMinimumSize()); //: gfx::Size());
  //gfx::Size toolbar_size(
  //    (dock()->SupportsWindowFeature(Dock::FEATURE_TOOLBAR) ||
  //     dock()->SupportsWindowFeature(Dock::FEATURE_LOCATIONBAR)) ?
  //         toolbar_->GetMinimumSize() : gfx::Size());
  //gfx::Size bookmark_bar_size;
  //if (bookmark_bar_ &&
      //bookmark_bar_->visible() &&
      //dock()->SupportsWindowFeature(Dock::FEATURE_BOOKMARKBAR)) {
    //bookmark_bar_size = bookmark_bar_->GetMinimumSize();
    //bookmark_bar_size.Enlarge(0, -bookmark_bar_->GetToolbarOverlap());
  //}
  //gfx::Size infobar_container_size(infobar_container_->GetMinimumSize());
  // TODO: Adjust the minimum height for the find bar.

  gfx::Size contents_size(contents_container_->GetMinimumSize());

  int min_height = delegate_->GetTopInsetInDockWindow(false) +
      tablist_size.height() + //toolbar_size.height() +
      //bookmark_bar_size.height() + infobar_container_size.height() +
      contents_size.height();
  int widths[] = {
        tablist_size.width(),
        //toolbar_size.width(),
        //bookmark_bar_size.width(),
        //infobar_container_size.width(),
        contents_size.width() };
  int min_width = *std::max_element(&widths[0], &widths[arraysize(widths)]);
  return gfx::Size(min_width, min_height);
}

// gfx::Rect DockWindowLayout::GetFindBarBoundingBox() const {
//   // This function returns the area the Find Bar can be laid out within. When
//   // the location bar/OmniBox is visible, the bounding box is the area extending
//   // from the bottom edge of the location bar/OmniBox to the bottom of the
//   // "user-perceived content area" of the dock window. The width matches the
//   // width of the location bar/OmniBox. If the location bar/OmniBox is not
//   // visible, the returned area is the full "user-perceived content area",
//   // excluding any vertical scrollbar.
//   // The "user-perceived content area" excludes the detached bookmark bar (in
//   // the New Tab case) and any infobars since they are not _visually_ connected
//   // to the Toolbar.

//   DockWindow* dock_view = DockWindow::GetDockWindowForDock(dock_);
//   LocationBarView* location_bar_view = dock_view->GetLocationBarView();

//   // Check for the presence of a visible OmniBox/location bar.
//   const bool has_location_bar =
//       dock_->SupportsWindowFeature(Dock::FEATURE_LOCATIONBAR) &&
//       location_bar_view && location_bar_view->visible() &&
//       (!immersive_mode_controller_->IsEnabled() ||
//        immersive_mode_controller_->IsRevealed());

//   gfx::Rect bounding_box;
//   // If the OmniBox/location bar is visible, anchor the find bar bounding box
//   // to its bottom edge.
//   if (has_location_bar) {
//     // The bounding box should be the area right below the OmniBox/location bar.
//     bounding_box = location_bar_view->ConvertRectToWidget(
//         location_bar_view->GetLocalBounds());
//     bounding_box.Inset(0, location_bar_view->height(), 0,
//                        -contents_container_->height());
//     return bounding_box;
//   }

//   // Otherwise, use the contents container minus any infobars and detached
//   // bookmark bar from the top and a scrollbar width from the appropriate edge.
//   bounding_box = contents_container_->ConvertRectToWidget(
//       contents_container_->GetLocalBounds());
//   // Under ChromeOS, the top_container_ may include the title bar for hosted
//   // apps. Just make sure something of consequence is visible before it's height
//   // is used.
//   const int top_container_height = (dock_view->tablist()->visible() ||
//                                     dock_view->toolbar()->visible() ||
//                                     dock_view->IsBookmarkBarVisible())
//                                        ? top_container_->height()
//                                        : 0;
//   if (base::i18n::IsRTL())
//     bounding_box.Inset(gfx::scrollbar_size(), top_container_height, 0, 0);
//   else
//     bounding_box.Inset(0, top_container_height, gfx::scrollbar_size(), 0);
//   return bounding_box;
// }

int DockWindowLayout::NonClientHitTest(const gfx::Point& point) {
  // Since the Tablist only renders in some parts of the top of the window,
  // the un-obscured area is considered to be part of the non-client caption
  // area of the window. So we need to treat hit-tests in these regions as
  // hit-tests of the titlebar.

  views::View* parent = dock_window_->parent();

  gfx::Point point_in_dock_window_coords(point);
  views::View::ConvertPointToTarget(
      parent, dock_window_, &point_in_dock_window_coords);
  gfx::Point test_point(point);

  // Determine if the Tablist exists and is capable of being clicked on. We
  // might be a popup window without a Tablist.
  if (delegate_->IsTablistVisible()) {
    // See if the mouse pointer is within the bounds of the Tablist.
    if (ConvertedHitTest(parent, tablist_, &test_point)) {
      if (tablist_->IsPositionInWindowCaption(test_point))
        return HTCAPTION;
      return HTCLIENT;
    }

    // The top few pixels of the Tablist are a drop-shadow - as we're pretty
    // starved of dragable area, let's give it to window dragging (this also
    // makes sense visually).
    views::Widget* widget = dock_window_->GetWidget();
    if (!(widget->IsMaximized() || widget->IsFullscreen()) &&
        (point_in_dock_window_coords.y() <
            (tablist_->y() + kTabShadowSize))) {
      // We return HTNOWHERE as this is a signal to our containing
      // NonClientView that it should figure out what the correct hit-test
      // code is given the mouse position...
      return HTNOWHERE;
    }
  }

  // If the point's y coordinate is below the top of the toolbar and otherwise
  // within the bounds of this view, the point is considered to be within the
  // client area.
  gfx::Rect bv_bounds = dock_window_->bounds();
  //bv_bounds.Offset(0, toolbar_->y());
  //bv_bounds.set_height(bv_bounds.height() - toolbar_->y());
  if (bv_bounds.Contains(point))
    return HTCLIENT;

  // If the point's y coordinate is above the top of the toolbar, but not
  // over the tablist (per previous checking in this function), then we
  // consider it in the window caption (e.g. the area to the right of the
  // tablist underneath the window controls). However, note that we DO NOT
  // return HTCAPTION here, because when the window is maximized the window
  // controls will fall into this space (since the DockWindow is sized to
  // entire size of the window at that point), and the HTCAPTION value will
  // cause the window controls not to work. So we return HTNOWHERE so that the
  // caller will hit-test the window controls before finally falling back to
  // HTCAPTION.
  bv_bounds = dock_window_->bounds();
  //bv_bounds.set_height(toolbar_->y());
  if (bv_bounds.Contains(point))
    return HTNOWHERE;

  // If the point is somewhere else, delegate to the default implementation.
  return dock_window_->views::ClientView::NonClientHitTest(point);
}

//////////////////////////////////////////////////////////////////////////////
// DockWindowLayout, views::LayoutManager implementation:

void DockWindowLayout::Layout(views::View* dock_view) {
  vertical_layout_rect_ = dock_view->GetLocalBounds();
  int top = delegate_->GetTopInsetInDockWindow(false);
  top = LayoutTablistRegion(top);
  if (delegate_->IsTablistVisible()) {
    // By passing true to GetTopInsetInDockWindow(), we position the tab
    // background to vertically align with the frame background image of a
    // restored-mode frame, even in a maximized window.  Then in the frame code,
    // we position the frame so the portion of the image that's behind the
    // restored-mode tablist is always behind the tablist.  Together these
    // ensure that the tab and frame images are always aligned, and that their
    // relative alignment with the toolbar image is always the same, so themes
    // which try to align all three will look correct in both restored and
    // maximized windows.
    int y = dock_window_->y() + delegate_->GetTopInsetInDockWindow(true);
    int x = tablist_->GetMirroredX() + dock_window_->GetMirroredX() +
            delegate_->GetThemeBackgroundXInset();
    tablist_->SetBackgroundOffset(gfx::Point(x, y));
  }
  //top = LayoutToolbar(top);

  //top = LayoutBookmarkAndInfoBars(top, dock_view->y());

  // Top container requires updated toolbar and bookmark bar to compute bounds.
  UpdateTopContainerBounds();

  int bottom = dock_view->height();//LayoutDownloadShelf(dock_view->height());
  // Treat a detached bookmark bar as if the web contents container is shifted
  // upwards and overlaps it.
  int active_top_margin = 0;//GetContentsOffsetForBookmarkBar();
  contents_layout_manager_->SetActiveTopMargin(active_top_margin);
  top -= active_top_margin;

  LayoutContentsContainerView(top, bottom);

  // This must be done _after_ we lay out the WebContents since this
  // code calls back into us to find the bounding box the find bar
  // must be laid out within, and that code depends on the
  // TabContentsContainer's bounds being up to date.
  //if (dock()->HasFindBarController()) {
  //  dock()->GetFindBarController()->find_bar()->MoveWindowIfNecessary(
  //      gfx::Rect());
  //}

  // Adjust the fullscreen exit bubble bounds for |top_container_|'s new bounds.
  // This makes the fullscreen exit bubble look like it animates with
  // |top_container_| in immersive fullscreen.
  ExclusiveAccessBubbleViews* exclusive_access_bubble =
      delegate_->GetExclusiveAccessBubble();
  if (exclusive_access_bubble)
    exclusive_access_bubble->RepositionIfVisible();

  // Adjust any hosted dialogs if the dock's dialog hosting bounds changed.
  //const gfx::Rect dialog_bounds(dialog_host_->GetDialogPosition(gfx::Size()),
  //                              dialog_host_->GetMaximumDialogSize());
  //if (latest_dialog_bounds_ != dialog_bounds) {
//    latest_dialog_bounds_ = dialog_bounds;
  //  dialog_host_->NotifyPositionRequiresUpdate();
  //}
}

// Return the preferred size which is the size required to give each
// children their respective preferred size.
gfx::Size DockWindowLayout::GetPreferredSize(const views::View* host) const {
  return gfx::Size();
}

//////////////////////////////////////////////////////////////////////////////
// DockWindowLayout, private:

int DockWindowLayout::LayoutTablistRegion(int top) {
  if (!delegate_->IsTablistVisible()) {
    tablist_->SetVisible(false);
    tablist_->SetBounds(0, 0, 0, 0);
    return top;
  }
  // This retrieves the bounds for the tab strip based on whether or not we show
  // anything to the left of it, like the incognito avatar.
  gfx::Rect tablist_bounds(delegate_->GetBoundsForTablistInDockWindow());

  tablist_->SetVisible(true);
  tablist_->SetBoundsRect(tablist_bounds);

  return tablist_bounds.bottom();
}

// int DockWindowLayout::LayoutToolbar(int top) {
//   int dock_window_width = vertical_layout_rect_.width();
//   bool toolbar_visible = delegate_->IsToolbarVisible();
//   int height = toolbar_visible ? toolbar_->GetPreferredSize().height() : 0;
//   toolbar_->SetVisible(toolbar_visible);
//   toolbar_->SetBounds(vertical_layout_rect_.x(), top, dock_window_width,
//                       height);
//   return toolbar_->bounds().bottom();
// }

// int DockWindowLayout::LayoutBookmarkAndInfoBars(int top, int dock_window_y) {
//   web_contents_modal_dialog_top_y_ =
//       top + dock_window_y - kConstrainedWindowOverlap;

//   if (bookmark_bar_) {
//     // If we're showing the Bookmark bar in detached style, then we
//     // need to show any Info bar _above_ the Bookmark bar, since the
//     // Bookmark bar is styled to look like it's part of the page.
//     if (bookmark_bar_->IsDetached()) {
//       web_contents_modal_dialog_top_y_ =
//           top + dock_window_y - kConstrainedWindowOverlap;
//       return LayoutBookmarkBar(LayoutInfoBar(top));
//     }
//     // Otherwise, Bookmark bar first, Info bar second.
//     top = std::max(toolbar_->bounds().bottom(), LayoutBookmarkBar(top));
//   }

//   return LayoutInfoBar(top);
// }

// int DockWindowLayout::LayoutBookmarkBar(int top) {
//   int y = top;
//   if (!delegate_->IsBookmarkBarVisible()) {
//     bookmark_bar_->SetVisible(false);
//     // TODO(jamescook): Don't change the bookmark bar height when it is
//     // invisible, so we can use its height for layout even in that state.
//     bookmark_bar_->SetBounds(0, y, dock_window_->width(), 0);
//     return y;
//   }

//   bookmark_bar_->set_infobar_visible(InfobarVisible());
//   int bookmark_bar_height = bookmark_bar_->GetPreferredSize().height();
//   y -= bookmark_bar_->GetToolbarOverlap();
//   bookmark_bar_->SetBounds(vertical_layout_rect_.x(),
//                            y,
//                            vertical_layout_rect_.width(),
//                            bookmark_bar_height);
//   // Set visibility after setting bounds, as the visibility update uses the
//   // bounds to determine if the mouse is hovering over a button.
//   bookmark_bar_->SetVisible(true);
//   return y + bookmark_bar_height;
// }

// int DockWindowLayout::LayoutInfoBar(int top) {
//   // In immersive fullscreen, the infobar always starts near the top of the
//   // screen.
//   if (immersive_mode_controller_->IsEnabled())
//     top = dock_window_->y();

//   infobar_container_->SetVisible(InfobarVisible());
//   infobar_container_->SetBounds(
//       vertical_layout_rect_.x(), top, vertical_layout_rect_.width(),
//       infobar_container_->GetPreferredSize().height());
//   return top + infobar_container_->height();
// }

void DockWindowLayout::LayoutContentsContainerView(int top, int bottom) {
  // |contents_container_| contains web page contents and devtools.
  // See dock_view.h for details.
  gfx::Rect contents_container_bounds(vertical_layout_rect_.x(),
                                      top,
                                      vertical_layout_rect_.width(),
                                      std::max(0, bottom - top));
  contents_container_->SetBoundsRect(contents_container_bounds);
}

void DockWindowLayout::UpdateTopContainerBounds() {
  // Set the bounds of the top container view such that it is tall enough to
  // fully show all of its children. In particular, the bottom of the bookmark
  // bar can be above the bottom of the toolbar while the bookmark bar is
  // animating. The top container view is positioned relative to the top of the
  // client view instead of relative to GetTopInsetInDockWindow() because the
  // top container view paints parts of the frame (title, window controls)
  // during an immersive fullscreen reveal.
  int height = 0;
  for (int i = 0; i < top_container_->child_count(); ++i) {
    views::View* child = top_container_->child_at(i);
    if (!child->visible())
      continue;
    int child_bottom = child->bounds().bottom();
    if (child_bottom > height)
      height = child_bottom;
  }

  // Ensure that the top container view reaches the topmost view in the
  // ClientView because the bounds of the top container view are used in
  // layout and we assume that this is the case.
  height = std::max(height, delegate_->GetTopInsetInDockWindow(false));

  gfx::Rect top_container_bounds(vertical_layout_rect_.width(), height);
  // If the immersive mode controller is animating the top container, it may be
  // partly offscreen.
  //top_container_bounds.set_y(
  //    immersive_mode_controller_->GetTopContainerVerticalOffset(
  //        top_container_bounds.size()));
  top_container_->SetBoundsRect(top_container_bounds);
}

// int DockWindowLayout::GetContentsOffsetForBookmarkBar() {
//   // If the bookmark bar is hidden or attached to the omnibox the web contents
//   // will appear directly underneath it and does not need an offset.
//   if (!bookmark_bar_ ||
//       !delegate_->IsBookmarkBarVisible() ||
//       !bookmark_bar_->IsDetached()) {
//     return 0;
//   }

//   // Offset for the detached bookmark bar.
//   return bookmark_bar_->height();
// }

// int DockWindowLayout::LayoutDownloadShelf(int bottom) {
//   if (delegate_->DownloadShelfNeedsLayout()) {
//     bool visible = dock()->SupportsWindowFeature(
//         Dock::FEATURE_DOWNLOADSHELF);
//     DCHECK(download_shelf_);
//     int height = visible ? download_shelf_->GetPreferredSize().height() : 0;
//     download_shelf_->SetVisible(visible);
//     download_shelf_->SetBounds(vertical_layout_rect_.x(), bottom - height,
//                                vertical_layout_rect_.width(), height);
//     download_shelf_->Layout();
//     bottom -= height;
//   }
//   return bottom;
// }

// bool DockWindowLayout::InfobarVisible() const {
//   // Cast to a views::View to access GetPreferredSize().
//   views::View* infobar_container = infobar_container_;
//   // NOTE: Can't check if the size IsEmpty() since it's always 0-width.
//   return dock_->SupportsWindowFeature(Dock::FEATURE_INFOBAR) &&
//       (infobar_container->GetPreferredSize().height() != 0);
// }

}