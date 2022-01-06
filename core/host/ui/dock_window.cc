// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_window.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/command_line.h"
#include "base/i18n/rtl.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "mumba/app/mumba_command_ids.h"
//#include "chrome/browser/app_mode/app_mode_utils.h"
//#include "chrome/browser/bookmarks/bookmark_stats.h"
#include "core/host/host.h"
//#include "chrome/browser/chrome_notification_types.h"
//#include "chrome/browser/extensions/extension_util.h"
//#include "chrome/browser/extensions/tab_helper.h"
//#include "chrome/browser/infobars/infobar_service.h"
#include "core/host/ui/native_window_notification_source.h"
//#include "chrome/browser/permissions/permission_request_manager.h"
//#include "chrome/browser/profiles/profile.h"
//#include "chrome/browser/profiles/profile_attributes_entry.h"
//#include "chrome/browser/profiles/profile_avatar_icon_util.h"
//#include "chrome/browser/profiles/profile_manager.h"
//#include "chrome/browser/profiles/profile_window.h"
//#include "chrome/browser/profiles/profiles_state.h"
//#include "chrome/browser/sessions/tab_restore_service_factory.h"
//#include "chrome/browser/signin/chrome_signin_helper.h"
#include "core/host/themes/theme_properties.h"
#include "core/host/themes/theme_service.h"
#include "core/host/themes/theme_service_custom.h"
//#include "chrome/browser/themes/theme_service.h"
//#include "chrome/browser/translate/chrome_translate_client.h"
//#include "core/host/ui/autofill/save_card_bubble_view.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_command_controller.h"
#include "core/host/ui/dock_commands.h"
//#include "core/host/ui/dock_dialogs.h"
//#include "core/host/ui/dock_finder.h"
//#include "core/host/ui/dock_list.h"
#include "core/host/ui/dock_window_state.h"
//#include "core/host/ui/extensions/hosted_app_dock_controller.h"
#include "core/host/ui/layout_constants.h"
#include "core/host/ui/tablist/sad_tab_helper.h"
//#include "core/host/ui/sync/bubble_sync_promo_delegate.h"
#include "core/host/ui/tablist/tab_menu_model.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/tab_utils.h"
#include "core/host/ui/tablist/dock_tablist_controller.h"
#include "core/host/ui/application_view_impl.h"
#include "core/host/ui/view_ids.h"
//#include "core/host/ui/views/accelerator_table.h"
//#include "core/host/ui/views/accessibility/invert_bubble_view.h"
//#include "core/host/ui/views/autofill/save_card_bubble_views.h"
//#include "core/host/ui/views/autofill/save_card_icon_view.h"
//#include "core/host/ui/views/bookmarks/bookmark_bar_view.h"
//#include "core/host/ui/views/bookmarks/bookmark_bubble_view.h"
//#include "core/host/ui/views/download/download_in_progress_dialog_view.h"
//#include "core/host/ui/views/download/download_shelf_view.h"
#include "core/host/ui/exclusive_access_bubble_views.h"
//#include "core/host/ui/views/extensions/extension_keybinding_registry_views.h"
//#include "core/host/ui/views/find_bar_host.h"
//#include "core/host/ui/views/frame/app_menu_button.h"
#include "core/host/notification_service.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_contents.h"
#include "core/host/ui/accelerator_table.h"
#include "core/host/ui/devtools/devtools_window.h"
#include "core/host/ui/devtools/devtools_contents_resizing_strategy.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_list.h"
#include "core/host/ui/dock_window_layout.h"
#include "core/host/ui/dock_window_layout_delegate.h"
#include "core/host/ui/contents_layout_manager.h"
//#include "core/host/ui/immersive_mode_controller.h"
#include "core/host/ui/top_container_view.h"
#include "core/host/ui/application_contents_close_handler.h"
#include "core/host/ui/fullscreen_control/fullscreen_control_host.h"
//#include "core/host/ui/views/ime/ime_warning_bubble_view.h"
//#include "core/host/ui/views/infobars/infobar_container_view.h"
//#include "core/host/ui/views/location_bar/location_bar_view.h"
//#include "core/host/ui/views/location_bar/star_view.h"
//#include "core/host/ui/views/omnibox/omnibox_view_views.h"
//#include "core/host/ui/views/profiles/profile_indicator_icon.h"
//#include "core/host/ui/views/status_bubble_views.h"
#include "core/host/application/application_contents_view_focus_helper.h"
#include "core/host/ui/tablist/dock_tablist_controller.h"
#include "core/host/ui/tablist/tab.h"
#include "core/host/ui/tablist/tablist.h"
//#include "core/host/ui/views/toolbar/dock_actions_container.h"
//#include "core/host/ui/views/toolbar/reload_button.h"
//#include "core/host/ui/views/toolbar/toolbar_view.h"
//#include "core/host/ui/views/translate/translate_bubble_view.h"
//#include "core/host/ui/views/update_recommended_message_box.h"
#include "core/host/ui/window_sizer/window_sizer.h"
#include "core/host/workspace/workspace.h"
//#include "core/common/channel_info.h"
#include "core/shared/common/switches.h"
#include "core/host/themes/theme_properties.h"
//#include "core/common/extensions/command.h"
//#include "core/common/pref_names.h"
//#include "core/common/url_constants.h"
#include "chrome/grit/chromium_strings.h"
#include "mumba/grit/generated_resources.h"
#include "chrome/grit/theme_resources.h"
//#include "components/app_modal/app_modal_dialog_queue.h"
//#include "components/app_modal/javascript_app_modal_dialog.h"
//#include "components/app_modal/native_app_modal_dialog.h"
//#include "components/omnibox/browser/omnibox_popup_model.h"
//#include "components/omnibox/browser/omnibox_popup_view.h"
//#include "components/omnibox/browser/omnibox_view.h"
//#include "components/prefs/pref_service.h"
//#include "components/sessions/core/tab_restore_service.h"
//#include "components/signin/core/browser/profile_management_switches.h"
//#include "components/translate/core/browser/language_state.h"
//#include "components/version_info/channel.h"
//#include "core/host/download_manager.h"
//#include "core/host/keyboard_event_processing_result.h"
#include "ui/accessibility/ax_node_data.h"
#include "ui/base/accelerators/accelerator.h"
#include "ui/base/hit_test.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/material_design/material_design_controller.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/base/theme_provider.h"
#include "ui/content_accelerators/accelerator_util.h"
#include "ui/display/screen.h"
#include "ui/events/event_utils.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/color_utils.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/scoped_canvas.h"
#include "ui/native_theme/native_theme_dark_aura.h"
#include "ui/views/controls/button/menu_button.h"
#include "ui/views/controls/textfield/textfield.h"
//#include "ui/views/controls/webview/webview.h"
#include "core/host/ui/application_view.h"
#include "ui/views/focus/external_focus_tracker.h"
#include "ui/views/layout/grid_layout.h"
#include "ui/views/widget/native_widget.h"
#include "ui/views/widget/root_view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/window/dialog_delegate.h"

#if defined(OS_CHROMEOS)
#include "core/host/ui/ash/ash_util.h"
#include "core/host/ui/views/location_bar/intent_picker_view.h"
//#else
//#include "core/host/ui/signin_view_controller.h"
//#include "core/host/ui/views/profiles/profile_chooser_view.h"
#endif  // !defined(OS_CHROMEOS)

#if defined(OS_MACOSX)
#include "core/host/ui/views/frame/dock_window_commands_mac.h"
#endif

#if defined(USE_AURA)
//#include "core/host/ui/views/theme_profile_key.h"
#include "ui/aura/client/window_parenting_client.h"
#include "ui/aura/window.h"
#include "ui/aura/window_tree_host.h"
#endif

#if defined(OS_WIN)
#include "base/win/windows_version.h"
#include "core/host/win/jumplist.h"
#include "core/host/win/jumplist_factory.h"
#include "ui/gfx/color_palette.h"
#include "ui/native_theme/native_theme_win.h"
#include "ui/views/win/scoped_fullscreen_visibility.h"
#include "core/host/ui/load_complete_listener.h"
#endif

using base::TimeDelta;
using base::UserMetricsAction;
using views::ColumnSet;
using views::GridLayout;
//using web_modal::ApplicationContentsModalDialogHost;

namespace host {

namespace {

// The name of a key to store on the window handle so that other code can
// locate this object using just the handle.
const char* const kDockWindowKey = "__DOCK_WINDOW__";

// The number of milliseconds between loading animation frames.
const int kLoadingAnimationFrameTimeMs = 30;

// See SetDisableRevealerDelayForTesting().
bool g_disable_revealer_delay_for_testing = false;

// Paints the horizontal border separating the Bookmarks Bar from the Toolbar
// or page content according to |at_top| with |color|.
// void PaintDetachedBookmarkBar(gfx::Canvas* canvas,
//                               BookmarkBarView* view) {
//   // Paint background for detached state; if animating, this is fade in/out.
//   const ui::ThemeProvider* tp = view->GetThemeProvider();
//   gfx::Rect fill_rect = view->GetLocalBounds();

//   // In detached mode, the bar is meant to overlap with |contents_container_|.
//   // The detached background color may be partially transparent, but the layer
//   // for |view| must be painted opaquely to avoid subpixel anti-aliasing
//   // artifacts, so we recreate the contents container base color here.
//   canvas->FillRect(fill_rect,
//                    tp->GetColor(ThemeProperties::COLOR_CONTROL_BACKGROUND));
//   canvas->FillRect(
//       fill_rect,
//       tp->GetColor(ThemeProperties::COLOR_DETACHED_BOOKMARK_BAR_BACKGROUND));

//   // Draw the separator below the detached bookmark bar.
//   DockWindow::Paint1pxHorizontalLine(
//       canvas,
//       tp->GetColor(ThemeProperties::COLOR_DETACHED_BOOKMARK_BAR_SEPARATOR),
//       view->GetLocalBounds(), true);
// }

// Paints the background (including the theme image behind content area) for
// the Bookmarks Bar when it is attached to the Toolbar into |bounds|.
// |background_origin| is the origin to use for painting the theme image.
// void PaintBackgroundAttachedMode(gfx::Canvas* canvas,
//                                  const ui::ThemeProvider* theme_provider,
//                                  const gfx::Rect& bounds,
//                                  const gfx::Point& background_origin) {
//   canvas->DrawColor(theme_provider->GetColor(ThemeProperties::COLOR_TOOLBAR));

//   // If there's a non-default background image, tile it.
//   if (theme_provider->HasCustomImage(IDR_THEME_TOOLBAR)) {
//     canvas->TileImageInt(*theme_provider->GetImageSkiaNamed(IDR_THEME_TOOLBAR),
//                          background_origin.x(),
//                          background_origin.y(),
//                          bounds.x(),
//                          bounds.y(),
//                          bounds.width(),
//                          bounds.height());
//   }
// }

// void PaintAttachedBookmarkBar(gfx::Canvas* canvas,
//                               BookmarkBarView* view,
//                               DockWindow* dock_window,
//                               int toolbar_overlap) {
//   // Paint background for attached state.
//   gfx::Point background_image_offset =
//       dock_window->OffsetPointForToolbarBackgroundImage(
//           gfx::Point(view->GetMirroredX(), view->y()));
//   PaintBackgroundAttachedMode(canvas, view->GetThemeProvider(),
//                               view->GetLocalBounds(), background_image_offset);
//   if (view->height() >= toolbar_overlap) {
//     DockWindow::Paint1pxHorizontalLine(
//         canvas, view->GetThemeProvider()->GetColor(
//                     ThemeProperties::COLOR_TOOLBAR_BOTTOM_SEPARATOR),
//         view->GetLocalBounds(), true);
//   }
// }

bool GetGestureCommand(ui::GestureEvent* event, int* command) {
  DCHECK(command);
  *command = 0;
#if defined(OS_MACOSX)
  if (event->details().type() == ui::ET_GESTURE_SWIPE) {
    if (event->details().swipe_left()) {
      *command = IDC_BACK;
      return true;
    } else if (event->details().swipe_right()) {
      *command = IDC_FORWARD;
      return true;
    }
  }
#endif  // OS_MACOSX
  return false;
}

}  // namespace

///////////////////////////////////////////////////////////////////////////////
// Delegate implementation for DockWindowLayout. Usually just forwards calls
// into DockWindow.
class DockWindowLayoutDelegateImpl : public DockWindowLayoutDelegate {
 public:
  explicit DockWindowLayoutDelegateImpl(DockWindow* dock_window)
      : dock_window_(dock_window) {}
  ~DockWindowLayoutDelegateImpl() override {}

  // DockWindowLayoutDelegate overrides:
  views::View* GetContentsApplicationView() const override {
    return dock_window_->contents_application_view_;
  }

  //bool DownloadShelfNeedsLayout() const override {
//    DownloadShelfView* download_shelf = dock_window_->download_shelf_.get();
    // Re-layout the shelf either if it is visible or if its close animation
    // is currently running.
//    return download_shelf &&
           //(download_shelf->IsShowing() || download_shelf->IsClosing());
  //}

  bool IsTablistVisible() const override {
    const bool visible = dock_window_->IsTablistVisible();
    return visible;
  }

  gfx::Rect GetBoundsForTablistInDockWindow() const override {
    gfx::RectF bounds_f(dock_window_->frame()->GetBoundsForTablist(
        dock_window_->tablist()));
    views::View::ConvertRectToTarget(dock_window_->parent(), dock_window_,
        &bounds_f);
    gfx::Rect bounds = gfx::ToEnclosingRect(bounds_f);   
    return bounds;
  }

  int GetTopInsetInDockWindow(bool restored) const override {
    return dock_window_->frame()->GetTopInset(restored) -
        dock_window_->y();
  }

  int GetThemeBackgroundXInset() const override {
    // TODO(pkotwicz): Return the inset with respect to the left edge of the
    // DockWindow.
    return dock_window_->frame()->GetThemeBackgroundXInset();
  }

  //bool IsToolbarVisible() const override {
//    return dock_window_->IsToolbarVisible();
 // }

  //bool IsBookmarkBarVisible() const override {
  //  return dock_window_->IsBookmarkBarVisible();
 // }

  ExclusiveAccessBubbleViews* GetExclusiveAccessBubble() const override {
    return dock_window_->exclusive_access_bubble();
  }

 private:
  DockWindow* dock_window_;

  DISALLOW_COPY_AND_ASSIGN(DockWindowLayoutDelegateImpl);
};

// This class is used to paint the background for Bookmarks Bar.
// class BookmarkBarViewBackground : public views::Background {
//  public:
//   BookmarkBarViewBackground(DockWindow* dock_window,
//                             BookmarkBarView* bookmark_bar_view);

//   // views:Background:
//   void Paint(gfx::Canvas* canvas, views::View* view) const override;

//  private:
//   DockWindow* dock_window_;

//   // The view hosting this background.
//   BookmarkBarView* bookmark_bar_view_;

//   DISALLOW_COPY_AND_ASSIGN(BookmarkBarViewBackground);
// };

// BookmarkBarViewBackground::BookmarkBarViewBackground(
//     DockWindow* dock_window,
//     BookmarkBarView* bookmark_bar_view)
//     : dock_window_(dock_window), bookmark_bar_view_(bookmark_bar_view) {}

// void BookmarkBarViewBackground::Paint(gfx::Canvas* canvas,
//                                       views::View* view) const {
//   int toolbar_overlap = bookmark_bar_view_->GetToolbarOverlap();

//   SkAlpha detached_alpha = static_cast<SkAlpha>(
//       bookmark_bar_view_->size_animation().CurrentValueBetween(0xff, 0));
//   if (detached_alpha != 0xff) {
//     PaintAttachedBookmarkBar(canvas, bookmark_bar_view_, dock_window_,
//                              toolbar_overlap);
//   }

//   if (!bookmark_bar_view_->IsDetached() || detached_alpha == 0)
//     return;

//   // While animating, set opacity to cross-fade between attached and detached
//   // backgrounds including their respective separators.
//   canvas->SaveLayerAlpha(detached_alpha);
//   PaintDetachedBookmarkBar(canvas, bookmark_bar_view_);
//   canvas->Restore();
// }

///////////////////////////////////////////////////////////////////////////////
// DockWindow, public:

// static
const char DockWindow::kViewClassName[] = "DockWindow";

DockWindow::DockWindow() : views::ClientView(nullptr, nullptr) {}

DockWindow::~DockWindow() {
  // All the tabs should have been destroyed already. If we were closed by the
  // OS with some tabs than the NativeDockFrame should have destroyed them.
  DCHECK_EQ(0, dock_->tablist_model()->count());

  // Stop the animation timer explicitly here to avoid running it in a nested
  // message loop, which may run by Dock destructor.
  loading_animation_timer_.Stop();

  // Immersive mode may need to reparent views before they are removed/deleted.
  //immersive_mode_controller_.reset();

  dock_->tablist_model()->RemoveObserver(this);

//  extensions::ExtensionCommandsGlobalRegistry* global_registry =
//      extensions::ExtensionCommandsGlobalRegistry::Get(dock_->profile());
  //if (global_registry->registry_for_active_window() ==
  //        extension_keybinding_registry_.get())
  //  global_registry->set_registry_for_active_window(nullptr);

  // We destroy the download shelf before |dock_| to remove its child
  // download views from the set of download observers (since the observed
  // downloads can be destroyed along with |dock_| and the observer
  // notifications will call back into deleted objects).
  DockWindowLayout* dock_window_layout = GetDockWindowLayout();
  //if (dock_window_layout)
//    dock_window_layout->set_download_shelf(nullptr);
  //download_shelf_.reset();

  // The Tablist attaches a listener to the model. Make sure we shut down the
  // Tablist first so that it can cleanly remove the listener.
  if (tablist_) {
    tablist_->parent()->RemoveChildView(tablist_);
    if (dock_window_layout)
      dock_window_layout->set_tablist(nullptr);
    delete tablist_;
    tablist_ = nullptr;
  }
  // Child views maintain PrefMember attributes that point to
  // OffTheRecordProfile's PrefService which gets deleted by ~Dock.
  RemoveAllChildViews(true);
  //toolbar_ = nullptr;
}

void DockWindow::Init(Dock* dock) {
  dock_.reset(dock);
  dock_->tablist_model()->AddObserver(this);
  //immersive_mode_controller_.reset(chrome::CreateImmersiveModeController());
}

// static
DockWindow* DockWindow::CreateDockWindow(Dock* dock,
                                         bool user_gesture,
                                         bool tabs_hidden) {
//#if defined(OS_MACOSX)
  //if (views_mode_controller::IsViewsDockCocoa())
  //  return DockWindow::CreateDockWindowCocoa(browser, user_gesture);
//#endif
  // Create the view and the frame. The frame will attach itself via the view
  // so we don't need to do anything with the pointer.
  DockWindow* window = new DockWindow();
  window->Init(dock);
  (new DockFrame(window))->InitDockFrame();
  window->GetWidget()->non_client_view()->SetAccessibleName(base::ASCIIToUTF16("Mumba"));
      //l10n_util::GetStringUTF16(IDS_PRODUCT_NAME));

//#if defined(USE_AURA)
  // For now, all browser windows are true. This only works when USE_AURA
  // because it requires gfx::NativeWindow to be an aura::Window*.
//  window->GetNativeWindow()->SetProperty(
      //aura::client::kCreatedByUserGesture, user_gesture);
//#endif
  if (tabs_hidden) {
    window->top_container()->SetVisible(false);
  }
  return window;
}


// static
DockWindow* DockWindow::GetDockWindowForNativeWindow(
    gfx::NativeWindow window) {
  views::Widget* widget = views::Widget::GetWidgetForNativeWindow(window);
  return widget ?
      reinterpret_cast<DockWindow*>(widget->GetNativeWindowProperty(
          kDockWindowKey)) : nullptr;
}

// static
DockWindow* DockWindow::GetDockWindowForDock(const Dock* dock) {
  return dock->window();
}

// static
void DockWindow::Paint1pxHorizontalLine(gfx::Canvas* canvas,
                                            SkColor color,
                                            const gfx::Rect& bounds,
                                            bool at_bottom) {
  gfx::ScopedCanvas scoped_canvas(canvas);
  const float scale = canvas->UndoDeviceScaleFactor();
  gfx::RectF rect(gfx::ScaleRect(gfx::RectF(bounds), scale));
  const float inset = rect.height() - 1;
  rect.Inset(0, at_bottom ? inset : 0, 0, at_bottom ? 0 : inset);
  cc::PaintFlags flags;
  flags.setColor(color);
  canvas->sk_canvas()->drawRect(gfx::RectFToSkRect(rect), flags);
}

// static
void DockWindow::SetDisableRevealerDelayForTesting(bool disable) {
  g_disable_revealer_delay_for_testing = disable;
}

// void DockWindow::InitStatusBubble() {
//   status_bubble_.reset(
//       new StatusBubbleViews(contents_application_view_, HasClientEdge()));
//   contents_application_view_->SetStatusBubble(status_bubble_.get());
// }

gfx::Rect DockWindow::GetToolbarBounds() const {
  //gfx::Rect toolbar_bounds(toolbar_->bounds());
  //if (toolbar_bounds.IsEmpty())
  //  return toolbar_bounds;
  // The apparent toolbar edges are outside the "real" toolbar edges.
  //toolbar_bounds.Inset(-views::NonClientFrameView::kClientEdgeThickness, 0);
  //return toolbar_bounds;
  return gfx::Rect();
}

//gfx::Rect DockWindow::GetFindBarBoundingBox() const {
//  return GetDockWindowLayout()->GetFindBarBoundingBox();
//}

int DockWindow::GetTablistHeight() const {
  // We want to return tablist_->height(), but we might be called in the midst
  // of layout, when that hasn't yet been updated to reflect the current state.
  // So return what the tablist height _ought_ to be right now.
  return IsTablistVisible() ? tablist_->GetPreferredSize().height() : 0;
}

gfx::Point DockWindow::OffsetPointForToolbarBackgroundImage(
    const gfx::Point& point) const {
  // The background image starts tiling horizontally at the window left edge and
  // vertically at the top edge of the horizontal tab strip (or where it would
  // be).  We expect our parent's origin to be the window origin.
  gfx::Point window_point(point + GetMirroredPosition().OffsetFromOrigin());
  window_point.Offset(frame_->GetThemeBackgroundXInset(),
                      -frame_->GetTopInset(false));
  return window_point;
}

bool DockWindow::IsTablistVisible() const {
  // Return false if this window does not normally display a tablist.
  //if (!dock_->SupportsWindowFeature(Dock::FEATURE_TABSTRIP))
  //  return false;

  // Return false if the tablist has not yet been created (by InitViews()),
  // since callers may otherwise try to access it. Note that we can't just check
  // this alone, as the tablist is created unconditionally even for windows
  // that won't display it.
  return tablist_ != nullptr && top_container_->visible();
}

//bool DockWindow::IsIncognito() const {
//  return dock_->profile()->IsOffTheRecord();
//}

//bool DockWindow::IsGuestSession() const {
//  return dock_->profile()->IsGuestSession();
//}

//bool DockWindow::IsRegularOrGuestSession() const {
//  return profiles::IsRegularOrGuestSession(dock_.get());
//}

bool DockWindow::HasClientEdge() const {
#if defined(OS_WIN)
  return base::win::GetVersion() < base::win::VERSION_WIN10 ||
         !frame_->ShouldUseNativeFrame();
#else
  return true;
#endif
}

bool DockWindow::GetAccelerator(int cmd_id,
                                ui::Accelerator* accelerator) const {
  // We retrieve the accelerator information for standard accelerators
  // for cut, copy and paste.
  if (GetAcceleratorForCommandId(cmd_id, accelerator))
    return true;
  // Else, we retrieve the accelerator information from the accelerator table.
  for (std::map<ui::Accelerator, int>::const_iterator it =
           accelerator_table_.begin(); it != accelerator_table_.end(); ++it) {
    if (it->second == cmd_id) {
      *accelerator = it->first;
      return true;
    }
  }
  return false;
}

bool DockWindow::IsAcceleratorRegistered(const ui::Accelerator& accelerator) {
  return accelerator_table_.find(accelerator) != accelerator_table_.end();
}

ApplicationContents* DockWindow::GetActiveApplicationContents() const {
  return dock_->tablist_model()->GetActiveApplicationContents();
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, DockWindow implementation:

void DockWindow::Show() {
#if !defined(OS_WIN) && !defined(OS_CHROMEOS)
  // The Dock associated with this browser window must become the active
  // browser at the time |Show()| is called. This is the natural behavior under
  // Windows and Chrome OS, but other platforms will not trigger
  // OnWidgetActivationChanged() until we return to the runloop. Therefore any
  // calls to Dock::GetLastActive() will return the wrong result if we do not
  // explicitly set it here.
  // A similar block also appears in DockWindowCocoa::Show().
  DockList::SetLastActive(dock());
#endif

  // If the window is already visible, just activate it.
  if (frame_->IsVisible()) {
    frame_->Activate();
    return;
  }

  // Showing the window doesn't make the browser window active right away.
  // This can cause SetFocusToLocationBar() to skip setting focus to the
  // location bar. To avoid this we explicilty let SetFocusToLocationBar()
  // know that it's ok to steal focus.
  //force_location_bar_focus_ = true;

  // Setting the focus doesn't work when the window is invisible, so any focus
  // initialization that happened before this will be lost.
  //
  // We really "should" restore the focus whenever the window becomes unhidden,
  // but I think initializing is the only time where this can happen where
  // there is some focus change we need to pick up, and this is easier than
  // plumbing through an un-hide message all the way from the frame.
  //
  // If we do find there are cases where we need to restore the focus on show,
  // that should be added and this should be removed.
  RestoreFocus();

  frame_->Show();

  //force_location_bar_focus_ = false;

  dock()->OnWindowDidShow();

//  MaybeShowInvertBubbleView(this);
}

void DockWindow::ShowInactive() {
  if (!frame_->IsVisible())
    frame_->ShowInactive();
}

void DockWindow::Hide() {
  // Not implemented.
}

bool DockWindow::IsVisible() const {
  return frame_->IsVisible();
}

void DockWindow::SetBounds(const gfx::Rect& bounds) {
  ExitFullscreen();
  GetWidget()->SetBounds(bounds);
}

void DockWindow::Close() {
  frame_->Close();
}

void DockWindow::Activate() {
  frame_->Activate();
}

void DockWindow::Deactivate() {
  frame_->Deactivate();
}

bool DockWindow::IsActive() const {
  return frame_->IsActive();
}

void DockWindow::FlashFrame(bool flash) {
  frame_->FlashFrame(flash);
}

bool DockWindow::IsAlwaysOnTop() const {
  return false;
}

void DockWindow::SetAlwaysOnTop(bool always_on_top) {
  // Not implemented for browser windows.
  NOTIMPLEMENTED();
}

gfx::NativeWindow DockWindow::GetNativeWindow() const {
  // While the browser destruction is going on, the widget can already be gone,
  // but utility functions like FindDockWithWindow will still call this.
  return GetWidget() ? GetWidget()->GetNativeWindow() : nullptr;
}

//StatusBubble* DockWindow::GetStatusBubble() {
//  return status_bubble_.get();
//}

void DockWindow::UpdateTitleBar() {
#if !defined(OS_CHROMEOS)
  if (ShouldShowWindowTitle())
    frame_->UpdateWindowTitle();
#else
  // ChromeOS needs this to be called even on a tabbed browser to
  // set the accessible title.
  frame_->UpdateWindowTitle();
#endif
  if (ShouldShowWindowIcon() && !loading_animation_timer_.IsRunning())
    frame_->UpdateWindowIcon();
}

// void DockWindow::BookmarkBarStateChanged(
//     BookmarkBar::AnimateChangeType change_type) {
//   if (bookmark_bar_view_.get()) {
//     BookmarkBar::State new_state = dock_->bookmark_bar_state();

//     // We don't properly support animating the bookmark bar to and from the
//     // detached state in immersive fullscreen.
//     bool detached_changed = (new_state == BookmarkBar::DETACHED) ||
//         bookmark_bar_view_->IsDetached();
//     if (detached_changed && immersive_mode_controller_->IsEnabled())
//       change_type = BookmarkBar::DONT_ANIMATE_STATE_CHANGE;

//     bookmark_bar_view_->SetBookmarkBarState(new_state, change_type);
//   }
//   if (MaybeShowBookmarkBar(GetActiveApplicationContents()))
//     Layout();
// }

void DockWindow::UpdateDevTools() {
  DLOG(INFO) << "DockWindow::UpdateDevTools";
  UpdateDevToolsForContents(GetActiveApplicationContents(), true);
  Layout();
}

void DockWindow::UpdateLoadingAnimations(bool should_animate) {
  if (should_animate) {
    if (!loading_animation_timer_.IsRunning()) {
      // Loads are happening, and the timer isn't running, so start it.
      loading_animation_timer_.Start(FROM_HERE,
          TimeDelta::FromMilliseconds(kLoadingAnimationFrameTimeMs), this,
          &DockWindow::LoadingAnimationCallback);
    }
  } else {
    if (loading_animation_timer_.IsRunning()) {
      loading_animation_timer_.Stop();
      // Loads are now complete, update the state if a task was scheduled.
      LoadingAnimationCallback();
    }
  }
}

//void DockWindow::SetStarredState(bool is_starred) {
//  GetLocationBarView()->SetStarToggled(is_starred);
//}

//void DockWindow::SetTranslateIconToggled(bool is_lit) {
  // Translate icon is never active on Views.
//}

bool DockWindow::IsDockTypeNormal() const {
  return dock_->is_type_tabbed();
}

void DockWindow::OnActiveTabChanged(ApplicationContents* old_contents,
                                    ApplicationContents* new_contents,
                                    int index,
                                    int reason) {
  DCHECK(new_contents);

  // Layout for DevTools _before_ setting the both main and devtools ApplicationContents
  // to avoid toggling the size of any of them.
  // if (!DevToolsWindow::HaveAnyInstance()) {
  //   // FIXME: WE ARE forcing this here
  //   DevToolsWindow::ToggleDevToolsWindow(dock_.get(), DevToolsToggleAction::Show());
  // }

  // If |contents_container_| already has the correct ApplicationContents, we can save
  // some work.  This also prevents extra events from being reported by the
  // Visibility API under Windows, as ChangeApplicationContents will briefly hide
  // the ApplicationContents window.
  bool change_tab_contents =
      contents_application_view_->application_contents() != new_contents;

  bool will_restore_focus = !dock_->tablist_model()->closing_all() &&
                            GetWidget()->IsActive() && GetWidget()->IsVisible();

  // Update various elements that are interested in knowing the current
  // ApplicationContents.

  // When we toggle the NTP floating bookmarks bar and/or the info bar,
  // we don't want any ApplicationContents to be attached, so that we
  // avoid an unnecessary resize and re-layout of a ApplicationContents.
  if (change_tab_contents) {
    if (will_restore_focus) {
      // Manually clear focus before setting focus behavior so that the focus
      // is not temporarily advanced to an arbitrary portal in the UI via
      // SetFocusBehavior(FocusBehavior::NEVER), confusing screen readers.
      // The saved focus for new_contents is restored after it is attached.
      // In addition, this ensures that the next RestoreFocus() will be
      // read out to screen readers, even if focus doesn't actually change.
      GetWidget()->GetFocusManager()->ClearFocus();
    }
    contents_application_view_->SetApplicationContents(nullptr);
    devtools_web_view_->SetApplicationContents(nullptr);
  }

  // Do this before updating InfoBarContainer as the InfoBarContainer may
  // callback to us and trigger layout.
  //if (bookmark_bar_view_.get()) {
//    bookmark_bar_view_->SetBookmarkBarState(
//        dock_->bookmark_bar_state(),
        //BookmarkBar::DONT_ANIMATE_STATE_CHANGE);
  //}

  //infobar_container_->ChangeInfoBarManager(
      //InfoBarService::FromApplicationContents(new_contents));

  UpdateUIForContents(new_contents);
  RevealTablistIfNeeded();

  if (change_tab_contents) {
    // When the location bar or other UI focus will be restored, first focus the
    // root view so that screen readers announce the current page title. The
    // kFocusContext event will delay the subsequent focus event so that screen
    // readers register them as distinct events.
    if (will_restore_focus) {
      ApplicationContentsViewFocusHelper* focus_helper =
          ApplicationContentsViewFocusHelper::FromApplicationContents(new_contents);
      if (focus_helper &&
          focus_helper->GetStoredFocus() != contents_application_view_) {
        GetWidget()->GetRootView()->NotifyAccessibilityEvent(
            ax::mojom::Event::kFocusContext, true);
      }
    }

    app_contents_close_handler_->ActiveTabChanged();
    contents_application_view_->SetApplicationContents(new_contents);
    SadTabHelper* sad_tab_helper = SadTabHelper::FromApplicationContents(new_contents);
    if (sad_tab_helper)
      sad_tab_helper->ReinstallInApplicationView();

    // The second layout update should be no-op. It will just set the
    // DevTools ApplicationContents.
    //UpdateDevToolsForContents(new_contents, true);
  }

  if (will_restore_focus) {
    // We only restore focus if our window is visible, to avoid invoking blur
    // handlers when we are eventually shown.
    new_contents->RestoreFocus();
  }

  // Update all the UI bits.
  UpdateTitleBar();

  UpdateDevToolsForContents(new_contents, !change_tab_contents);

  //TranslateBubbleView::CloseCurrentBubble();
}

void DockWindow::ZoomChangedForActiveTab(bool can_show_bubble) {
  //const AppMenuButton* app_menu_button =
  //    toolbar_button_provider_->GetAppMenuButton();
  //bool app_menu_showing = app_menu_button && app_menu_button->IsMenuShowing();
  //GetLocationBarView()->ZoomChangedForActiveWindow(can_show_bubble &&
  //                                              !app_menu_showing);
}

gfx::Rect DockWindow::GetRestoredBounds() const {
  gfx::Rect bounds;
  ui::WindowShowState state;
  frame_->GetWindowPlacement(&bounds, &state);
  return bounds;
}

ui::WindowShowState DockWindow::GetRestoredState() const {
  gfx::Rect bounds;
  ui::WindowShowState state;
  frame_->GetWindowPlacement(&bounds, &state);
  return state;
}

gfx::Rect DockWindow::GetBounds() const {
  return frame_->GetWindowBoundsInScreen();
}

gfx::Size DockWindow::GetContentsSize() const {
  DCHECK(initialized_);
  return contents_application_view_->size();
}

bool DockWindow::IsMaximized() const {
  return frame_->IsMaximized();
}

bool DockWindow::IsMinimized() const {
  return frame_->IsMinimized();
}

void DockWindow::Maximize() {
  frame_->Maximize();
}

void DockWindow::Minimize() {
  frame_->Minimize();
}

void DockWindow::Restore() {
  frame_->Restore();
}

void DockWindow::EnterFullscreen(const GURL& url,
                                  ExclusiveAccessBubbleType bubble_type) {
  if (IsFullscreen())
    return;  // Nothing to do.

  ProcessFullscreen(true, url, bubble_type);
}

void DockWindow::ExitFullscreen() {
  if (!IsFullscreen())
    return;  // Nothing to do.

  ProcessFullscreen(false, GURL(), EXCLUSIVE_ACCESS_BUBBLE_TYPE_NONE);
}

void DockWindow::UpdateExclusiveAccessExitBubbleContent(
    const GURL& url,
    ExclusiveAccessBubbleType bubble_type,
    ExclusiveAccessBubbleHideCallback bubble_first_hide_callback) {
  // Immersive mode has no exit bubble because it has a visible strip at the
  // top that gives the user a hover target. In a public session we show the
  // bubble.
  // TODO(jamescook): Figure out what to do with mouse-lock.
  //if (bubble_type == EXCLUSIVE_ACCESS_BUBBLE_TYPE_NONE ||
  //    (ShouldUseImmersiveFullscreenForUrl(url) &&
  //     !profiles::IsPublicSession())) {
    // |exclusive_access_bubble_.reset()| will trigger callback for current
    // bubble with |ExclusiveAccessBubbleHideReason::kInterrupted| if available.
  //  exclusive_access_bubble_.reset();
  //  if (bubble_first_hide_callback) {
  //    std::move(bubble_first_hide_callback)
  //        .Run(ExclusiveAccessBubbleHideReason::kNotShown);
  //  }
  //  return;
  //}

  if (exclusive_access_bubble_) {
    exclusive_access_bubble_->UpdateContent(
        url, bubble_type, std::move(bubble_first_hide_callback));
    return;
  }

  exclusive_access_bubble_.reset(new ExclusiveAccessBubbleViews(
      this, url, bubble_type, std::move(bubble_first_hide_callback)));
}

void DockWindow::OnExclusiveAccessUserInput() {
  if (exclusive_access_bubble_.get())
    exclusive_access_bubble_->OnUserInput();
}

bool DockWindow::ShouldHideUIForFullscreen() const {
  // Immersive mode needs UI for the slide-down top panel.
  //if (immersive_mode_controller_->IsEnabled())
  //  return false;

  return IsFullscreen();
}

bool DockWindow::IsFullscreen() const {
  return frame_->IsFullscreen();
}

bool DockWindow::IsFullscreenBubbleVisible() const {
  return exclusive_access_bubble_ != nullptr;
}

void DockWindow::RestoreFocus() {
  ApplicationContents* selected_app_contents = GetActiveApplicationContents();
  if (selected_app_contents)
    selected_app_contents->RestoreFocus();
}

void DockWindow::FullscreenStateChanged() {
  CHECK(!IsFullscreen());
  ProcessFullscreen(false, GURL(), EXCLUSIVE_ACCESS_BUBBLE_TYPE_NONE);
}

//void DockWindow::SetToolbarButtonProvider(ToolbarButtonProvider* provider) {
  // There should only be one toolbar button provider.
//  DCHECK(!toolbar_button_provider_);
//  toolbar_button_provider_ = provider;
//}

// LocationBar* DockWindow::GetLocationBar() const {
//   return GetLocationBarView();
// }

// void DockWindow::SetFocusToLocationBar(bool select_all) {
//   // On Windows, changing focus to the location bar causes the browser window to
//   // become active. This can steal focus if the user has another window open
//   // already. On Chrome OS, changing focus makes a view believe it has a focus
//   // even if the widget doens't have a focus. Either cases, we need to ignore
//   // this when the browser window isn't active.
// #if defined(OS_WIN) || defined(OS_CHROMEOS)
//   if (!force_location_bar_focus_ && !IsActive())
//     return;
// #endif

//   // Temporarily reveal the top-of-window views (if not already revealed) so
//   // that the location bar view is visible and is considered focusable. If the
//   // location bar view gains focus, |immersive_mode_controller_| will keep the
//   // top-of-window views revealed.
//   std::unique_ptr<ImmersiveRevealedLock> focus_reveal_lock(
//       immersive_mode_controller_->GetRevealedLock(
//           ImmersiveModeController::ANIMATE_REVEAL_YES));

//   LocationBarView* location_bar = GetLocationBarView();
//   if (location_bar->omnibox_view()->IsFocusable()) {
//     // Location bar got focus.
//     location_bar->FocusLocation(select_all);
//   } else {
//     // If none of location bar got focus, then clear focus.
//     views::FocusManager* focus_manager = GetFocusManager();
//     DCHECK(focus_manager);
//     focus_manager->ClearFocus();
//   }
// }

void DockWindow::UpdateReloadStopState(bool is_loading, bool force) {
  //if (toolbar_->reload_button()) {
  //  toolbar_->reload_button()->ChangeMode(
  //      is_loading ? ReloadButton::Mode::kStop : ReloadButton::Mode::kReload,
  //      force);
  //}
}

//void DockWindow::UpdateToolbar(ApplicationContents* contents) {
  // We may end up here during destruction.
//  if (toolbar_)
    //toolbar_->Update(contents);
//}

//void DockWindow::ResetToolbarWindowState(ApplicationContents* contents) {
  // We may end up here during destruction.
//  if (toolbar_)
    //toolbar_->ResetWindowState(contents);
//}

//void DockWindow::FocusToolbar() {
  // Temporarily reveal the top-of-window views (if not already revealed) so
  // that the toolbar is visible and is considered focusable. If the
  // toolbar gains focus, |immersive_mode_controller_| will keep the
  // top-of-window views revealed.
//  std::unique_ptr<ImmersiveRevealedLock> focus_reveal_lock(
      //immersive_mode_controller_->GetRevealedLock(
          //ImmersiveModeController::ANIMATE_REVEAL_YES));

  // Start the traversal within the main toolbar. SetPaneFocus stores
  // the current focused view before changing focus.
  //toolbar_button_provider_->FocusToolbar();
//}

//ToolbarActionsBar* DockWindow::GetToolbarActionsBar() {
//  DockActionsContainer* container =
      //toolbar_button_provider_->GetDockActionsContainer();
  //return container ? container->toolbar_actions_bar() : nullptr;
//}

//void DockWindow::ToolbarSizeChanged(bool is_animating) {
//  if (is_animating)
    //contents_application_view_->SetFastResize(true);
  //UpdateUIForContents(GetActiveApplicationContents());
  //if (is_animating)
//    contents_application_view_->SetFastResize(false);

  // When transitioning from animating to not animating we need to make sure the
  // contents_container_ gets layed out. If we don't do this and the bounds
  // haven't changed contents_container_ won't get a Layout and we'll end up
  // with a gray rect because the clip wasn't updated.
  //if (!is_animating) {
//    contents_application_view_->InvalidateLayout();
    //contents_container_->Layout();
  //}
//}

//void DockWindow::FocusBookmarksToolbar() {
//  DCHECK(!immersive_mode_controller_->IsEnabled());
//  if (bookmark_bar_view_.get() &&
      //bookmark_bar_view_->visible() &&
      //bookmark_bar_view_->GetPreferredSize().height() != 0) {
    //bookmark_bar_view_->SetPaneFocusAndFocusDefault();
  //}
//}

//void DockWindow::FocusInactivePopupForAccessibility() {
  //if (GetLocationBarView()->ActivateFirstInactiveBubbleForAccessibility())
  //  return;

  //if (infobar_container_->child_count() > 0)
  //  infobar_container_->SetPaneFocusAndFocusDefault();
//}

//void DockWindow::FocusAppMenu() {
  // Chrome doesn't have a traditional menu bar, but it has a menu button in the
  // main toolbar that plays the same role.  If the user presses a key that
  // would typically focus the menu bar, tell the toolbar to focus the menu
  // button.  If the user presses the key again, return focus to the previous
  // location.
  //
  // Not used on the Mac, which has a normal menu bar.
//  if (toolbar_->IsAppMenuFocused()) {
    //RestoreFocus();
  //} else {
//    DCHECK(!immersive_mode_controller_->IsEnabled());
    //toolbar_->SetPaneFocusAndFocusAppMenu();
  //}
//}

//void DockWindow::RotatePaneFocus(bool forwards) {
  // If an inactive bubble is showing this intentionally focuses that dialog to
  // provide an easy access method to these dialogs without requring additional
  // keyboard shortcuts or commands. To get back out to pane cycling the dialog
  // needs to be accepted or dismissed.
 // if (GetLocationBarView()->ActivateFirstInactiveBubbleForAccessibility())
  //  return;

  //GetFocusManager()->RotatePaneFocus(
      //forwards ?
          //views::FocusManager::kForward : views::FocusManager::kBackward,
      //views::FocusManager::kWrap);
//}

void DockWindow::DestroyDock() {
  // After this returns other parts of Chrome are going to be shutdown. Close
  // the window now so that we are deleted immediately and aren't left holding
  // references to deleted objects.
  GetWidget()->RemoveObserver(this);
  frame_->CloseNow();
}

// bool DockWindow::IsBookmarkBarVisible() const {
//   if (!dock_->SupportsWindowFeature(Dock::FEATURE_BOOKMARKBAR))
//     return false;
//   if (!bookmark_bar_view_.get())
//     return false;
//   if (!bookmark_bar_view_->parent())
//     return false;
//   if (bookmark_bar_view_->GetPreferredSize().height() == 0)
//     return false;
//   // New tab page needs visible bookmarks even when top-views are hidden.
//   if (immersive_mode_controller_->ShouldHideTopViews() &&
//       !bookmark_bar_view_->IsDetached())
//     return false;
//   return true;
// }

// bool DockWindow::IsBookmarkBarAnimating() const {
//   return bookmark_bar_view_.get() &&
//          bookmark_bar_view_->size_animation().is_animating();
// }

 bool DockWindow::IsTablistEditable() const {
   return tablist_->IsTablistEditable();
 }

// bool DockWindow::IsToolbarVisible() const {
//   if (immersive_mode_controller_->ShouldHideTopViews())
//     return false;
//   // It's possible to reach here before we've been notified of being added to a
//   // widget, so |toolbar_| is still null.  Return false in this case so callers
//   // don't assume they can access the toolbar yet.
//   return (dock_->SupportsWindowFeature(Dock::FEATURE_TOOLBAR) ||
//           dock_->SupportsWindowFeature(Dock::FEATURE_LOCATIONBAR)) &&
//          toolbar_;
// }

// bool DockWindow::IsToolbarShowing() const {
//   return IsToolbarVisible();
// }

// void DockWindow::ShowUpdateChromeDialog() {
//   UpdateRecommendedMessageBox::Show(GetNativeWindow());
// }

// #if defined(OS_CHROMEOS)
// void DockWindow::ShowIntentPickerBubble(
//     std::vector<IntentPickerBubbleView::AppInfo> app_info,
//     IntentPickerResponse callback) {
//   toolbar_->ShowIntentPickerBubble(std::move(app_info), std::move(callback));
// }

// void DockWindow::SetIntentPickerViewVisibility(bool visible) {
//   LocationBarView* location_bar = GetLocationBarView();

//   if (!location_bar->intent_picker_view())
//     return;

//   if (location_bar->intent_picker_view()->visible() != visible) {
//     location_bar->intent_picker_view()->SetVisible(visible);
//     location_bar->Layout();
//   }
// }
// #endif  //  defined(OS_CHROMEOS)

// void DockWindow::ShowBookmarkBubble(const GURL& url, bool already_bookmarked) {
//   toolbar_->ShowBookmarkBubble(url, already_bookmarked,
//                                bookmark_bar_view_.get());
// }

// autofill::SaveCardBubbleView* DockWindow::ShowSaveCreditCardBubble(
//     ApplicationContents* app_contents,
//     autofill::SaveCardBubbleController* controller,
//     bool user_gesture) {
//   LocationBarView* location_bar = GetLocationBarView();
//   BubbleIconView* card_view = location_bar->save_credit_card_icon_view();

//   views::View* anchor_view = location_bar;
//   if (!ui::MaterialDesignController::IsSecondaryUiMaterial()) {
//     if (card_view && card_view->visible())
//       anchor_view = card_view;
//     else
//       anchor_view = toolbar_button_provider()->GetAppMenuButton();
//   }

//   autofill::SaveCardBubbleViews* bubble = new autofill::SaveCardBubbleViews(
//       anchor_view, gfx::Point(), app_contents, controller);
//   views::Widget* bubble_widget =
//       views::BubbleDialogDelegateView::CreateBubble(bubble);
//   if (card_view)
//     card_view->OnBubbleWidgetCreated(bubble_widget);
//   bubble->Show(user_gesture ? autofill::SaveCardBubbleViews::USER_GESTURE
//                             : autofill::SaveCardBubbleViews::AUTOMATIC);
//   return bubble;
// }

// ShowTranslateBubbleResult DockWindow::ShowTranslateBubble(
//     ApplicationContents* app_contents,
//     translate::TranslateStep step,
//     translate::TranslateErrors::Type error_type,
//     bool is_user_gesture) {
//   if (contents_application_view_->HasFocus() &&
//       !GetLocationBarView()->IsMouseHovered() &&
//       app_contents->IsFocusedElementEditable()) {
//     return ShowTranslateBubbleResult::EDITABLE_FIELD_IS_ACTIVE;
//   }

//   translate::LanguageState& language_state =
//       ChromeTranslateClient::FromApplicationContents(app_contents)->GetLanguageState();
//   language_state.SetTranslateEnabled(true);

//   if (IsMinimized())
//     return ShowTranslateBubbleResult::BROWSER_WINDOW_MINIMIZED;

//   toolbar_->ShowTranslateBubble(app_contents, step, error_type,
//                                 is_user_gesture);
//   return ShowTranslateBubbleResult::SUCCESS;
// }

// #if BUILDFLAG(ENABLE_ONE_CLICK_SIGNIN)
// void DockWindow::ShowOneClickSigninConfirmation(
//     const base::string16& email,
//     const StartSyncCallback& start_sync_callback) {
//   std::unique_ptr<OneClickSigninLinksDelegate> delegate(
//       new OneClickSigninLinksDelegateImpl(dock()));
//   OneClickSigninDialogView::ShowDialog(email, std::move(delegate),
//                                        GetNativeWindow(), start_sync_callback);
// }
// #endif

// void DockWindow::SetDownloadShelfVisible(bool visible) {
//   DCHECK(download_shelf_);
//   dock_->UpdateDownloadShelfVisibility(visible);

//   // SetDownloadShelfVisible can force-close the shelf, so make sure we lay out
//   // everything correctly, as if the animation had finished. This doesn't
//   // matter for showing the shelf, as the show animation will do it.
//   ToolbarSizeChanged(false);
// }

// bool DockWindow::IsDownloadShelfVisible() const {
//   return download_shelf_.get() && download_shelf_->IsShowing();
// }

// DownloadShelf* DockWindow::GetDownloadShelf() {
//   DCHECK(dock_->SupportsWindowFeature(Dock::FEATURE_DOWNLOADSHELF));
//   if (!download_shelf_.get()) {
//     download_shelf_.reset(new DownloadShelfView(dock_.get(), this));
//     download_shelf_->set_owned_by_client();
//     GetDockWindowLayout()->set_download_shelf(download_shelf_.get());
//   }
//   return download_shelf_.get();
// }

// void DockWindow::ConfirmDockCloseWithPendingDownloads(
//     int download_count,
//     Dock::DownloadClosePreventionType dialog_type,
//     bool app_modal,
//     const base::Callback<void(bool)>& callback) {
//   DownloadInProgressDialogView::Show(
//       GetNativeWindow(), download_count, dialog_type, app_modal, callback);
// }

// void DockWindow::UserChangedTheme() {
//   frame_->FrameTypeChanged();
// }

// void DockWindow::ShowAppMenu() {
//   if (!toolbar_button_provider_->GetAppMenuButton())
//     return;

//   // Keep the top-of-window views revealed as long as the app menu is visible.
//   std::unique_ptr<ImmersiveRevealedLock> revealed_lock(
//       immersive_mode_controller_->GetRevealedLock(
//           ImmersiveModeController::ANIMATE_REVEAL_NO));

//   toolbar_button_provider_->GetAppMenuButton()->Activate(nullptr);
// }

KeyboardEventProcessingResult DockWindow::PreHandleKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  DLOG(INFO) << "DockWindow::PreHandleKeyboardEvent";

// CHECKME: mumba just changed here to add this stuff
//          see if we dont break others

   if ((event.GetType() != blink::WebInputEvent::kRawKeyDown) &&
       (event.GetType() != blink::WebInputEvent::kKeyUp)) {
     return KeyboardEventProcessingResult::NOT_HANDLED;
   }

  views::FocusManager* focus_manager = GetFocusManager();
  DCHECK(focus_manager);

  if (focus_manager->shortcut_handling_suspended())
     return KeyboardEventProcessingResult::NOT_HANDLED;

  ui::Accelerator accelerator =
    ui::GetAcceleratorFromNativeWebKeyboardEvent(event);

//   // What we have to do here is as follows:
//   // - If the |dock_| is for an app, do nothing.
//   // - On CrOS if |accelerator| is deprecated, we allow web contents to consume
//   //   it if needed.
//   // - If the |dock_| is not for an app, and the |accelerator| is not
//   //   associated with the browser (e.g. an Ash shortcut), process it.
//   // - If the |dock_| is not for an app, and the |accelerator| is associated
//   //   with the browser, and it is a reserved one (e.g. Ctrl+w), process it.
//   // - If the |dock_| is not for an app, and the |accelerator| is associated
//   //   with the browser, and it is not a reserved one, do nothing.

//   //if (dock_->is_app()) {
//     // Let all keys fall through to a v1 app's web content, even accelerators.
//     // We don't use NOT_HANDLED_IS_SHORTCUT here. If we do that, the app
//     // might not be able to see a subsequent Char event. See OnHandleInputEvent
//     // in content/renderer/render_widget.cc for details.
//     //return KeyboardEventProcessingResult::NOT_HANDLED;
//   //}

// #if defined(OS_CHROMEOS)
//   if (ash_util::IsAcceleratorDeprecated(accelerator)) {
//     return (event.GetType() == blink::WebInputEvent::kRawKeyDown)
//                ? content::KeyboardEventProcessingResult::NOT_HANDLED_IS_SHORTCUT
//                : content::KeyboardEventProcessingResult::NOT_HANDLED;
//   }
// #endif  // defined(OS_CHROMEOS)

  if (frame_->PreHandleKeyboardEvent(event))
    return KeyboardEventProcessingResult::HANDLED;

// #if defined(OS_CHROMEOS)
//   if (event.os_event && event.os_event->IsKeyEvent() &&
//       ash_util::WillAshProcessAcceleratorForEvent(
//           *event.os_event->AsKeyEvent())) {
//     return KeyboardEventProcessingResult::HANDLED_DONT_UPDATE_EVENT;
//   }
// #endif

  int id;
  if (!FindCommandIdForAccelerator(accelerator, &id)) {
    // |accelerator| is not a browser command, it may be handled by ash (e.g.
    // F4-F10). Report if we handled it.
    if (focus_manager->ProcessAccelerator(accelerator))
      return KeyboardEventProcessingResult::HANDLED;
    // Otherwise, it's not an accelerator.
    return KeyboardEventProcessingResult::NOT_HANDLED;
  }

  // If it's a known browser command, we decide whether to consume it now, i.e.
  // reserved by browser.
  DockCommandController* controller = dock_->command_controller();
  // Executing the command may cause |this| object to be destroyed.
  if (controller->IsReservedCommandOrKey(id, event)) {
//    UpdateAcceleratorMetrics(accelerator, id);
    return focus_manager->ProcessAccelerator(accelerator)
               ? KeyboardEventProcessingResult::HANDLED
               : KeyboardEventProcessingResult::NOT_HANDLED;
  }

//   // DockWindow does not register RELEASED accelerators. So if we can find the
//   // command id from |accelerator_table_|, it must be a keydown event. This
//   // DCHECK ensures we won't accidentally return NOT_HANDLED for a later added
//   // RELEASED accelerator in DockWindow.
  DCHECK_EQ(event.GetType(), blink::WebInputEvent::kRawKeyDown);
//   // |accelerator| is a non-reserved browser shortcut (e.g. Ctrl+f).
  return KeyboardEventProcessingResult::NOT_HANDLED_IS_SHORTCUT;
//  return KeyboardEventProcessingResult::NOT_HANDLED;
}

void DockWindow::HandleKeyboardEvent(const NativeWebKeyboardEvent& event) {
  if (frame_->HandleKeyboardEvent(event))
    return;

  unhandled_keyboard_event_handler_.HandleKeyboardEvent(event,
                                                        GetFocusManager());
}

// TODO(devint): http://b/issue?id=1117225 Cut, Copy, and Paste are always
// enabled in the page menu regardless of whether the command will do
// anything. When someone selects the menu item, we just act as if they hit
// the keyboard shortcut for the command by sending the associated key press
// to windows. The real fix to this bug is to disable the commands when they
// won't do anything. We'll need something like an overall clipboard command
// manager to do that.
void DockWindow::CutCopyPaste(int command_id) {
#if defined(OS_MACOSX)
  ForwardCutCopyPasteToNSApp(command_id);
#else
  // If a ApplicationContents is focused, call its member method.
  //
  // We could make ApplicationContents register accelerators and then just use the
  // plumbing for accelerators below to dispatch these, but it's not clear
  // whether that would still allow keypresses of ctrl-X/C/V to be sent as
  // key events (and not accelerators) to the ApplicationContents so it can give the web
  // page a chance to override them.
  ApplicationContents* contents = dock_->tablist_model()->GetActiveApplicationContents();
  if (contents) {
    void (ApplicationContents::*method)();
    if (command_id == IDC_CUT)
      method = &ApplicationContents::Cut;
    else if (command_id == IDC_COPY)
      method = &ApplicationContents::Copy;
    else
      method = &ApplicationContents::Paste;
    if (DoCutCopyPasteForApplicationContents(contents, method))
      return;

    // ApplicationContents* devtools =
    //     DevToolsWindow::GetInTabApplicationContents(contents, nullptr);
    // if (devtools && DoCutCopyPasteForApplicationContents(devtools, method))
    //   return;
  }

  // Any Views which want to handle the clipboard commands in the Chrome menu
  // should:
  //   (a) Register ctrl-X/C/V as accelerators
  //   (b) Implement CanHandleAccelerators() to not return true unless they're
  //       focused, as the FocusManager will try all registered accelerator
  //       handlers, not just the focused one.
  // Currently, Textfield (which covers the omnibox and find bar, and likely any
  // other native UI in the future that wants to deal with clipboard commands)
  // does the above.
  ui::Accelerator accelerator;
  GetAccelerator(command_id, &accelerator);
  GetFocusManager()->ProcessAccelerator(accelerator);
#endif  // defined(OS_MACOSX)
}

WindowOpenDisposition DockWindow::GetDispositionForPopupBounds(
    const gfx::Rect& bounds) {
  return WindowOpenDisposition::NEW_POPUP;
}

//FindBar* DockWindow::CreateFindBar() {
//  return new FindBarHost(this);
//}

//ApplicationContentsModalDialogHost* DockWindow::GetApplicationContentsModalDialogHost() {
//  return GetDockWindowLayout()->GetApplicationContentsModalDialogHost();
//}

//BookmarkBarView* DockWindow::GetBookmarkBarView() const {
//  return bookmark_bar_view_.get();
//}

//LocationBarView* DockWindow::GetLocationBarView() const {
//  return toolbar_ ? toolbar_->location_bar() : nullptr;
//}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, TablistModelObserver implementation:

void DockWindow::TabInsertedAt(TablistModel* tablist_model,
                               ApplicationContents* contents,
                               int index,
                               bool foreground) {
#if defined(USE_AURA)
  // ApplicationContents inserted in tabs might not have been added to the root
  // window yet. Per http://crbug/342672 add them now since drawing the
  // ApplicationContents requires root window specific data - information about
  // the screen the ApplicationContents is drawn on, for example.
  if (!contents->GetNativeView()->GetRootWindow()) {
    aura::Window* window = contents->GetNativeView();
    aura::Window* root_window = GetNativeWindow()->GetRootWindow();
    aura::client::ParentWindowWithContext(
        window, root_window, root_window->GetBoundsInScreen());
    DCHECK(contents->GetNativeView()->GetRootWindow());
  }
#endif
  app_contents_close_handler_->TabInserted();
}

void DockWindow::TabDetachedAt(ApplicationContents* contents, int index) {
  // We use index here rather than comparing |contents| because by this time
  // the model has already removed |contents| from its list, so
  // dock_->GetActiveApplicationContents() will return null or something else.
  if (index == dock_->tablist_model()->active_index()) {
    // We need to reset the current tab contents to null before it gets
    // freed. This is because the focus manager performs some operations
    // on the selected ApplicationContents when it is removed.
    app_contents_close_handler_->ActiveTabChanged();
    contents_application_view_->SetApplicationContents(nullptr);
    //infobar_container_->ChangeInfoBarManager(nullptr);
    UpdateDevToolsForContents(nullptr, true);
  }
}

void DockWindow::TabDeactivated(ApplicationContents* contents) {
  // We do not store the focus when closing the tab to work-around bug 4633.
  // Some reports seem to show that the focus manager and/or focused view can
  // be garbage at that point, it is not clear why.
  if (!contents->IsBeingDestroyed())
    contents->StoreFocus();
}

void DockWindow::TablistEmpty() {
  // Make sure all optional UI is removed before we are destroyed, otherwise
  // there will be consequences (since our view hierarchy will still have
  // references to freed views).
  UpdateUIForContents(nullptr);
}

void DockWindow::WillCloseAllTabs() {
  app_contents_close_handler_->WillCloseAllTabs();
}

void DockWindow::CloseAllTabsCanceled() {
  app_contents_close_handler_->CloseAllTabsCanceled();
}

ThemeService* DockWindow::GetThemeServiceForActiveTab() {
  return dock_->tablist_model()->GetThemeServiceForActiveTab();
}

void DockWindow::TablistColorChanged(TablistModel* tablist_model, SkColor color, int tab_index) {
  CustomThemeService* theme_service = tablist_model->GetThemeServiceForTab(tab_index);
  DCHECK(theme_service);

  SkColor toolbar_color = theme_service->GetThemeProvider()->GetColor(ThemeProperties::COLOR_TOOLBAR);

  if (toolbar_color != color) {
    //SkColor back_color = color_utils::BlendTowardOppositeLuma(color, 70);
    //SkColor inactive_color = color_utils::BlendTowardOppositeLuma(color, 90);
    SkColor back_color = color_utils::AlphaBlend(color, SK_ColorDKGRAY, 60);
    SkColor inactive_color = color_utils::AlphaBlend(color, SK_ColorBLACK, 100);
    theme_service->SetColor(ThemeProperties::COLOR_TOOLBAR, color);
    theme_service->SetColor(ThemeProperties::COLOR_BACKGROUND_TAB, back_color);
    theme_service->SetColor(ThemeProperties::COLOR_FRAME, back_color);
    theme_service->SetColor(ThemeProperties::COLOR_FRAME_INACTIVE, inactive_color);
    //theme_service->SetColor(ThemeProperties::COLOR_TOOLBAR_TOP_SEPARATOR, color);
    //theme_service->SetColor(ThemeProperties::COLOR_TOOLBAR_TOP_SEPARATOR_INACTIVE, color);
    if (tablist_model->active_index() == tab_index) {
      top_container()->SchedulePaint();
    }
  }
}

void DockWindow::ActiveTabChanged(ApplicationContents* old_contents,
                                  ApplicationContents* new_contents,
                                  int index,
                                  int reason) {
  // force the recalculation of colors according to the tab selected
  top_container()->SchedulePaint();
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, ui::AcceleratorProvider implementation:

bool DockWindow::GetAcceleratorForCommandId(
    int command_id,
    ui::Accelerator* accelerator) const {
  // Let's let the ToolbarView own the canonical implementation of this method.
  //return toolbar_->GetAcceleratorForCommandId(command_id, accelerator);
  return false;
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, views::WidgetDelegate implementation:

bool DockWindow::CanResize() const {
  return true;
}

bool DockWindow::CanMaximize() const {
  return true;
}

bool DockWindow::CanMinimize() const {
  return true;
}

bool DockWindow::CanActivate() const {
  //app_modal::AppModalDialogQueue* queue =
      //app_modal::AppModalDialogQueue::GetInstance();
  //if (!queue->active_dialog() || !queue->active_dialog()->native_dialog() ||
      //!queue->active_dialog()->native_dialog()->IsShowing()) {
    //return true;
  //}

//#if defined(USE_AURA) && defined(OS_CHROMEOS)
  // On Aura window manager controls all windows so settings focus via PostTask
  // will make only worse because posted task will keep trying to steal focus.
  //queue->ActivateModalDialog();
//#else
  // If another browser is app modal, flash and activate the modal browser. This
  // has to be done in a post task, otherwise if the user clicked on a window
  // that doesn't have the modal dialog the windows keep trying to get the focus
  // from each other on Windows. http://crbug.com/141650.
  //base::ThreadTaskRunnerHandle::Get()->PostTask(
  //    FROM_HERE, base::BindOnce(&DockWindow::ActivateAppModalDialog,
  //                              activate_modal_dialog_factory_.GetWeakPtr()));
//#endif
  return false;
}

base::string16 DockWindow::GetWindowTitle() const {
  //return dock_->GetWindowTitleForCurrentWindow(true /* include_app_name */);
  // TODO: fix
  std::string title = dock_->app_name();
  std::string page_name = dock_->page_name();
  if (!title.empty()) {
    title = base::ToUpperASCII(title[0]) + title.substr(1);
    if (!page_name.empty()) {
      title = title + " - " + base::ToUpperASCII(page_name[0]) + page_name.substr(1);
    }
  }
  return base::ASCIIToUTF16(title);
}

base::string16 DockWindow::GetAccessibleWindowTitle() const {
  //return GetAccessibleWindowTitleForChannelAndProfile(chrome::GetChannel(),
           //                                           dock_->profile());
  //return dock_->GetWindowTitleForCurrentWindow(true /* include_app_name */);
  //base::string16 title;
  //return l10n_util::GetStringFUTF16(IDS_ACCESSIBLE_BROWSER_WINDOW_TITLE_FORMAT, title);
  return base::ASCIIToUTF16(dock_->app_name());//"title");
}

// base::string16 DockWindow::GetAccessibleWindowTitleForChannelAndProfile(
//     version_info::Channel channel,
//     Profile* profile) const {
//   // Start with the tab title, which includes properties of the tab
//   // like playing audio or network error.
//   const bool include_app_name = false;
//   int active_index = dock_->tablist_model()->active_index();
//   base::string16 title;
//   if (active_index > -1)
//     title = GetAccessibleWindowLabel(include_app_name, active_index);
//   else
//     title = dock_->GetWindowTitleForCurrentWindow(include_app_name);

//   // Add the name of the browser, unless this is an app window.
//   if (!dock()->is_app()) {
//     int message_id;
//     switch (channel) {
//       case version_info::Channel::CANARY:
//         message_id = IDS_ACCESSIBLE_CANARY_BROWSER_WINDOW_TITLE_FORMAT;
//         break;
//       case version_info::Channel::DEV:
//         message_id = IDS_ACCESSIBLE_DEV_BROWSER_WINDOW_TITLE_FORMAT;
//         break;
//       case version_info::Channel::BETA:
//         message_id = IDS_ACCESSIBLE_BETA_BROWSER_WINDOW_TITLE_FORMAT;
//         break;
//       default:
//         // Stable or unknown.
//         message_id = IDS_ACCESSIBLE_BROWSER_WINDOW_TITLE_FORMAT;
//         break;
//     }
//     title = l10n_util::GetStringFUTF16(message_id, title);
//   }

//   // Finally annotate with the user - add Incognito if it's an incognito
//   // window, otherwise use the avatar name.
//   ProfileManager* profile_manager = g_dock_process->profile_manager();
//   if (profile->IsOffTheRecord()) {
//     title = l10n_util::GetStringFUTF16(
//         IDS_ACCESSIBLE_INCOGNITO_WINDOW_TITLE_FORMAT, title);
//   } else if (profile->GetWorkspaceType() == Profile::REGULAR_PROFILE &&
//              profile_manager->GetNumberOfProfiles() > 1) {
//     base::string16 profile_name =
//         profiles::GetAvatarNameForProfile(profile->GetPath());
//     if (!profile_name.empty()) {
//       title = l10n_util::GetStringFUTF16(
//           IDS_ACCESSIBLE_WINDOW_TITLE_WITH_PROFILE_FORMAT, title, profile_name);
//     }
//   }

//   return title;
// }

base::string16 DockWindow::GetAccessibleWindowLabel(bool include_app_name,
                                                  int index) const {
  // ChromeVox provides an invalid index on browser start up before
  // any tabs are created.
  if (index == -1)
    return base::string16();

      //dock_->GetWindowTitleForWindow(include_app_name, index);
  //return chrome::AssembleWindowAccessibilityLabel(
  //    window_title, tablist_->IsWindowCrashed(index),
      //tablist_->WindowHasNetworkError(index), tablist_->GetWindowAlertState(index));
  // TODO: fix
  return base::ASCIIToUTF16(dock_->app_name());
}

void DockWindow::NativeThemeUpdated(const ui::NativeTheme* theme) {
  // We don't handle theme updates in OnThemeChanged() as that function is
  // called while views are being iterated over. Please see
  // View::PropagateNativeThemeChanged() for details. The theme update
  // handling in UserChangedTheme() can cause views to be nuked or created
  // which is a bad thing during iteration.

  // Do not handle native theme changes before the browser view is initialized.
  //if (!initialized_)
//    return;
  // Don't infinitely recurse.
  //if (!handling_theme_changed_)
//    UserChangedTheme();
  //MaybeShowInvertBubbleView(this);
}

FullscreenControlHost* DockWindow::GetFullscreenControlHost() {
  if (!fullscreen_control_host_) {
    // This is a do-nothing view that controls the z-order of the fullscreen
    // control host. See DropdownBarHost::SetHostViewNative() for more details.
    auto fullscreen_exit_host_view = std::make_unique<views::View>();
    fullscreen_control_host_ = std::make_unique<FullscreenControlHost>(
        this, fullscreen_exit_host_view.get());
    AddChildView(fullscreen_exit_host_view.release());
  }

  return fullscreen_control_host_.get();
}

views::View* DockWindow::GetInitiallyFocusedView() {
  return contents_container_;//nullptr;
}

bool DockWindow::ShouldShowWindowTitle() const {
#if defined(OS_CHROMEOS)
  // For Chrome OS only, trusted windows (apps and settings) do not show a
  // title, crbug.com/119411. Child windows (i.e. popups) do show a title.
  if (dock_->is_trusted_source()) {
    return false;
  }
#endif  // OS_CHROMEOS

  //return dock_->SupportsWindowFeature(Dock::FEATURE_TITLEBAR);
  return true;
}

gfx::ImageSkia DockWindow::GetWindowAppIcon() {
  //extensions::HostedAppDockController* app_controller =
  //    dock()->hosted_app_controller();
  //return app_controller ? app_controller->GetWindowAppIcon() : GetWindowIcon();
  return GetWindowIcon();
}

gfx::ImageSkia DockWindow::GetWindowIcon() {
  // Use the default icon for devtools.
  //if (dock_->is_devtools())
//    return gfx::ImageSkia();

  // Hosted apps always show their app icon.
  //extensions::HostedAppDockController* app_controller =
      //dock()->hosted_app_controller();
  //if (app_controller)
//    return app_controller->GetWindowIcon();

  //if (dock_->is_app() || dock_->is_type_popup())
    return dock_->GetCurrentPageIcon().AsImageSkia();

//#if defined(OS_CHROMEOS)
//  if (dock_->is_type_tabbed()) {
//    ui::ResourceBundle& rb = ui::ResourceBundle::GetSharedInstance();
//    return rb.GetImageNamed(IDR_PRODUCT_LOGO_32).AsImageSkia();
//  }
//#endif

  //return gfx::ImageSkia();
}

bool DockWindow::ShouldShowWindowIcon() const {
  // Currently the icon and title are always shown together.
  return ShouldShowWindowTitle();
}

bool DockWindow::ExecuteWindowsCommand(int command_id) {
  // This function handles WM_SYSCOMMAND, WM_APPCOMMAND, and WM_COMMAND.
#if defined(OS_WIN)
  if (command_id == IDC_DEBUG_FRAME_TOGGLE)
    GetWidget()->DebugToggleFrameType();
#endif
  // Translate WM_APPCOMMAND command ids into a command id that the browser
  // knows how to handle.
  int command_id_from_app_command = GetCommandIDForAppCommandID(command_id);
  if (command_id_from_app_command != -1)
    command_id = command_id_from_app_command;

  return host::ExecuteCommand(dock_.get(), command_id);
}

std::string DockWindow::GetWindowName() const {
  return "Mumba";//host::GetWindowName(dock_.get());
}

void DockWindow::SaveWindowPlacement(const gfx::Rect& bounds,
                                      ui::WindowShowState show_state) {
  // If IsFullscreen() is true, we've just changed into fullscreen mode, and
  // we're catching the going-into-fullscreen sizing and positioning calls,
  // which we want to ignore.
  if (!IsFullscreen() && frame_->ShouldSaveWindowPlacement() &&
      host::ShouldSaveWindowPlacement(dock_.get())) {
    WidgetDelegate::SaveWindowPlacement(bounds, show_state);
    host::SaveWindowPlacement(dock_.get(), bounds, show_state);
  }
}

bool DockWindow::GetSavedWindowPlacement(
    const views::Widget* widget,
    gfx::Rect* bounds,
    ui::WindowShowState* show_state) const {
  host::GetSavedWindowBoundsAndShowState(dock_.get(), bounds, show_state);

  if (host::SavedBoundsAreContentBounds(dock_.get())) {
    // This is normal non-app popup window. The value passed in |bounds|
    // represents two pieces of information:
    // - the position of the window, in screen coordinates (outer position).
    // - the size of the content area (inner size).
    // We need to use these values to determine the appropriate size and
    // position of the resulting window.
    //if (IsToolbarVisible()) {
      // If we're showing the toolbar, we need to adjust |*bounds| to include
      // its desired height, since the toolbar is considered part of the
      // window's client area as far as GetWindowBoundsForClientBounds is
      // concerned...
//      bounds->set_height(
          //bounds->height() + toolbar_->GetPreferredSize().height());
    //}

    gfx::Rect window_rect = frame_->non_client_view()->
        GetWindowBoundsForClientBounds(*bounds);
    window_rect.set_origin(bounds->origin());

    // When we are given x/y coordinates of 0 on a created popup window,
    // assume none were given by the window.open() command.
    if (window_rect.x() == 0 && window_rect.y() == 0) {
      gfx::Size size = window_rect.size();
      window_rect.set_origin(WindowSizer::GetDefaultPopupOrigin(size));
    }

    *bounds = window_rect;
    *show_state = ui::SHOW_STATE_NORMAL;
  }

  // We return true because we can _always_ locate reasonable bounds using the
  // WindowSizer, and we don't want to trigger the Window's built-in "size to
  // default" handling because the browser window has no default preferred
  // size.
  return true;
}

views::View* DockWindow::GetContentsView() {
  return contents_container_;//contents_application_view_;
}

views::ClientView* DockWindow::CreateClientView(views::Widget* widget) {
  return this;
}

void DockWindow::OnWidgetDestroying(views::Widget* widget) {
  // Destroy any remaining ApplicationContents early on. Doing so may result in
  // calling back to one of the Views/LayoutManagers or supporting classes of
  // DockWindow. By destroying here we ensure all said classes are valid.
  std::vector<std::unique_ptr<ApplicationContents>> contents;
  while (dock()->tablist_model()->count())
    contents.push_back(dock()->tablist_model()->DetachApplicationContentsAt(0));
  // Note: The DockWindowTest tests rely on the contents being destroyed in the
  // order that they were present in the tab strip.
  for (auto& content : contents)
    content.reset();
}

void DockWindow::OnWidgetActivationChanged(views::Widget* widget,
                                            bool active) {
  if (dock_->window()) {
    if (active)
      DockList::SetLastActive(dock_.get());
    else
      DockList::NotifyDockNoLongerActive(dock_.get());
  }

  //if (!extension_keybinding_registry_ &&
      //GetFocusManager()) {  // focus manager can be null in tests.
    //extension_keybinding_registry_.reset(new ExtensionKeybindingRegistryViews(
        //dock_->profile(), GetFocusManager(),
        //extensions::ExtensionKeybindingRegistry::ALL_EXTENSIONS, this));
  //}

  //extensions::ExtensionCommandsGlobalRegistry* registry =
      //extensions::ExtensionCommandsGlobalRegistry::Get(dock_->profile());
  //if (active) {
//    registry->set_registry_for_active_window(
        //extension_keybinding_registry_.get());
  //} else if (registry->registry_for_active_window() ==
             //extension_keybinding_registry_.get()) {
    //registry->set_registry_for_active_window(nullptr);
  //}

  //immersive_mode_controller()->OnWidgetActivationChanged(widget, active);
}

void DockWindow::OnWindowBeginUserBoundsChange() {
  if (interactive_resize_)
    return;
  ApplicationContents* app_contents = GetActiveApplicationContents();
  if (!app_contents)
    return;
  interactive_resize_ = ResizeSession();
  interactive_resize_->begin_timestamp = base::TimeTicks::Now();
  app_contents->GetApplicationWindowHost()->NotifyMoveOrResizeStarted();
}

void DockWindow::OnWindowEndUserBoundsChange() {
  if (!interactive_resize_)
    return;
  auto now = base::TimeTicks::Now();
  DCHECK(!interactive_resize_->begin_timestamp.is_null());
  UMA_HISTOGRAM_TIMES("DockWindow.Resize.Duration",
                      now - interactive_resize_->begin_timestamp);
  UMA_HISTOGRAM_COUNTS_1000("DockWindow.Resize.StepCount",
                            interactive_resize_->step_count);
  interactive_resize_.reset();
}

void DockWindow::OnWidgetMove() {
  if (!initialized_) {
    // Creating the widget can trigger a move. Ignore it until we've initialized
    // things.
    return;
  }

  // Cancel any tablist animations, some of them may be invalidated by the
  // window being repositioned.
  // Comment out for one cycle to see if this fixes dist tests.
  // tablist_->DestroyDragController();

  // status_bubble_ may be null if this is invoked during construction.
  //if (status_bubble_.get())
  //  status_bubble_->Reposition();

  //BookmarkBubbleView::Hide();

  // Close the omnibox popup, if any.
  //LocationBarView* location_bar_view = GetLocationBarView();
  //if (location_bar_view)
//    location_bar_view->GetOmniboxView()->CloseOmniboxPopup();
}

views::Widget* DockWindow::GetWidget() {
  return View::GetWidget();
}

const views::Widget* DockWindow::GetWidget() const {
  return View::GetWidget();
}

void DockWindow::RevealTablistIfNeeded() {
  //if (!immersive_mode_controller_->IsEnabled())
  //  return;

  // std::unique_ptr<ImmersiveRevealedLock> revealer(
  //     immersive_mode_controller_->GetRevealedLock(
  //         ImmersiveModeController::ANIMATE_REVEAL_YES));
  // auto delete_revealer = base::BindOnce(
  //     [](std::unique_ptr<ImmersiveRevealedLock>) {}, std::move(revealer));
  // constexpr auto kDefaultDelay = base::TimeDelta::FromSeconds(1);
  // constexpr auto kZeroDelay = base::TimeDelta::FromSeconds(0);
  // base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
  //     FROM_HERE, std::move(delete_revealer),
  //     g_disable_revealer_delay_for_testing ? kZeroDelay : kDefaultDelay);
}

void DockWindow::GetAccessiblePanes(std::vector<views::View*>* panes) {
  // This should be in the order of pane traversal of the panes using F6
  // (Windows) or Ctrl+Back/Forward (Chrome OS).  If one of these is
  // invisible or has no focusable children, it will be automatically
  // skipped.
//  panes->push_back(toolbar_button_provider_->GetAsAccessiblePaneView());
  //if (bookmark_bar_view_.get())
//    panes->push_back(bookmark_bar_view_.get());
  //if (infobar_container_)
  //  panes->push_back(infobar_container_);
  //if (download_shelf_.get())
//    panes->push_back(download_shelf_.get());
  panes->push_back(contents_application_view_);
  if (devtools_web_view_->visible())
    panes->push_back(devtools_web_view_);
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, views::ClientView overrides:

bool DockWindow::CanClose() {
  // You cannot close a frame for which there is an active originating drag
  // session.
  if (tablist_ && !tablist_->IsTablistCloseable())
    return false;

  // Give beforeunload handlers the chance to cancel the close before we hide
  // the window below.
//  if (!dock_->ShouldCloseTab())
//    return false;

  //bool fast_tab_closing_enabled = false;
    //  base::CommandLine::ForCurrentProcess()->HasSwitch(
    //      switches::kEnableFastUnload);

  if (!dock_->tablist_model()->empty()) {
    // Window strip isn't empty.  Hide the frame (so it appears to have closed
    // immediately) and close all the tabs, allowing the renderers to shut
    // down. When the tab strip is empty we'll be called back again.
    frame_->Hide();
    dock_->OnWindowClosing();
    // Commented: the OnWindowClosing() already do this for us..
    //if (fast_tab_closing_enabled)
    //  dock_->tablist_model()->CloseAllTabs();
    return false;
  } //else if (fast_tab_closing_enabled &&
    //    !dock_->HasCompletedUnloadProcessing()) {
    // The browser needs to finish running unload handlers.
    // Hide the frame (so it appears to have closed immediately), and
    // the browser will call us back again when it is ready to close.
    //frame_->Hide();
    //return false;
  //}

  return true;
}

int DockWindow::NonClientHitTest(const gfx::Point& point) {
  return GetDockWindowLayout()->NonClientHitTest(point);
}

gfx::Size DockWindow::GetMinimumSize() const {
  return GetDockWindowLayout()->GetMinimumSize();
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, views::View overrides:

const char* DockWindow::GetClassName() const {
  return kViewClassName;
}

void DockWindow::Layout() {
  if (!initialized_) //|| in_process_fullscreen_)
    return;

  views::View::Layout();

  // TODO(jamescook): Why was this in the middle of layout code?
  //toolbar_->location_bar()->omnibox_view()->SetFocusBehavior(
      //IsToolbarVisible() ? FocusBehavior::ALWAYS : FocusBehavior::NEVER);
  frame()->GetFrameView()->UpdateMinimumSize();
}

void DockWindow::OnGestureEvent(ui::GestureEvent* event) {
  int command;
  if (GetGestureCommand(event, &command) &&
      host::IsCommandEnabled(dock(), command)) {
    host::ExecuteCommandWithDisposition(
        dock(), command, ui::DispositionFromEventFlags(event->flags()));
    return;
  }

  ClientView::OnGestureEvent(event);
}

void DockWindow::ViewHierarchyChanged(
    const ViewHierarchyChangedDetails& details) {
  if (details.child != this)
    return;

  // On removal, this class may not have a widget anymore, so go to the parent.
  auto* widget = details.is_add ? GetWidget() : details.parent->GetWidget();
  if (!widget)
    return;

  bool init = !initialized_ && details.is_add;
  if (init) {
    InitViews();
    initialized_ = true;
  }
}

void DockWindow::PaintChildren(const views::PaintInfo& paint_info) {
  views::ClientView::PaintChildren(paint_info);
  // Don't reset the instance before it had a chance to get compositor callback.
 // if (!histogram_helper_) {
 //   histogram_helper_ = DockWindowHistogramHelper::
 //       MaybeRecordValueAndCreateInstanceOnDockPaint(
 //           GetWidget()->GetCompositor());
 // }
}

void DockWindow::OnBoundsChanged(const gfx::Rect& previous_bounds) {
  if (!interactive_resize_)
    return;
  auto now = base::TimeTicks::Now();
  if (!interactive_resize_->last_resize_timestamp.is_null()) {
    const auto& current_size = size();
    // If size doesn't change, then do not update the timestamp.
    if (current_size == previous_bounds.size())
      return;
    UMA_HISTOGRAM_CUSTOM_TIMES("DockWindow.Resize.StepInterval",
                               now - interactive_resize_->last_resize_timestamp,
                               base::TimeDelta::FromMilliseconds(1),
                               base::TimeDelta::FromSeconds(1), 50);
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "DockWindow.Resize.StepBoundsChange.Width",
        std::abs(previous_bounds.size().width() - current_size.width()),
        1 /* min */, 300 /* max */, 100 /* buckets */);
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "DockWindow.Resize.StepBoundsChange.Height",
        std::abs(previous_bounds.size().height() - current_size.height()),
        1 /* min */, 300 /* max */, 100 /* buckets */);
  }
  ++interactive_resize_->step_count;
  interactive_resize_->last_resize_timestamp = now;
}

void DockWindow::ChildPreferredSizeChanged(View* child) {
  Layout();
}

void DockWindow::GetAccessibleNodeData(ui::AXNodeData* node_data) {
  node_data->role = ax::mojom::Role::kClient;
}

void DockWindow::OnThemeChanged() {
  //if (!IsRegularOrGuestSession()) {
    // When the theme changes, the native theme may also change (in incognito,
    // the usage of dark or normal hinges on the browser theme), so we have to
    // propagate both kinds of change.
//    base::AutoReset<bool> reset(&handling_theme_changed_, true);
//#if defined(USE_AURA)
    //ui::NativeThemeDarkAura::instance()->NotifyObservers();
//#endif
    //ui::NativeTheme::GetInstanceForNativeUi()->NotifyObservers();
  //}

  views::View::OnThemeChanged();
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, ui::AcceleratorTarget overrides:

bool DockWindow::AcceleratorPressed(const ui::Accelerator& accelerator) {
  int command_id;
  // Though AcceleratorManager should not send unknown |accelerator| to us, it's
  // still possible the command cannot be executed now.
  if (!FindCommandIdForAccelerator(accelerator, &command_id))
    return false;

  UpdateAcceleratorMetrics(accelerator, command_id);
  return host::ExecuteCommand(dock_.get(), command_id);
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, infobars::InfoBarContainer::Delegate overrides:

//void DockWindow::InfoBarContainerStateChanged(bool is_animating) {
//  ToolbarSizeChanged(is_animating);
//}

void DockWindow::InitViews() {
  GetWidget()->AddObserver(this);

  // Stow a pointer to this object onto the window handle so that we can get at
  // it later when all we have is a native view.
  GetWidget()->SetNativeWindowProperty(kDockWindowKey, this);

  // Stow a pointer to the browser's profile onto the window handle so that we
  // can get it later when all we have is a native view.
  GetWidget()->SetNativeWindowProperty("workspace",//Profile::kProfileKey,
                                       dock_->workspace().get());

//#if defined(USE_AURA)
  // Stow a pointer to the browser's profile onto the window handle so
  // that windows will be styled with the appropriate NativeTheme.
//  SetThemeProfileForWindow(GetNativeWindow(), dock_->workspace());
//#endif

  LoadAccelerators();

  contents_application_view_ = new ApplicationViewImpl();
  contents_application_view_->set_id(VIEW_ID_TAB_CONTAINER);
  
  devtools_web_view_ = new ApplicationViewImpl();//new views::WebView(dock_->profile());
  devtools_web_view_->set_id(VIEW_ID_DEV_TOOLS_DOCKED);
  
  //contents_application_view_->SetEmbedFullscreenWindowMode(true);
  //contents_application_view_->SetEmbedFullscreenWindowMode(false);
  
  app_contents_close_handler_.reset(
      new ApplicationContentsCloseHandler(contents_application_view_));

  
  contents_container_ = new views::View();
  contents_container_->SetBackground(views::CreateSolidBackground(
      GetThemeProvider()->GetColor(ThemeProperties::COLOR_CONTROL_BACKGROUND)));
  contents_container_->AddChildView(contents_application_view_);
  //contents_container_->AddChildView(devtools_web_view_);
  contents_container_->SetLayoutManager(std::make_unique<ContentsLayoutManager>(
     devtools_web_view_, contents_application_view_));
  AddChildView(contents_container_);
  set_contents_view(contents_container_);

  // Top container holds tab strip and toolbar and lives at the front of the
  // view hierarchy.
  top_container_ = new TopContainerView(this);
  AddChildView(top_container_);

  // Tablist takes ownership of the controller.
  DockTablistController* tablist_controller =
      new DockTablistController(dock_->tablist_model(), this);
  tablist_ =
      new Tablist(std::unique_ptr<TablistController>(tablist_controller));
  top_container_->AddChildView(tablist_);  // Takes ownership.
  tablist_controller->InitFromModel(tablist_);

  //toolbar_ = new ToolbarView(dock_.get());
  //top_container_->AddChildView(toolbar_);
  //toolbar_->Init();

  // This browser view may already have a custom button provider set (e.g the
  // hosted app frame).
  //if (!toolbar_button_provider_)
//    SetToolbarButtonProvider(toolbar_);

  //infobar_container_ = new InfoBarContainerView(this);
  //AddChildView(infobar_container_);

  //InitStatusBubble();

  // Create do-nothing view for the sake of controlling the z-order of the find
  // bar widget.
  //find_bar_host_view_ = new View();
  //AddChildView(find_bar_host_view_);

  //immersive_mode_controller_->Init(this);

  auto dock_window_layout = std::make_unique<DockWindowLayout>();
  dock_window_layout->Init(new DockWindowLayoutDelegateImpl(this),
                            dock(),
                            this,
                            top_container_,
                            tablist_,
    //                        toolbar_,
      //                      infobar_container_,
                            contents_container_,
                            //contents_application_view_,
                            GetContentsLayoutManager());//,
        //                    immersive_mode_controller_.get());
  SetLayoutManager(std::move(dock_window_layout));

#if defined(OS_WIN)
  // Create a custom JumpList and add it to an observer of WindowRestoreService
  // so we can update the custom JumpList when a tab is added or removed.
  if (JumpList::Enabled()) {
    load_complete_listener_.reset(new LoadCompleteListener(this));
  }
#endif

  frame_->OnDockWindowInitViewsComplete();
  frame_->GetFrameView()->UpdateMinimumSize();
}

void DockWindow::LoadingAnimationCallback() {
  if (dock_->is_type_tabbed()) {
    // Loading animations are shown in the tab for tabbed windows.  We check the
    // browser type instead of calling IsTablistVisible() because the latter
    // will return false for fullscreen windows, but we still need to update
    // their animations (so that when they come out of fullscreen mode they'll
    // be correct).
    tablist_->UpdateLoadingAnimations();
  } else if (ShouldShowWindowIcon()) {
    // ... or in the window icon area for popups and app windows.
    ApplicationContents* app_contents =
        dock_->tablist_model()->GetActiveApplicationContents();
    // GetActiveApplicationContents can return null for example under Purify when
    // the animations are running slowly and this function is called on a timer
    // through LoadingAnimationCallback.
    frame_->UpdateThrobber(app_contents && app_contents->IsLoading());
  }
}

void DockWindow::OnLoadCompleted() {
#if defined(OS_WIN)
  // Ensure that this browser's Profile has a JumpList so that the JumpList is
  // kept up to date.
  JumpListFactory::Get();//ForProfile(dock_->profile());
#endif
}

DockWindowLayout* DockWindow::GetDockWindowLayout() const {
  return static_cast<DockWindowLayout*>(GetLayoutManager());
}

ContentsLayoutManager* DockWindow::GetContentsLayoutManager() const {
  return static_cast<ContentsLayoutManager*>(
      contents_container_->GetLayoutManager());
}

//views::FillLayout* DockWindow::GetContentsLayoutManager() const {
//  return static_cast<views::FillLayout*>(
//      contents_application_view_->GetLayoutManager());
//}

// bool DockWindow::MaybeShowBookmarkBar(ApplicationContents* contents) {
//   const bool show_bookmark_bar =
//       contents && dock_->SupportsWindowFeature(Dock::FEATURE_BOOKMARKBAR);
//   if (!show_bookmark_bar && !bookmark_bar_view_.get())
//     return false;
//   if (!bookmark_bar_view_.get()) {
//     bookmark_bar_view_.reset(new BookmarkBarView(dock_.get(), this));
//     bookmark_bar_view_->set_owned_by_client();
//     bookmark_bar_view_->SetBackground(
//         std::make_unique<BookmarkBarViewBackground>(this,
//                                                     bookmark_bar_view_.get()));
//     bookmark_bar_view_->SetBookmarkBarState(
//         dock_->bookmark_bar_state(),
//         BookmarkBar::DONT_ANIMATE_STATE_CHANGE);
//     GetDockWindowLayout()->set_bookmark_bar(bookmark_bar_view_.get());
//   }
//   // Don't change the visibility of the BookmarkBarView. DockWindowLayout
//   // handles it.
//   bookmark_bar_view_->SetPageNavigator(GetActiveApplicationContents());

//   // Update parenting for the bookmark bar. This may detach it from all views.
//   bool needs_layout = false;
//   views::View* new_parent = nullptr;
//   if (show_bookmark_bar) {
//     if (bookmark_bar_view_->IsDetached())
//       new_parent = this;
//     else
//       new_parent = top_container_;
//   }
//   if (new_parent != bookmark_bar_view_->parent()) {
//     SetBookmarkBarParent(new_parent);
//     needs_layout = true;
//   }

//   // Check for updates to the desired size.
//   if (bookmark_bar_view_->GetPreferredSize().height() !=
//       bookmark_bar_view_->height())
//     needs_layout = true;

//   return needs_layout;
// }

// void DockWindow::SetBookmarkBarParent(views::View* new_parent) {
//   // Because children are drawn in order, the child order also affects z-order:
//   // earlier children will appear "below" later ones.  This is important for ink
//   // drops, which are drawn with the z-order of the view that parents them.  Ink
//   // drops in the toolbar can spread beyond the toolbar bounds, so if the
//   // bookmark bar is attached, we want it to be below the toolbar so the toolbar
//   // ink drops draw atop it.  This doesn't cause a problem for interactions with
//   // the bookmark bar, since it does not host any ink drops that spread beyond
//   // its bounds.  If it did, we would need to change how ink drops are drawn.
//   // TODO(bruthig): Consider a more general mechanism for manipulating the
//   // z-order of the ink drops.

//   if (new_parent == this) {
//     // BookmarkBarView is detached.
//     const int top_container_index = GetIndexOf(top_container_);
//     DCHECK_GE(top_container_index, 0);
//     // |top_container_| contains the toolbar, so putting the bookmark bar ahead
//     // of it will ensure it's drawn before the toolbar.
//     AddChildViewAt(bookmark_bar_view_.get(), top_container_index);
//   } else if (new_parent == top_container_) {
//     // BookmarkBarView is attached.

//     // The toolbar is a child of |top_container_|, so making the bookmark bar
//     // the first child ensures it's drawn before the toolbar.
//     new_parent->AddChildViewAt(bookmark_bar_view_.get(), 0);
//   } else {
//     DCHECK(!new_parent);
//     // Bookmark bar is being detached from all views because it is hidden.
//     bookmark_bar_view_->parent()->RemoveChildView(bookmark_bar_view_.get());
//   }
// }

// bool DockWindow::MaybeShowInfoBar(ApplicationContents* contents) {
//   // TODO(beng): Remove this function once the interface between
//   //             InfoBarContainer, DownloadShelfView and ApplicationContents and this
//   //             view is sorted out.
//   return true;
// }

void DockWindow::UpdateDevToolsForContents(ApplicationContents* app_contents, bool update_devtools_app_contents) {
  DevToolsWindow::GetInTabApplicationContents(app_contents, base::BindOnce(
    &DockWindow::OnDevToolsContentsAvailable, base::Unretained(this)));
}

void DockWindow::OnDevToolsContentsAvailable(ApplicationContents* devtools, DevToolsContentsResizingStrategy strategy, bool update_devtools_app_contents) {
  DLOG(INFO) << "DockWindow::OnDevToolsContentsAvailable: devtools(ApplicationContents) => " << devtools;
  if (!devtools_web_view_->application_contents() && devtools &&
      !devtools_focus_tracker_.get()) {
    // Install devtools focus tracker when dev tools window is shown for the
    // first time.
    devtools_focus_tracker_.reset(
        new views::ExternalFocusTracker(devtools_web_view_,
                                        GetFocusManager()));
  }

  // Restore focus to the last focused view when hiding devtools window.
  if (devtools_web_view_->application_contents() && !devtools &&
      devtools_focus_tracker_.get()) {
    devtools_focus_tracker_->FocusLastFocusedExternalView();
    devtools_focus_tracker_.reset();
  }

  // Replace devtools ApplicationContents.
  if (devtools_web_view_->application_contents() != devtools &&
      update_devtools_app_contents) {
    DLOG(INFO) << "DockWindow::UpdateDevToolsForContents: devtools_web_view_->SetApplicationContents(devtools: " << devtools << ")";
    devtools_web_view_->SetApplicationContents(devtools);
  }

  if (devtools) {
    DLOG(INFO) << "DockWindow::UpdateDevToolsForContents: devtools_web_view_->SetVisible(true)";
    devtools_web_view_->SetVisible(true);
    GetContentsLayoutManager()->SetContentsResizingStrategy(strategy);
  } else {
    DLOG(INFO) << "DockWindow::UpdateDevToolsForContents: devtools_web_view_->SetVisible(false)";
    devtools_web_view_->SetVisible(false);
    GetContentsLayoutManager()->SetContentsResizingStrategy(
        DevToolsContentsResizingStrategy());
  }
  contents_container_->Layout();

  if (devtools) {
    // When strategy.hide_inspected_contents() returns true, we are hiding
    // contents_application_view_ behind the devtools_web_view_. Otherwise,
    // contents_application_view_ should be right above the devtools_web_view_.
    int devtools_index = contents_container_->GetIndexOf(devtools_web_view_);
    int contents_index = contents_container_->GetIndexOf(contents_application_view_);
    bool devtools_is_on_top = devtools_index > contents_index;
    if (strategy.hide_inspected_contents() != devtools_is_on_top)
      contents_container_->ReorderChildView(contents_application_view_, devtools_index);
  }
}

void DockWindow::UpdateUIForContents(ApplicationContents* contents) {
  //bool needs_layout = true;//MaybeShowBookmarkBar(contents);
  bool needs_layout = false;//MaybeShowBookmarkBar(contents);
  // TODO(jamescook): This function always returns true. Remove it and figure
  // out when layout is actually required.
  //needs_layout |= MaybeShowInfoBar(contents);
  if (needs_layout)
    Layout();
}

void DockWindow::ProcessFullscreen(bool fullscreen,
                                    const GURL& url,
                                    ExclusiveAccessBubbleType bubble_type) {
  if (in_process_fullscreen_)
    return;
  in_process_fullscreen_ = true;

  // Reduce jankiness during the following position changes by:
  //   * Hiding the window until it's in the final position
  //   * Ignoring all intervening Layout() calls, which resize the webpage and
  //     thus are slow and look ugly (enforced via |in_process_fullscreen_|).
  if (fullscreen) {
    // Move focus out of the location bar if necessary.
    views::FocusManager* focus_manager = GetFocusManager();
    DCHECK(focus_manager);
    // Look for focus in the location bar itself or any child view.
    //if (GetLocationBarView()->Contains(focus_manager->GetFocusedView()))
     // focus_manager->ClearFocus();

#if defined(USE_AURA)
    if (FullscreenControlHost::IsFullscreenExitUIEnabled()) {
      frame_->GetNativeView()->AddPreTargetHandler(
          GetFullscreenControlHost(), ui::EventTarget::Priority::kSystem);
    }
#endif
  } else {
    // Hide the fullscreen bubble as soon as possible, since the mode toggle can
    // take enough time for the user to notice.
    exclusive_access_bubble_.reset();

    if (fullscreen_control_host_) {
      fullscreen_control_host_->Hide(false);
#if defined(USE_AURA)
      auto* native_view = frame_->GetNativeView();
      if (native_view)
        native_view->RemovePreTargetHandler(fullscreen_control_host_.get());
#endif
    }
  }

  // Toggle fullscreen mode.
  frame_->SetFullscreen(fullscreen);

  // Enable immersive before the browser refreshes its list of enabled commands.
  //const bool should_stay_in_immersive =
      //!fullscreen &&
      //immersive_mode_controller_->ShouldStayImmersiveAfterExitingFullscreen();
  //if (ShouldUseImmersiveFullscreenForUrl(url) && !should_stay_in_immersive)
//    immersive_mode_controller_->SetEnabled(fullscreen);

  dock_->WindowFullscreenStateWillChange();
  dock_->WindowFullscreenStateChanged();

  if (fullscreen) { //&& !chrome::IsRunningInAppMode()) {
    UpdateExclusiveAccessExitBubbleContent(url, bubble_type,
                                           ExclusiveAccessBubbleHideCallback());
  }

  // Undo our anti-jankiness hacks and force a re-layout.
  in_process_fullscreen_ = false;
  //ToolbarSizeChanged(false);

  //ApplicationContents* contents = dock_->tablist_model()->GetActiveApplicationContents();
  //if (contents && PermissionRequestManager::FromApplicationContents(contents))
//    PermissionRequestManager::FromApplicationContents(contents)->UpdateAnchorPosition();
}

//bool DockWindow::ShouldUseImmersiveFullscreenForUrl(const GURL& url) const {
//#if defined(OS_CHROMEOS)
  // Kiosk mode needs the whole screen.
//  if (base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kKioskMode))
    //return false;

  // In Public Session, always use immersive fullscreen.
  //if (profiles::IsPublicSession())
//    return true;

//  return url.is_empty();
//#else
  // No immersive except in Chrome OS.
//  return false;
//#endif
//}

void DockWindow::LoadAccelerators() {
  views::FocusManager* focus_manager = GetFocusManager();
  DCHECK(focus_manager);

  // Let's fill our own accelerator table.
  //const bool is_app_mode = host::IsRunningInForcedAppMode();
  const std::vector<AcceleratorMapping> accelerator_list(GetAcceleratorList());
  for (const auto& entry : accelerator_list) {
    // In app mode, only allow accelerators of white listed commands to pass
    // through.
    //if (is_app_mode && !host::IsCommandAllowedInAppMode(entry.command_id))
//      continue;

    ui::Accelerator accelerator(entry.keycode, entry.modifiers);
    accelerator_table_[accelerator] = entry.command_id;

    // Also register with the focus manager.
    focus_manager->RegisterAccelerator(
        accelerator, ui::AcceleratorManager::kNormalPriority, this);
  }
}

int DockWindow::GetCommandIDForAppCommandID(int app_command_id) const {
#if defined(OS_WIN)
  switch (app_command_id) {
    // NOTE: The order here matches the APPCOMMAND declaration order in the
    // Windows headers.
    case APPCOMMAND_BROWSER_BACKWARD: return IDC_BACK;
    case APPCOMMAND_BROWSER_FORWARD:  return IDC_FORWARD;
    case APPCOMMAND_BROWSER_REFRESH:  return IDC_RELOAD;
    case APPCOMMAND_BROWSER_HOME:     return IDC_HOME;
    case APPCOMMAND_BROWSER_STOP:     return IDC_STOP;
    case APPCOMMAND_BROWSER_SEARCH:   return IDC_FOCUS_SEARCH;
    case APPCOMMAND_HELP:             return IDC_HELP_PAGE_VIA_KEYBOARD;
    case APPCOMMAND_NEW:              return IDC_NEW_TAB;
    case APPCOMMAND_OPEN:             return IDC_OPEN_FILE;
    case APPCOMMAND_CLOSE:            return IDC_CLOSE_TAB;
    case APPCOMMAND_SAVE:             return IDC_SAVE_PAGE;
    case APPCOMMAND_PRINT:            return IDC_PRINT;
    case APPCOMMAND_COPY:             return IDC_COPY;
    case APPCOMMAND_CUT:              return IDC_CUT;
    case APPCOMMAND_PASTE:            return IDC_PASTE;

      // TODO(pkasting): http://b/1113069 Handle these.
    case APPCOMMAND_UNDO:
    case APPCOMMAND_REDO:
    case APPCOMMAND_SPELL_CHECK:
    default:                          return -1;
  }
#else
  // App commands are Windows-specific so there's nothing to do here.
  return -1;
#endif
}

void DockWindow::UpdateAcceleratorMetrics(const ui::Accelerator& accelerator,
                                           int command_id) {
  //const ui::KeyboardCode key_code = accelerator.key_code();
  //if (command_id == IDC_HELP_PAGE_VIA_KEYBOARD && key_code == ui::VKEY_F1)
//    base::RecordAction(UserMetricsAction("ShowHelpTabViaF1"));

  //if (command_id == IDC_BOOKMARK_PAGE)
  //  UMA_HISTOGRAM_ENUMERATION("Bookmarks.EntryPoint",
   //                           BOOKMARK_ENTRY_POINT_ACCELERATOR,
    //                          BOOKMARK_ENTRY_POINT_LIMIT);

#if defined(OS_CHROMEOS)
  // Collect information about the relative popularity of various accelerators
  // on Chrome OS.
  switch (command_id) {
    case IDC_BACK:
      if (key_code == ui::VKEY_BROWSER_BACK)
        base::RecordAction(UserMetricsAction("Accel_Back_F1"));
      else if (key_code == ui::VKEY_LEFT)
        base::RecordAction(UserMetricsAction("Accel_Back_Left"));
      break;
    case IDC_FORWARD:
      if (key_code == ui::VKEY_BROWSER_FORWARD)
        base::RecordAction(UserMetricsAction("Accel_Forward_F2"));
      else if (key_code == ui::VKEY_RIGHT)
        base::RecordAction(UserMetricsAction("Accel_Forward_Right"));
      break;
    //case IDC_RELOAD:
    //case IDC_RELOAD_BYPASSING_CACHE:
//      if (key_code == ui::VKEY_R)
        //base::RecordAction(UserMetricsAction("Accel_Reload_R"));
      //else if (key_code == ui::VKEY_BROWSER_REFRESH)
//        base::RecordAction(UserMetricsAction("Accel_Reload_F3"));
  //    break;
    //case IDC_FOCUS_LOCATION:
//      if (key_code == ui::VKEY_D)
        //base::RecordAction(UserMetricsAction("Accel_FocusLocation_D"));
      //else if (key_code == ui::VKEY_L)
//        base::RecordAction(UserMetricsAction("Accel_FocusLocation_L"));
  //    break;
  //  case IDC_FOCUS_SEARCH:
    //  if (key_code == ui::VKEY_E)
      //  base::RecordAction(UserMetricsAction("Accel_FocusSearch_E"));
      //else if (key_code == ui::VKEY_K)
//        base::RecordAction(UserMetricsAction("Accel_FocusSearch_K"));
  //    break;
    default:
      // Do nothing.
      break;
  }
#endif
}

// void DockWindow::ShowAvatarBubbleFromAvatarButton(
//     AvatarBubbleMode mode,
//     const signin::ManageAccountsParams& manage_accounts_params,
//     signin_metrics::AccessPoint access_point,
//     bool focus_first_profile_button) {
// #if !defined(OS_CHROMEOS)
//   views::Button* avatar_button = toolbar_->avatar_button();
//   if (!avatar_button)
//     avatar_button = frame_->GetNewAvatarMenuButton();
//   // Do not show avatar bubble if there is no avatar menu button.
//   if (!avatar_button)
//     return;

//   profiles::BubbleViewMode bubble_view_mode;
//   profiles::BubbleViewModeFromAvatarBubbleMode(mode, &bubble_view_mode);
//   if (SigninViewController::ShouldShowSigninForMode(bubble_view_mode)) {
//     dock_->signin_view_controller()->ShowSignin(
//         bubble_view_mode, dock_.get(), access_point);
//   } else {
//     ProfileChooserView::ShowBubble(
//         bubble_view_mode, manage_accounts_params, access_point, avatar_button,
//         nullptr, gfx::Rect(), dock(), focus_first_profile_button);
//     ProfileMetrics::LogProfileOpenMethod(ProfileMetrics::ICON_AVATAR_BUBBLE);
//   }
// #else
//   NOTREACHED();
// #endif
// }

int DockWindow::GetRenderViewHeightInsetWithDetachedBookmarkBar() {
  //if (dock_->bookmark_bar_state() != BookmarkBar::DETACHED ||
      //!bookmark_bar_view_ || !bookmark_bar_view_->IsDetached()) {
    return 0;
  //}
  // Don't use bookmark_bar_view_->height() which won't be the final height if
  // the bookmark bar is animating.
  //return GetLayoutConstant(BOOKMARK_BAR_NTP_HEIGHT);
}

// void DockWindow::ExecuteExtensionCommand(
//     const extensions::Extension* extension,
//     const extensions::Command& command) {
//   extension_keybinding_registry_->ExecuteCommand(extension->id(),
//                                                  command.accelerator());
// }

ExclusiveAccessContext* DockWindow::GetExclusiveAccessContext() {
  return this;
}

// void DockWindow::ShowImeWarningBubble(
//     const extensions::Extension* extension,
//     const base::Callback<void(ImeWarningBubblePermissionStatus status)>&
//         callback) {
//   ImeWarningBubbleView::ShowBubble(extension, this, callback);
// }

scoped_refptr<Workspace> DockWindow::GetWorkspace() const {
  return dock_->workspace();  
}

std::string DockWindow::GetDesktopWorkspace() const {
  return frame_->GetWorkspace();
}

bool DockWindow::IsVisibleOnAllDesktopWorkspaces() const {
  return frame_->IsVisibleOnAllWorkspaces();
}

bool DockWindow::DoCutCopyPasteForApplicationContents(
    ApplicationContents* contents,
    void (ApplicationContents::*method)()) {
  // It's possible for a non-null ApplicationContents to have a null RWHV if it's
  // crashed or otherwise been killed.
  ApplicationWindowHostView* rwhv = contents->GetApplicationWindowHostView();
  if (!rwhv || !rwhv->HasFocus())
    return false;
  // Calling |method| rather than using a fake key event is important since a
  // fake event might be consumed by the web content.
  (contents->*method)();
  return true;
}

// void DockWindow::ActivateAppModalDialog() const {
//   // If another browser is app modal, flash and activate the modal browser.
//   app_modal::JavaScriptAppModalDialog* active_dialog =
//       app_modal::AppModalDialogQueue::GetInstance()->active_dialog();
//   if (!active_dialog)
//     return;

//   Dock* modal_browser =
//       chrome::FindDockWithApplicationContents(active_dialog->app_contents());
//   if (modal_browser && (dock_.get() != modal_browser)) {
//     modal_browser->window()->FlashFrame(true);
//     modal_browser->window()->Activate();
//   }

//   app_modal::AppModalDialogQueue::GetInstance()->ActivateModalDialog();
// }

bool DockWindow::FindCommandIdForAccelerator(
    const ui::Accelerator& accelerator,
    int* command_id) const {
  std::map<ui::Accelerator, int>::const_iterator iter =
      accelerator_table_.find(accelerator);
  if (iter == accelerator_table_.end())
    return false;

  *command_id = iter->second;
  //if (accelerator.IsRepeat() && !IsCommandRepeatable(*command_id))
  //  return false;

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// DockWindow, ExclusiveAccessContext implementation:
scoped_refptr<Workspace> DockWindow::GetWorkspace() {
  return dock_->workspace();
}

ApplicationContents* DockWindow::GetActiveApplicationContents() {
  return dock_->tablist_model()->GetActiveApplicationContents();
}

// void DockWindow::UnhideDownloadShelf() {
//   if (download_shelf_)
//     download_shelf_->Unhide();
// }

// void DockWindow::HideDownloadShelf() {
//   if (download_shelf_)
//     download_shelf_->Hide();

//   StatusBubble* status_bubble = GetStatusBubble();
//   if (status_bubble)
//     status_bubble->Hide();
// }

// ///////////////////////////////////////////////////////////////////////////////
// // DockWindow, ExclusiveAccessBubbleViewsContext implementation:
ExclusiveAccessManager* DockWindow::GetExclusiveAccessManager() {
  return dock_->exclusive_access_manager();
}

views::Widget* DockWindow::GetBubbleAssociatedWidget() {
  return GetWidget();
}

ui::AcceleratorProvider* DockWindow::GetAcceleratorProvider() {
  return this;
}

gfx::NativeView DockWindow::GetBubbleParentView() const {
  return GetWidget()->GetNativeView();
}

gfx::Point DockWindow::GetCursorPointInParent() const {
  gfx::Point cursor_pos = display::Screen::GetScreen()->GetCursorScreenPoint();
  views::View::ConvertPointFromScreen(GetWidget()->GetRootView(), &cursor_pos);
  return cursor_pos;
}

gfx::Rect DockWindow::GetClientAreaBoundsInScreen() const {
  return GetWidget()->GetClientAreaBoundsInScreen();
}

//bool DockWindow::IsImmersiveModeEnabled() const {
//  return immersive_mode_controller()->IsEnabled();
//}

gfx::Rect DockWindow::GetTopContainerBoundsInScreen() {
  gfx::Rect bounds = top_container_->GetBoundsInScreen();
  return bounds;
}

void DockWindow::DestroyAnyExclusiveAccessBubble() {
  exclusive_access_bubble_.reset();
}

bool DockWindow::CanTriggerOnMouse() const {
  //return !IsImmersiveModeEnabled();
  return true;
}

//extensions::ActiveTabPermissionGranter*
//DockWindow::GetActiveTabPermissionGranter() {
//  ApplicationContents* app_contents = GetActiveApplicationContents();
//  if (!app_contents)
    //return nullptr;
  //return extensions::TabHelper::FromApplicationContents(app_contents)
  //    ->active_tab_permission_granter();
//}

}