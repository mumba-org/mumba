// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_AURA_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_AURA_H_

#include <memory>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "core/host/loader/global_routing_id.h"
#include "core/host/application/overscroll_controller_delegate.h"
#include "core/host/application/application_window_host_delegate_view.h"
#include "core/host/application/application_contents_view.h"
//#include "core/common/buildflags.h"
#include "core/shared/common/content_export.h"
#include "ui/aura/client/drag_drop_delegate.h"
#include "ui/aura/window.h"
#include "ui/aura/window_delegate.h"

namespace ui {
class DropTargetEvent;
class TouchSelectionController;
}

namespace host {
class GestureNavSimple;
class OverscrollNavigationOverlay;
class ApplicationWindowHost;
class ApplicationWindowHostViewAura;
class TouchSelectionControllerClientAura;
class ApplicationContentsViewDelegate;
class ApplicationContents;
class ApplicationDragDestDelegate;

class CONTENT_EXPORT ApplicationContentsViewAura
    : public ApplicationContentsView,
      public ApplicationWindowHostDelegateView,
      public OverscrollControllerDelegate,
      public aura::WindowDelegate,
      public aura::client::DragDropDelegate {
 public:
  ApplicationContentsViewAura(ApplicationContents* app_contents,
                              ApplicationContentsViewDelegate* delegate);

  // Allow the ApplicationContentsViewDelegate to be set explicitly.
  void SetDelegateForTesting(ApplicationContentsViewDelegate* delegate);

  // Set a flag to pass nullptr as the parent_view argument to
  // ApplicationWindowHostViewAura::InitAsChild().
  //void set_init_rwhv_with_null_parent_for_testing(bool set) {
  //  init_rwhv_with_null_parent_for_testing_ = set;
  //}

  using ApplicationWindowHostViewCreateFunction =
      ApplicationWindowHostViewAura* (*)(ApplicationWindowHost*, bool);

  // Used to override the creation of ApplicationWindowHostViews in tests.
  static void InstallCreateHookForTests(
      ApplicationWindowHostViewCreateFunction create_application_window_host_view);

 private:
  class WindowObserver;

  ~ApplicationContentsViewAura() override;

  void SizeChangedCommon(const gfx::Size& size);

  void EndDrag(ApplicationWindowHost* source_rwh, blink::WebDragOperationsMask ops);

  void InstallOverscrollControllerDelegate(ApplicationWindowHostViewAura* view);

  // Sets up the content window in preparation for starting an overscroll
  // gesture.
  void PrepareContentWindowForOverscroll();

  // Completes the navigation in response to a completed overscroll gesture.
  // The navigation happens after an animation (either the overlay window
  // animates in, or the content window animates out).
  void CompleteOverscrollNavigation(OverscrollMode mode);

  ui::TouchSelectionController* GetSelectionController() const;
  TouchSelectionControllerClientAura* GetSelectionControllerClient() const;

  // Returns GetNativeView unless overridden for testing.
  gfx::NativeView GetApplicationWindowHostViewParent() const;

  // Returns whether |target_rwh| is a valid ApplicationWindowHost to be dragging
  // over. This enforces that same-page, cross-site drags are not allowed. See
  // crbug.com/666858.
  bool IsValidDragTarget(ApplicationWindowHost* target_rwh) const;

  // Called from CreateView() to create |window_|.
  void CreateAuraWindow(aura::Window* context);

  // Overridden from ApplicationContentsView:
  gfx::NativeView GetNativeView() const override;
  gfx::NativeView GetContentNativeView() const override;
  gfx::NativeWindow GetTopLevelNativeWindow() const override;
  void GetContainerBounds(gfx::Rect* out) const override;
  void SizeContents(const gfx::Size& size) override;
  void Focus() override;
  void SetInitialFocus() override;
  void StoreFocus() override;
  void RestoreFocus() override;
  void FocusThroughWindowTraversal(bool reverse) override;
  common::DropData* GetDropData() const override;
  gfx::Rect GetViewBounds() const override;
  void CreateView(const gfx::Size& initial_size,
                  gfx::NativeView context) override;
  ApplicationWindowHostView* CreateViewForWindow(
      ApplicationWindowHost* application_window_host) override;
  ApplicationWindowHostView* CreateViewForPopupWindow(
      ApplicationWindowHost* application_window_host) override;
  void SetPageTitle(const base::string16& title) override;
  void ApplicationWindowCreated(ApplicationWindowHost* host) override;
  void ApplicationWindowSwappedIn(ApplicationWindowHost* host) override;
  void SetOverscrollControllerEnabled(bool enabled) override;

  // Overridden from ApplicationWindowHostDelegateView:
  void ShowContextMenu(ApplicationWindowHost* app_window_host,
                       const common::ContextMenuParams& params) override;
  void StartDragging(const common::DropData& drop_data,
                     blink::WebDragOperationsMask operations,
                     const gfx::ImageSkia& image,
                     const gfx::Vector2d& image_offset,
                     const common::DragEventSourceInfo& event_info,
                     ApplicationWindowHost* source_rwh) override;
  void UpdateDragCursor(blink::WebDragOperation operation) override;
  void GotFocus(ApplicationWindowHost* application_window_host) override;
  void LostFocus(ApplicationWindowHost* application_window_host) override;
  void TakeFocus(bool reverse) override;
//#if BUILDFLAG(USE_EXTERNAL_POPUP_MENU)
  void ShowPopupMenu(ApplicationWindowHost* app_window_host,
                     const gfx::Rect& bounds,
                     int item_height,
                     double item_font_size,
                     int selected_item,
                     const std::vector<common::MenuItem>& items,
                     bool right_aligned,
                     bool allow_multiple_selection) override;

  void HidePopupMenu() override;
//#endif

  // Overridden from OverscrollControllerDelegate:
  gfx::Size GetDisplaySize() const override;
  bool OnOverscrollUpdate(float delta_x, float delta_y) override;
  void OnOverscrollComplete(OverscrollMode overscroll_mode) override;
  void OnOverscrollModeChange(OverscrollMode old_mode,
                              OverscrollMode new_mode,
                              OverscrollSource source,
                              cc::OverscrollBehavior behavior) override;
  base::Optional<float> GetMaxOverscrollDelta() const override;

  // Overridden from aura::WindowDelegate:
  gfx::Size GetMinimumSize() const override;
  gfx::Size GetMaximumSize() const override;
  void OnBoundsChanged(const gfx::Rect& old_bounds,
                       const gfx::Rect& new_bounds) override;
  gfx::NativeCursor GetCursor(const gfx::Point& point) override;
  int GetNonClientComponent(const gfx::Point& point) const override;
  bool ShouldDescendIntoChildForEventHandling(
      aura::Window* child,
      const gfx::Point& location) override;
  bool CanFocus() override;
  void OnCaptureLost() override;
  void OnPaint(const ui::PaintContext& context) override;
  void OnDeviceScaleFactorChanged(float old_device_scale_factor,
                                  float new_device_scale_factor) override;
  void OnWindowDestroying(aura::Window* window) override;
  void OnWindowDestroyed(aura::Window* window) override;
  void OnWindowTargetVisibilityChanged(bool visible) override;
  void OnWindowOcclusionChanged(
      aura::Window::OcclusionState occlusion_state) override;
  bool HasHitTestMask() const override;
  void GetHitTestMask(gfx::Path* mask) const override;

  // Overridden from ui::EventHandler:
  void OnKeyEvent(ui::KeyEvent* event) override;
  void OnMouseEvent(ui::MouseEvent* event) override;

  // Overridden from aura::client::DragDropDelegate:
  void OnDragEntered(const ui::DropTargetEvent& event) override;
  int OnDragUpdated(const ui::DropTargetEvent& event) override;
  void OnDragExited() override;
  int OnPerformDrop(const ui::DropTargetEvent& event) override;

  FRIEND_TEST_ALL_PREFIXES(ApplicationContentsViewAuraTest, EnableDisableOverscroll);

  // NOTE: this is null when running in mus and |is_mus_browser_plugin_guest_|.
  std::unique_ptr<aura::Window> window_;

  std::unique_ptr<WindowObserver> window_observer_;

  // The ApplicationContents whose contents we display.
  ApplicationContents* app_contents_;

  std::unique_ptr<ApplicationContentsViewDelegate> delegate_;

  blink::WebDragOperationsMask current_drag_op_;

  std::unique_ptr<common::DropData> current_drop_data_;

  ApplicationDragDestDelegate* drag_dest_delegate_;

  // We keep track of the ApplicationWindowHost we're dragging over. If it changes
  // during a drag, we need to re-send the DragEnter message.
  base::WeakPtr<ApplicationWindowHost> current_rwh_for_drag_;

  // We also keep track of the ID of the ApplicationWindowHost we're dragging over to
  // avoid sending the drag exited message after leaving the current view.
  GlobalRoutingID current_rvh_for_drag_;

  // We track the IDs of the source RenderProcessHost and ApplicationWindowHost from
  // which the current drag originated. These are used to ensure that drag
  // events do not fire over a cross-site frame (with respect to the source
  // frame) in the same page (see crbug.com/666858). Specifically, the
  // ApplicationWindowHost is used to check the "same page" property, while the
  // RenderProcessHost is used to check the "cross-site" property. Note that the
  // reason the RenderProcessHost is tracked instead of the ApplicationWindowHost is
  // so that we still allow drags between non-contiguous same-site frames (such
  // frames will have the same process, but different widgets). Note also that
  // the ApplicationWindowHost may not be in the same process as the RenderProcessHost,
  // since the view corresponds to the page, while the process is specific to
  // the frame from which the drag started.
  int drag_start_process_id_;
  GlobalRoutingID drag_start_view_id_;

  // The overscroll gesture currently in progress.
  OverscrollMode current_overscroll_gesture_;

  // This is the completed overscroll gesture. This is used for the animation
  // callback that happens in response to a completed overscroll gesture.
  OverscrollMode completed_overscroll_gesture_;

  // This manages the overlay window that shows the screenshot during a history
  // navigation triggered by the overscroll gesture.
  //std::unique_ptr<OverscrollNavigationOverlay> navigation_overlay_;

  //std::unique_ptr<GestureNavSimple> gesture_nav_simple_;

  //bool init_rwhv_with_null_parent_for_testing_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsViewAura);
};

}  // namespace host

#endif  // CONTENT_BROWSER_WEB_CONTENTS_WEB_CONTENTS_VIEW_AURA_H_
