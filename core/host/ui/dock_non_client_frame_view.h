// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_NON_CLIENT_FRAME_VIEW_H_
#define MUMBA_HOST_UI_WINDOW_HOST_NON_CLIENT_FRAME_VIEW_H_

#include "base/macros.h"
#include "ui/views/window/non_client_view.h"

namespace host {
class DockWindow;
class DockFrame;

// Type used for functions whose return values depend on the active state of
// the frame.
enum class DockFrameActiveState {
  kUseCurrent,  // Use current frame active state.
  kActive,      // Treat frame as active regardless of current state.
  kInactive,    // Treat frame as inactive regardless of current state.
};

class DockNonClientFrameView : public views::NonClientFrameView {
public:
  DockNonClientFrameView(DockFrame* frame, DockWindow* window);
  ~DockNonClientFrameView() override;

  DockWindow* dock_window() const { return dock_window_; }
  DockFrame* frame() const { return frame_; }

  // Called when BrowserView creates all it's child views.
  virtual void OnDockWindowInitViewsComplete();

  // Called on Linux X11 after the browser window is maximized or restored.
  virtual void OnMaximizedStateChanged();

  // Called on Linux X11 after the browser window is fullscreened or
  // unfullscreened.
  virtual void OnFullscreenStateChanged();

  // Returns whether the caption buttons are drawn at the leading edge (i.e. the
  // left in LTR mode, or the right in RTL mode).
  virtual bool CaptionButtonsOnLeadingEdge() const;

  virtual gfx::Rect GetBoundsForTablist(views::View* tablist) const = 0;

  virtual int GetTablistLeftInset() const;


    // Returns the inset of the topmost view in the client view from the top of
  // the non-client view. The topmost view depends on the window type. The
  // topmost view is the tab strip for tabbed browser windows, the toolbar for
  // popups, the web contents for app windows and varies for fullscreen windows.
  // If |restored| is true, this is calculated as if the window was restored,
  // regardless of its current state.
  virtual int GetTopInset(bool restored) const = 0;

  // Returns the amount that the theme background should be inset.
  virtual int GetThemeBackgroundXInset() const = 0;

    // Returns COLOR_TOOLBAR_TOP_SEPARATOR[,_INACTIVE] depending on the activation
  // state of the window.
  SkColor GetToolbarTopSeparatorColor() const;

  // Updates the throbber.
  virtual void UpdateThrobber(bool running) = 0;

  // Provided for mus. Updates the client-area of the WindowTreeHostMus.
  virtual void UpdateClientArea();

  // Provided for mus to update the minimum window size property.
  virtual void UpdateMinimumSize();

  // Overriden from views::View.
  void ChildPreferredSizeChanged(views::View* child) override;
  void VisibilityChanged(views::View* starting_from, bool is_visible) override;

 protected:
  // Whether the frame should be painted with theming.
  // By default, tabbed browser windows are themed but popup and app windows are
  // not.
  virtual bool ShouldPaintAsThemed() const;

  // Compute aspects of the frame needed to paint the frame background.
  SkColor GetFrameColor(bool active) const;
  gfx::ImageSkia GetFrameImage(bool active) const;
  gfx::ImageSkia GetFrameOverlayImage(bool active) const;

  // Convenience versions of the above which use ShouldPaintAsActive() for
  // |active|.
  SkColor GetFrameColor() const;
  gfx::ImageSkia GetFrameImage() const;
  gfx::ImageSkia GetFrameOverlayImage() const;

  void PaintToolbarBackground(gfx::Canvas* canvas) const;

  // views::NonClientFrameView:
  void ActivationChanged(bool active) override;
  bool DoesIntersectRect(const views::View* target,
                         const gfx::Rect& rect) const override;

 private:
  // views::NonClientFrameView:
  void ViewHierarchyChanged(
      const ViewHierarchyChangedDetails& details) override;

  // Draws a taskbar icon if avatars are enabled, erases it otherwise.
  void UpdateTaskbarDecoration();

  // The frame that hosts this view.
  DockFrame* frame_;

  // The DockWindow hosted within this View.
  DockWindow* dock_window_;

  DISALLOW_COPY_AND_ASSIGN(DockNonClientFrameView);
};

// Provided by a browser_non_client_frame_view_factory_*.cc implementation
DockNonClientFrameView* CreateDockNonClientFrameView(
    DockFrame* frame, DockWindow* dock_window);

}

#endif