// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_FRAME_VIEW_H_
#define MUMBA_HOST_UI_WINDOW_HOST_FRAME_VIEW_H_

#include "base/macros.h"
#include "core/host/ui/view_ids.h"
#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_non_client_frame_view.h"
#include "core/host/ui/dock_frame_view_layout.h"
#include "core/host/ui/dock_frame_view_layout_delegate.h"
#include "core/host/ui/tab_icon_view_model.h"
#include "ui/views/controls/button/button.h"
#include "ui/views/controls/button/menu_button_listener.h"
#include "ui/views/linux_ui/linux_ui.h"
#include "ui/views/window/non_client_view.h"

namespace views {
class ImageButton;
class FrameBackground;
class Label;
}

namespace host {
class DockWindow;
class DockFrameViewLayout;
class DockFrameViewPlatformSpecific;
class TabIconView;

class DockFrameView : public DockNonClientFrameView,
                      public views::ButtonListener,
                      public views::MenuButtonListener,
                      public TabIconViewModel,
                      public DockFrameViewLayoutDelegate {
public:
  
  DockFrameView(DockFrame* dock_frame,
                DockWindow* dock_window,
                DockFrameViewLayout* layout);

  ~DockFrameView() override;

  // DockNonClientFrameView
  void OnDockWindowInitViewsComplete() override;
  void OnMaximizedStateChanged() override;
  void OnFullscreenStateChanged() override;
  gfx::Rect GetBoundsForTablist(views::View* tablist) const override;
  int GetTopInset(bool restored) const override;
  int GetThemeBackgroundXInset() const override;
  void UpdateThrobber(bool running) override;
  gfx::Size GetMinimumSize() const override;
  int GetTablistLeftInset() const override;

  // views::NonClientFrameView:
  gfx::Rect GetBoundsForClientView() const override;
  gfx::Rect GetWindowBoundsForClientBounds(
      const gfx::Rect& client_bounds) const override;
  int NonClientHitTest(const gfx::Point& point) override;
  void GetWindowMask(const gfx::Size& size, gfx::Path* window_mask) override;
  void ResetWindowControls() override;
  void UpdateWindowIcon() override;
  void UpdateWindowTitle() override;
  void SizeConstraintsChanged() override;
  void ActivationChanged(bool active) override;

  // views::View:
  void GetAccessibleNodeData(ui::AXNodeData* node_data) override;
  void OnNativeThemeChanged(const ui::NativeTheme* native_theme) override;

  // views::ButtonListener:
  void ButtonPressed(views::Button* sender, const ui::Event& event) override;

  // views::MenuButtonListener:
  void OnMenuButtonClicked(views::MenuButton* source,
                           const gfx::Point& point,
                           const ui::Event* event) override;

  // TabIconViewModel:
  bool ShouldTabIconViewAnimate() const override;
  gfx::ImageSkia GetFaviconForTabIconView() override;

  // OpaqueBrowserFrameViewLayoutDelegate implementation:
  //bool IsIncognito() const override;
  bool ShouldShowWindowIcon() const override;
  bool ShouldShowWindowTitle() const override;
  base::string16 GetWindowTitle() const override;
  int GetIconSize() const override;
  gfx::Size GetDockWindowMinimumSize() const override;
  bool ShouldShowCaptionButtons() const override;
  //bool IsRegularOrGuestSession() const override;
  //gfx::ImageSkia GetIncognitoAvatarIcon() const override;
  bool IsMaximized() const override;
  bool IsMinimized() const override;
  bool IsFullscreen() const override;
  bool IsTablistVisible() const override;
  int GetTablistHeight() const override;
  bool IsToolbarVisible() const override;
  gfx::Size GetTablistPreferredSize() const override;
  int GetTopAreaHeight() const override;
  bool UseCustomFrame() const override;

 protected:
  views::ImageButton* minimize_button() const { return minimize_button_; }
  views::ImageButton* maximize_button() const { return maximize_button_; }
  views::ImageButton* restore_button() const { return restore_button_; }
  views::ImageButton* close_button() const { return close_button_; }

  // views::View:
  void OnPaint(gfx::Canvas* canvas) override;

  // BrowserNonClientFrameView:
  bool ShouldPaintAsThemed() const override;
  //AvatarButtonStyle GetAvatarButtonStyle() const override;

  DockFrameViewLayout* layout() { return layout_; }

  // If native window frame buttons are enabled, redraws the image resources
  // associated with |{minimize,maximize,restore,close}_button_|.
  virtual void MaybeRedrawFrameButtons();

 private:
  // Creates, adds and returns a new image button with |this| as its listener.
  // Memory is owned by the caller.
  views::ImageButton* InitWindowCaptionButton(int normal_image_id,
                                              int hot_image_id,
                                              int pushed_image_id,
                                              int mask_image_id,
                                              int accessibility_string_id,
                                              ViewID view_id);

  // Returns the thickness of the border that makes up the window frame edges.
  // This does not include any client edge.  If |restored| is true, this is
  // calculated as if the window was restored, regardless of its current
  // node_data.
  int FrameBorderThickness(bool restored) const;

  // Returns true if the specified point is within the avatar menu buttons.
  bool IsWithinAvatarMenuButtons(const gfx::Point& point) const;

  // Returns the thickness of the entire nonclient left, right, and bottom
  // borders, including both the window frame and any client edge.
  int NonClientBorderThickness() const;

  // Returns the bounds of the titlebar icon (or where the icon would be if
  // there was one).
  gfx::Rect IconBounds() const;

  // Returns true if the view should draw its own custom title bar.
  bool ShouldShowWindowTitleBar() const;

  // Paint various sub-components of this view.  The *FrameBorder() functions
  // also paint the background of the titlebar area, since the top frame border
  // and titlebar background are a contiguous component.
  void PaintRestoredFrameBorder(gfx::Canvas* canvas) const;
  void PaintMaximizedFrameBorder(gfx::Canvas* canvas) const;
  void PaintClientEdge(gfx::Canvas* canvas) const;
  void FillClientEdgeRects(int x,
                           int y,
                           int w,
                           int h,
                           bool draw_bottom,
                           SkColor color,
                           gfx::Canvas* canvas) const;

  // Our layout manager also calculates various bounds.
  DockFrameViewLayout* layout_;

  // Window controls.
  views::ImageButton* minimize_button_;
  views::ImageButton* maximize_button_;
  views::ImageButton* restore_button_;
  views::ImageButton* close_button_;

  // The window icon and title.
  TabIconView* window_icon_;
  views::Label* window_title_;

  // Background painter for the window frame.
  std::unique_ptr<views::FrameBackground> frame_background_;

  // Observer that handles platform dependent configuration.
  std::unique_ptr<DockFrameViewPlatformSpecific> platform_observer_;

  DISALLOW_COPY_AND_ASSIGN(DockFrameView);
};


}

#endif