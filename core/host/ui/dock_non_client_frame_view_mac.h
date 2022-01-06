// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_NON_CLIENT_FRAME_VIEW_MAC_H_
#define MUMBA_HOST_UI_WINDOW_HOST_NON_CLIENT_FRAME_VIEW_MAC_H_

#include "base/macros.h"
//#include "chrome/browser/ui/views/frame/avatar_button_manager.h"
#include "core/host/dock_non_client_frame_view.h"
//#include "chrome/browser/ui/views/profiles/profile_indicator_icon.h"

namespace host {

class DockNonClientFrameViewMac : public DockNonClientFrameView {
 public:
  // Mac implementation of BrowserNonClientFrameView.
  DockNonClientFrameViewMac(BrowserFrame* frame, BrowserView* browser_view);
  ~DockNonClientFrameViewMac() override;

  // BrowserNonClientFrameView:
  bool CaptionButtonsOnLeadingEdge() const override;
  gfx::Rect GetBoundsForTabStrip(views::View* tabstrip) const override;
  int GetTopInset(bool restored) const override;
  int GetThemeBackgroundXInset() const override;
  void UpdateThrobber(bool running) override;
  int GetTabStripLeftInset() const override;

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

  // views::View:
  void Layout() override;
  gfx::Size GetMinimumSize() const override;

 protected:
  // views::View:
  void OnPaint(gfx::Canvas* canvas) override;

  // BrowserNonClientFrameView:
  //AvatarButtonStyle GetAvatarButtonStyle() const override;

 private:
  void PaintThemedFrame(gfx::Canvas* canvas);
  int GetTabStripRightInset() const;

  DISALLOW_COPY_AND_ASSIGN(DockNonClientFrameViewMac);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_BROWSER_NON_CLIENT_FRAME_VIEW_MAC_H_
