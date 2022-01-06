// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_WINDOW_HOST_FRAME_VIEW_LAYOUT_DELEGATE_H_
#define MUMBA_HOST_UI_WINDOW_HOST_FRAME_VIEW_LAYOUT_DELEGATE_H_

#include "base/strings/string16.h"

namespace gfx {
class ImageSkia;
class Size;
}

namespace host {
// Delegate interface to control layout decisions without having to depend on
// Browser{,Frame,View}.
class DockFrameViewLayoutDelegate {
 public:
  virtual ~DockFrameViewLayoutDelegate() {}
  // Controls the visual placement of the window icon/title in non-tabstrip
  // mode.
  virtual bool ShouldShowWindowIcon() const = 0;
  virtual bool ShouldShowWindowTitle() const = 0;
  virtual base::string16 GetWindowTitle() const = 0;

  // Returns the size of the window icon. This can be platform dependent
  // because of differences in fonts, so its part of the interface.
  virtual int GetIconSize() const = 0;

  // Returns the browser's minimum view size. Used because we need to calculate
  // the minimum size for the entire non-client area.
  virtual gfx::Size GetDockWindowMinimumSize() const = 0;

  // Whether we should show the (minimize,maximize,close) buttons. This can
  // depend on the current state of the window (e.g., whether it is maximized).
  virtual bool ShouldShowCaptionButtons() const = 0;

  // Controls window state.
  virtual bool IsMaximized() const = 0;
  virtual bool IsMinimized() const = 0;
  virtual bool IsFullscreen() const = 0;

  virtual bool IsTablistVisible() const = 0;
  virtual int GetTablistHeight() const = 0;
  virtual bool IsToolbarVisible() const = 0;

  // Returns the tabstrips preferred size so the frame layout can work around
  // it.
  virtual gfx::Size GetTablistPreferredSize() const = 0;

  // Computes the height of the top area of the frame.
  virtual int GetTopAreaHeight() const = 0;

  // Returns true if the window frame is rendered by Chrome.
  virtual bool UseCustomFrame() const = 0;  
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_OPAQUE_BROWSER_FRAME_VIEW_LAYOUT_DELEGATE_H_
