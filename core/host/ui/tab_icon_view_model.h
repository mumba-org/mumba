// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_DOCK_WINDOW_ICON_VIEW_MODEL_H_
#define MUMBA_HOST_UI_DOCK_WINDOW_ICON_VIEW_MODEL_H_

namespace gfx {
class ImageSkia;
}

namespace host {

// Classes implement this interface to provide state for the TabIconView.
class TabIconViewModel {
 public:
  // Returns true if the TabIconView should show a loading animation.
  virtual bool ShouldTabIconViewAnimate() const = 0;

  // Returns the favicon to display in the icon view
  virtual gfx::ImageSkia GetFaviconForTabIconView() = 0;

 protected:
  virtual ~TabIconViewModel() {}
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_TAB_ICON_VIEW_MODEL_H_
