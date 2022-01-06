// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_BROWSER_TABSTRIP_H_
#define CHROME_BROWSER_UI_BROWSER_TABSTRIP_H_

#include "core/host/application/application_contents.h"
#include "core/host/ui/tablist/tab_style.h"
#include "ui/base/page_transition_types.h"
#include "ui/base/window_open_disposition.h"

class GURL;

namespace gfx {
class Rect;
}

namespace host {
class Dock;
// Adds a tab to the tab strip of the specified dock and loads |url| into it.
// If |url| is an empty URL, then the new tab-page is laoded. An |index| of -1
// means to append it to the end of the tab strip.
void AddTabAt(Dock* dock, const GURL& url, Application* app, int index, bool foreground, TabStyle style);

// Adds a selected tab with the specified URL and transition, returns the
// created ApplicationContents.
ApplicationContents* AddSelectedTabWithURL(Dock* dock,
                                           const GURL& url,
                                           ui::PageTransition transition);

// Creates a new tab with the already-created ApplicationContents 'new_contents'.
// The window for the added contents will be reparented correctly when this
// method returns.  If |disposition| is NEW_POPUP, |initial_rect| should hold
// the initial position and size.
void AddApplicationContents(
  Dock* dock,
  ApplicationContents* source_contents,
  ApplicationContents* new_contents,
  WindowOpenDisposition disposition,
  const gfx::Rect& initial_rect,
  bool user_gesture);

// Closes the specified ApplicationContents in the specified Dock. If
// |add_to_history| is true, an entry in the historical tab database is created.
void CloseApplicationContents(
  Dock* dock,
  ApplicationContents* contents,
  bool add_to_history);

}  // namespace chrome

#endif  // CHROME_BROWSER_UI_BROWSER_TABSTRIP_H_
