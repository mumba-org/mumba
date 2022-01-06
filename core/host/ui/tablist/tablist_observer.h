// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TABS_TAB_STRIP_OBSERVER_H_
#define CHROME_BROWSER_UI_VIEWS_TABS_TAB_STRIP_OBSERVER_H_

namespace host {
class Tablist;

////////////////////////////////////////////////////////////////////////////////
//
// TabStripObserver
//
//  Objects implement this interface when they wish to be notified of changes
//  to the TabStrip.
//
//  Register your TabStripObserver with the TabStrip using its
//  Add/RemoveObserver methods.
//
////////////////////////////////////////////////////////////////////////////////
class TablistObserver {
 public:
  // A new tab was added to |tab_strip| at |index|.
  virtual void TablistAddedTabAt(Tablist* tablist, int index);

  // The tab at |from_index| was moved to |to_index| in |tab_strip|.
  virtual void TablistMovedTab(Tablist* tablist,
                               int from_index,
                               int to_index);

  // The tab at |index| was removed from |tab_strip|.
  virtual void TablistRemovedTabAt(Tablist* tablist, int index);

  // Sent when the |tabstrip| is about to be deleted and any reference held must
  // be dropped.
  virtual void TablistDeleted(Tablist* tablist);

  // tab_strip->max_x() has changed.
  virtual void TablistMaxXChanged(Tablist* tablist);

 protected:
  virtual ~TablistObserver() {}
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_TABS_TAB_STRIP_OBSERVER_H_
