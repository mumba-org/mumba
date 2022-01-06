// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_DELEGATE_H_
#define CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_DELEGATE_H_

#include <vector>

#include "base/uuid.h"
#include "core/host/ui/tablist/tab_style.h"

class GURL;


namespace gfx {
class Rect;
}

namespace host {
class Dock;
class ApplicationContents;
class Application;

///////////////////////////////////////////////////////////////////////////////
//
// TablistModelDelegate
//
//  A delegate interface that the TablistModel uses to perform work that it
//  can't do itself, such as obtain a container HWND for creating new
//  ApplicationContentses, creating new TablistModels for detached tabs, etc.
//
//  This interface is typically implemented by the controller that instantiates
//  the TablistModel (in our case the Browser object).
//
///////////////////////////////////////////////////////////////////////////////
class TablistModelDelegate {
 public:
  enum {
    TAB_MOVE_ACTION = 1,
    TAB_TEAROFF_ACTION = 2
  };

  enum RestoreTabType {
    RESTORE_NONE,
    RESTORE_TAB,
    RESTORE_WINDOW
  };

  virtual ~TablistModelDelegate() {}

  // Adds a tab to the model and loads |url| in the tab. If |url| is an empty
  // URL, then the new tab-page is loaded instead. An |index| value of -1
  // means to append the contents to the end of the tab strip.
  virtual void AddTabAt(const GURL& url, Application* app, int index, bool foreground, TabStyle style) = 0;

  // Asks for a new TablistModel to be created and the given web contentses to
  // be added to it. Its size and position are reflected in |window_bounds|.
  // Returns the Browser object representing the newly created window and tab
  // strip. This does not show the window; it's up to the caller to do so.
  //
  // TODO(avi): This is a layering violation; the TablistModel should not know
  // about the Browser type. At least fix so that this returns a
  // TablistModelDelegate, or perhaps even move this code elsewhere.
  struct NewListContents {
    // The ApplicationContents to add.
    ApplicationContents* app_contents;
    // A bitmask of TablistModel::AddTabTypes to apply to the added contents.
    int add_types;
  };
  virtual Dock* CreateNewListWithContents(
      const std::vector<NewListContents>& contentses,
      const gfx::Rect& window_bounds,
      bool maximize) = 0;

  // Notifies the delegate that the specified ApplicationContents will be added to the
  // tab strip (via insertion/appending/replacing existing) and allows it to do
  // any preparation that it deems necessary.
  virtual void WillAddApplicationContents(ApplicationContents* contents) = 0;

  // Determines what drag actions are possible for the specified strip.
  virtual int GetDragActions() const = 0;

  // Returns whether some contents can be duplicated.
  virtual bool CanDuplicateContentsAt(int index) = 0;

  // Duplicates the contents at the provided index and places it into its own
  // window.
  virtual void DuplicateContentsAt(int index) = 0;

  // Creates an entry in the historical tab database for the specified
  // ApplicationContents.
  //virtual void CreateHistoricalTab(ApplicationContents* contents) = 0;

  // Runs any unload listeners associated with the specified ApplicationContents
  // before it is closed. If there are unload listeners that need to be run,
  // this function returns true and the TablistModel will wait before closing
  // the ApplicationContents. If it returns false, there are no unload listeners
  // and the TablistModel will close the ApplicationContents immediately.
  virtual bool RunUnloadListenerBeforeClosing(
      ApplicationContents* contents) = 0;

  // Returns true if we should run unload listeners before attempts
  // to close |contents|.
  virtual bool ShouldRunUnloadListenerBeforeClosing(
      ApplicationContents* contents) = 0;

  // Returns the current tab restore type.
  virtual RestoreTabType GetRestoreTabType() = 0;

  // Restores the last closed tab unless tab restore type is none.
  virtual void RestoreTab() = 0;

  // Returns true if we should allow "bookmark all tabs" in this window; this is
  // true when there is more than one bookmarkable tab open.
  //virtual bool CanBookmarkAllTabs() const = 0;

  // Creates a bookmark folder containing a bookmark for all open tabs.
  //virtual void BookmarkAllTabs() = 0;
};

}

#endif  // CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_DELEGATE_H_
