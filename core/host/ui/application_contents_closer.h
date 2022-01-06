// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_TABS_WEB_CONTENTS_CLOSER_H_
#define CHROME_BROWSER_UI_TABS_WEB_CONTENTS_CLOSER_H_

#include <stdint.h>

#include "base/containers/span.h"

namespace host {
class ApplicationContents;

class ApplicationContentsCloseDelegate {
 public:
  // Returns true if the delegate still contains the tab.
  virtual bool ContainsApplicationContents(ApplicationContents* contents) = 0;

  // Called right befor deleting |contents|. Gives the delegate a change to do
  // last minute cleaning. |close_types| is the |close_types| supplied to
  // CloseWebContentses().
  virtual void OnWillDeleteApplicationContents(ApplicationContents* contents,
                                               uint32_t close_types) = 0;

  // These mirror that of TabStripModelDelegate, see it for details.
  virtual bool RunUnloadListenerBeforeClosing(
      ApplicationContents* contents) = 0;
  virtual bool ShouldRunUnloadListenerBeforeClosing(
      ApplicationContents* contents) = 0;

 protected:
  virtual ~ApplicationContentsCloseDelegate() {}
};

// |close_types| is a bitmask of the types in TabStripModel::CloseTypes.
// Returns true if all the tabs have been deleted. A return value of false means
// some portion (potentially none) of the WebContents were deleted. WebContents
// not deleted by this function are processing unload handlers which may
// eventually be deleted based on the results of the unload handler.
// Additionally processing the unload handlers may result in needing to show UI
// for the WebContents. See UnloadController for details on how unload handlers
// are processed.
bool CloseApplicationContentses(ApplicationContentsCloseDelegate* delegate,
                                base::span<ApplicationContents* const> items,
                                uint32_t close_types);

}

#endif  // CHROME_BROWSER_UI_TABS_WEB_CONTENTS_CLOSER_H_
