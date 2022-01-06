// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_BROWSER_LIST_OBSERVER_H_
#define CHROME_BROWSER_UI_BROWSER_LIST_OBSERVER_H_

namespace host {
class Dock;
class DockListObserver {
  public:
  // Called immediately after a browser is added to the list
  virtual void OnDockAdded(Dock* dock) {}

  // Called when a Browser starts closing. This is called prior to
  // removing the tabs. Removing the tabs may delay or stop the close.
  virtual void OnDockClosing(Dock* dock) {}

  // Called immediately after a browser is removed from the list
  virtual void OnDockRemoved(Dock* dock) {}

  // Called immediately after a browser is set active (SetLastActive)
  virtual void OnDockSetLastActive(Dock* dock) {}

  // Called immediately after a browser becomes not active.
  virtual void OnDockNoLongerActive(Dock* dock) {}

 protected:
  virtual ~DockListObserver() {}
};

}

#endif  // CHROME_BROWSER_UI_BROWSER_LIST_OBSERVER_H_
