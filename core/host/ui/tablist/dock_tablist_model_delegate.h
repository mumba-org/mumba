// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_DOCK_TABLIST_MODEL_DELEGATE_H_
#define CHROME_BROWSER_UI_DOCK_TABLIST_MODEL_DELEGATE_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "core/host/ui/tablist/tablist_model_delegate.h"

class GURL;

namespace host {

class DockTablistModelDelegate : public TablistModelDelegate {
 public:
  explicit DockTablistModelDelegate(Dock* dock);
  ~DockTablistModelDelegate() override;

 private:
  // Overridden from TabStripModelDelegate:
  void AddTabAt(const GURL& url, Application* app, int index, bool foreground, TabStyle style) override;
  Dock* CreateNewListWithContents(
      const std::vector<NewListContents>& contentses,
      const gfx::Rect& window_bounds,
      bool maximize) override;
  void WillAddApplicationContents(ApplicationContents* contents) override;
  int GetDragActions() const override;
  bool CanDuplicateContentsAt(int index) override;
  void DuplicateContentsAt(int index) override;
  //void CreateHistoricalTab(ApplicationContents* contents) override;
  bool RunUnloadListenerBeforeClosing(ApplicationContents* contents) override;
  bool ShouldRunUnloadListenerBeforeClosing(
      ApplicationContents* contents) override;
  //bool CanBookmarkAllTabs() const override;
  //void BookmarkAllTabs() override;
  RestoreTabType GetRestoreTabType() override;
  void RestoreTab() override;

  void CloseFrame();

  Dock* const dock_;

  // The following factory is used to close the frame at a later time.
  base::WeakPtrFactory<DockTablistModelDelegate> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(DockTablistModelDelegate);
};

}  // namespace chrome

#endif  // CHROME_BROWSER_UI_BROWSER_TAB_STRIP_MODEL_DELEGATE_H_
