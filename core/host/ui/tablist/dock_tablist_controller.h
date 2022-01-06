// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TABS_BROWSER_TAB_STRIP_CONTROLLER_H_
#define CHROME_BROWSER_UI_VIEWS_TABS_BROWSER_TAB_STRIP_CONTROLLER_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "core/host/ui/tablist/hover_tab_selector.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/tablist_controller.h"
#include "core/host/ui/dock_window.h"
//#include "core/host/ui/immersive_mode_controller.h"
//#include "components/prefs/pref_change_registrar.h"

namespace ui {
class ListSelectionModel;
}

namespace host {
class ApplicationContents;
class Dock;
class Tab;
struct TabRendererData;

// An implementation of TablistController that sources data from the
// ApplicationContentses in a TablistModel.
class DockTablistController : public TablistController,
                              public TablistModelObserver {
 public:
  DockTablistController(TablistModel* model, DockWindow* dock_view);
  ~DockTablistController() override;

  void InitFromModel(Tablist* tablist);

  TablistModel* model() const { return model_; }

  bool IsCommandEnabledForTab(TablistModel::ContextMenuCommand command_id,
                              Tab* tab) const;
  void ExecuteCommandForTab(TablistModel::ContextMenuCommand command_id,
                            Tab* tab);
  bool IsTabPinned(Tab* tab) const;

  // TablistController implementation:
  const ui::ListSelectionModel& GetSelectionModel() const override;
  int GetCount() const override;
  bool IsValidIndex(int model_index) const override;
  bool IsActiveTab(int model_index) const override;
  int GetActiveIndex() const override;
  bool IsTabSelected(int model_index) const override;
  bool IsTabPinned(int model_index) const override;
  void SelectTab(int model_index) override;
  void ExtendSelectionTo(int model_index) override;
  void ToggleSelected(int model_index) override;
  void AddSelectionFromAnchorTo(int model_index) override;
  void CloseTab(int model_index, CloseTabSource source) override;
  void ToggleTabAudioMute(int model_index) override;
  void ShowContextMenuForTab(Tab* tab,
                             const gfx::Point& p,
                             ui::MenuSourceType source_type) override;
  int HasAvailableDragActions() const override;
  void OnDropIndexUpdate(int index, bool drop_before) override;
  void PerformDrop(bool drop_before, int index, const GURL& url) override;
  bool IsCompatibleWith(Tablist* other) const override;
  void CreateNewTab() override;
  void CreateNewTabWithLocation(const base::string16& loc) override;
  bool IsIncognito() override;
  void StackedLayoutMaybeChanged() override;
  void OnStartedDraggingTabs() override;
  void OnStoppedDraggingTabs() override;
  void CheckFileSupported(const GURL& url) override;
  SkColor GetToolbarTopSeparatorColor() const override;
  base::string16 GetAccessibleTabName(const Tab* tab) const override;
  scoped_refptr<Workspace> GetWorkspace() const override;

  // TablistModelObserver implementation:
  void TabInsertedAt(TablistModel* tab_strip_model,
                     ApplicationContents* contents,
                     int model_index,
                     bool is_active) override;
  void TabDetachedAt(ApplicationContents* contents, int model_index) override;
  void ActiveTabChanged(ApplicationContents* old_contents,
                        ApplicationContents* new_contents,
                        int index,
                        int reason) override;
  void TabSelectionChanged(TablistModel* tab_strip_model,
                           const ui::ListSelectionModel& old_model) override;
  void TabMoved(ApplicationContents* contents,
                int from_model_index,
                int to_model_index) override;
  void TabChangedAt(ApplicationContents* contents,
                    int model_index,
                    TabChangeType change_type) override;
  void TabReplacedAt(TablistModel* tab_strip_model,
                     ApplicationContents* old_contents,
                     ApplicationContents* new_contents,
                     int model_index) override;
  void TabPinnedStateChanged(TablistModel* tab_strip_model,
                             ApplicationContents* contents,
                             int model_index) override;
  void TabBlockedStateChanged(ApplicationContents* contents,
                              int model_index) override;
  void SetTabNeedsAttentionAt(int index, bool attention) override;

  const Dock* dock() const { return dock_window_->dock(); }

 private:
  class TabContextMenuContents;

  // The context in which TabRendererDataFromModel is being called.
  enum TabStatus {
    NEW_TAB,
    EXISTING_TAB
  };

  // Returns the TabRendererData for the specified tab.
  TabRendererData TabRendererDataFromModel(ApplicationContents* contents,
                                           int model_index,
                                           TabStatus tab_status);

  // Invokes tablist_->SetTabData.
  void SetTabDataAt(ApplicationContents* web_contents, int model_index);

  void StartHighlightTabsForCommand(
      TablistModel::ContextMenuCommand command_id,
      Tab* tab);
  void StopHighlightTabsForCommand(
      TablistModel::ContextMenuCommand command_id,
      Tab* tab);

  // Adds a tab.
  void AddTab(ApplicationContents* contents, int index, bool is_active);

  // Resets the tablists stacked layout (true or false) from prefs.
  void UpdateStackedLayout();

  // Notifies the tablist whether |url| is supported once a MIME type request
  // has completed.
  void OnFindURLMimeTypeCompleted(const GURL& url,
                                  const std::string& mime_type);

  TablistModel* model_;

  Tablist* tablist_;

  DockWindow* dock_window_;

  // If non-NULL it means we're showing a menu for the tab.
  std::unique_ptr<TabContextMenuContents> context_menu_contents_;

  // Helper for performing tab selection as a result of dragging over a tab.
  HoverTabSelector hover_tab_selector_;

  // Forces the tabs to use the regular (non-immersive) style and the
  // top-of-window views to be revealed when the user is dragging |tablist|'s
  // tabs.
  //std::unique_ptr<ImmersiveRevealedLock> immersive_reveal_lock_;

  //PrefChangeRegistrar local_pref_registrar_;

  base::WeakPtrFactory<DockTablistController> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(DockTablistController);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_TABS_BROWSER_TAB_STRIP_CONTROLLER_H_
