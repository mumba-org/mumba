// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_OBSERVER_H_
#define CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_OBSERVER_H_

#include "base/macros.h"
#include "core/host/ui/tab_change_type.h"
#include "components/tab_groups/tab_group_id.h"
#include "components/tab_groups/tab_group_visual_data.h"
#include "third_party/skia/include/core/SkColor.h"

namespace ui {
class ListSelectionModel;
}

namespace host {
class ApplicationContents;
class TablistModel;

// Struct to carry changes to tab groups. The tab group model is independent of
// the tab strip model, so these changes are not bundled with
// TabStripModelChanges or TabStripSelectionChanges.
struct TabGroupChange {
  // A group is created when the first tab is added to it and closed when the
  // last tab is removed from it. Whenever the set of tabs in the group changes,
  // a kContentsChange event is fired. Whenever the group's visual data changes,
  // such as its title or color, a kVisualsChange event is fired. Whenever the
  // group is moved by interacting with its header, a kMoved event is fired.
  enum Type {
    kCreated,
    kEditorOpened,
    kContentsChanged,
    kVisualsChanged,
    kMoved,
    kClosed
  };

  // Base class for all changes. Similar to TabStripModelChange::Delta.
  struct Delta {
    virtual ~Delta() = default;
  };

  // The TabGroupVisualData that was changed at the specified group.
  struct VisualsChange : public Delta {
    VisualsChange();
    ~VisualsChange() override;
    const tab_groups::TabGroupVisualData* old_visuals;
    const tab_groups::TabGroupVisualData* new_visuals;
  };

  TabGroupChange(tab_groups::TabGroupId group,
                 Type type,
                 std::unique_ptr<Delta> deltap = nullptr);
  explicit TabGroupChange(tab_groups::TabGroupId group, VisualsChange deltap);
  ~TabGroupChange();

  const VisualsChange* GetVisualsChange() const;

  tab_groups::TabGroupId group;
  Type type;

 private:
  std::unique_ptr<Delta> delta;
};

////////////////////////////////////////////////////////////////////////////////
//
// TablistModelObserver
//
//  Objects implement this interface when they wish to be notified of changes
//  to the TablistModel.
//
//  Two major implementers are the TabList, which uses notifications sent
//  via this interface to update the presentation of the strip, and the Browser
//  object, which updates bookkeeping and shows/hides individual ApplicationContentses.
//
//  Register your TablistModelObserver with the TablistModel using its
//  Add/RemoveObserver methods.
//
////////////////////////////////////////////////////////////////////////////////
class TablistModelObserver {
 public:
  enum ChangeReason {
    // Used to indicate that none of the reasons below are responsible for the
    // active tab change.
    CHANGE_REASON_NONE = 0,
    // The active tab changed because the tab's web contents was replaced.
    CHANGE_REASON_REPLACED = 1 << 0,
    // The active tab changed due to a user input event.
    CHANGE_REASON_USER_GESTURE = 1 << 1,
  };

  // A new ApplicationContents was inserted into the TablistModel at the
  // specified index. |foreground| is whether or not it was opened in the
  // foreground (selected).
  virtual void TabInsertedAt(TablistModel* tablist_model,
                             ApplicationContents* contents,
                             int index,
                             bool foreground);

  // The specified ApplicationContents at |index| is being closed (and eventually
  // destroyed). |tablist_model| is the TablistModel that contained the tab.
  virtual void TabClosingAt(TablistModel* tablist_model,
                               ApplicationContents* contents,
                               int index);

  // The specified ApplicationContents at |index| is being detached, perhaps to
  // be inserted in another TablistModel. The implementer should take whatever
  // action is necessary to deal with the ApplicationContents no longer being
  // present.
  virtual void TabDetachedAt(ApplicationContents* contents, int index);

  // The active ApplicationContents is about to change from |old_contents|.
  // This gives observers a chance to prepare for an impending switch before it
  // happens.
  virtual void TabDeactivated(ApplicationContents* contents);

  // Sent when the active tab changes. The previously active tab is identified
  // by |old_contents| and the newly active tab by |new_contents|. |index| is
  // the index of |new_contents|. If |reason| has CHANGE_REASON_REPLACED set
  // then the web contents was replaced (see TabChangedAt). If |reason| has
  // CHANGE_REASON_USER_GESTURE set then the web contents was changed due to a
  // user input event (e.g. clicking on a tab, keystroke).
  // Note: It is possible for the selection to change while the active tab
  // remains unchanged. For example, control-click may not change the active tab
  // but does change the selection. In this case |ActiveTabChanged| is not sent.
  // If you care about any changes to the selection, override
  // TabSelectionChanged.
  // Note: |old_contents| will be NULL if there was no contents previously
  // active.
  virtual void ActiveTabChanged(ApplicationContents* old_contents,
                                   ApplicationContents* new_contents,
                                   int index,
                                   int reason);

  // Sent when the selection changes in |tablist_model|. More precisely when
  // selected tabs, anchor tab or active tab change. |old_model| is a snapshot
  // of the selection model before the change. See also ActiveTabChanged for
  // details.
  virtual void TabSelectionChanged(TablistModel* tablist_model,
                                      const ui::ListSelectionModel& old_model);

  // The specified ApplicationContents at |from_index| was moved to |to_index|.
  virtual void TabMoved(ApplicationContents* contents,
                           int from_index,
                           int to_index);

  // The specified ApplicationContents at |index| changed in some way. |contents|
  // may be an entirely different object and the old value is no longer
  // available by the time this message is delivered.
  //
  // See tab_change_type.h for a description of |change_type|.
  virtual void TabChangedAt(ApplicationContents* contents,
                               int index,
                               TabChangeType change_type);

  // The ApplicationContents was replaced at the specified index. This is invoked when
  // prerendering swaps in a prerendered ApplicationContents.
  virtual void TabReplacedAt(TablistModel* tablist_model,
                                ApplicationContents* old_contents,
                                ApplicationContents* new_contents,
                                int index);

  // Invoked when the pinned state of a tab changes.
  virtual void TabPinnedStateChanged(TablistModel* tablist_model,
                                        ApplicationContents* contents,
                                        int index);

  // Invoked when the blocked state of a tab changes.
  // NOTE: This is invoked when a tab becomes blocked/unblocked by a tab modal
  // window.
  virtual void TabBlockedStateChanged(ApplicationContents* contents,
                                      int index);

  // The TablistModel now no longer has any tabs. The implementer may
  // use this as a trigger to try and close the window containing the
  // TablistModel, for example...
  virtual void TablistEmpty();

  // Sent any time an attempt is made to close all the tabs. This is not
  // necessarily the result of CloseAllTabs(). For example, if the user closes
  // the last tab WillCloseAllTabs() is sent. If the close does not succeed
  // during the current event (say unload handlers block it) then
  // CloseAllTabsCanceled() is sent. Also note that if the last tab is detached
  // (DetachApplicationContentsAt()) then this is not sent.
  virtual void WillCloseAllTabs();
  virtual void CloseAllTabsCanceled();

  // The specified tab at |index| requires the display of a UI indication to the
  // user that it needs their attention. The UI indication is set iff
  // |attention| is true.
  virtual void SetTabNeedsAttentionAt(int index, bool attention);

  virtual void TablistColorChanged(TablistModel* tablist_model, SkColor color, int tab_index);

 protected:
  TablistModelObserver();
  virtual ~TablistModelObserver() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(TablistModelObserver);
};

}

#endif  // CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_OBSERVER_H_
