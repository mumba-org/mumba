// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tablist_model_order_controller.h"

#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/application/application_contents.h"

namespace host {

///////////////////////////////////////////////////////////////////////////////
// TablistModelOrderController, public:

TablistModelOrderController::TablistModelOrderController(
    TablistModel* tablist)
    : tablist_(tablist) {
  tablist_->AddObserver(this);
}

TablistModelOrderController::~TablistModelOrderController() {
  tablist_->RemoveObserver(this);
}

int TablistModelOrderController::DetermineInsertionIndex(
    ui::PageTransition transition,
    bool foreground) {
  int tab_count = tablist_->count();
  if (!tab_count)
    return 0;

  // NOTE: TablistModel enforces that all non-mini-tabs occur after mini-tabs,
  // so we don't have to check here too.
  if (ui::PageTransitionCoreTypeIs(transition, ui::PAGE_TRANSITION_LINK) &&
      tablist_->active_index() != -1) {
    if (foreground) {
      // If the page was opened in the foreground by a link click in another
      // tab, insert it adjacent to the tab that opened that link.
      return tablist_->active_index() + 1;
    }
    ApplicationContents* opener = tablist_->GetActiveApplicationContents();
    // Get the index of the next item opened by this tab, and insert after
    // it...
    int index = tablist_->GetIndexOfLastApplicationContentsOpenedBy(
        opener, tablist_->active_index());
    if (index != TablistModel::kNoTab)
      return index + 1;
    // Otherwise insert adjacent to opener...
    return tablist_->active_index() + 1;
  }
  // In other cases, such as Ctrl+T, open at the end of the strip.
  return tablist_->count();
}

int TablistModelOrderController::DetermineNewSelectedIndex(
    int removing_index) const {
  int tab_count = tablist_->count();
  DCHECK(removing_index >= 0 && removing_index < tab_count);
  ApplicationContents* parent_opener =
      tablist_->GetOpenerOfApplicationContentsAt(removing_index);
  // First see if the index being removed has any "child" tabs. If it does, we
  // want to select the first in that child group, not the next tab in the same
  // group of the removed tab.
  ApplicationContents* removed_contents =
      tablist_->GetApplicationContentsAt(removing_index);
  // The parent opener should never be the same as the controller being removed.
  DCHECK(parent_opener != removed_contents);
  int index = tablist_->GetIndexOfNextApplicationContentsOpenedBy(removed_contents,
                                                           removing_index,
                                                           false);
  if (index != TablistModel::kNoTab)
    return GetValidIndex(index, removing_index);

  if (parent_opener) {
    // If the tab was in a group, shift selection to the next tab in the group.
    int index = tablist_->GetIndexOfNextApplicationContentsOpenedBy(parent_opener,
                                                             removing_index,
                                                             false);
    if (index != TablistModel::kNoTab)
      return GetValidIndex(index, removing_index);

    // If we can't find a subsequent group member, just fall back to the
    // parent_opener itself. Note that we use "group" here since opener is
    // reset by select operations..
    index = tablist_->GetIndexOfApplicationContents(parent_opener);
    if (index != TablistModel::kNoTab)
      return GetValidIndex(index, removing_index);
  }

  // No opener set, fall through to the default handler...
  int selected_index = tablist_->active_index();
  if (selected_index >= (tab_count - 1))
    return selected_index - 1;

  return selected_index;
}

void TablistModelOrderController::ActiveTabChanged(
    ApplicationContents* old_contents,
    ApplicationContents* new_contents,
    int index,
    int reason) {
  ApplicationContents* old_opener = NULL;
  if (old_contents) {
    int index = tablist_->GetIndexOfApplicationContents(old_contents);
    if (index != TablistModel::kNoTab) {
      old_opener = tablist_->GetOpenerOfApplicationContentsAt(index);

      // Forget any group/opener relationships that need to be reset whenever
      // selection changes (see comment in TablistModel::AddApplicationContentsAt).
      if (tablist_->ShouldResetGroupOnSelect(old_contents))
        tablist_->ForgetGroup(old_contents);
    }
  }
  ApplicationContents* new_opener = tablist_->GetOpenerOfApplicationContentsAt(index);

  if ((reason & CHANGE_REASON_USER_GESTURE) && new_opener != old_opener &&
      ((old_contents == NULL && new_opener == NULL) ||
          new_opener != old_contents) &&
      ((new_contents == NULL && old_opener == NULL) ||
          old_opener != new_contents)) {
    tablist_->ForgetAllOpeners();
  }
}

///////////////////////////////////////////////////////////////////////////////
// TablistModelOrderController, private:

int TablistModelOrderController::GetValidIndex(
    int index, int removing_index) const {
  if (removing_index < index)
    index = std::max(0, index - 1);
  return index;
}

}