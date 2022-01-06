// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_ORDER_CONTROLLER_H_
#define CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_ORDER_CONTROLLER_H_

#include "base/macros.h"
#include "core/host/ui/tablist/tablist_model_observer.h"
#include "ui/base/page_transition_types.h"

namespace host {
class TablistModel;

///////////////////////////////////////////////////////////////////////////////
// TabStripModelOrderController
//
//  An object that allows different types of ordering and reselection to be
//  heuristics plugged into a TabStripModel.
//
class TablistModelOrderController : public TablistModelObserver {
 public:
  explicit TablistModelOrderController(TablistModel* tablist);
  ~TablistModelOrderController() override;

  // Determine where to portal a newly opened tab by using the supplied
  // transition and foreground flag to figure out how it was opened.
  int DetermineInsertionIndex(ui::PageTransition transition,
                              bool foreground);

  // Determine where to shift selection after a tab is closed.
  int DetermineNewSelectedIndex(int removed_index) const;

  // Overridden from TabStripModelObserver:
  void ActiveTabChanged(ApplicationContents* old_contents,
                        ApplicationContents* new_contents,
                        int index,
                        int reason) override;

 private:
  // Returns a valid index to be selected after the tab at |removing_index| is
  // closed. If |index| is after |removing_index|, |index| is adjusted to
  // reflect the fact that |removing_index| is going away.
  int GetValidIndex(int index, int removing_index) const;

  TablistModel* tablist_;

  DISALLOW_COPY_AND_ASSIGN(TablistModelOrderController);
};

}

#endif  // CHROME_BROWSER_UI_TABS_TAB_STRIP_MODEL_ORDER_CONTROLLER_H_
