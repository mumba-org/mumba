// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/hover_tab_selector.h"

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/host/ui/tablist/tablist_model.h"

namespace host {

HoverTabSelector::HoverTabSelector(
    TablistModel* tablist_model)
    : tablist_model_(tablist_model),
      tab_transition_tab_index_(-1),
      weak_factory_(this) {
  DCHECK(tablist_model_);
}

HoverTabSelector::~HoverTabSelector() {
}

void HoverTabSelector::StartTabTransition(int index) {
  // If there is a transition underway already, only start a new
  // transition (canceling the old one) if the target tab differs.
  if (weak_factory_.HasWeakPtrs()) {
    if (index == tab_transition_tab_index_)
      return;
    CancelTabTransition();
  }
  // Start a new transition if the target isn't active already.
  if (index != tablist_model_->active_index()) {
    // The delay between beginning to hover over a tab and the transition
    // to that tab taking portal.
    const base::TimeDelta kHoverTransitionDelay =
        base::TimeDelta::FromMilliseconds(500);
    tab_transition_tab_index_ = index;
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&HoverTabSelector::PerformTabTransition,
                       weak_factory_.GetWeakPtr()),
        kHoverTransitionDelay);
  }
}

void HoverTabSelector::CancelTabTransition() {
  weak_factory_.InvalidateWeakPtrs();
}

void HoverTabSelector::PerformTabTransition() {
  DCHECK(tab_transition_tab_index_ >= 0 &&
         tab_transition_tab_index_ < tablist_model_->count());
  tablist_model_->ActivateTabAt(tab_transition_tab_index_, true);
}

}