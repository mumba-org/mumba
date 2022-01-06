// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tablist_model_observer.h"

namespace host {

////////////////////////////////////////////////////////////////////////////////
// TabGroupChange
//
TabGroupChange::TabGroupChange(tab_groups::TabGroupId group,
                               Type type,
                               std::unique_ptr<Delta> deltap)
    : group(group), type(type), delta(std::move(deltap)) {}

TabGroupChange::~TabGroupChange() = default;

TabGroupChange::VisualsChange::VisualsChange() = default;
TabGroupChange::VisualsChange::~VisualsChange() = default;

const TabGroupChange::VisualsChange* TabGroupChange::GetVisualsChange() const {
  DCHECK_EQ(type, Type::kVisualsChanged);
  return static_cast<const VisualsChange*>(delta.get());
}

TabGroupChange::TabGroupChange(tab_groups::TabGroupId group,
                               VisualsChange deltap)
    : TabGroupChange(group,
                     Type::kVisualsChanged,
                     std::make_unique<VisualsChange>(std::move(deltap))) {}

TablistModelObserver::TablistModelObserver() {
}

void TablistModelObserver::TabInsertedAt(TablistModel* tablist_model,
                                          ApplicationContents* contents,
                                          int index,
                                          bool foreground) {
}

void TablistModelObserver::TabClosingAt(TablistModel* tablist_model,
                                         ApplicationContents* contents,
                                         int index) {
}

void TablistModelObserver::TabDetachedAt(ApplicationContents* contents,
                                          int index) {
}

void TablistModelObserver::TabDeactivated(ApplicationContents* contents) {
}

void TablistModelObserver::ActiveTabChanged(ApplicationContents* old_contents,
                                             ApplicationContents* new_contents,
                                             int index,
                                             int reason) {
}

void TablistModelObserver::TabSelectionChanged(
    TablistModel* tablist_model,
    const ui::ListSelectionModel& model) {
}

void TablistModelObserver::TabMoved(ApplicationContents* contents,
                                     int from_index,
                                     int to_index) {
}

void TablistModelObserver::TabChangedAt(ApplicationContents* contents,
                                         int index,
                                         TabChangeType change_type) {
}

void TablistModelObserver::TabReplacedAt(TablistModel* tablist_model,
                                          ApplicationContents* old_contents,
                                          ApplicationContents* new_contents,
                                          int index) {
}

void TablistModelObserver::TabPinnedStateChanged(
    TablistModel* tablist_model,
    ApplicationContents* contents,
    int index) {
}

void TablistModelObserver::TabBlockedStateChanged(ApplicationContents* contents,
                                                   int index) {
}

void TablistModelObserver::TablistColorChanged(TablistModel* tablist_model, SkColor color, int tab_index) {
    
}

void TablistModelObserver::TablistEmpty() {
}

void TablistModelObserver::WillCloseAllTabs() {
}

void TablistModelObserver::CloseAllTabsCanceled() {
}

void TablistModelObserver::SetTabNeedsAttentionAt(int index, bool attention) {}

}