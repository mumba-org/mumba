// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tab_contents_iterator.h"

#include "base/logging.h"
#include "base/no_destructor.h"
#include "core/host/host.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/tablist/tablist_model.h"

namespace host {

// This does not create a useful iterator, but providing a default constructor
// is required for forward iterators by the C++ spec.
AllTabContentsesList::Iterator::Iterator() : Iterator(true) {}

AllTabContentsesList::Iterator::Iterator(bool is_end_iter)
    : tab_index_(-1),
      cur_(nullptr),
      dock_iterator_(DockList::GetInstance()->begin()) {
  if (!is_end_iter) {
    // Load the first WebContents into |cur_|.
    Next();
  }
}

AllTabContentsesList::Iterator::Iterator(const Iterator& iterator) = default;

AllTabContentsesList::Iterator::~Iterator() = default;

void AllTabContentsesList::Iterator::Next() {
  // The current WebContents should be valid unless we are at the beginning.
  DCHECK(cur_ || tab_index_ == -1) << "Trying to advance past the end";

  // Update |cur_| to the next WebContents in the list.
  while (dock_iterator_ != DockList::GetInstance()->end()) {
    if (++tab_index_ >= (*dock_iterator_)->tablist_model()->count()) {
      // Advance to the next Dock in the list.
      ++dock_iterator_;
      tab_index_ = -1;
      continue;
    }

    auto* next_tab =
        (*dock_iterator_)->tablist_model()->GetApplicationContentsAt(tab_index_);
    if (next_tab) {
      cur_ = next_tab;
      return;
    }
  }

  // Reached the end.
  cur_ = nullptr;
}

const AllTabContentsesList& AllTabContentses() {
  static const base::NoDestructor<AllTabContentsesList> all_tabs;
  return *all_tabs;
}

}