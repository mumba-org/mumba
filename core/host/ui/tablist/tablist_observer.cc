// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tablist_observer.h"

namespace host {

void TablistObserver::TablistAddedTabAt(Tablist* tablist, int index) {
}

void TablistObserver::TablistMovedTab(Tablist* tablist,
                                      int from_index,
                                      int to_index) {
}

void TablistObserver::TablistRemovedTabAt(Tablist* tablist, int index) {
}

void TablistObserver::TablistDeleted(Tablist* tablist) {
}

void TablistObserver::TablistMaxXChanged(Tablist* tablist) {}

}