// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tab_network_state.h"

//#include "core/host/navigation_entry.h"
#include "core/host/application/application_contents.h"

namespace host {

TabNetworkState TabNetworkStateForApplicationContents(ApplicationContents* contents) {
  DCHECK(contents);

  //if (!contents->IsLoadingToDifferentDocument()) {
  //  content::NavigationEntry* entry =
  //      contents->GetController().GetLastCommittedEntry();
  //  if (entry && (entry->GetPageType() == content::PAGE_TYPE_ERROR))
  //    return TabNetworkState::kError;
  //  return TabNetworkState::kNone;
  //}

  //if (contents->IsWaitingForResponse())
  //  return TabNetworkState::kWaiting;
  //return TabNetworkState::kLoading;
  return TabNetworkState::kNone;
}

}