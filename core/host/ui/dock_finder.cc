// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_finder.h"

#include <stdint.h>

#include <algorithm>

#include "build/build_config.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock_list.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/tablist/tab_contents_iterator.h"
#include "core/host/ui/tablist/tablist_model.h"
//#include "content/public/dock/navigation_controller.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"

#if defined(OS_CHROMEOS)
#include "core/host/ui/ash/multi_user/multi_user_util.h"
#include "core/host/ui/ash/multi_user/multi_user_window_manager.h"
//#include "components/signin/core/account_id/account_id.h"
#endif

namespace host {

namespace {


// Type used to indicate to match anything.
const int kMatchAny                     = 0;

// See DockMatches for details.
const int kMatchOriginalWorkspace       = 1 << 0;
//const int kMatchCanSupportWindowFeature = 1 << 1;
const int kMatchTabbed                  = 1 << 2;
const int kMatchDisplayId               = 1 << 3;
const int kMatchURLScheme               = 1 << 4;

// Returns true if the specified |dock| matches the specified arguments.
// |match_types| is a bitmask dictating what parameters to match:
// . If it contains kMatchOriginalWorkspace then the original workspace of the
//   dock must match |workspace->GetOriginalWorkspace()|. This is used to match
//   incognito windows.
// . If it contains kMatchCanSupportWindowFeature
//   |CanSupportWindowFeature(window_feature)| must return true.
// . If it contains kMatchTabbed, the dock must be a tabbed dock.
bool DockMatches(Dock* dock,
                 scoped_refptr<Workspace> workspace,
                 Dock::WindowFeature window_feature,
                 uint32_t match_types,
                 int64_t display_id,
                 const GURL& url) {
  //if ((match_types & kMatchCanSupportWindowFeature) &&
  //    !dock->CanSupportWindowFeature(window_feature)) {
  //  return false;
  //}
  // changed here: we filter by url first if is asked
  if (match_types & kMatchURLScheme) {
    if (url.is_valid()) {
      return dock->is_grouped_by_app() && dock->scheme() == url.scheme();
      //return workspace->HaveDockForScheme(scheme);
    } else {
      DLOG(INFO) << "kMatchURLScheme: URL " << url << " is invalid";
    }
  }
  

#if defined(OS_CHROMEOS)
  // Get the workspace on which the window is currently shown.
  // MultiUserWindowManager might be NULL under test scenario.
  MultiUserWindowManager* const window_manager =
      MultiUserWindowManager::GetInstance();
  scoped_refptr<Workspace> shown_workspace = nullptr;
  if (window_manager) {
    const AccountId& shown_account_id = window_manager->GetUserPresentingWindow(
        dock->window()->GetNativeWindow());
    shown_workspace =
        shown_account_id.is_valid()
            ? multi_user_util::GetWorkspaceFromAccountId(shown_account_id)
            : nullptr;
  }
#endif
  if (match_types & kMatchOriginalWorkspace) {
    if (dock->workspace() !=
        workspace)
      return false;
#if defined(OS_CHROMEOS)
    if (shown_workspace &&
        shown_workspace->GetOriginalWorkspace() != workspace->GetOriginalWorkspace()) {
      return false;
    }
#endif
  } else {
    if (dock->workspace() != workspace)
      return false;
#if defined(OS_CHROMEOS)
    if (shown_workspace && shown_workspace != workspace)
      return false;
#endif
  }

  if ((match_types & kMatchTabbed) && !dock->is_type_tabbed())
    return false;

  if (match_types & kMatchDisplayId) {
    return display::Screen::GetScreen()
               ->GetDisplayNearestWindow(dock->window()->GetNativeWindow())
               .id() == display_id;
  }

  return true;
}

// Returns the first dock in the specified iterator that returns true from
// |DockMatches|, or null if no docks match the arguments. See
// |DockMatches| for details on the arguments.
template <class T>
Dock* FindDockMatching(const T& begin,
                             const T& end,
                             scoped_refptr<Workspace> workspace,
                             Dock::WindowFeature window_feature,
                             uint32_t match_types,
                             int64_t display_id = display::kInvalidDisplayId,
                             GURL url = GURL()) {
  for (T i = begin; i != end; ++i) {
    if (DockMatches(*i, workspace, window_feature, match_types, display_id, url))
      return *i;
  }
  return NULL;
}

Dock* FindDockWithTabbedOrAnyType(
    scoped_refptr<Workspace> workspace,
    bool match_tabbed,
    bool match_original_workspaces,
    int64_t display_id = display::kInvalidDisplayId,
    GURL url = GURL()) {
  DockList* dock_list_impl = DockList::GetInstance();
  if (!dock_list_impl)
    return NULL;
  uint32_t match_types = kMatchAny;
  if (match_tabbed)
    match_types |= kMatchTabbed;
  if (match_original_workspaces)
    match_types |= kMatchOriginalWorkspace;
  if (display_id != display::kInvalidDisplayId)
    match_types |= kMatchDisplayId;

  // Commented here: this is the rule that we were using to 
  //                 launch a new window only if its a new scheme
  //                 so as to each different scheme would have its own window

  // if (url.is_valid()) {
  //   match_types |= kMatchURLScheme;
  // } else {
  //   DLOG(INFO) << "FindDockWithTabbedOrAnyType: url is invalid. not adding kMatchURLScheme to flags";
  // }
  Dock* dock =
      FindDockMatching(dock_list_impl->begin_last_active(),
                       dock_list_impl->end_last_active(), workspace,
                       Dock::FEATURE_NONE, match_types, display_id, url);
  // Fall back to a forward scan of all Docks if no active one was found.
  return dock ? dock
                 : FindDockMatching(
                       dock_list_impl->begin(), dock_list_impl->end(),
                       workspace, Dock::FEATURE_NONE, match_types, display_id, url);
}

size_t GetDockCountImpl(scoped_refptr<Workspace> workspace,
                           uint32_t match_types,
                           int64_t display_id = display::kInvalidDisplayId) {
  DockList* dock_list_impl = DockList::GetInstance();
  size_t count = 0;
  if (dock_list_impl) {
    for (DockList::const_iterator i = dock_list_impl->begin();
         i != dock_list_impl->end(); ++i) {
      if (DockMatches(*i, workspace, Dock::FEATURE_NONE, match_types, display_id, GURL()))
        count++;
    }
  }
  return count;
}

}  // namespace

Dock* FindTabbedDock(scoped_refptr<Workspace> workspace,
                     const GURL& url,
                     bool match_original_workspaces,
                     int64_t display_id) {
  return FindDockWithTabbedOrAnyType(workspace, true, match_original_workspaces,
                                     display_id, url);
}

Dock* FindAnyDock(scoped_refptr<Workspace> workspace,
                  bool match_original_workspaces) {
  return FindDockWithTabbedOrAnyType(workspace,
                                        false,
                                        match_original_workspaces);
}

Dock* FindDockWithWorkspace(scoped_refptr<Workspace> workspace) {
  return FindDockWithTabbedOrAnyType(workspace, false, false);
}

//Dock* FindDockWithID(SessionID desired_id) {
//  for (auto* dock : *DockList::GetInstance()) {
//    if (dock->session_id() == desired_id)
//      return dock;
//  }
//  return NULL;
//}

Dock* FindDockWithWindow(gfx::NativeWindow window) {
  if (!window)
    return NULL;
  for (auto* dock : *DockList::GetInstance()) {
    if (dock->window() && dock->window()->GetNativeWindow() == window)
      return dock;
  }
  return NULL;
}

Dock* FindDockWithActiveWindow() {
  Dock* dock = DockList::GetInstance()->GetLastActive();
  return dock && dock->window()->IsActive() ? dock : nullptr;
}

Dock* FindDockWithApplicationContents(const ApplicationContents* app_contents) {
  DCHECK(app_contents);
  auto& all_tabs = AllTabContentses();
  auto it = std::find(all_tabs.begin(), all_tabs.end(), app_contents);

  return (it == all_tabs.end()) ? nullptr : it.dock();
}

Dock* FindLastActiveWithWorkspace(scoped_refptr<Workspace> workspace) {
  DockList* list = DockList::GetInstance();
  // We are only interested in last active docks, so we don't fall back to
  // all docks like FindDockWith* do.
  return FindDockMatching(list->begin_last_active(), list->end_last_active(),
                             workspace, Dock::FEATURE_NONE, kMatchAny);
}

Dock* FindLastActive() {
  DockList* dock_list_impl = DockList::GetInstance();
  if (dock_list_impl)
    return dock_list_impl->GetLastActive();
  return NULL;
}

size_t GetTotalDockCount() {
  return DockList::GetInstance()->size();
}

size_t GetDockCount(scoped_refptr<Workspace> workspace) {
  return GetDockCountImpl(workspace, kMatchAny);
}

size_t GetTabbedDockCount(scoped_refptr<Workspace> workspace) {
  return GetDockCountImpl(workspace, kMatchTabbed);
}

}  // namespace chrome
