// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_list.h"

#include <algorithm>

#include "base/auto_reset.h"
#include "base/logging.h"
#include "base/metrics/user_metrics.h"
#include "core/host/host.h"
//#include "core/host/host_shutdown.h"
#include "core/host/notification_types.h"
//#include "chrome/browser/lifetime/application_lifetime.h"
//#include "chrome/browser/lifetime/termination_notification.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/dock.h"
//#include "core/host/ui/dock_finder.h"
#include "core/host/ui/dock_list_observer.h"
#include "core/host/ui/dock_window.h"
#include "core/host/notification_service.h"

using base::UserMetricsAction;

namespace host {

namespace {

DockList::DockVector GetDocksToClose(scoped_refptr<Workspace> workspace) {
  DockList::DockVector docks_to_close;
  for (auto* dock : *DockList::GetInstance()) {
    //if (browser->workspace()->GetOriginalWorkspace() ==
    //    workspace->GetOriginalWorkspace())
      docks_to_close.push_back(dock);
  }
  return docks_to_close;
}

}  // namespace

// static
base::LazyInstance<base::ObserverList<DockListObserver>>::Leaky
    DockList::observers_ = LAZY_INSTANCE_INITIALIZER;

// static
DockList* DockList::instance_ = NULL;

////////////////////////////////////////////////////////////////////////////////
// DockList, public:

Dock* DockList::GetLastActive() const {
  if (!last_active_docks_.empty())
    return *(last_active_docks_.rbegin());
  return NULL;
}

// static
DockList* DockList::GetInstance() {
  DockList** list = &instance_;
  if (!*list)
    *list = new DockList;
  return *list;
}

// static
void DockList::AddDock(Dock* dock) {
  DCHECK(dock);
  DCHECK(dock->window()) << "Dock should not be added to DockList "
                               "until it is fully constructed.";
  GetInstance()->docks_.push_back(dock);

  //dock->RegisterKeepAlive();

  NotificationService::current()->Notify(
      NOTIFICATION_BROWSER_OPENED,
      Source<Dock>(dock),
      NotificationService::NoDetails());

  for (DockListObserver& observer : observers_.Get())
    observer.OnDockAdded(dock);

  if (dock->window()->IsActive())
    SetLastActive(dock);
}

// static
void DockList::RemoveDock(Dock* dock) {
  // Remove |dock| from the appropriate list instance.
  DockList* dock_list = GetInstance();
  RemoveDockFrom(dock, &dock_list->last_active_docks_);
  dock_list->currently_closing_docks_.erase(dock);

  NotificationService::current()->Notify(
      NOTIFICATION_BROWSER_CLOSED,
      Source<Dock>(dock),
      NotificationService::NoDetails());

  RemoveDockFrom(dock, &dock_list->docks_);

  for (DockListObserver& observer : observers_.Get())
    observer.OnDockRemoved(dock);

  //dock->UnregisterKeepAlive();

  // If we're exiting, send out the APP_TERMINATING notification to allow other
  // modules to shut themselves down.
  //if (host::GetTotalDockCount() == 0 &&
  //    (dock_shutdown::IsTryingToQuit() ||
  //     g_dock_process->IsShuttingDown())) {
    // Last dock has just closed, and this is a user-initiated quit or there
    // is no module keeping the app alive, so send out our notification. No need
    // to call WorkspaceManager::ShutdownSessionServices() as part of the
    // shutdown, because Dock::WindowClosing() already makes sure that the
    // SessionService is created and notified.
  //  dock_shutdown::NotifyAppTerminating();
  //  chrome::OnAppExiting();
  //}
}

// static
void DockList::AddObserver(DockListObserver* observer) {
  observers_.Get().AddObserver(observer);
}

// static
void DockList::RemoveObserver(DockListObserver* observer) {
  observers_.Get().RemoveObserver(observer);
}

// static
void DockList::CloseAllDocksWithWorkspace(scoped_refptr<Workspace> workspace) {
  DockVector docks_to_close;
  for (auto* dock : *DockList::GetInstance()) {
    if (dock->workspace() == workspace)
      docks_to_close.push_back(dock);
  }

  for (DockVector::const_iterator it = docks_to_close.begin();
       it != docks_to_close.end(); ++it) {
    (*it)->window()->Close();
  }
}

// static
void DockList::CloseAllDocksWithWorkspace(
    scoped_refptr<Workspace> workspace,
    const CloseCallback& on_close_success,
    const CloseCallback& on_close_aborted,
    bool skip_beforeunload) {
  TryToCloseDockList(GetDocksToClose(workspace), on_close_success,
                     on_close_aborted, workspace->root_path(),
                     skip_beforeunload);
}

// static
void DockList::TryToCloseDockList(const DockVector& docks_to_close,
                                        const CloseCallback& on_close_success,
                                        const CloseCallback& on_close_aborted,
                                        const base::FilePath& workspace_path,
                                        const bool skip_beforeunload) {
  for (DockVector::const_iterator it = docks_to_close.begin();
       it != docks_to_close.end(); ++it) {
    if ((*it)->TryToCloseWindow(
            skip_beforeunload,
            base::Bind(&DockList::PostTryToCloseDockWindow,
                       docks_to_close, on_close_success, on_close_aborted,
                       workspace_path, skip_beforeunload))) {
      return;
    }
  }

  if (on_close_success)
    on_close_success.Run(workspace_path);

  for (Dock* b : docks_to_close) {
    // BeforeUnload handlers may close dock windows, so we need to explicitly
    // check whether they still exist.
    if (b->window())
      b->window()->Close();
  }
}

// static
void DockList::PostTryToCloseDockWindow(
    const DockVector& docks_to_close,
    const CloseCallback& on_close_success,
    const CloseCallback& on_close_aborted,
    const base::FilePath& workspace_path,
    const bool skip_beforeunload,
    bool tab_close_confirmed) {
  // We need this bool to avoid infinite recursion when resetting the
  // BeforeUnload handlers, since doing that will trigger calls back to this
  // method for each affected window.
  static bool resetting_handlers = false;

  if (tab_close_confirmed) {
    TryToCloseDockList(docks_to_close, on_close_success, on_close_aborted,
                          workspace_path, skip_beforeunload);
  } else if (!resetting_handlers) {
    base::AutoReset<bool> resetting_handlers_scoper(&resetting_handlers, true);
    for (DockVector::const_iterator it = docks_to_close.begin();
         it != docks_to_close.end(); ++it) {
      (*it)->ResetTryToCloseWindow();
    }
    if (on_close_aborted)
      on_close_aborted.Run(workspace_path);
  }
}

// static
void DockList::MoveDocksInWorkspaceToFront(const std::string& new_workspace) {
  DCHECK(!new_workspace.empty());

  DockList* instance = GetInstance();

  Dock* old_last_active = instance->GetLastActive();
  DockVector& last_active_docks = instance->last_active_docks_;

  // Perform a stable partition on the docks in the list so that the docks
  // in the new workspace appear after the docks in the other workspaces.
  //
  // For example, if we have a list of dock-workspace pairs
  // [{b1, 0}, {b2, 1}, {b3, 0}, {b4, 1}]
  // and we switch to workspace 1, we want the resulting dock list to look
  // like [{b1, 0}, {b3, 0}, {b2, 1}, {b4, 1}].
  std::stable_partition(
      last_active_docks.begin(), last_active_docks.end(),
      [&new_workspace](Dock* dock) {
        return !dock->window()->IsVisibleOnAllDesktopWorkspaces() &&
               dock->window()->GetDesktopWorkspace() != new_workspace;
      });

  Dock* new_last_active = instance->GetLastActive();
  if (old_last_active != new_last_active) {
    for (DockListObserver& observer : observers_.Get())
      observer.OnDockSetLastActive(new_last_active);
  }
}

// static
void DockList::SetLastActive(Dock* dock) {
  DockList* instance = GetInstance();
  DCHECK(std::find(instance->begin(), instance->end(), dock) !=
         instance->end())
      << "SetLastActive called for a dock before the dock was added to "
         "the DockList.";
  DCHECK(dock->window() != nullptr)
      << "SetLastActive called for a dock with no window set.";

  //base::RecordAction(UserMetricsAction("ActiveDockChanged"));

  RemoveDockFrom(dock, &instance->last_active_docks_);
  instance->last_active_docks_.push_back(dock);

  for (DockListObserver& observer : observers_.Get())
    observer.OnDockSetLastActive(dock);
}

// static
void DockList::NotifyDockNoLongerActive(Dock* dock) {
  DockList* instance = GetInstance();
  DCHECK(std::find(instance->begin(), instance->end(), dock) !=
         instance->end())
      << "NotifyDockNoLongerActive called for a dock before the dock "
         "was added to the DockList.";
  DCHECK(dock->window() != nullptr)
      << "NotifyDockNoLongerActive called for a dock with no window set.";

  for (DockListObserver& observer : observers_.Get())
    observer.OnDockNoLongerActive(dock);
}

// static
void DockList::NotifyDockCloseStarted(Dock* dock) {
  GetInstance()->currently_closing_docks_.insert(dock);

  for (DockListObserver& observer : observers_.Get())
    observer.OnDockClosing(dock);
}

// static
bool DockList::IsIncognitoSessionActive() {
  //for (auto* dock : *DockList::GetInstance()) {
//    if (dock->workspace()->IsOffTheRecord())
      //return true;
  //}
  return false;
}

// static
bool DockList::IsIncognitoSessionActiveForWorkspace(scoped_refptr<Workspace> workspace) {
  //for (auto* dock : *DockList::GetInstance()) {
//    if (dock->workspace()->IsSameWorkspace(workspace) &&
        //dock->workspace()->IsOffTheRecord()) {
      //return true;
    //}
  //}
  return false;
}

////////////////////////////////////////////////////////////////////////////////
// DockList, private:

DockList::DockList() {
}

DockList::~DockList() {
}

// static
void DockList::RemoveDockFrom(Dock* dock,
                                    DockVector* dock_list) {
  DockVector::iterator remove_dock =
      std::find(dock_list->begin(), dock_list->end(), dock);
  if (remove_dock != dock_list->end())
    dock_list->erase(remove_dock);
}

}