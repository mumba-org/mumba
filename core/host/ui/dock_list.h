// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_HOST_UI_DOCK_LIST_H_
#define CORE_HOST_UI_DOCK_LIST_H_

#include <stddef.h>

#include <vector>

#include "base/callback_forward.h"
#include "base/containers/flat_set.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/observer_list.h"
#include "core/host/data/resource.h"

namespace base {
class FilePath;
}

namespace host {
class Dock;
class DockListObserver;
class Workspace;

// Maintains a list of Dock objects.
class DockList : public ResourceManager {
 public:
  using DockSet = base::flat_set<Dock*>;
  using DockVector = std::vector<Dock*>;
  using CloseCallback = base::Callback<void(const base::FilePath&)>;
  using const_iterator = DockVector::const_iterator;
  using const_reverse_iterator = DockVector::const_reverse_iterator;

  // Returns the last active dock for this list.
  Dock* GetLastActive() const;

  const_iterator begin() const { return docks_.begin(); }
  const_iterator end() const { return docks_.end(); }

  bool empty() const { return docks_.empty(); }
  size_t size() const { return docks_.size(); }

  Dock* get(size_t index) const { return docks_[index]; }

  // Returns iterated access to list of open docks ordered by when
  // they were last active. The underlying data structure is a vector
  // and we push_back on recent access so a reverse iterator gives the
  // latest accessed dock first.
  const_reverse_iterator begin_last_active() const {
    return last_active_docks_.rbegin();
  }
  const_reverse_iterator end_last_active() const {
    return last_active_docks_.rend();
  }

  // Returns the set of docks that are currently in the closing state.
  const DockSet& currently_closing_docks() const {
    return currently_closing_docks_;
  }

  // ResourceManager 
  bool HaveResource(const base::UUID& id) override;
  bool HaveResource(const std::string& name) override;
  Resource* GetResource(const base::UUID& id) override;
  Resource* GetResource(const std::string& name) override;
  const google::protobuf::Descriptor* resource_descriptor() override;
  std::string resource_classname() const override;

  static DockList* GetInstance();

  // Adds or removes |dock| from the list it is associated with. The dock
  // object should be valid BEFORE these calls (for the benefit of observers),
  // so notify and THEN delete the object.
  static void AddDock(Dock* dock);
  static void RemoveDock(Dock* dock);

  // Adds and removes |observer| from the observer list for all desktops.
  // Observers are responsible for making sure the notifying dock is relevant
  // to them (e.g., on the specific desktop they care about if any).
  static void AddObserver(DockListObserver* observer);
  static void RemoveObserver(DockListObserver* observer);

  // Moves all the docks that show on workspace |new_workspace| to the end of
  // the dock list (i.e. the docks that were "activated" most recently).
  static void MoveDocksInWorkspaceToFront(const std::string& new_workspace);

  // Called by Dock objects when their window is activated (focused).  This
  // allows us to determine what the last active Dock was on each desktop.
  static void SetLastActive(Dock* dock);

  // Notifies the observers when the current active dock becomes not active.
  static void NotifyDockNoLongerActive(Dock* dock);

  // Notifies the observers when dock close was started. This may be called
  // more than once for a particular dock.
  static void NotifyDockCloseStarted(Dock* dock);

  // Closes all docks for |workspace| across all desktops.
  // TODO(mlerman): Move the Workspace Deletion flow to use the overloaded
  // version of this method with a callback, then remove this method.
  static void CloseAllDocksWithWorkspace(scoped_refptr<Workspace> workspace);

  // Closes all docks for |workspace| across all desktops. Uses
  // TryToCloseDockList() to do the actual closing. Triggers any
  // OnBeforeUnload events unless |skip_beforeunload| is true. If all
  // OnBeforeUnload events are confirmed or |skip_beforeunload| is true,
  // |on_close_success| is called, otherwise |on_close_aborted| is called. Both
  // callbacks may be null.
  // Note that if there is any dock window that has been used before, the
  // user should always have a chance to save their work before closing windows
  // without triggering beforeunload events.
  static void CloseAllDocksWithWorkspace(scoped_refptr<Workspace> workspace,
                                       const CloseCallback& on_close_success,
                                       const CloseCallback& on_close_aborted,
                                       bool skip_beforeunload);

  // Returns true if at least one incognito session is active across all
  // desktops.
  static bool IsIncognitoSessionActive();

  // Returns true if at least one incognito session is active for |workspace|
  // across all desktops.
  static bool IsIncognitoSessionActiveForWorkspace(scoped_refptr<Workspace> workspace);

 private:
  DockList(scoped_refptr<Workspace> workspace);
  ~DockList();

  // Helper method to remove a dock instance from a list of docks
  static void RemoveDockFrom(Dock* dock, DockVector* dock_list);

  // Attempts to close |docks_to_close| while respecting OnBeforeUnload
  // events. If there are no OnBeforeUnload events to be called,
  // |on_close_success| will be called, with a parameter of |workspace_path|,
  // and the Docks will then be closed. If at least one unfired
  // OnBeforeUnload event is found, handle it with a callback to
  // PostTryToCloseDockWindow, which upon success will recursively call this
  // method to handle any other OnBeforeUnload events. If aborted in the
  // OnBeforeUnload event, PostTryToCloseDockWindow will call
  // |on_close_aborted| instead and reset all OnBeforeUnload event handlers.
  static void TryToCloseDockList(const DockVector& docks_to_close,
                                 const CloseCallback& on_close_success,
                                 const CloseCallback& on_close_aborted,
                                 const base::FilePath& workspace_path,
                                 const bool skip_beforeunload);

  // Called after handling an OnBeforeUnload event. If |tab_close_confirmed| is
  // true, calls |TryToCloseDockList()|, passing the parameters
  // |docks_to_close|, |on_close_success|, |on_close_aborted|, and
  // |workspace_path|. Otherwise, resets all the OnBeforeUnload event handlers and
  // calls |on_close_aborted|.
  static void PostTryToCloseDockWindow(
      const DockVector& docks_to_close,
      const CloseCallback& on_close_success,
      const CloseCallback& on_close_aborted,
      const base::FilePath& workspace_path,
      const bool skip_beforeunload,
      bool tab_close_confirmed);

  scoped_refptr<Workspace> workspace_;
  
  // A vector of the docks in this list, in the order they were added.
  DockVector docks_;
  // A vector of the docks in this list that have been activated, in the
  // reverse order in which they were last activated.
  DockVector last_active_docks_;
  // A vector of the docks that are currently in the closing state.
  DockSet currently_closing_docks_;

  // A list of observers which will be notified of every dock addition and
  // removal across all DockLists.
  static base::LazyInstance<base::ObserverList<DockListObserver>>::Leaky
      observers_;

  static DockList* instance_;

  DISALLOW_COPY_AND_ASSIGN(DockList);
};

}

#endif  // CHROME_BROWSER_UI_BROWSER_LIST_H_
