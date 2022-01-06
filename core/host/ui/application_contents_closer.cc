// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_contents_closer.h"

#include <memory>

#include "core/host/host.h"
#include "core/host/ui/tablist/core_tab_helper.h"
#include "core/host/ui/tablist/core_tab_helper_delegate.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/tablist.h"
#include "core/host/ui/tablist/tab.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_window.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"

namespace host {

namespace {

// CloseTracker is used when closing a set of ApplicationContents. It listens for
// deletions of the ApplicationContents and removes from the internal set any time one
// is deleted.
class CloseTracker {
 public:
  using Contents = base::span<ApplicationContents* const>;

  explicit CloseTracker(const Contents& contents);
  ~CloseTracker();

  // Returns true if there is another ApplicationContents in the Tracker.
  bool HasNext() const;

  // Returns the next ApplicationContents, or NULL if there are no more.
  ApplicationContents* Next();

 private:
  class DeletionObserver : public ApplicationContentsObserver {
   public:
    DeletionObserver(CloseTracker* parent, ApplicationContents* application_contents)
        : ApplicationContentsObserver(application_contents), parent_(parent) {
     
    }

    ~DeletionObserver() override {
      //DLOG(INFO) << "~CloseTracker::DeletionObserver: " << this;
    }

   private:
    // ApplicationContentsObserver:
    void ApplicationContentsDestroyed() override {
      parent_->OnApplicationContentsDestroyed(this);
    }

    CloseTracker* parent_;

    DISALLOW_COPY_AND_ASSIGN(DeletionObserver);
  };

  void OnApplicationContentsDestroyed(DeletionObserver* observer);

  using Observers = std::vector<std::unique_ptr<DeletionObserver>>;
  Observers observers_;

  DISALLOW_COPY_AND_ASSIGN(CloseTracker);
};

CloseTracker::CloseTracker(const Contents& contents) {
  observers_.reserve(contents.size());
  for (ApplicationContents* current : contents)
    observers_.push_back(std::make_unique<DeletionObserver>(this, current));
}

CloseTracker::~CloseTracker() {
  DCHECK(observers_.empty());
}

bool CloseTracker::HasNext() const {
  return !observers_.empty();
}

ApplicationContents* CloseTracker::Next() {
  if (observers_.empty())
    return nullptr;

  DeletionObserver* observer = observers_[0].get();
  ApplicationContents* application_contents = observer->application_contents();
  observers_.erase(observers_.begin());
  return application_contents;
}

void CloseTracker::OnApplicationContentsDestroyed(DeletionObserver* observer) {
  for (auto i = observers_.begin(); i != observers_.end(); ++i) {
    if (observer == i->get()) {
      observers_.erase(i);
      return;
    }
  }
  NOTREACHED() << "ApplicationContents destroyed that wasn't in the list";
}

}  // namespace

bool CloseApplicationContentses(ApplicationContentsCloseDelegate* delegate,
                        base::span<ApplicationContents* const> items,
                        uint32_t close_types) {
  //Dock* dock = nullptr;
  //bool should_close_window = false;

  if (items.empty()) {
    return true;
  }

  CloseTracker close_tracker(items);

  // We only try the fast shutdown path if the whole browser process is *not*
  // shutting down. Fast shutdown during browser termination is handled in
  // browser_shutdown::OnShutdownStarting.
  //if (browser_shutdown::GetShutdownType() == browser_shutdown::NOT_VALID) {
    // Construct a map of processes to the number of associated tabs that are
    // closing.
    base::flat_map<ApplicationProcessHost*, size_t> processes;
    for (ApplicationContents* contents : items) {
      if (delegate->ShouldRunUnloadListenerBeforeClosing(contents))
        continue;
      ApplicationProcessHost* process =
          contents->GetApplicationProcessHost();//GetMainFrame()->GetProcess();
      ++processes[process];
    }

    // Try to fast shutdown the tabs that can close.
    for (const auto& pair : processes)
      pair.first->FastShutdownIfPossible(pair.second, false);
  //}

  // We now return to our regularly scheduled shutdown procedure.
  bool closed_all = true;
  while (close_tracker.HasNext()) {
    ApplicationContents* closing_contents = close_tracker.Next();
    if (!delegate->ContainsApplicationContents(closing_contents)) {
      continue;
    }

    CoreTabHelper* core_tab_helper =
        CoreTabHelper::FromApplicationContents(closing_contents);
    core_tab_helper->OnCloseStarted();

    // Update the explicitly closed state. If the unload handlers cancel the
    // close the state is reset in Browser. We don't update the explicitly
    // closed state if already marked as explicitly closed as unload handlers
    // call back to this if the close is allowed.
    if (!closing_contents->GetClosedByUserGesture()) {
      closing_contents->SetClosedByUserGesture(
          close_types & TablistModel::CLOSE_USER_GESTURE);
    }

    //if (delegate->RunUnloadListenerBeforeClosing(closing_contents)) {
    //  closed_all = false;
    //  continue;
    //}

    delegate->OnWillDeleteApplicationContents(closing_contents, close_types);

    // NOTE: ADDED here but it might not be the right portal for this
    //       in chrome i guess this happens on Session

    // if (!dock) {
    //   dock = static_cast<Dock*>(closing_contents->GetDelegate());
    //   should_close_window = items.size() == dock->tablist_model()->count();
    // }

    // int index = dock->tablist_model()->GetIndexOfApplicationContents(closing_contents);
    // if (index != TablistModel::kNoTab) {
    //   // we dont need to kill tab by tab if the window will close
    //   if (!should_close_window) {
    //     Tablist* tablist = dock->window()->tablist();
    //     Tab* tab = tablist->tab_at(index);
    //     tablist->CloseTab(tab, CLOSE_TAB_FROM_MOUSE);
    //   }
    // }
    delete closing_contents;
  }

  // NOTE: ADDED here but it might not be the right portal for this
  //       in chrome i guess this happens on Session

  // if (should_close_window && dock) {
  //   DLOG(INFO) << "closing window..";
  //   dock->window()->Close();
  // }

  return closed_all;
}

}
