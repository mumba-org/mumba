// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_ZOOM_MAP_OBSERVER_H_
#define MUMBA_HOST_HOST_ZOOM_MAP_OBSERVER_H_

#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "core/shared/common/host_zoom.mojom.h"
#include "core/host/application/application_contents_observer.h"

namespace host {
class ApplicationWindowHost;

class HostZoomMapObserver : private ApplicationContentsObserver {
 public:
  explicit HostZoomMapObserver(ApplicationContents* application_contents);
  ~HostZoomMapObserver() override;

 private:
  // ApplicationContentsObserver implementation:
  //void ReadyToCommitNavigation(NavigationHandle* navigation_handle) override;
  void ApplicationWindowCreated(ApplicationWindowHost* awh) override;
  void ApplicationWindowDeleted(ApplicationWindowHost* awh) override;
  void GetHostZoomInterfaceOnIOThread(ApplicationWindowHost* awh);
  void ApplicationWindowDeletedOnIOThread(ApplicationWindowHost* awh);

  std::map<ApplicationWindowHost*, common::mojom::HostZoomAssociatedPtr> host_zoom_ptrs_;
  base::Lock map_lock;
  base::WaitableEvent wait_event_;
  base::WeakPtrFactory<HostZoomMapObserver> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(HostZoomMapObserver);
};

}  // namespace host

#endif  // CONTENT_BROWSER_HOST_ZOOM_MAP_OBSERVER_H_
