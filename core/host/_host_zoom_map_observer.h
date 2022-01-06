// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_HOST_ZOOM_MAP_OBSERVER_H_
#define CONTENT_BROWSER_HOST_ZOOM_MAP_OBSERVER_H_

#include "core/common/host_zoom.mojom.h"
#include "core/host/application/application_contents_observer.h"

namespace host {
class ApplicationWindowHost;

class HostZoomMapObserver : private ApplicationContentsObserver {
 public:
  explicit HostZoomMapObserver(ApplicationContents* web_contents);
  ~HostZoomMapObserver() override;

 private:
  // WebContentsObserver implementation:
  //void ReadyToCommitNavigation(NavigationHandle* navigation_handle) override;
  void ApplicationWindowCreated(ApplicationWindowHost* rfh) override;
  void ApplicationWindowDeleted(ApplicationWindowHost* rfh) override;

  std::map<ApplicationWindowHost*, mojom::HostZoomAssociatedPtr> host_zoom_ptrs_;
};

}  // namespace host

#endif  // CONTENT_BROWSER_HOST_ZOOM_MAP_OBSERVER_H_
