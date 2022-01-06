// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_zoom_map_observer.h"

#include "core/host/application/application_window_host.h"
#include "core/host/host_zoom_map_impl.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"

namespace host {

HostZoomMapObserver::HostZoomMapObserver(ApplicationContents* app_contents)
    : ApplicationContentsObserver(app_contents) {
  DLOG(INFO) << "HostZoomMapObserver: " << this;
}

HostZoomMapObserver::~HostZoomMapObserver() {
  //DLOG(INFO) << "~HostZoomMapObserver: " << this;
}

// void HostZoomMapObserver::ReadyToCommitNavigation(
//     NavigationHandle* navigation_handle) {
//   if (!navigation_handle->IsInMainFrame())
//     return;

//   RenderFrameHost* render_frame_host =
//       navigation_handle->GetRenderFrameHost();
//   const auto& entry = host_zoom_ptrs_.find(render_frame_host);
//   if (entry == host_zoom_ptrs_.end())
//     return;

//   const mojom::HostZoomAssociatedPtr& host_zoom = entry->second;
//   DCHECK(host_zoom.is_bound());
//   if (host_zoom.encountered_error())
//     return;

//   RenderProcessHost* render_process_host = render_frame_host->GetProcess();
//   HostZoomMapImpl* host_zoom_map = static_cast<HostZoomMapImpl*>(
//       render_process_host->GetStoragePartition()->GetHostZoomMap());
//   double zoom_level = host_zoom_map->GetZoomLevelForView(
//       navigation_handle->GetURL(), render_process_host->GetID(),
//       render_frame_host->GetRenderViewHost()->GetRoutingID());
//   host_zoom->SetHostZoomLevel(navigation_handle->GetURL(), zoom_level);
// }

void HostZoomMapObserver::ApplicationWindowCreated(ApplicationWindowHost* rfh) {
  mojom::HostZoomAssociatedPtr host_zoom;
  rfh->GetRemoteAssociatedInterfaces()->GetInterface(&host_zoom);
  host_zoom_ptrs_[rfh] = std::move(host_zoom);
}

void HostZoomMapObserver::ApplicationWindowDeleted(ApplicationWindowHost* rfh) {
  const auto& entry = host_zoom_ptrs_.find(rfh);
  DCHECK(entry != host_zoom_ptrs_.end());
  host_zoom_ptrs_.erase(entry);
}

}  // namespace host
