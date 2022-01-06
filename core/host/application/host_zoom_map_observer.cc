// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/host_zoom_map_observer.h"

#include "core/host/application/application_window_host.h"
#include "core/host/application/host_zoom_map.h"
#include "core/host/host_thread.h"
//#include "core/host/navigation_handle.h"
//#include "core/host/render_view_host.h"
//#include "core/host/storage_partition.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"

namespace host {

HostZoomMapObserver::HostZoomMapObserver(ApplicationContents* application_contents)
    : ApplicationContentsObserver(application_contents),
      wait_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
      weak_factory_(this) {
  
}

HostZoomMapObserver::~HostZoomMapObserver() {
  
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

void HostZoomMapObserver::ApplicationWindowCreated(ApplicationWindowHost* awh) {
  HostThread::PostTask(
  	HostThread::IO, 
  	FROM_HERE, 
  	base::BindOnce(&HostZoomMapObserver::GetHostZoomInterfaceOnIOThread, weak_factory_.GetWeakPtr(), base::Unretained(awh)));
}

void HostZoomMapObserver::ApplicationWindowDeleted(ApplicationWindowHost* awh) {
  // HostThread::PostTask(
  //   HostThread::IO, 
  //   FROM_HERE, 
  //   base::BindOnce(&HostZoomMapObserver::ApplicationWindowDeletedOnIOThread, weak_factory_.GetWeakPtr(), base::Unretained(awh)));
}

void HostZoomMapObserver::ApplicationWindowDeletedOnIOThread(ApplicationWindowHost* awh) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  //map_lock.Acquire();
  const auto& entry = host_zoom_ptrs_.find(awh);
  DCHECK(entry != host_zoom_ptrs_.end());
  host_zoom_ptrs_.erase(entry);
}

void HostZoomMapObserver::GetHostZoomInterfaceOnIOThread(ApplicationWindowHost* awh) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  common::mojom::HostZoomAssociatedPtr host_zoom;
  awh->GetRemoteAssociatedInterfaces()->GetInterface(&host_zoom);
  //map_lock.Acquire();
  host_zoom_ptrs_[awh] = std::move(host_zoom);
  //map_lock.Release();
}

}  // namespace host
