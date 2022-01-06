// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/frame_sink_provider_impl.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain_process_host.h"

namespace host {

FrameSinkProviderImpl::FrameSinkProviderImpl(Domain* domain, int32_t process_id)
    : domain_(domain), process_id_(process_id), binding_(this) {}

FrameSinkProviderImpl::~FrameSinkProviderImpl() = default;

void FrameSinkProviderImpl::Bind(common::mojom::FrameSinkProviderRequest request) {
  if (binding_.is_bound()) {
    DLOG(ERROR) << "Received multiple requests for FrameSinkProvider. "
                << "There should be only one instance per renderer.";
    return;
  }
  binding_.Bind(std::move(request));
}

void FrameSinkProviderImpl::Unbind() {
  binding_.Close();
}

// void FrameSinkProviderImpl::CreateForWidget(
//     int32_t widget_id,
//     viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
//     viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
//     common::mojom::RenderFrameMetadataObserverClientRequest
//         render_frame_metadata_observer_client_request,
//     common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer) {
//   ApplicationWindowHost* application_window_host =
//       ApplicationWindowHost::FromID(process_id_, widget_id);
//   if (!application_window_host) {
//     DLOG(ERROR) << "No ApplicationWindowHost exists with id " << widget_id
//                 << " in process " << process_id_;
//     return;
//   }
//   application_window_host->RequestCompositorFrameSink(
//       std::move(compositor_frame_sink_request),
//       std::move(compositor_frame_sink_client),
//       std::move(render_frame_metadata_observer_client_request),
//       std::move(render_frame_metadata_observer));
// }

void FrameSinkProviderImpl::CreateForWidget(
    int32_t widget_id,
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client) {
  ApplicationWindowHost* application_window_host =
    ApplicationWindowHost::FromID(process_id_, widget_id);
  if (!application_window_host) {
    DLOG(ERROR) << "No ApplicationWindowHost exists with id " << widget_id
                << " in process " << process_id_;
    return;
  }
  application_window_host->RequestCompositorFrameSink(
      std::move(compositor_frame_sink_request),
      std::move(compositor_frame_sink_client));
}

void FrameSinkProviderImpl::CreateForService(
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client) {
  DomainProcessHost* domain_process_host = domain_->process();
  if (!domain_process_host) {
    DLOG(ERROR) << "No Domain for process " << process_id_;
    return;
  }
  domain_process_host->RequestCompositorFrameSink(
      std::move(compositor_frame_sink_request),
      std::move(compositor_frame_sink_client));
}

void FrameSinkProviderImpl::RegisterRenderFrameMetadataObserver(
    int32_t widget_id,
    common::mojom::RenderFrameMetadataObserverClientRequest
        render_frame_metadata_observer_client_request,
    common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer) {
  
  ApplicationWindowHost* application_window_host =
    ApplicationWindowHost::FromID(process_id_, widget_id);
  if (!application_window_host) {
    DLOG(ERROR) << "No ApplicationWindowHost exists with id " << widget_id
                << " in process " << process_id_;
    return;
  }
  application_window_host->RegisterRenderFrameMetadataObserver(
      std::move(render_frame_metadata_observer_client_request),
      std::move(render_frame_metadata_observer));
}

}  // namespace host
