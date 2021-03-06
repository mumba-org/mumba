// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDER_WIDGET_COMPOSITOR_FRAME_SINK_PROVIDER_H_
#define CONTENT_BROWSER_RENDER_WIDGET_COMPOSITOR_FRAME_SINK_PROVIDER_H_

#include "core/shared/common/frame_sink_provider.mojom.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"

namespace host {
class Domain;
// This class lives in the browser and provides CompositorFrameSink for the
// renderer.
class FrameSinkProviderImpl : public common::mojom::FrameSinkProvider {
 public:
  explicit FrameSinkProviderImpl(Domain* domain, int32_t process_id);
  ~FrameSinkProviderImpl() override;

  void Bind(common::mojom::FrameSinkProviderRequest request);
  void Unbind();

  // mojom::FrameSinkProvider implementation.
  // void CreateForWidget(
  //     int32_t widget_id,
  //     viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
  //     viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
  //     common::mojom::RenderFrameMetadataObserverClientRequest
  //         render_frame_metadata_observer_client_request,
  //     common::mojom::RenderFrameMetadataObserverPtr observer) override;

  // mojom::FrameSinkProvider implementation.
  void CreateForWidget(
      int32_t widget_id,
      viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
      viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client)
      override;
  void CreateForService(
      viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
      viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client)
      override;
  void RegisterRenderFrameMetadataObserver(
      int32_t widget_id,
      common::mojom::RenderFrameMetadataObserverClientRequest
          render_frame_metadata_observer_client_request,
      common::mojom::RenderFrameMetadataObserverPtr observer) override;

 private:
  Domain* domain_;
  const int32_t process_id_;
  mojo::Binding<common::mojom::FrameSinkProvider> binding_;

  DISALLOW_COPY_AND_ASSIGN(FrameSinkProviderImpl);
};

}  // namespace host

#endif  //  CONTENT_BROWSER_RENDER_WIDGET_COMPOSITOR_FRAME_SINK_PROVIDER_H_
