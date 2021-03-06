// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_PROVIDER_IMPL_H_
#define CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_PROVIDER_IMPL_H_

#include <memory>

#include "base/containers/flat_map.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding_set.h"
#include "third_party/blink/public/platform/modules/frame_sinks/embedded_frame_sink.mojom.h"

namespace viz {
class HostFrameSinkManager;
}

namespace host {

class EmbeddedFrameSinkImpl;

// Provides embedded frame sinks for a renderer.
class CONTENT_EXPORT EmbeddedFrameSinkProviderImpl
    : public blink::mojom::EmbeddedFrameSinkProvider {
 public:
  EmbeddedFrameSinkProviderImpl(
      viz::HostFrameSinkManager* host_frame_sink_manager,
      uint32_t renderer_client_id);
  ~EmbeddedFrameSinkProviderImpl() override;

  void Add(blink::mojom::EmbeddedFrameSinkProviderRequest request);

  // blink::mojom::EmbeddedFrameSinkProvider implementation.
  void RegisterEmbeddedFrameSink(
      const viz::FrameSinkId& parent_frame_sink_id,
      const viz::FrameSinkId& frame_sink_id,
      blink::mojom::EmbeddedFrameSinkClientPtr client) override;
  void CreateCompositorFrameSink(
      const viz::FrameSinkId& frame_sink_id,
      viz::mojom::CompositorFrameSinkClientPtr client,
      viz::mojom::CompositorFrameSinkRequest request) override;
  void CreateSimpleCompositorFrameSink(
      const viz::FrameSinkId& parent_frame_sink_id,
      const viz::FrameSinkId& frame_sink_id,
      blink::mojom::EmbeddedFrameSinkClientPtr embedded_frame_sink_client,
      viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
      viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request)
      override;

 private:
  friend class EmbeddedFrameSinkProviderImplTest;

  // Destroys the |frame_sink_map_| entry for |frame_sink_id|. Provided as
  // a callback to each EmbeddedFrameSinkImpl so they can destroy themselves.
  void DestroyEmbeddedFrameSink(viz::FrameSinkId frame_sink_id);

  viz::HostFrameSinkManager* const host_frame_sink_manager_;

  // FrameSinkIds for embedded frame sinks must use the renderer client id.
  const uint32_t renderer_client_id_;

  mojo::BindingSet<blink::mojom::EmbeddedFrameSinkProvider> bindings_;

  base::flat_map<viz::FrameSinkId, std::unique_ptr<EmbeddedFrameSinkImpl>>
      frame_sink_map_;

  DISALLOW_COPY_AND_ASSIGN(EmbeddedFrameSinkProviderImpl);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_PROVIDER_IMPL_H_
