// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_IMPL_H_
#define CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_IMPL_H_

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "components/viz/common/surfaces/surface_info.h"
#include "components/viz/host/host_frame_sink_client.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/platform/modules/frame_sinks/embedded_frame_sink.mojom.h"

namespace viz {
class HostFrameSinkManager;
}

namespace host {

// The browser owned object for an embedded frame sink in a renderer process.
// Both the embedder and embedded frame sink are in the same renderer. Holds a
// client connection to the renderer that is notified when a new SurfaceId
// activates for the embedded frame sink.
class CONTENT_EXPORT EmbeddedFrameSinkImpl : public viz::HostFrameSinkClient {
 public:
  using DestroyCallback = base::OnceCallback<void()>;

  EmbeddedFrameSinkImpl(viz::HostFrameSinkManager* host_frame_sink_manager,
                        const viz::FrameSinkId& parent_frame_sink_id,
                        const viz::FrameSinkId& frame_sink_id,
                        blink::mojom::EmbeddedFrameSinkClientPtr client,
                        DestroyCallback destroy_callback);
  ~EmbeddedFrameSinkImpl() override;

  const viz::FrameSinkId& frame_sink_id() const { return frame_sink_id_; }
  const viz::LocalSurfaceId& local_surface_id() const {
    return local_surface_id_;
  }

  // Creates a CompositorFrameSink connection to FrameSinkManagerImpl. This
  // should only ever be called once.
  void CreateCompositorFrameSink(
      viz::mojom::CompositorFrameSinkClientPtr client,
      viz::mojom::CompositorFrameSinkRequest request);

  // viz::HostFrameSinkClient implementation.
  void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
  void OnFrameTokenChanged(uint32_t frame_token) override;

 private:
  viz::HostFrameSinkManager* const host_frame_sink_manager_;

  blink::mojom::EmbeddedFrameSinkClientPtr client_;

  // Surface-related state
  const viz::FrameSinkId parent_frame_sink_id_;
  const viz::FrameSinkId frame_sink_id_;
  viz::LocalSurfaceId local_surface_id_;

  bool has_created_compositor_frame_sink_ = false;

  DISALLOW_COPY_AND_ASSIGN(EmbeddedFrameSinkImpl);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_EMBEDDED_FRAME_SINK_IMPL_H_
