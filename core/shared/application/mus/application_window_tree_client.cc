// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/mus/application_window_tree_client.h"

#include <map>

#include "base/command_line.h"
#include "base/lazy_instance.h"
#include "cc/base/switches.h"
#include "components/viz/client/client_layer_tree_frame_sink.h"
#include "components/viz/client/hit_test_data_provider.h"
#include "components/viz/client/hit_test_data_provider_draw_quad.h"
#include "components/viz/client/hit_test_data_provider_surface_layer.h"
#include "components/viz/client/local_surface_id_provider.h"
#include "components/viz/common/features.h"
#include "core/shared/application/mus/mus_embedded_frame.h"
#include "core/shared/application/mus/mus_embedded_frame_delegate.h"
#include "core/shared/application/render_frame_proxy.h"
#include "ui/base/ui_base_features.h"

namespace application {

namespace {

using ConnectionMap = std::map<int, ApplicationWindowTreeClient*>;
base::LazyInstance<ConnectionMap>::Leaky g_connections =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
void ApplicationWindowTreeClient::CreateIfNecessary(int routing_id) {
  if (!features::IsMusEnabled() || Get(routing_id))
    return;
  ApplicationWindowTreeClient* connection =
      new ApplicationWindowTreeClient(routing_id);
  g_connections.Get().insert(std::make_pair(routing_id, connection));
}

// static
void ApplicationWindowTreeClient::Destroy(int routing_id) {
  delete Get(routing_id);
}

// static
ApplicationWindowTreeClient* ApplicationWindowTreeClient::Get(int routing_id) {
  auto it = g_connections.Get().find(routing_id);
  if (it != g_connections.Get().end())
    return it->second;
  return nullptr;
}

void ApplicationWindowTreeClient::Bind(
    ui::mojom::WindowTreeClientRequest request,
    mojom::ApplicationWindowTreeClientRequest
        application_widget_window_tree_client_request) {
  // Bind() may be called multiple times.
  binding_.Close();
  application_widget_window_tree_client_binding_.Close();

  binding_.Bind(std::move(request));
  application_widget_window_tree_client_binding_.Bind(
      std::move(application_widget_window_tree_client_request));
}

std::unique_ptr<MusEmbeddedFrame>
ApplicationWindowTreeClient::OnRenderFrameProxyCreated(
    RenderFrameProxy* render_frame_proxy) {
  auto iter = pending_frames_.find(render_frame_proxy->routing_id());
  if (iter == pending_frames_.end())
    return nullptr;

  const base::UnguessableToken token = iter->second;
  pending_frames_.erase(iter);
  return CreateMusEmbeddedFrame(render_frame_proxy, token);
}

void ApplicationWindowTreeClient::SetVisible(bool visible) {
  if (visible_ == visible)
    return;

  visible_ = visible;
  if (tree_) {
    tree_->SetWindowVisibility(GetAndAdvanceNextChangeId(), root_window_id_,
                               visible);
  }
}

void ApplicationWindowTreeClient::RequestLayerTreeFrameSink(
    scoped_refptr<viz::ContextProvider> context_provider,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    const LayerTreeFrameSinkCallback& callback) {
  DCHECK(pending_layer_tree_frame_sink_callback_.is_null());
  if (tree_) {
    RequestLayerTreeFrameSinkInternal(std::move(context_provider),
                                      gpu_memory_buffer_manager, callback);
    return;
  }

  pending_context_provider_ = std::move(context_provider);
  pending_gpu_memory_buffer_manager_ = gpu_memory_buffer_manager;
  pending_layer_tree_frame_sink_callback_ = callback;
}

std::unique_ptr<MusEmbeddedFrame>
ApplicationWindowTreeClient::CreateMusEmbeddedFrame(
    MusEmbeddedFrameDelegate* delegate,
    const base::UnguessableToken& token) {
  std::unique_ptr<MusEmbeddedFrame> frame = base::WrapUnique<MusEmbeddedFrame>(
      new MusEmbeddedFrame(this, delegate, ++next_window_id_, token));
  embedded_frames_.insert(frame.get());
  return frame;
}

ApplicationWindowTreeClient::ApplicationWindowTreeClient(int routing_id)
    : routing_id_(routing_id),
      binding_(this),
      application_widget_window_tree_client_binding_(this) {}

ApplicationWindowTreeClient::~ApplicationWindowTreeClient() {
  g_connections.Get().erase(routing_id_);
  DCHECK(embedded_frames_.empty());
}

void ApplicationWindowTreeClient::RequestLayerTreeFrameSinkInternal(
    scoped_refptr<viz::ContextProvider> context_provider,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    const LayerTreeFrameSinkCallback& callback) {
  viz::mojom::CompositorFrameSinkPtrInfo sink_info;
  viz::mojom::CompositorFrameSinkRequest sink_request =
      mojo::MakeRequest(&sink_info);
  viz::mojom::CompositorFrameSinkClientPtr client;
  viz::mojom::CompositorFrameSinkClientRequest client_request =
      mojo::MakeRequest(&client);
  viz::ClientLayerTreeFrameSink::InitParams params;
  params.gpu_memory_buffer_manager = gpu_memory_buffer_manager;
  params.pipes.compositor_frame_sink_info = std::move(sink_info);
  params.pipes.client_request = std::move(client_request);
  params.local_surface_id_provider =
      std::make_unique<viz::DefaultLocalSurfaceIdProvider>();
  params.enable_surface_synchronization = true;
  if (features::IsVizHitTestingDrawQuadEnabled()) {
    params.hit_test_data_provider =
        std::make_unique<viz::HitTestDataProviderDrawQuad>(
            true /* should_ask_for_child_region */);
  } else if (features::IsVizHitTestingSurfaceLayerEnabled()) {
    params.hit_test_data_provider =
        std::make_unique<viz::HitTestDataProviderSurfaceLayer>();
  }
  auto frame_sink = std::make_unique<viz::ClientLayerTreeFrameSink>(
      std::move(context_provider), nullptr /* worker_context_provider */,
      &params);
  tree_->AttachCompositorFrameSink(root_window_id_, std::move(sink_request),
                                   std::move(client));
  callback.Run(std::move(frame_sink));
}

void ApplicationWindowTreeClient::OnEmbeddedFrameDestroyed(
    MusEmbeddedFrame* frame) {
  embedded_frames_.erase(embedded_frames_.find(frame));
}

void ApplicationWindowTreeClient::Embed(uint32_t frame_routing_id,
                                     const base::UnguessableToken& token) {
  RenderFrameProxy* render_frame_proxy =
      RenderFrameProxy::FromRoutingID(frame_routing_id);
  if (!render_frame_proxy) {
    pending_frames_[frame_routing_id] = token;
    return;
  }
  render_frame_proxy->SetMusEmbeddedFrame(
      CreateMusEmbeddedFrame(render_frame_proxy, token));
}

void ApplicationWindowTreeClient::OnEmbedFromToken(
    const base::UnguessableToken& token,
    ui::mojom::WindowDataPtr root,
    int64_t display_id,
    const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  // Renderers don't use ScheduleEmbedForExistingClient(), so this path should
  // never be hit.
  NOTREACHED();
}

void ApplicationWindowTreeClient::DestroyFrame(uint32_t frame_routing_id) {
  pending_frames_.erase(frame_routing_id);
}

void ApplicationWindowTreeClient::OnEmbed(
    ui::mojom::WindowDataPtr root,
    ui::mojom::WindowTreePtr tree,
    int64_t display_id,
    ui::Id focused_window_id,
    bool drawn,
    const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  const bool is_reembed = tree_.is_bound();
  if (is_reembed) {
    for (MusEmbeddedFrame* frame : embedded_frames_)
      frame->OnTreeWillChange();
  }
  root_window_id_ = root->window_id;

  tree_ = std::move(tree);
  tree_->SetWindowVisibility(GetAndAdvanceNextChangeId(), root_window_id_,
                             visible_);
  if (!is_reembed) {
    for (MusEmbeddedFrame* frame : embedded_frames_)
      frame->OnTreeAvailable();
  }

  if (!pending_layer_tree_frame_sink_callback_.is_null()) {
    RequestLayerTreeFrameSinkInternal(std::move(pending_context_provider_),
                                      pending_gpu_memory_buffer_manager_,
                                      pending_layer_tree_frame_sink_callback_);
    pending_context_provider_ = nullptr;
    pending_gpu_memory_buffer_manager_ = nullptr;
    pending_layer_tree_frame_sink_callback_.Reset();
  }
}

void ApplicationWindowTreeClient::OnEmbeddedAppDisconnected(ui::Id window_id) {
  // TODO(sad): Embedded mus-client (oopif) is gone. Figure out what to do.
}

void ApplicationWindowTreeClient::OnUnembed(ui::Id window_id) {
  // At this point all operations will fail. We don't delete this as it would
  // mean all consumers have to null check (as would MusEmbeddedFrames).
}

void ApplicationWindowTreeClient::OnCaptureChanged(ui::Id new_capture_window_id,
                                                ui::Id old_capture_window_id) {}

void ApplicationWindowTreeClient::OnFrameSinkIdAllocated(
    ui::Id window_id,
    const viz::FrameSinkId& frame_sink_id) {
  // When mus is not hosting viz FrameSinkIds come from the browser, so we
  // ignore them here.
  if (!base::FeatureList::IsEnabled(features::kMash))
    return;

  for (MusEmbeddedFrame* embedded_frame : embedded_frames_) {
    if (embedded_frame->window_id_ == window_id) {
      embedded_frame->delegate_->OnMusEmbeddedFrameSinkIdAllocated(
          frame_sink_id);
      return;
    }
  }
}

void ApplicationWindowTreeClient::OnTopLevelCreated(
    uint32_t change_id,
    ui::mojom::WindowDataPtr data,
    int64_t display_id,
    bool drawn,
    const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  NOTREACHED();
}

void ApplicationWindowTreeClient::OnWindowBoundsChanged(
    ui::Id window_id,
    const gfx::Rect& old_bounds,
    const gfx::Rect& new_bounds,
    const base::Optional<viz::LocalSurfaceId>& local_surface_id) {}

void ApplicationWindowTreeClient::OnWindowTransformChanged(
    ui::Id window_id,
    const gfx::Transform& old_transform,
    const gfx::Transform& new_transform) {}

void ApplicationWindowTreeClient::OnClientAreaChanged(
    ui::Id window_id,
    const gfx::Insets& new_client_area,
    const std::vector<gfx::Rect>& new_additional_client_areas) {}

void ApplicationWindowTreeClient::OnTransientWindowAdded(
    ui::Id window_id,
    ui::Id transient_window_id) {}

void ApplicationWindowTreeClient::OnTransientWindowRemoved(
    ui::Id window_id,
    ui::Id transient_window_id) {}

void ApplicationWindowTreeClient::OnWindowHierarchyChanged(
    ui::Id window_id,
    ui::Id old_parent_id,
    ui::Id new_parent_id,
    std::vector<ui::mojom::WindowDataPtr> windows) {}

void ApplicationWindowTreeClient::OnWindowReordered(
    ui::Id window_id,
    ui::Id relative_window_id,
    ui::mojom::OrderDirection direction) {}

void ApplicationWindowTreeClient::OnWindowDeleted(ui::Id window_id) {
  // See comments on OnUnembed() for why we do nothing here.
}

void ApplicationWindowTreeClient::OnWindowVisibilityChanged(ui::Id window_id,
                                                         bool visible) {}

void ApplicationWindowTreeClient::OnWindowOpacityChanged(ui::Id window_id,
                                                      float old_opacity,
                                                      float new_opacity) {}

void ApplicationWindowTreeClient::OnWindowParentDrawnStateChanged(ui::Id window_id,
                                                               bool drawn) {}

void ApplicationWindowTreeClient::OnWindowSharedPropertyChanged(
    ui::Id window_id,
    const std::string& name,
    const base::Optional<std::vector<uint8_t>>& new_data) {}

void ApplicationWindowTreeClient::OnWindowInputEvent(
    uint32_t event_id,
    ui::Id window_id,
    int64_t display_id,
    ui::Id display_root_window_id,
    const gfx::PointF& event_location_in_screen_pixel_layout,
    std::unique_ptr<ui::Event> event,
    bool matches_pointer_watcher) {
  NOTREACHED();
}

void ApplicationWindowTreeClient::OnPointerEventObserved(
    std::unique_ptr<ui::Event> event,
    ui::Id window_id,
    int64_t display_id) {
  NOTREACHED();
}

void ApplicationWindowTreeClient::OnWindowFocused(ui::Id focused_window_id) {}

void ApplicationWindowTreeClient::OnWindowCursorChanged(ui::Id window_id,
                                                     ui::CursorData cursor) {}

void ApplicationWindowTreeClient::OnWindowSurfaceChanged(
    ui::Id window_id,
    const viz::SurfaceInfo& surface_info) {
  DCHECK(base::FeatureList::IsEnabled(features::kMash));
  for (MusEmbeddedFrame* embedded_frame : embedded_frames_) {
    if (embedded_frame->window_id_ == window_id) {
      embedded_frame->delegate_->OnMusEmbeddedFrameSurfaceChanged(surface_info);
      return;
    }
  }
}

void ApplicationWindowTreeClient::OnDragDropStart(
    const base::flat_map<std::string, std::vector<uint8_t>>& mime_data) {}

void ApplicationWindowTreeClient::OnDragEnter(ui::Id window_id,
                                           uint32_t event_flags,
                                           const gfx::Point& position,
                                           uint32_t effect_bitmask,
                                           OnDragEnterCallback callback) {}

void ApplicationWindowTreeClient::OnDragOver(ui::Id window_id,
                                          uint32_t event_flags,
                                          const gfx::Point& position,
                                          uint32_t effect_bitmask,
                                          OnDragOverCallback callback) {}

void ApplicationWindowTreeClient::OnDragLeave(ui::Id window_id) {}

void ApplicationWindowTreeClient::OnCompleteDrop(ui::Id window_id,
                                              uint32_t event_flags,
                                              const gfx::Point& position,
                                              uint32_t effect_bitmask,
                                              OnCompleteDropCallback callback) {
}

void ApplicationWindowTreeClient::OnPerformDragDropCompleted(
    uint32_t change_id,
    bool success,
    uint32_t action_taken) {}

void ApplicationWindowTreeClient::OnDragDropDone() {}

void ApplicationWindowTreeClient::OnChangeCompleted(uint32_t change_id,
                                                 bool success) {
  // Don't DCHECK success, as it's possible we'll try to do some operations
  // after unembedded, which means all operations will fail. Additionally
  // setting the window visibility may fail for the root frame (the browser
  // controls the visibility of the root frame).
}

void ApplicationWindowTreeClient::RequestClose(ui::Id window_id) {}

void ApplicationWindowTreeClient::GetWindowManager(
    mojo::AssociatedInterfaceRequest<ui::mojom::WindowManager> internal) {
  NOTREACHED();
}

}  // namespace application
