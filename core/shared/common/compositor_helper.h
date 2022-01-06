// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_COMPOSITOR_HELPER_H_
#define MUMBA_COMMON_COMPOSITOR_HELPER_H_

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread.h"
#include "cc/base/switches.h"
#include "cc/test/test_image_factory.h"
#include "cc/test/pixel_test_output_surface.h"
#include "cc/test/test_task_graph_runner.h"
#include "cc/trees/layer_tree_host_client.h"
#include "cc/layers/layer.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_host_single_thread_client.h"
#include "core/shared/common/compositor_dependencies.h"
#include "core/shared/common/content_export.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/frame_sinks/delay_based_time_source.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/host/host_frame_sink_manager.h"
//#include "components/viz/test/test_shared_bitmap_manager.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/display/display_scheduler.h"
#include "components/viz/service/display/output_surface_client.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/frame_sinks/direct_layer_tree_frame_sink.h"
//#include "components/viz/test/test_gpu_memory_buffer_manager.h"
//#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "gpu/command_buffer/common/context_creation_attribs.h"
#include "gpu/ipc/common/surface_handle.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/context_creation_attribs.h"
#include "ui/compositor/compositor_switches.h"
#include "ui/compositor/layer.h"
#include "ui/compositor/reflector.h"
#include "ui/compositor/test/in_process_context_provider.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gfx/switches.h"
#include "ui/gl/gl_implementation.h"
#include "ui/gl/gl_utils.h"
//#include "ui/gl/test/gl_surface_test_support.h"

class DirectOutputSurface;
class InProcessContextProvider;
class HostFrameSinkManagerWrapper;
class FrameSinkManagerImplWrapper;

namespace common {

class CONTENT_EXPORT CompositorHelper {
public:
  CompositorHelper(CompositorDependencies* deps);
  ~CompositorHelper();

  scoped_refptr<base::SingleThreadTaskRunner> GetCompositorThreadTaskRunner();
  bool is_single_threaded() const;

  void SetLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink);
  cc::LayerTreeHost* CreateLayerTreeHostThreaded(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner);
  cc::LayerTreeHost* CreateLayerTreeHostSingleThreaded(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client);
  void SetRootLayer(cc::LayerTreeHost* layer_tree_host, scoped_refptr<cc::Layer> layer);

  viz::DirectLayerTreeFrameSink* CreateDirectLayerTreeFrameSink(
    const viz::FrameSinkId& frame_sink_id,
    viz::CompositorFrameSinkSupportManager* support_manager,
    viz::FrameSinkManagerImpl* frame_sink_manager,
    viz::Display* display,
    //mojom::DisplayClient* display_client,
    scoped_refptr<viz::ContextProvider> context_provider,
    scoped_refptr<viz::RasterContextProvider> worker_context_provider,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager);

  DirectOutputSurface* CreateDirectOutputSurface(scoped_refptr<InProcessContextProvider> provider);

  viz::Display* CreateDisplay(
    viz::SharedBitmapManager* bitmap_manager,
    const viz::RendererSettings& settings,
    const viz::FrameSinkId& frame_sink_id,
    std::unique_ptr<viz::OutputSurface> output_surface,
    std::unique_ptr<viz::DisplayScheduler> scheduler,
    scoped_refptr<base::SingleThreadTaskRunner> current_task_runner);

  FrameSinkManagerImplWrapper* CreateFrameSinkManagerImpl();
  HostFrameSinkManagerWrapper* CreateHostFrameSinkManagerWrapper();
 
  void SynchronouslyComposite(
    cc::LayerTreeHost* layer_tree_host,
    bool raster,
    std::unique_ptr<cc::SwapPromise> swap_promise);

  void SynchronouslyCompositeImpl(
    cc::LayerTreeHost* layer_tree_host,
    bool raster,
    std::unique_ptr<cc::SwapPromise> swap_promise);

  void QueueImageDecode(cc::LayerTreeHost* layer_tree_host, void* peer, SkImage* image, void(*callback)(void*, int));

  void RequestNewLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, void* peer, void(*callback)(void*));
  
  std::unique_ptr<viz::CopyOutputRequest> CreateCopyOutputRequestWithBitmapRequest(
    void* state,
    cc::LayerTreeHost* layer_tree_host, 
    void(*callback)(void*, void*));

private:

  void OnQueueImageDecode(void* peer, void(*callback)(void*, int), bool result);
  void OnRequestNewLayerTreeFrameSink(void* peer, void(*callback)(void*));
  void OnCreateCopyOutputRequest(void *state, void(*callback)(void*, void*), const SkBitmap& bitmap);

  void CreateLayerTreeHostThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner, base::WaitableEvent* event, cc::LayerTreeHost** out);
  void CreateLayerTreeHostSingleThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client, base::WaitableEvent* event, cc::LayerTreeHost** out);

  void SetRootLayerOnCompositor(cc::LayerTreeHost* layer_tree_host, cc::Layer* layer);
  
  void CreateDirectLayerTreeFrameSinkOnCompositor(
    const viz::FrameSinkId& frame_sink_id,
    viz::CompositorFrameSinkSupportManager* support_manager,
    viz::FrameSinkManagerImpl* frame_sink_manager,
    viz::Display* display,
    //mojom::DisplayClient* display_client,
    scoped_refptr<viz::ContextProvider> context_provider,
    scoped_refptr<viz::RasterContextProvider> worker_context_provider,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    base::WaitableEvent* event,
    viz::DirectLayerTreeFrameSink** out);

  void CreateDirectOutputSurfaceOnCompositor(scoped_refptr<InProcessContextProvider> provider, base::WaitableEvent* event, DirectOutputSurface** out);
 
  void CreateDisplayOnCompositor(
    viz::SharedBitmapManager* bitmap_manager,
    const viz::RendererSettings& settings,
    const viz::FrameSinkId& frame_sink_id,
    std::unique_ptr<viz::OutputSurface> output_surface,
    std::unique_ptr<viz::DisplayScheduler> scheduler,
    scoped_refptr<base::SingleThreadTaskRunner> current_task_runner,
    base::WaitableEvent* event,
    viz::Display** out);

  void SetLayerTreeFrameSinkOnCompositor(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink);

  void CreateFrameSinkManagerImplOnCompositor(base::WaitableEvent* event, FrameSinkManagerImplWrapper** out);
  
  void CreateHostFrameSinkManagerWrapperOnCompositor(base::WaitableEvent* event, HostFrameSinkManagerWrapper** out);
  
  CompositorDependencies* deps_;

  base::WeakPtrFactory<CompositorHelper> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(CompositorHelper);
};

}

#endif