// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_COMPOSITOR_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_COMPOSITOR_HELPER_H_

#include <string>
#include <memory>

#include "CompositorCallbacks.h"

#ifdef COUNT
#undef COUNT
#endif

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread.h"
#include "cc/base/switches.h"
//#include "cc/test/test_image_factory.h"
//#include "cc/test/pixel_test_output_surface.h"
//#include "cc/test/test_task_graph_runner.h"
#include "cc/trees/layer_tree_host_client.h"
#include "cc/layers/layer.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_host_single_thread_client.h"
#include "core/shared/common/compositor_dependencies.h"
#include "core/shared/common/compositor_helper.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/frame_sinks/delay_based_time_source.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/test/test_shared_bitmap_manager.h"
//#include "components/viz/service/display/display.h"
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
//#include "ui/compositor/test/in_process_context_provider.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gfx/switches.h"
#include "ui/gl/gl_implementation.h"
#include "ui/gl/gl_utils.h"
#include "ui/gl/test/gl_surface_test_support.h"

#if !defined(GPU_SURFACE_HANDLE_IS_ACCELERATED_WINDOW)
#include "gpu/ipc/common/gpu_surface_tracker.h"
#endif

namespace gpu {
class GLInProcessContext;
class GpuMemoryBufferManager;
class ImageFactory;
}

namespace skia_bindings {
class GrContextForGLES2Interface;
}

// class SingleThreadedCompositorDependencies : public common::CompositorDependencies {
//  public:
//   SingleThreadedCompositorDependencies(scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner);//, bool is_single_threaded);
//   ~SingleThreadedCompositorDependencies() override;

//   bool IsGpuRasterizationForced() override;
//   int GetGpuRasterizationMSAASampleCount() override;
//   bool IsLcdTextEnabled() override;
//   bool IsZeroCopyEnabled() override;
//   bool IsPartialRasterEnabled() override;
//   bool IsGpuMemoryBufferCompositorResourcesEnabled() override;
//   bool IsElasticOverscrollEnabled() override;
//   scoped_refptr<base::SingleThreadTaskRunner> GetCompositorMainThreadTaskRunner() override;
//   scoped_refptr<base::SingleThreadTaskRunner> GetCompositorImplThreadTaskRunner() override;
//   blink::scheduler::WebMainThreadScheduler* GetWebMainThreadScheduler() override;
//   cc::TaskGraphRunner* GetTaskGraphRunner() override;
//   gpu::GpuMemoryBufferManager* GetGpuMemoryBufferManager() override;
//   bool IsThreadedAnimationEnabled() override;
//   bool IsScrollAnimatorEnabled() override;
//   std::unique_ptr<cc::UkmRecorderFactory> CreateUkmRecorderFactory() override;
//   common::CompositorHelper* compositor_helper() override;

//   viz::SharedBitmapManager* GetSharedBitmapManager() override;
//   gpu::ImageFactory* GetImageFactory() override;


//  private:

//   scoped_refptr<base::SingleThreadTaskRunner> GetCompositorThreadTaskRunner();

//   //TODO: we should use the 'Test' flavour only when in single_thread mode
//   //      we need to make this variable, depending if this is single threaded or not
//   //viz::TestSharedBitmapManager shared_bitmap_manager_;
//   //viz::TestGpuMemoryBufferManager gpu_memory_buffer_manager_;
//   //cc::TestImageFactory image_factory_;
//   //cc::TestTaskGraphRunner task_graph_runner_;
//   scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner_;
//   scoped_refptr<base::SingleThreadTaskRunner> main_thread_compositor_task_runner_;
//   std::unique_ptr<base::Thread> compositor_thread_;
   
//   // always true now.. when not single threaded the deps is ApplicationThread
//   //bool is_single_threaded_;

//   common::CompositorHelper helper_;

//   base::WeakPtrFactory<SingleThreadedCompositorDependencies> weak_factory_;
  
//   DISALLOW_COPY_AND_ASSIGN(SingleThreadedCompositorDependencies);
// };

// class DirectOutputSurface : public viz::OutputSurface {
//  public:
//   DirectOutputSurface(
//       scoped_refptr<cc::ContextProvider> context_provider,
//       scoped_refptr<cc::ContextProvider> worker_context_provider);
//   DirectOutputSurface(
//       scoped_refptr<cc::ContextProvider> context_provider);

//   ~DirectOutputSurface() override;

//   // cc::OutputSurface implementation
//   void SwapBuffers(cc::CompositorFrame* frame) override;

//  private:
//   base::WeakPtrFactory<DirectOutputSurface> weak_ptr_factory_;

//   DISALLOW_COPY_AND_ASSIGN(DirectOutputSurface);
// };

class CompositorLayerTreeHostClient : public cc::LayerTreeHostClient,
                                      public cc::LayerTreeHostSingleThreadClient {
public:
  CompositorLayerTreeHostClient(void* payload, CLayerTreeHostSingleThreadClientCbs callbacks);
  ~CompositorLayerTreeHostClient() override;

  void set_client_peer(void* peer);
  
  void WillBeginMainFrame() override;
  void BeginMainFrame(const viz::BeginFrameArgs& args) override;
  void BeginMainFrameNotExpectedSoon() override;
  void BeginMainFrameNotExpectedUntil(base::TimeTicks time) override;
  void DidBeginMainFrame() override;
  void UpdateLayerTreeHost(VisualStateUpdate requested_update) override;
  void ApplyViewportDeltas(
      const gfx::Vector2dF& inner_delta,
      const gfx::Vector2dF& outer_delta,
      const gfx::Vector2dF& elastic_overscroll_delta,
      float page_scale,
      float top_controls_delta) override;
  void RecordWheelAndTouchScrollingCount(
      bool has_scrolled_by_wheel,
      bool has_scrolled_by_touch) override;
  void RequestNewLayerTreeFrameSink() override;
  void DidInitializeLayerTreeFrameSink() override;
  void DidFailToInitializeLayerTreeFrameSink() override;
  void WillCommit() override;
  void DidCommit() override;
  void DidCommitAndDrawFrame() override;
  void DidReceiveCompositorFrameAck() override;
  void DidCompletePageScaleAnimation() override;
 bool IsForSubframe() override;
 // cc::LayerTreeHostSingleThreadClient
 void DidSubmitCompositorFrame() override;
 void DidLoseLayerTreeFrameSink() override;
 void RequestScheduleComposite() override;
 void RequestScheduleAnimation() override;

private:
  void* state_;
  //base::MessageLoop message_loop_;
  //const CLayerTreeHostSingleThreadClientCbs* callbacks_;
  CLayerTreeHostSingleThreadClientCbs callbacks_;

  DISALLOW_COPY_AND_ASSIGN(CompositorLayerTreeHostClient);
};

//class FakeReflector {
 //public:
  //FakeReflector() {}
  //~FakeReflector()  {}
  //void AddMirroringLayer(Layer* layer) {}
  //void OnMirroringCompositorResized() {}
  //void RemoveMirroringLayer(Layer* layer) {}
//};

EXPORT int PaintingControlSettingToInt(cc::ContentLayerClient::PaintingControlSetting status);

#endif
