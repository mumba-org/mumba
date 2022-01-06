// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/compositor_helper.h"

#include "core/shared/common/compositor/direct_output_surface.h"
#include "core/shared/common/compositor/frame_sink_manager_impl_wrapper.h"
#include "core/shared/common/compositor/host_frame_sink_manager_wrapper.h"
#include "core/shared/common/compositor/in_process_context_provider.h"
#include "components/viz/common/gpu/context_cache_controller.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/paint/paint_image_builder.h"
#include "gpu/command_buffer/client/gles2_implementation.h"
#include "gpu/command_buffer/client/raster_implementation_gles.h"
#include "gpu/command_buffer/client/shared_memory_limits.h"
#include "gpu/ipc/gl_in_process_context.h"
#include "gpu/skia_bindings/grcontext_for_gles2_interface.h"
#include "third_party/skia/include/gpu/GrContext.h"
#include "third_party/skia/include/gpu/gl/GrGLInterface.h"

namespace common {

CompositorHelper::CompositorHelper(CompositorDependencies* deps):
 deps_(deps),
 weak_factory_(this) {

}

CompositorHelper::~CompositorHelper() {

}


bool CompositorHelper::is_single_threaded() const {
  return deps_->GetCompositorImplThreadTaskRunner() == nullptr;
}

scoped_refptr<base::SingleThreadTaskRunner> CompositorHelper::GetCompositorThreadTaskRunner() {
  return is_single_threaded() ? deps_->GetCompositorMainThreadTaskRunner() : deps_->GetCompositorImplThreadTaskRunner();
}

viz::DirectLayerTreeFrameSink* CompositorHelper::CreateDirectLayerTreeFrameSink(
  const viz::FrameSinkId& frame_sink_id,
  viz::CompositorFrameSinkSupportManager* support_manager,
  viz::FrameSinkManagerImpl* frame_sink_manager,
  viz::Display* display,
  //mojom::DisplayClient* display_client,
  scoped_refptr<viz::ContextProvider> context_provider,
  scoped_refptr<viz::RasterContextProvider> worker_context_provider,
  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
  gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager) {

  viz::DirectLayerTreeFrameSink* result = nullptr;

  if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
    base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
      base::BindOnce(&CompositorHelper::CreateDirectLayerTreeFrameSinkOnCompositor,
        base::Unretained(this),
        frame_sink_id, 
        base::Unretained(support_manager),
        base::Unretained(frame_sink_manager),
        base::Unretained(display),
        context_provider,
        worker_context_provider,
        compositor_task_runner,
        base::Unretained(gpu_memory_buffer_manager),
        base::Unretained(&waiter),
        base::Unretained(&result)));
    waiter.Wait();
  } else {
    CreateDirectLayerTreeFrameSinkOnCompositor(
      frame_sink_id, support_manager, frame_sink_manager,
      display, context_provider, worker_context_provider,
      compositor_task_runner, gpu_memory_buffer_manager, nullptr, &result);
  }
  DCHECK(result);  
  return result;
}

void CompositorHelper::CreateDirectLayerTreeFrameSinkOnCompositor(
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
  viz::DirectLayerTreeFrameSink** out) {

  if (worker_context_provider) {
    worker_context_provider->BindToCurrentThread();
  }

  *out = new viz::DirectLayerTreeFrameSink(
    frame_sink_id,
    support_manager,
    frame_sink_manager,
    display,
    //display_client,
    nullptr,
    context_provider,
    worker_context_provider,
    compositor_task_runner,
    gpu_memory_buffer_manager,  
    false);
  if (event) {
    event->Signal();
  }
}

DirectOutputSurface* CompositorHelper::CreateDirectOutputSurface(scoped_refptr<InProcessContextProvider> context_provider) {
  DirectOutputSurface* result = nullptr;
 
 if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
   base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
   GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
    base::BindOnce(&CompositorHelper::CreateDirectOutputSurfaceOnCompositor,
      base::Unretained(this),
      context_provider,
      base::Unretained(&waiter),
      base::Unretained(&result)));

   waiter.Wait();
 } else {
   CreateDirectOutputSurfaceOnCompositor(context_provider, nullptr, &result);
 }
 DCHECK(result);  
 return result;
}

void CompositorHelper::SetLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink) {
  if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
    GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
        base::BindOnce(&CompositorHelper::SetLayerTreeFrameSinkOnCompositor,
          base::Unretained(this),
          base::Unretained(layer_tree_host),
          base::Passed(std::move(frame_sink))));
  } else {
    SetLayerTreeFrameSinkOnCompositor(layer_tree_host, std::move(frame_sink));
  } 
}

void CompositorHelper::SetLayerTreeFrameSinkOnCompositor(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink) {
  layer_tree_host->SetLayerTreeFrameSink(std::move(frame_sink));
}

void CompositorHelper::CreateDirectOutputSurfaceOnCompositor(scoped_refptr<InProcessContextProvider> context_provider, base::WaitableEvent* event, DirectOutputSurface** out) {
    *out = new DirectOutputSurface(context_provider);
    if (event) {
      event->Signal();
    }
}

cc::LayerTreeHost* CompositorHelper::CreateLayerTreeHostThreaded(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner) {
  //cc::LayerTreeHost* result = nullptr;
   
  //if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
  //  base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
  //  GetCompositorThreadTaskRunner()->PostTask(
  //   FROM_HERE, 
  //   base::BindOnce(&CompositorHelper::CreateLayerTreeHostThreadedOnCompositor,
  //    base::Unretained(this),
  //    base::Unretained(params),
  //    thread_task_runner,
  //    base::Unretained(&waiter),
  //    base::Unretained(&result)));
  //
  //  waiter.Wait();
  //} else {
    //CreateLayerTreeHostThreadedOnCompositor(params, thread_task_runner, nullptr, &result);
  //}
  std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateThreaded(thread_task_runner, params);
  //DCHECK(result);  
  //return result;
  return ptr.release();
}

void CompositorHelper::SetRootLayer(cc::LayerTreeHost* layer_tree_host, scoped_refptr<cc::Layer> layer) {
  // if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
  //   GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
  //     base::BindOnce(&CompositorHelper::SetRootLayerOnCompositor,
  //       base::Unretained(this),
  //       base::Unretained(layer_tree_host),
  //       base::Unretained(layer.get())));
  // } else {
    SetRootLayerOnCompositor(layer_tree_host, layer.get());
  //}
}

cc::LayerTreeHost* CompositorHelper::CreateLayerTreeHostSingleThreaded(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client) {
  cc::LayerTreeHost* result = nullptr;
   
   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
     base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
     params->main_task_runner = GetCompositorThreadTaskRunner();
     GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
      base::BindOnce(&CompositorHelper::CreateLayerTreeHostSingleThreadedOnCompositor,
        base::Unretained(this),
        base::Unretained(params),
        base::Unretained(client),
        base::Unretained(&waiter),
        base::Unretained(&result)));

     waiter.Wait();
   } else {
     params->main_task_runner = deps_->GetCompositorMainThreadTaskRunner();
     CreateLayerTreeHostSingleThreadedOnCompositor(params, client, nullptr, &result);
   }
   DCHECK(result);  
   return result;
}

void CompositorHelper::SetRootLayerOnCompositor(cc::LayerTreeHost* layer_tree_host, cc::Layer* layer) {
  scoped_refptr<cc::Layer> layer_ptr(layer);
  layer_tree_host->SetRootLayer(layer_ptr);
}

void CompositorHelper::CreateLayerTreeHostThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner, base::WaitableEvent* event, cc::LayerTreeHost** out) {
  std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateThreaded(thread_task_runner, params);
  *out = ptr.release();
  if (event) {
    event->Signal();
  }
}

void CompositorHelper::CreateLayerTreeHostSingleThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client, base::WaitableEvent* event, cc::LayerTreeHost** out) {
  std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateSingleThreaded(client, params);
  *out = ptr.release();
  if (event) {
    event->Signal();
  }
}
  

viz::Display* CompositorHelper::CreateDisplay(
    viz::SharedBitmapManager* bitmap_manager,
    const viz::RendererSettings& settings,
    const viz::FrameSinkId& frame_sink_id,
    std::unique_ptr<viz::OutputSurface> output_surface,
    std::unique_ptr<viz::DisplayScheduler> scheduler,
    scoped_refptr<base::SingleThreadTaskRunner> current_task_runner) {
    
    viz::Display* result = nullptr;
   
   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
     base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
        base::BindOnce(&CompositorHelper::CreateDisplayOnCompositor,
          base::Unretained(this),
          base::Unretained(bitmap_manager),
          settings,
          frame_sink_id,
          base::Passed(std::move(output_surface)),
          base::Passed(std::move(scheduler)),
          current_task_runner,
          base::Unretained(&waiter),
          base::Unretained(&result)));
      waiter.Wait();
   } else {
     CreateDisplayOnCompositor(
       bitmap_manager, 
       settings, 
       frame_sink_id, 
       std::move(output_surface), 
       std::move(scheduler), 
       current_task_runner,
       nullptr,
       &result);
   }
   
   DCHECK(result);  
   return result;
}

void CompositorHelper::CreateDisplayOnCompositor(
    viz::SharedBitmapManager* bitmap_manager,
    const viz::RendererSettings& settings,
    const viz::FrameSinkId& frame_sink_id,
    std::unique_ptr<viz::OutputSurface> output_surface,
    std::unique_ptr<viz::DisplayScheduler> scheduler,
    scoped_refptr<base::SingleThreadTaskRunner> current_task_runner,
    base::WaitableEvent* event,
    viz::Display** out) {
  
  *out = new viz::Display(
      bitmap_manager, settings, frame_sink_id,
      std::move(output_surface), std::move(scheduler),
      current_task_runner);
  
  if (event) {
    event->Signal();
  }
}

FrameSinkManagerImplWrapper* CompositorHelper::CreateFrameSinkManagerImpl() {
  FrameSinkManagerImplWrapper* result = nullptr;
   
  if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
     base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
        base::BindOnce(&CompositorHelper::CreateFrameSinkManagerImplOnCompositor,
          base::Unretained(this),
          base::Unretained(&waiter),
          base::Unretained(&result)));
      waiter.Wait();
   } else {
     CreateFrameSinkManagerImplOnCompositor(
       nullptr,
       &result);
   }
   
   DCHECK(result);  
   return result;
}

void CompositorHelper::CreateFrameSinkManagerImplOnCompositor(base::WaitableEvent* event, FrameSinkManagerImplWrapper** out) {
  *out = new FrameSinkManagerImplWrapper();
  if (event) {
    event->Signal();
  }
}

HostFrameSinkManagerWrapper* CompositorHelper::CreateHostFrameSinkManagerWrapper() {
  HostFrameSinkManagerWrapper* result = nullptr;
   
  if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
     base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      deps_->GetCompositorImplThreadTaskRunner()->PostTask(FROM_HERE, 
        base::BindOnce(&CompositorHelper::CreateHostFrameSinkManagerWrapperOnCompositor,
          base::Unretained(this),
          base::Unretained(&waiter),
          base::Unretained(&result)));
      waiter.Wait();
   } else {
     CreateHostFrameSinkManagerWrapperOnCompositor(
       nullptr,
       &result);
   }
   
   DCHECK(result);  
   return result;
}

void CompositorHelper::CreateHostFrameSinkManagerWrapperOnCompositor(base::WaitableEvent* event, HostFrameSinkManagerWrapper** out) {
  *out = new HostFrameSinkManagerWrapper();
  if (event) {
    event->Signal();
  }
}

void CompositorHelper::SynchronouslyComposite(
    cc::LayerTreeHost* layer_tree_host,
    bool raster,
    std::unique_ptr<cc::SwapPromise> swap_promise) {
    layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CompositorHelper::SynchronouslyCompositeImpl,
                       weak_factory_.GetWeakPtr(),
                       base::Unretained(layer_tree_host),
                       raster, 
                       base::Passed(std::move(swap_promise))));
}

void CompositorHelper::SynchronouslyCompositeImpl(
    cc::LayerTreeHost* layer_tree_host,
    bool raster,
    std::unique_ptr<cc::SwapPromise> swap_promise) {
  if (!layer_tree_host->IsVisible())
    return;

  if (swap_promise) {
    // Force a redraw to ensure that the copy swap promise isn't cancelled due
    // to no damage.
    layer_tree_host->SetNeedsCommitWithForcedRedraw();
    layer_tree_host->QueueSwapPromise(std::move(swap_promise));
  }

  layer_tree_host->Composite(base::TimeTicks::Now(), raster);
}

void CompositorHelper::QueueImageDecode(cc::LayerTreeHost* layer_tree_host, void* peer, SkImage* image, void(*callback)(void*, int)) {
  cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
                        .set_image(sk_ref_sp(image), cc::PaintImage::GetNextContentId())
                        .TakePaintImage();
  layer_tree_host->QueueImageDecode(
    paint_image, 
    base::Bind(&CompositorHelper::OnQueueImageDecode, 
      weak_factory_.GetWeakPtr(), 
      base::Unretained(peer),
      base::Unretained(callback)));
}

void CompositorHelper::RequestNewLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, void* peer, void(*callback)(void*)) {
  layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner()->PostTask(
      FROM_HERE,
      base::Bind(&CompositorHelper::OnRequestNewLayerTreeFrameSink,
                  weak_factory_.GetWeakPtr(),
                  base::Unretained(peer),
                  base::Unretained(callback)));
}

std::unique_ptr<viz::CopyOutputRequest> CompositorHelper::CreateCopyOutputRequestWithBitmapRequest(
  void* state,
  cc::LayerTreeHost* layer_tree_host, 
  void(*callback)(void*, void*)) {

  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner =
      layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner();
  std::unique_ptr<viz::CopyOutputRequest> request =
      std::make_unique<viz::CopyOutputRequest>(
          viz::CopyOutputRequest::ResultFormat::RGBA_BITMAP,
          base::BindOnce(
              [](void *state,
                 void(*cb)(void*, void*),
                 scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                 base::WeakPtr<CompositorHelper> weak_ptr,
                 std::unique_ptr<viz::CopyOutputResult> result) {
                task_runner->PostTask(
                    FROM_HERE,
                    base::BindOnce(
                               &CompositorHelper::OnCreateCopyOutputRequest,
                               // not sure, but i think we need a move right here
                               // anyway, i guess the weak ptr const reference wont hurt anyway
                               std::move(weak_ptr),
                               base::Unretained(state),
                               base::Unretained(cb),
                               result->AsSkBitmap()));
              },
              state, callback, std::move(main_thread_task_runner), weak_factory_.GetWeakPtr()));
              //std::move(callback), std::move(main_thread_task_runner)));
  
  return request;
}

void CompositorHelper::OnCreateCopyOutputRequest(void *state, void(*callback)(void*, void*), const SkBitmap& bitmap) {
  DCHECK(callback);
  callback(state, const_cast<SkBitmap *>(&bitmap));
}

void CompositorHelper::OnRequestNewLayerTreeFrameSink(void* peer, void(*callback)(void*)) {
  DCHECK(callback);
  callback(peer);
}

void CompositorHelper::OnQueueImageDecode(void* peer, void(*callback)(void*, int), bool result) {
  DCHECK(callback);
  callback(peer, result ? 1 : 0);
}

}