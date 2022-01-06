// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "CompositorHelper.h"

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/gpu/context_cache_controller.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/ukm_manager.h"
#include "cc/paint/paint_image_builder.h"
#include "gpu/command_buffer/client/gles2_implementation.h"
#include "gpu/command_buffer/client/raster_implementation_gles.h"
#include "gpu/command_buffer/client/shared_memory_limits.h"
#include "gpu/ipc/gl_in_process_context.h"
#include "gpu/skia_bindings/grcontext_for_gles2_interface.h"
#include "third_party/skia/include/gpu/GrContext.h"
#include "third_party/skia/include/gpu/gl/GrGLInterface.h"

// SingleThreadedCompositorDependencies::SingleThreadedCompositorDependencies(scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner):
//       main_thread_compositor_task_runner_(compositor_task_runner),
//       helper_(this),
//       weak_factory_(this) {//,
//       //next_surface_id_namespace_(1u),
//       //use_test_surface_(true),
//       //context_factory_for_test_(context_factory_for_test),
//       //surface_manager_(surface_manager) {
        
        
//     base::Thread::Options options;
// #if defined(OS_ANDROID)
//     options.priority = base::ThreadPriority::DISPLAY;
// #endif
//     compositor_thread_.reset(new base::Thread("compositor thread"));
//     bool started = compositor_thread_->StartWithOptions(options);
//     CHECK(started);
//     //blink_platform_impl_->SetCompositorThread(compositor_thread_.get());
//     compositor_task_runner_ = compositor_thread_->task_runner();
//     compositor_task_runner_->PostTask(
//         FROM_HERE,
//         base::BindOnce(base::IgnoreResult(&base::ThreadRestrictions::SetIOAllowed),
//                    false));        
        
// }

// SingleThreadedCompositorDependencies::~SingleThreadedCompositorDependencies() {
//   main_thread_compositor_task_runner_ = nullptr;
//   compositor_task_runner_ = nullptr;
//   compositor_thread_->Stop();
//   compositor_thread_.reset();
// }

// // std::vector<unsigned> SingleThreadedCompositorDependencies::GetImageTextureTargets() {
// //   return std::vector<unsigned>();
// // }

// // uint32_t SingleThreadedCompositorDependencies::GetImageTextureTarget(gfx::BufferFormat format,
// //                                                        gfx::BufferUsage usage) const {
// //  return GL_TEXTURE_2D;
// // }

//  scoped_refptr<base::SingleThreadTaskRunner>
//   SingleThreadedCompositorDependencies::GetCompositorMainThreadTaskRunner() {
//     return scoped_refptr<base::SingleThreadTaskRunner>(main_thread_compositor_task_runner_.get());
//     //return nullptr;
//  }
// // // Returns null if the compositor is in single-threaded mode (ie. there is no
// // // compositor thread).

//  scoped_refptr<base::SingleThreadTaskRunner>
//   SingleThreadedCompositorDependencies::GetCompositorImplThreadTaskRunner() {
//    return scoped_refptr<base::SingleThreadTaskRunner>(compositor_task_runner_.get());
//  }

//  blink::scheduler::WebMainThreadScheduler* SingleThreadedCompositorDependencies::GetWebMainThreadScheduler() {
//    DCHECK(false);
//    return nullptr;
//  }

// viz::SharedBitmapManager* SingleThreadedCompositorDependencies::GetSharedBitmapManager() {
//   DCHECK(false);
//   return nullptr;
//   //return &shared_bitmap_manager_;
// }

// gpu::ImageFactory* SingleThreadedCompositorDependencies::GetImageFactory() {
//   DCHECK(false);
//   return nullptr;
//   //return &image_factory_;
// }

// gpu::GpuMemoryBufferManager* SingleThreadedCompositorDependencies::GetGpuMemoryBufferManager() {
//   DCHECK(false);
//   return nullptr;
//   //return &gpu_memory_buffer_manager_;
// }

// cc::TaskGraphRunner* SingleThreadedCompositorDependencies::GetTaskGraphRunner() {
//   DCHECK(false);
//   return nullptr;
//  //return &task_graph_runner_;
// }

// common::CompositorHelper* SingleThreadedCompositorDependencies::compositor_helper() {
//   return &helper_;
// }

// scoped_refptr<base::SingleThreadTaskRunner> SingleThreadedCompositorDependencies::GetCompositorThreadTaskRunner() {
//    //return is_single_threaded_ ? GetCompositorMainThreadTaskRunner() : GetCompositorImplThreadTaskRunner();
//   return GetCompositorMainThreadTaskRunner();
// }

// bool SingleThreadedCompositorDependencies::IsGpuRasterizationForced() {
//   return false;
// }

// int SingleThreadedCompositorDependencies::GetGpuRasterizationMSAASampleCount() {
//   return 1;
// }

// bool SingleThreadedCompositorDependencies::IsLcdTextEnabled() {
//   return true;
// }

// bool SingleThreadedCompositorDependencies::IsZeroCopyEnabled() {
//   return false;
// }

// bool SingleThreadedCompositorDependencies::IsPartialRasterEnabled() {
//   return false;
// }

// bool SingleThreadedCompositorDependencies::IsGpuMemoryBufferCompositorResourcesEnabled() {
//   return true;
// }

// bool SingleThreadedCompositorDependencies::IsElasticOverscrollEnabled() {
//   return false;
// }

// bool SingleThreadedCompositorDependencies::IsThreadedAnimationEnabled() {
//   return true;
// }

// bool SingleThreadedCompositorDependencies::IsScrollAnimatorEnabled() {
//   return false;
// }

// std::unique_ptr<cc::UkmRecorderFactory> SingleThreadedCompositorDependencies::CreateUkmRecorderFactory() {
//   return std::unique_ptr<cc::UkmRecorderFactory>();
// }

//  viz::DirectLayerTreeFrameSink* SingleThreadedCompositorDependencies::CreateDirectLayerTreeFrameSink(
//     const viz::FrameSinkId& frame_sink_id,
//     viz::CompositorFrameSinkSupportManager* support_manager,
//     viz::FrameSinkManagerImpl* frame_sink_manager,
//     viz::Display* display,
//     //mojom::DisplayClient* display_client,
//     scoped_refptr<viz::ContextProvider> context_provider,
//     scoped_refptr<viz::RasterContextProvider> worker_context_provider,
//     scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
//     gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager) {
 
//     viz::DirectLayerTreeFrameSink* result = nullptr;

//     if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//       base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//       GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//         base::BindOnce(&SingleThreadedCompositorDependencies::CreateDirectLayerTreeFrameSinkOnCompositor,
//           base::Unretained(this),
//           frame_sink_id, 
//           base::Unretained(support_manager),
//           base::Unretained(frame_sink_manager),
//           base::Unretained(display),
//           context_provider,
//           worker_context_provider,
//           compositor_task_runner,
//           base::Unretained(gpu_memory_buffer_manager),
//           base::Unretained(&waiter),
//           base::Unretained(&result)));
//       waiter.Wait();
//     } else {
//       CreateDirectLayerTreeFrameSinkOnCompositor(
//         frame_sink_id, support_manager, frame_sink_manager,
//         display, context_provider, worker_context_provider,
//         compositor_task_runner, gpu_memory_buffer_manager, nullptr, &result);
//     }
//     DCHECK(result);  
//     return result;
// }

// void SingleThreadedCompositorDependencies::CreateDirectLayerTreeFrameSinkOnCompositor(
//     const viz::FrameSinkId& frame_sink_id,
//     viz::CompositorFrameSinkSupportManager* support_manager,
//     viz::FrameSinkManagerImpl* frame_sink_manager,
//     viz::Display* display,
//     //mojom::DisplayClient* display_client,
//     scoped_refptr<viz::ContextProvider> context_provider,
//     scoped_refptr<viz::RasterContextProvider> worker_context_provider,
//     scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
//     gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
//     base::WaitableEvent* event,
//     viz::DirectLayerTreeFrameSink** out) {

//     if (worker_context_provider) {
//       worker_context_provider->BindToCurrentThread();
//     }

//     *out = new viz::DirectLayerTreeFrameSink(
//       frame_sink_id,
//       support_manager,
//       frame_sink_manager,
//       display,
//       //display_client,
//       nullptr,
//       context_provider,
//       worker_context_provider,
//       compositor_task_runner,
//       gpu_memory_buffer_manager,  
//       false);
//     if (event) {
//       event->Signal();
//     }
// }

// DirectOutputSurface* SingleThreadedCompositorDependencies::CreateDirectOutputSurface(scoped_refptr<InProcessContextProvider> context_provider) {
//     DirectOutputSurface* result = nullptr;
   
//    if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//      GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//       base::BindOnce(&SingleThreadedCompositorDependencies::CreateDirectOutputSurfaceOnCompositor,
//         base::Unretained(this),
//         context_provider,
//         base::Unretained(&waiter),
//         base::Unretained(&result)));

//      waiter.Wait();
//    } else {
//      CreateDirectOutputSurfaceOnCompositor(context_provider, nullptr, &result);
//    }
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::SetLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink) {
//   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//     GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//         base::BindOnce(&SingleThreadedCompositorDependencies::SetLayerTreeFrameSinkOnCompositor,
//           base::Unretained(this),
//           base::Unretained(layer_tree_host),
//           base::Passed(std::move(frame_sink))));
//   } else {
//     SetLayerTreeFrameSinkOnCompositor(layer_tree_host, std::move(frame_sink));
//   } 
// }

// void SingleThreadedCompositorDependencies::SetLayerTreeFrameSinkOnCompositor(cc::LayerTreeHost* layer_tree_host, std::unique_ptr<cc::LayerTreeFrameSink> frame_sink) {
//   layer_tree_host->SetLayerTreeFrameSink(std::move(frame_sink));
// }

// void SingleThreadedCompositorDependencies::CreateDirectOutputSurfaceOnCompositor(scoped_refptr<InProcessContextProvider> context_provider, base::WaitableEvent* event, DirectOutputSurface** out) {
//     *out = new DirectOutputSurface(context_provider);
//     if (event) {
//       event->Signal();
//     }
// }

// cc::LayerTreeHost* SingleThreadedCompositorDependencies::CreateLayerTreeHostThreaded(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner) {
//   cc::LayerTreeHost* result = nullptr;
   
//    if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//      GetCompositorThreadTaskRunner()->PostTask(
//        FROM_HERE, 
//        base::BindOnce(&SingleThreadedCompositorDependencies::CreateLayerTreeHostThreadedOnCompositor,
//         base::Unretained(this),
//         base::Unretained(params),
//         thread_task_runner,
//         base::Unretained(&waiter),
//         base::Unretained(&result)));

//      waiter.Wait();
//    } else {
//      CreateLayerTreeHostThreadedOnCompositor(params, thread_task_runner, nullptr, &result);
//    }
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::SetRootLayer(cc::LayerTreeHost* layer_tree_host, scoped_refptr<cc::Layer> layer) {
//   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//     GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//       base::BindOnce(&SingleThreadedCompositorDependencies::SetRootLayerOnCompositor,
//         base::Unretained(this),
//         base::Unretained(layer_tree_host),
//         base::Unretained(layer.get())));
//   } else {
//     SetRootLayerOnCompositor(layer_tree_host, layer.get());
//   }
// }

// cc::LayerTreeHost* SingleThreadedCompositorDependencies::CreateLayerTreeHostSingleThreaded(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client) {
//   cc::LayerTreeHost* result = nullptr;
   
//    if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//      params->main_task_runner = GetCompositorThreadTaskRunner();
//      GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//       base::BindOnce(&SingleThreadedCompositorDependencies::CreateLayerTreeHostSingleThreadedOnCompositor,
//         base::Unretained(this),
//         base::Unretained(params),
//         base::Unretained(client),
//         base::Unretained(&waiter),
//         base::Unretained(&result)));

//      waiter.Wait();
//    } else {
//      params->main_task_runner = GetCompositorMainThreadTaskRunner();
//      CreateLayerTreeHostSingleThreadedOnCompositor(params, client, nullptr, &result);
//    }
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::SetRootLayerOnCompositor(cc::LayerTreeHost* layer_tree_host, cc::Layer* layer) {
//   scoped_refptr<cc::Layer> layer_ptr(layer);
//   layer_tree_host->SetRootLayer(layer_ptr);
// }

// void SingleThreadedCompositorDependencies::CreateLayerTreeHostThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, scoped_refptr<base::SingleThreadTaskRunner> thread_task_runner, base::WaitableEvent* event, cc::LayerTreeHost** out) {
//   std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateThreaded(thread_task_runner, params);
//   *out = ptr.release();
//   if (event) {
//     event->Signal();
//   }
// }

// void SingleThreadedCompositorDependencies::CreateLayerTreeHostSingleThreadedOnCompositor(cc::LayerTreeHost::InitParams* params, cc::LayerTreeHostSingleThreadClient* client, base::WaitableEvent* event, cc::LayerTreeHost** out) {
//   std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateSingleThreaded(client, params);
//   *out = ptr.release();
//   if (event) {
//     event->Signal();
//   }
// }
  

// viz::Display* SingleThreadedCompositorDependencies::CreateDisplay(
//     viz::SharedBitmapManager* bitmap_manager,
//     const viz::RendererSettings& settings,
//     const viz::FrameSinkId& frame_sink_id,
//     std::unique_ptr<viz::OutputSurface> output_surface,
//     std::unique_ptr<viz::DisplayScheduler> scheduler,
//     scoped_refptr<base::SingleThreadTaskRunner> current_task_runner) {
    
//     viz::Display* result = nullptr;
   
//    if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//       GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//         base::BindOnce(&SingleThreadedCompositorDependencies::CreateDisplayOnCompositor,
//           base::Unretained(this),
//           base::Unretained(bitmap_manager),
//           settings,
//           frame_sink_id,
//           base::Passed(std::move(output_surface)),
//           base::Passed(std::move(scheduler)),
//           current_task_runner,
//           base::Unretained(&waiter),
//           base::Unretained(&result)));
//       waiter.Wait();
//    } else {
//      CreateDisplayOnCompositor(
//        bitmap_manager, 
//        settings, 
//        frame_sink_id, 
//        std::move(output_surface), 
//        std::move(scheduler), 
//        current_task_runner,
//        nullptr,
//        &result);
//    }
   
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::CreateDisplayOnCompositor(
//     viz::SharedBitmapManager* bitmap_manager,
//     const viz::RendererSettings& settings,
//     const viz::FrameSinkId& frame_sink_id,
//     std::unique_ptr<viz::OutputSurface> output_surface,
//     std::unique_ptr<viz::DisplayScheduler> scheduler,
//     scoped_refptr<base::SingleThreadTaskRunner> current_task_runner,
//     base::WaitableEvent* event,
//     viz::Display** out) {
  
//   *out = new viz::Display(
//       bitmap_manager, settings, frame_sink_id,
//       std::move(output_surface), std::move(scheduler),
//       current_task_runner);
  
//   if (event) {
//     event->Signal();
//   }
// }

// FrameSinkManagerImplWrapper* SingleThreadedCompositorDependencies::CreateFrameSinkManagerImpl() {
//   FrameSinkManagerImplWrapper* result = nullptr;
   
//   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//       GetCompositorThreadTaskRunner()->PostTask(FROM_HERE, 
//         base::BindOnce(&SingleThreadedCompositorDependencies::CreateFrameSinkManagerImplOnCompositor,
//           base::Unretained(this),
//           base::Unretained(&waiter),
//           base::Unretained(&result)));
//       waiter.Wait();
//    } else {
//      CreateFrameSinkManagerImplOnCompositor(
//        nullptr,
//        &result);
//    }
   
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::CreateFrameSinkManagerImplOnCompositor(base::WaitableEvent* event, FrameSinkManagerImplWrapper** out) {
//   *out = new FrameSinkManagerImplWrapper();
//   if (event) {
//     event->Signal();
//   }
// }

// HostFrameSinkManagerWrapper* SingleThreadedCompositorDependencies::CreateHostFrameSinkManagerWrapper() {
//   HostFrameSinkManagerWrapper* result = nullptr;
   
//   if (GetCompositorThreadTaskRunner() != base::ThreadTaskRunnerHandle::Get()) {
//      base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
//       GetCompositorImplThreadTaskRunner()->PostTask(FROM_HERE, 
//         base::BindOnce(&SingleThreadedCompositorDependencies::CreateHostFrameSinkManagerWrapperOnCompositor,
//           base::Unretained(this),
//           base::Unretained(&waiter),
//           base::Unretained(&result)));
//       waiter.Wait();
//    } else {
//      CreateHostFrameSinkManagerWrapperOnCompositor(
//        nullptr,
//        &result);
//    }
   
//    DCHECK(result);  
//    return result;
// }

// void SingleThreadedCompositorDependencies::CreateHostFrameSinkManagerWrapperOnCompositor(base::WaitableEvent* event, HostFrameSinkManagerWrapper** out) {
//   *out = new HostFrameSinkManagerWrapper();
//   if (event) {
//     event->Signal();
//   }
// }

// cc::ContextProvider* SingleThreadedCompositorDependencies::GetSharedMainThreadContextProvider() {
//   if (shared_main_thread_contexts_ &&
//       shared_main_thread_contexts_->ContextGL()->GetGraphicsResetStatusKHR() ==
//           GL_NO_ERROR)
//     return shared_main_thread_contexts_.get();

//   shared_main_thread_contexts_ = InProcessContextProvider::CreateOffscreen(
//       &gpu_memory_buffer_manager_, &image_factory_);
//   if (shared_main_thread_contexts_.get() &&
//       !shared_main_thread_contexts_->BindToCurrentThread())
//     shared_main_thread_contexts_ = NULL;

//   return shared_main_thread_contexts_.get();
// }

// scoped_ptr<cc::BeginFrameSource> SingleThreadedCompositorDependencies::CreateExternalBeginFrameSource(
//  int routing_id) { return scoped_ptr<cc::BeginFrameSource>(); }

// void SingleThreadedCompositorDependencies::SynchronouslyComposite(
//     cc::LayerTreeHost* layer_tree_host,
//     bool raster,
//     std::unique_ptr<cc::SwapPromise> swap_promise) {
//     layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner()->PostTask(
//         FROM_HERE,
//         base::BindOnce(&SingleThreadedCompositorDependencies::SynchronouslyCompositeImpl,
//                        weak_factory_.GetWeakPtr(),
//                        base::Unretained(layer_tree_host),
//                        raster, 
//                        base::Passed(std::move(swap_promise))));
// }

// void SingleThreadedCompositorDependencies::SynchronouslyCompositeImpl(
//     cc::LayerTreeHost* layer_tree_host,
//     bool raster,
//     std::unique_ptr<cc::SwapPromise> swap_promise) {
//   if (!layer_tree_host->IsVisible())
//     return;

//   if (swap_promise) {
//     // Force a redraw to ensure that the copy swap promise isn't cancelled due
//     // to no damage.
//     layer_tree_host->SetNeedsCommitWithForcedRedraw();
//     layer_tree_host->QueueSwapPromise(std::move(swap_promise));
//   }

//   layer_tree_host->Composite(base::TimeTicks::Now(), raster);
// }

// void SingleThreadedCompositorDependencies::QueueImageDecode(cc::LayerTreeHost* layer_tree_host, SkImage* image, void(*callback)(int)) {
//   cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
//                         .set_image(sk_ref_sp(image), cc::PaintImage::GetNextContentId())
//                         .TakePaintImage();
//   layer_tree_host->QueueImageDecode(
//     paint_image, 
//     base::Bind(&SingleThreadedCompositorDependencies::OnQueueImageDecode, 
//       weak_factory_.GetWeakPtr(), 
//       base::Unretained(callback)));
// }

// void SingleThreadedCompositorDependencies::RequestNewLayerTreeFrameSink(cc::LayerTreeHost* layer_tree_host, void(*callback)()) {
//   layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner()->PostTask(
//       FROM_HERE,
//       base::Bind(&SingleThreadedCompositorDependencies::OnRequestNewLayerTreeFrameSink,
//                   weak_factory_.GetWeakPtr(),
//                   base::Unretained(callback)));
// }

// std::unique_ptr<viz::CopyOutputRequest> SingleThreadedCompositorDependencies::CreateCopyOutputRequestWithBitmapRequest(
//   void* state,
//   cc::LayerTreeHost* layer_tree_host, 
//   void(*callback)(void*, void*)) {

//   scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner =
//       layer_tree_host->GetTaskRunnerProvider()->MainThreadTaskRunner();
//   std::unique_ptr<viz::CopyOutputRequest> request =
//       std::make_unique<viz::CopyOutputRequest>(
//           viz::CopyOutputRequest::ResultFormat::RGBA_BITMAP,
//           base::BindOnce(
//               [](void *state,
//                  void(*cb)(void*, void*),
//                  scoped_refptr<base::SingleThreadTaskRunner> task_runner,
//                  base::WeakPtr<SingleThreadedCompositorDependencies> weak_ptr,
//                  std::unique_ptr<viz::CopyOutputResult> result) {
//                 task_runner->PostTask(
//                     FROM_HERE,
//                     base::BindOnce(
//                                &SingleThreadedCompositorDependencies::OnCreateCopyOutputRequest,
//                                // not sure, but i think we need a move right here
//                                // anyway, i guess the weak ptr const reference wont hurt anyway
//                                std::move(weak_ptr),
//                                base::Unretained(state),
//                                base::Unretained(cb),
//                                result->AsSkBitmap()));
//               },
//               state, callback, std::move(main_thread_task_runner), weak_factory_.GetWeakPtr()));
//               //std::move(callback), std::move(main_thread_task_runner)));
  
//   return request;
// }

// void SingleThreadedCompositorDependencies::OnCreateCopyOutputRequest(void *state, void(*callback)(void*, void*), const SkBitmap& bitmap) {
//   DCHECK(callback);
//   callback(state, const_cast<SkBitmap *>(&bitmap));
// }

// void SingleThreadedCompositorDependencies::OnRequestNewLayerTreeFrameSink(void(*callback)()) {
//   DCHECK(callback);
//   callback();
// }

// void SingleThreadedCompositorDependencies::OnQueueImageDecode(void(*callback)(int), bool result) {
//   DCHECK(callback);
//   callback(result != 0);
// }

CompositorLayerTreeHostClient::CompositorLayerTreeHostClient(void* payload, CLayerTreeHostSingleThreadClientCbs callbacks): 
  callbacks_(callbacks) {
  state_ = payload;
}

CompositorLayerTreeHostClient::~CompositorLayerTreeHostClient() {}

void CompositorLayerTreeHostClient::set_client_peer(void* peer) {
  state_ = peer;
}

void CompositorLayerTreeHostClient::WillBeginMainFrame() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::WillBeginMainFrame";
  callbacks_.willBeginMainFrame(state_);
}
void CompositorLayerTreeHostClient::BeginMainFrame(const viz::BeginFrameArgs& args) {
  //LOG(INFO) << "CompositorLayerTreeHostClient::BeginMainFrame";
  callbacks_.beginMainFrame(state_, 
    args.source_id,
    args.sequence_number,
    args.frame_time.ToInternalValue(), 
    args.deadline.ToInternalValue(), 
    args.interval.ToInternalValue());
}
void CompositorLayerTreeHostClient::BeginMainFrameNotExpectedSoon() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::BeginMainFrameNotExpectedSoon";
  callbacks_.beginMainFrameNotExpectedSoon(state_);
}

void CompositorLayerTreeHostClient::BeginMainFrameNotExpectedUntil(base::TimeTicks time) {
  //LOG(INFO) << "CompositorLayerTreeHostClient::BeginMainFrameNotExpectedUntil";
  callbacks_.beginMainFrameNotExpectedUntil(state_, time.ToInternalValue());
}

void CompositorLayerTreeHostClient::DidBeginMainFrame() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidBeginMainFrame";
  callbacks_.didBeginMainFrame(state_);
}
void CompositorLayerTreeHostClient::UpdateLayerTreeHost(VisualStateUpdate requested_update) {
  //LOG(INFO) << "CompositorLayerTreeHostClient::UpdateLayerTreeHost";
  callbacks_.updateLayerTreeHost(state_, static_cast<int>(requested_update));
}
void CompositorLayerTreeHostClient::ApplyViewportDeltas(
    const gfx::Vector2dF& inner_delta,
    const gfx::Vector2dF& outer_delta,
    const gfx::Vector2dF& elastic_overscroll_delta,
    float page_scale,
    float top_controls_delta) {
  //LOG(INFO) << "CompositorLayerTreeHostClient::ApplyViewportDeltas";
  callbacks_.applyViewportDeltas(state_);
}

void CompositorLayerTreeHostClient::RecordWheelAndTouchScrollingCount(
    bool has_scrolled_by_wheel,
    bool has_scrolled_by_touch) {
  //callbacks_.RecordWheelAndTouchScrollingCount(state_);
}

void CompositorLayerTreeHostClient::RequestNewLayerTreeFrameSink() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::RequestNewLayerTreeFrameSink";
  callbacks_.requestNewLayerTreeFrameSink(state_);
}

void CompositorLayerTreeHostClient::DidInitializeLayerTreeFrameSink() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidInitializeLayerTreeFrameSink";
  callbacks_.didInitializeLayerTreeFrameSink(state_);
}

void CompositorLayerTreeHostClient::DidFailToInitializeLayerTreeFrameSink() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidFailToInitializeLayerTreeFrameSink";
  callbacks_.didFailToInitializeLayerTreeFrameSink(state_);
}

void CompositorLayerTreeHostClient::WillCommit() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::WillCommit";
  callbacks_.willCommit(state_);
}
void CompositorLayerTreeHostClient::DidCommit() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidCommit";
  callbacks_.didCommit(state_);
}
void CompositorLayerTreeHostClient::DidCommitAndDrawFrame() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidCommitAndDrawFrame";
  callbacks_.didCommitAndDrawFrame(state_);
}

void CompositorLayerTreeHostClient::DidReceiveCompositorFrameAck() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidReceiveCompositorFrameAck";
  callbacks_.didReceiveCompositorFrameAck(state_);
}

void CompositorLayerTreeHostClient::DidCompletePageScaleAnimation() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidCompletePageScaleAnimation";
  callbacks_.didCompletePageScaleAnimation(state_);
}

bool CompositorLayerTreeHostClient::IsForSubframe() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::IsForSubframe";
  return callbacks_.isForSubframe(state_) == 1 ? true : false;
}

// cc::LayerTreeHostSingleThreadClient
void CompositorLayerTreeHostClient::DidSubmitCompositorFrame() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidSubmitCompositorFrame";
  callbacks_.didSubmitCompositorFrame(state_);
}

void CompositorLayerTreeHostClient::DidLoseLayerTreeFrameSink() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::DidLoseLayerTreeFrameSink";
  callbacks_.didLoseLayerTreeFrameSink(state_);
}

void CompositorLayerTreeHostClient::RequestScheduleComposite() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::RequestScheduleComposite";
  callbacks_.requestScheduleComposite(state_);
}

void CompositorLayerTreeHostClient::RequestScheduleAnimation() {
  //LOG(INFO) << "CompositorLayerTreeHostClient::RequestScheduleAnimation";
  callbacks_.requestScheduleAnimation(state_);
}

// declared on CompositorStructsPrivate
int PaintingControlSettingToInt(cc::ContentLayerClient::PaintingControlSetting status) {
 switch (status) {
  case cc::ContentLayerClient::PAINTING_BEHAVIOR_NORMAL:
   return 0;
  case cc::ContentLayerClient::DISPLAY_LIST_CONSTRUCTION_DISABLED:
   return 1;
  case cc::ContentLayerClient::DISPLAY_LIST_CACHING_DISABLED:
   return 2;
  case cc::ContentLayerClient::DISPLAY_LIST_PAINTING_DISABLED:
   return 3;
  default:
   return 0;
 }
}
