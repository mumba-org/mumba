// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "CompositorShims.h"

#include <stdlib.h>

#include "CompositorHelper.h"
#include "CompositorStructsPrivate.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/common/compositor/direct_output_surface.h"
#include "core/shared/common/compositor/in_process_context_provider.h"
#include "core/shared/common/compositor/host_frame_sink_manager_wrapper.h"
#include "core/shared/common/compositor/frame_sink_manager_impl_wrapper.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/time.h"
#include "base/lazy_instance.h"
#include "base/threading/thread_local.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_number_conversions.h"
#include "cc/animation/animation_curve.h"
#include "cc/animation/animation_id_provider.h"
#include "cc/animation/keyframe_model.h"
#include "cc/animation/keyframed_animation_curve.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation.h"
#include "cc/animation/animation_events.h"
#include "cc/animation/animation_timeline.h"
#include "cc/animation/animation_delegate.h"
#include "cc/animation/transform_operation.h"
#include "cc/animation/transform_operations.h"
#include "cc/animation/single_keyframe_effect_animation.h"
#include "cc/trees/swap_promise.h"
#include "cc/trees/latency_info_swap_promise.h"
#include "cc/base/switches.h"
#include "cc/blink/web_layer_impl.h"
#include "cc/debug/layer_tree_debug_state.h"
#include "cc/input/layer_selection_bound.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_host_common.h"
#include "cc/trees/layer_tree_frame_sink.h"
#include "cc/layers/layer.h"
#include "cc/layers/layer_impl.h"
#include "cc/layers/nine_patch_layer.h"
#include "cc/layers/picture_layer.h"
#include "cc/layers/solid_color_layer.h"
#include "cc/layers/surface_layer.h"
#include "cc/layers/texture_layer.h"
#include "cc/layers/texture_layer_client.h"
#include "cc/paint/paint_shader.h"
#include "cc/paint/paint_image_builder.h"
#include "cc/paint/filter_operations.h"
#include "cc/paint/filter_operation.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "gpu/ipc/common/gpu_surface_tracker.h"
//#include "core/shared/common/compositor_dependencies.h"
//#include "core/shared/common/compositor_helper.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/service/display/display.h"
#include "ui/base/x/x11_util.h"
#include "ui/gfx/x/x11_connection.h"
#include "ui/gfx/overlay_transform.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gl/gl_surface.h"
#include "ui/gl/gl_context_glx.h"
#include "ui/gl/gl_image_glx.h"
#include "ui/gl/gl_surface_glx.h"
#include "ui/gl/gl_share_group.h"
//#include "ui/gl/gl_bindings.h"
#include "ui/gl/init/gl_factory.h"
#include "ui/gl/gl_implementation.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/skia/include/core/SkPoint.h"
#include "third_party/skia/include/core/SkRegion.h"
#include "third_party/skia/include/core/SkPicture.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkPicture.h"
#include "third_party/skia/include/core/SkMatrix.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageFilter.h"
#include "third_party/skia/include/core/SkShader.h"
#include "third_party/skia/include/core/SkTypeface.h"
#include "third_party/skia/include/core/SkDrawFilter.h"
#include "third_party/skia/include/core/SkColorFilter.h"
#include "third_party/skia/include/core/SkDrawLooper.h"
#include "third_party/skia/include/core/SkPathEffect.h"
#include "third_party/skia/include/effects/SkBlurDrawLooper.h"
#include "third_party/skia/include/effects/SkLayerDrawLooper.h"
#include "third_party/skia/include/effects/SkBlurMaskFilter.h"
#include "third_party/skia/include/core/SkDrawable.h"
#include "third_party/skia/include/ports/SkFontMgr.h"
#include "third_party/skia/src/core/SkXfermodePriv.h"
#include "third_party/blink/public/platform/web_layer.h"
#include "third_party/blink/public/platform/web_layer_tree_view.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_data.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/font_platform_data.h"

namespace {

  //static base::LazyInstance<base::ThreadLocalPointer<common::CompositorDependencies>>::Leaky g_deps =
  //     LAZY_INSTANCE_INITIALIZER;

 ui::LatencyComponentType DidNotSwapReasonToLatencyComponentType(
    cc::SwapPromise::DidNotSwapReason reason) {
  switch (reason) {
    case cc::SwapPromise::ACTIVATION_FAILS:
    case cc::SwapPromise::SWAP_FAILS:
      return ui::INPUT_EVENT_LATENCY_TERMINATED_SWAP_FAILED_COMPONENT;
    case cc::SwapPromise::COMMIT_FAILS:
      return ui::INPUT_EVENT_LATENCY_TERMINATED_COMMIT_FAILED_COMPONENT;
    case cc::SwapPromise::COMMIT_NO_UPDATE:
      return ui::INPUT_EVENT_LATENCY_TERMINATED_COMMIT_NO_UPDATE_COMPONENT;
  }
  NOTREACHED() << "Unhandled DidNotSwapReason.";
  return ui::INPUT_EVENT_LATENCY_TERMINATED_SWAP_FAILED_COMPONENT;
 }

bool AddRenderingScheduledComponent(ui::LatencyInfo* latency_info,
                                    bool on_main) {
  ui::LatencyComponentType type =
      on_main ? ui::INPUT_EVENT_LATENCY_RENDERING_SCHEDULED_MAIN_COMPONENT
              : ui::INPUT_EVENT_LATENCY_RENDERING_SCHEDULED_IMPL_COMPONENT;
  if (latency_info->FindLatency(type, nullptr))
    return false;
  latency_info->AddLatencyNumber(type);
  return true;
}

bool AddForwardingScrollUpdateToMainComponent(ui::LatencyInfo* latency_info) {
  if (latency_info->FindLatency(
          ui::INPUT_EVENT_LATENCY_FORWARD_SCROLL_UPDATE_TO_MAIN_COMPONENT,
          nullptr))
    return false;
  latency_info->AddLatencyNumber(
      ui::INPUT_EVENT_LATENCY_FORWARD_SCROLL_UPDATE_TO_MAIN_COMPONENT);
  return true;
}

}


using ReportTimeCallback =
    base::Callback<void(bool /* swap ok?*/, cc::SwapPromise::DidNotSwapReason, double)>;

static double MonotonicallyIncreasingTime() {
  return static_cast<double>(base::TimeTicks::Now().ToInternalValue()) /
         base::Time::kMicrosecondsPerSecond;
}

template <typename Functor>
struct OnceFunction {
  uintptr_t entry; 
  base::OnceCallback<Functor> callback;
  OnceFunction(
    uintptr_t entry,
    base::OnceCallback<Functor> callback):
   entry(entry),
   callback(std::move(callback)){}
  
  ~OnceFunction() {}
};

template <typename Functor>
struct Function {
  uintptr_t entry; 
  base::Callback<Functor> callback;
  Function(
    uintptr_t entry,
    base::Callback<Functor> callback):
   entry(entry),
   callback(std::move(callback)){}
  
  ~Function() {}
};

struct ReportTimeFunction {
  blink::WebLayerTreeView::ReportTimeCallback callback;
  ReportTimeFunction(
    blink::WebLayerTreeView::ReportTimeCallback callback):
   callback(std::move(callback)){}
  ~ReportTimeFunction() {}
};

struct _SwapPromiseMonitor {
  std::unique_ptr<cc::SwapPromiseMonitor> handle;
 _SwapPromiseMonitor(cc::SwapPromiseMonitor* ptr): handle(ptr) {}
 _SwapPromiseMonitor(std::unique_ptr<cc::SwapPromiseMonitor> ptr): handle(std::move(ptr)) {}
};

class AlwaysDrawSwapPromise : public cc::SwapPromise {
 public:
  explicit AlwaysDrawSwapPromise(
      ui::LatencyInfo latency_info,
      void* state,
      void(*cb)(void*, int, int, double),
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner)
      : latency_info_(std::move(latency_info)),
        state_(state), 
        callback_(cb), 
        task_runner_(task_runner) {}

  ~AlwaysDrawSwapPromise() override = default;

  void DidActivate() override {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::OnCommit";
  }

  void WillSwap(viz::CompositorFrameMetadata* metadata,
                cc::FrameTokenAllocator* frame_token_allocator) override {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::WillSwap";
    DCHECK(!latency_info_.terminated());
    metadata->latency_info.push_back(latency_info_);
  }

  void DidSwap() override {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::DidSwap";
    if (callback_ && state_) {
      task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&AlwaysDrawSwapPromise::OnSwap,
                       base::Unretained(this),
                       true, // did wap goes here now
                       cc::SwapPromise::DidNotSwapReason::SWAP_FAILS,// note: will be ignored in this case
                       MonotonicallyIncreasingTime()));
    }
  }

  DidNotSwapAction DidNotSwap(DidNotSwapReason reason) override {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::DidNotSwap: returning " << (reason == DidNotSwapReason::SWAP_FAILS ? "KEEP_ACTIVE" : "BREAK_PROMISE");
    if (callback_ && state_) {
      task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
          &AlwaysDrawSwapPromise::OnSwap,
          base::Unretained(this),
          false, 
          reason, 
          MonotonicallyIncreasingTime()));
    }
    return reason == DidNotSwapReason::SWAP_FAILS
               ? DidNotSwapAction::KEEP_ACTIVE
               : DidNotSwapAction::BREAK_PROMISE;
  }

  void OnCommit() override {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::OnCommit";
  }

  int64_t TraceId() const override { return latency_info_.trace_id(); }

 private:
  
  void OnSwap(bool did_swap, cc::SwapPromise::DidNotSwapReason reason, double time) {
    //DLOG(INFO) << "AlwaysDrawSwapPromise::OnSwap";
    if (callback_ && state_) {
      callback_(state_, did_swap ? 1 : 0, did_swap ? -1 : static_cast<int>(reason), time);
    }
  }

  ui::LatencyInfo latency_info_;
  void* state_;
  void(*callback_)(void*, int, int, double);
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

typedef enum {
  WebSwapResultDidSwap = 0,
  WebSwapResultDidNotSwapSwapFails = 1,
  WebSwapResultDidNotSwapCommitFails = 2,
  WebSwapResultDidNotSwapCommitNoUpdate = 3,
  WebSwapResultDidNotSwapActivationFails = 4
} WebSwapResultEnum;

class ReportTimeSwapPromise : public cc::SwapPromise {
 public:
  ReportTimeSwapPromise(
      void* state,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  ~ReportTimeSwapPromise() override;

  void* state() const {
    return state_;
  }

  void DidActivate() override {
    //DLOG(INFO) << "ReportTimeSwapPromise::OnCommit";
  }
  void WillSwap(viz::CompositorFrameMetadata* metadata,
                cc::FrameTokenAllocator* frame_token_allocator) override {
    //DLOG(INFO) << "ReportTimeSwapPromise::WillSwap";
  }
  void DidSwap() override;
  DidNotSwapAction DidNotSwap(DidNotSwapReason reason) override;

  int64_t TraceId() const override;

 private:

  void OnSwap(bool did_swap, cc::SwapPromise::DidNotSwapReason reason, double time);

  void* state_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(ReportTimeSwapPromise);
};

ReportTimeSwapPromise::ReportTimeSwapPromise(
    void* state,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : state_(state), task_runner_(std::move(task_runner)) {}

ReportTimeSwapPromise::~ReportTimeSwapPromise() {}

void ReportTimeSwapPromise::DidSwap() {
  //DLOG(INFO) << "\n\nReportTimeSwapPromise::DidSwap: state_ here = " << state_;
  if (state_) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&ReportTimeSwapPromise::OnSwap,
                     base::Unretained(this),
                     true, // did swap goes here now
                     cc::SwapPromise::DidNotSwapReason::SWAP_FAILS,// note: will be ignored in this case
                     MonotonicallyIncreasingTime()));
  }
}

cc::SwapPromise::DidNotSwapAction ReportTimeSwapPromise::DidNotSwap(
    cc::SwapPromise::DidNotSwapReason reason) {
  //DLOG(INFO) << "\n\nReportTimeSwapPromise::DidNotSwap: state_ here = " << state_;
  
  //WebLayerTreeView::SwapResult result;
  //switch (reason) {
//    case cc::SwapPromise::DidNotSwapReason::SWAP_FAILS:
      //result = WebLayerTreeView::SwapResult::kDidNotSwapSwapFails;
      //break;
    //case cc::SwapPromise::DidNotSwapReason::COMMIT_FAILS:
//      result = WebLayerTreeView::SwapResult::kDidNotSwapCommitFails;
//      break;
    //case cc::SwapPromise::DidNotSwapReason::COMMIT_NO_UPDATE:
//      result = WebLayerTreeView::SwapResult::kDidNotSwapCommitNoUpdate;
  //    break;
//    case cc::SwapPromise::DidNotSwapReason::ACTIVATION_FAILS:
  //    result = WebLayerTreeView::SwapResult::kDidNotSwapActivationFails;
      //break;
  //}
  if (state_) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
          &ReportTimeSwapPromise::OnSwap,
          base::Unretained(this),
          false, 
          reason, 
          MonotonicallyIncreasingTime()));
  }
  return cc::SwapPromise::DidNotSwapAction::BREAK_PROMISE;
}

int64_t ReportTimeSwapPromise::TraceId() const {
  return 0;
}

void ReportTimeSwapPromise::OnSwap(bool did_swap, cc::SwapPromise::DidNotSwapReason reason, double time) {
  //DLOG(INFO) << "\n **\n **\n **\n ** ReportTimeSwapPromise::OnSwap: state_: " << state_ << " did_swap? " << did_swap << " reason: " << reason;  
  if (state_) {
    //DLOG(INFO) << "NotifySwapTimeCallback: casting state_ " << state_ << " to function pointer..";
    ReportTimeFunction* fn_ptr = static_cast<ReportTimeFunction*>(state_);
    ////DLOG(INFO) << "NotifySwapTimeCallback: recovered function pointer: " << fn_ptr << ". entry: " << fn_ptr->entry << " is the function address. running it..";
    //reinterpret_cast<void(*)(base::Callback<void(blink::WebLayerTreeView::SwapResult, double)>, blink::WebLayerTreeView::SwapResult, double)>(fn_ptr->entry)(std::move(fn_ptr->callback), static_cast<blink::WebLayerTreeView::SwapResult>(reason), time);
    if (fn_ptr) {
      //DLOG(INFO) << "NotifySwapTimeImpl: executing callback";
      std::move(fn_ptr->callback).Run(static_cast<blink::WebLayerTreeView::SwapResult>(reason), time);
    }
    //DLOG(INFO) << "NotifySwapTimeCallback: deleting function pointer";
    delete fn_ptr;
    //callback_(state_, did_swap ? 1 : 0, did_swap ? -1 : static_cast<int>(reason), time);
  }
}

//void NotifySwapTimeImpl(base::Callback<void(blink::WebLayerTreeView::SwapResult, double)> cb, WebSwapResultEnum swap, double time) {
//  //DLOG(INFO) << "NotifySwapTimeImpl: cb ? " << !cb.is_null();
//  if (cb) {
//    //DLOG(INFO) << "NotifySwapTimeImpl: executing callback";
//    std::move(cb).Run(static_cast<blink::WebLayerTreeView::SwapResult>(swap), time);
//  }
//  //DLOG(INFO) << "NotifySwapTimeImpl: end";
//}

// this is a copy of cc::LatencyInfoSwapPromise with custom changes

class CC_EXPORT LatencyInfoSwapPromise : public cc::SwapPromise {
 public:
  explicit LatencyInfoSwapPromise(
    ui::LatencyInfo& latency): 
    latency_(latency){

  }

  ~LatencyInfoSwapPromise() override {}

  void DidActivate() override {
    //DLOG(INFO) << "LatencyInfoSwapPromise::WillSwap";
  }
 
  void WillSwap(viz::CompositorFrameMetadata* metadata,
                cc::FrameTokenAllocator* frame_token_allocator) override {
    int component_type = -1;
    for (auto it = latency_.latency_components().begin(); it != latency_.latency_components().end(); ++it) {
      component_type = it->first;
    }
   
    DCHECK(!latency_.terminated());
    metadata->latency_info.push_back(latency_);
  }
 
  void DidSwap() override {
    //DLOG(INFO) << "LatencyInfoSwapPromise::DidSwap";
  }
 
  DidNotSwapAction DidNotSwap(DidNotSwapReason reason) override {
    //DLOG(INFO) << "LatencyInfoSwapPromise::DidNotSwap: reason: " << reason;
    latency_.AddLatencyNumber(DidNotSwapReasonToLatencyComponentType(reason));
    return DidNotSwapAction::BREAK_PROMISE;
  }
 
  void OnCommit() override {
    //DLOG(INFO) << "LatencyInfoSwapPromise::OnCommit";
    TRACE_EVENT_WITH_FLOW1("input,benchmark", "LatencyInfo.Flow",
                         TRACE_ID_DONT_MANGLE(TraceId()),
                         TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                         "step", "HandleInputEventMainCommit");
  }

  int64_t TraceId() const override {
    return latency_.trace_id();
  }

 private:
  
  //void OnSwap(bool did_swap, cc::SwapPromise::DidNotSwapReason reason, double time) {
  //  //DLOG(INFO) << "LatencyInfoSwapPromise::OnSwap: callback_: " << callback_ << " state: " << state_ << " did_swap? " << did_swap << " reason: " << reason;
  //  if (callback_ && state_) {
  //    callback_(state_, did_swap ? 1 : 0, did_swap ? -1 : static_cast<int>(reason), time);
  //  }
  //}

   ui::LatencyInfo& latency_;
  //void* state_;
  //void(*callback_)(void*, int, int, double);
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

struct _SwapPromise {
  enum Type {
    kUNKNOWN = 0,
    kLATENCY = 1,
    kALWAYSDRAW = 2,
    kREPORTTIME = 2,
  };

  static _SwapPromise* CreateLatency(
    ui::LatencyInfo& latency_info) {
    _SwapPromise* promise = new _SwapPromise(std::make_unique<LatencyInfoSwapPromise>(latency_info));//state, cb, task_runner));
    promise->type = kLATENCY;
    return promise;
  }

  static _SwapPromise* CreateAlwaysDraw(
    ui::LatencyInfo latency_info,
    void* state,
    void(*cb)(void*, int, int, double),
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
    _SwapPromise* promise = new _SwapPromise(std::make_unique<AlwaysDrawSwapPromise>(std::move(latency_info), state, cb, task_runner));
    promise->type = kALWAYSDRAW;
    return promise;
  }

  static _SwapPromise* CreateReportTime(
    void* state,
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
    _SwapPromise* promise = new _SwapPromise(std::make_unique<ReportTimeSwapPromise>(state, task_runner));
    promise->type = kREPORTTIME;
    return promise;
  }

  Type type;
  std::unique_ptr<cc::SwapPromise> handle;
 
 _SwapPromise(cc::SwapPromise* ptr): type(kUNKNOWN), handle(ptr) {}
 _SwapPromise(std::unique_ptr<cc::SwapPromise> ptr): type(kUNKNOWN), handle(std::move(ptr)) {}

};

class LatencyInfoSwapPromiseMonitor : public cc::SwapPromiseMonitor {
 public:
  LatencyInfoSwapPromiseMonitor(ui::LatencyInfo* latency,
                                cc::SwapPromiseManager* swap_promise_manager,
                                cc::LayerTreeHostImpl* host_impl):
      cc::SwapPromiseMonitor(swap_promise_manager, host_impl),
      latency_(latency) {
    
  }
  
  ~LatencyInfoSwapPromiseMonitor() override = default;

  void OnSetNeedsCommitOnMain() override {
    //DLOG(INFO) << "LatencyInfoSwapPromiseMonitor::OnSetNeedsCommitOnMain";
    if (AddRenderingScheduledComponent(latency_, true /* on_main */)) {
      std::unique_ptr<cc::SwapPromise> swap_promise(
        new LatencyInfoSwapPromise(*latency_));
      swap_promise_manager_->QueueSwapPromise(std::move(swap_promise));
    }
  }
  
  void OnSetNeedsRedrawOnImpl() override {
    //DLOG(INFO) << "LatencyInfoSwapPromiseMonitor::OnSetNeedsRedrawOnImpl";
    if (AddRenderingScheduledComponent(latency_, false /* on_main */)) {
      std::unique_ptr<cc::SwapPromise> swap_promise(
        new LatencyInfoSwapPromise(*latency_));
      // Queue a pinned swap promise on the active tree. This will allow
      // measurement of the time to the next SwapBuffers(). The swap
      // promise is pinned so that it is not interrupted by new incoming
      // activations (which would otherwise break the swap promise).
      host_impl_->active_tree()->QueuePinnedSwapPromise(std::move(swap_promise));
    }
  }
  
  void OnForwardScrollUpdateToMainThreadOnImpl() override {
    //DLOG(INFO) << "LatencyInfoSwapPromiseMonitor::OnForwardScrollUpdateToMainThreadOnImpl";
    if (AddForwardingScrollUpdateToMainComponent(latency_)) {
      // int64_t new_sequence_number = 0;
      // for (ui::LatencyInfo::LatencyMap::const_iterator it =
      //          latency_->latency_components().begin();
      //      it != latency_->latency_components().end(); ++it) {
      //   if (it->first == ui::INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT) {
      //     new_sequence_number =
      //         ((static_cast<int64_t>(base::PlatformThread::CurrentId()) << 32) ^
      //          (reinterpret_cast<uint64_t>(this) << 32)) |
      //         (it->second.sequence_number & 0xffffffff);
      //     if (new_sequence_number == it->second.sequence_number)
      //       return;
      //     break;
      //   }
      // }
      // if (!new_sequence_number)
      //   return;
      ui::LatencyInfo new_latency;
      new_latency.CopyLatencyFrom(
          *latency_,
          ui::INPUT_EVENT_LATENCY_FORWARD_SCROLL_UPDATE_TO_MAIN_COMPONENT);
      new_latency.AddLatencyNumberWithTraceName(
          ui::LATENCY_BEGIN_SCROLL_LISTENER_UPDATE_MAIN_COMPONENT, "ScrollUpdate");
      std::unique_ptr<cc::SwapPromise> swap_promise(
          new LatencyInfoSwapPromise(new_latency));
      host_impl_->QueueSwapPromiseForMainThreadScrollUpdate(
          std::move(swap_promise));
    }
  }

 private:
  
  ui::LatencyInfo* latency_;
};


//struct  {
//  std::unique_ptr<viz::OutputSurface> handle;

// (std::unique_ptr<viz::OutputSurface> surface): handle(std::move(surface)) {}
// (viz::OutputSurface* surface): handle(surface) {}

// () {}

// void set_output_surface(viz::OutputSurface* surface) { handle.reset(surface); }

//};

// struct _LayerAnimationEventObserver {
//  //scoped_ptr<cc::LayerAnimationEventObserver> handle;
//  cc::LayerAnimationEventObserver* handle;
//  _LayerAnimationEventObserver(cc::LayerAnimationEventObserver* ptr): handle(ptr) {}
// };


inline cc::Layer* GetLayer(LayerRef layer) {
  return reinterpret_cast<_Layer *>(layer)->layer();
}

template<typename T> 
T* GetLayerAs(LayerRef layer) {
  return static_cast<T*>(reinterpret_cast<_Layer *>(layer)->layer());
}

// void _AnimationRegistrarDestroy(AnimationRegistrarRef handle) {
//   delete handle;
// }

void _PropertyTreesDestroy(PropertyTreesRef handle) {
  delete reinterpret_cast<_PropertyTrees *>(handle);
}

// DisplayItemRef _DisplayItemClipCreate() {
//  return new cc::ClipDisplayItem();
// }

// DisplayItemRef _DisplayItemEndClipCreate() {
//  return new cc::EndClipDisplayItem();
// }

// DisplayItemRef _DisplayItemClipPathCreate() {
//  return new cc::ClipPathDisplayItem();
// }

// DisplayItemRef _DisplayItemEndClipPathCreate() {
//  return new cc::EndClipPathDisplayItem();
// }

// DisplayItemRef _DisplayItemCompositingCreate() {
//  return new cc::CompositingDisplayItem();
// }

// DisplayItemRef _DisplayItemEndCompositingCreate() {
//  return new cc::EndCompositingDisplayItem();
// }

// DisplayItemRef _DisplayItemFilterCreate() {
//  return new cc::FilterDisplayItem();
// }

// DisplayItemRef _DisplayItemEndFilterCreate() {
//  return new cc::EndFilterDisplayItem();
// }

// DisplayItemRef _DisplayItemDrawingCreate() {
//  return new cc::DrawingDisplayItem();
// }

// DisplayItemRef _DisplayItemFloatClipCreate() {
//  return new cc::FloatClipDisplayItem();
// }

// DisplayItemRef _DisplayItemEndFloatClipCreate() {
//  return new cc::EndFloatClipDisplayItem();
// }

// DisplayItemRef _DisplayItemTransformCreate() {
//  return new cc::TransformDisplayItem();
// }

// DisplayItemRef _DisplayItemEndTransformCreate() {
//  return new cc::EndTransformDisplayItem();
// }


// void _ClipPathDisplayItemSetNew(DisplayItemRef handle, PathRef path, int clip_op, int antialias) {
//  cc::ClipPathDisplayItem* item = reinterpret_cast<cc::ClipPathDisplayItem *>(handle);
//  SkRegion::Op op;
 
//  switch (clip_op) { 
//   case 0:
//     op = SkRegion::kDifference_Op;
//     break;
//   case 1:
//     op = SkRegion::kIntersect_Op;
//     break;
//   case 2:
//     op = SkRegion::kUnion_Op;
//     break;
//   case 3:
//     op = SkRegion::kXOR_Op;
//     break;
//   case 4:
//     op = SkRegion::kReverseDifference_Op;
//     break;
//   case 5:
//     op = SkRegion::kReplace_Op;
//     break;
//   default:
//    break;  
//  }

//  // const SkPath& path, SkRegion::Op clip_op, bool antialias
//  item->SetNew(reinterpret_cast<SkiaPath *>(path)->ref(), op, antialias == 0 ? false : true);
// }

// void _CompositingDisplayItemSetNew(DisplayItemRef handle, uint8_t alpha, int blend_mode, int* bx, int* by, int* bw, int* bh, ColorFilterRef filter) {
//  cc::CompositingDisplayItem* item = reinterpret_cast<cc::CompositingDisplayItem *>(handle);
 
//  SkXfermode::Mode mode;

//  switch (blend_mode) {
//    case 0:
//     mode = SkXfermode::kClear_Mode;
//     break;
//    case 1:
//     mode = SkXfermode::kSrc_Mode;
//     break;
//    case 2:
//     mode = SkXfermode::kDst_Mode;
//     break;
//    case 3:
//     mode = SkXfermode::kSrcOver_Mode;
//     break;
//    case 4:
//     mode = SkXfermode::kDstOver_Mode;
//     break;
//    case 5:
//     mode = SkXfermode::kSrcIn_Mode;
//     break;
//    case 6:
//     mode = SkXfermode::kDstIn_Mode;
//     break;
//    case 7:
//     mode = SkXfermode::kSrcOut_Mode;
//     break;
//    case 8:
//     mode = SkXfermode::kDstOut_Mode;
//     break;
//    case 9:
//     mode = SkXfermode::kSrcATop_Mode;
//     break;
//    case 10:
//     mode = SkXfermode::kDstATop_Mode;
//     break;
//    case 11:
//     mode = SkXfermode::kXor_Mode;
//     break;
//    case 12:
//     mode = SkXfermode::kPlus_Mode;
//     break;
//    case 13:
//     mode = SkXfermode::kModulate_Mode;
//     break;
//    case 14:
//     mode = SkXfermode::kScreen_Mode;
//     break;
//    case 15:
//     mode = SkXfermode::kOverlay_Mode;
//     break;
//    case 16:
//     mode = SkXfermode::kDarken_Mode;
//     break;
//    case 17:
//     mode = SkXfermode::kLighten_Mode;
//     break;
//    case 18:
//     mode = SkXfermode::kColorDodge_Mode;
//     break;
//    case 19:
//     mode = SkXfermode::kColorBurn_Mode;
//     break;
//    case 20:
//     mode = SkXfermode::kHardLight_Mode;
//     break;
//    case 21:
//     mode = SkXfermode::kSoftLight_Mode;
//     break;
//    case 22:
//     mode = SkXfermode::kDifference_Mode;
//     break;
//    case 23: 
//     mode = SkXfermode::kExclusion_Mode;
//     break;
//    case 24:
//     mode = SkXfermode::kMultiply_Mode;
//     break;
//    case 25:
//     mode = SkXfermode::kHue_Mode;
//     break;
//    case 26:
//     mode = SkXfermode::kSaturation_Mode;
//     break;
//    case 27:
//     mode = SkXfermode::kColor_Mode;
//     break;
//    case 28:
//     mode = SkXfermode::kLuminosity_Mode;
//     break;
//    default:
//     mode = SkXfermode::kSrcOver_Mode;
//  }
//  // uint8_t alpha,
//  // SkXfermode::Mode xfermode,
//  // SkRect* bounds,
//  // skia::RefPtr<SkColorFilter> color_filter
//  SkRect rect = SkRect::MakeXYWH(*bx, *by, *bw, *bh);
//  skia::RefPtr<SkColorFilter> color_filter = skia::AdoptRef(reinterpret_cast<SkColorFilter *>(filter));
//  item->SetNew(alpha, mode, &rect, color_filter);
//  *bx = rect.x();
//  *by = rect.y();
//  *bw = rect.width();
//  *bh = rect.height();
// }

// void _DrawingDisplayItemSetNew(DisplayItemRef handle, PictureRef picture) {
//   cc::DrawingDisplayItem* item = reinterpret_cast<cc::DrawingDisplayItem *>(handle);
//   item->SetNew(reinterpret_cast<SkiaPicture *>(picture)->handle());
// }

// void _FilterDisplayItemSetNew(DisplayItemRef handle, float rx, float ry, float rw, float rh) {
//  cc::FilterDisplayItem* item = reinterpret_cast<cc::FilterDisplayItem *>(handle);
//  cc::FilterOperations ops; // fixit: for now!
//  gfx::RectF rect(rx, ry, rw, rh);
//  // const FilterOperations& filters, const gfx::RectF& bounds
//  item->SetNew(ops, rect);
// }

// void _FloatClipDisplayItemSetNew(DisplayItemRef handle, float rx, float ry, float rw, float rh) {
//  cc::FloatClipDisplayItem* item = reinterpret_cast<cc::FloatClipDisplayItem *>(handle);
//  // const gfx::RectF& clip_rect
//  gfx::RectF clip_rect(rx, ry, rw, rh); 
//  item->SetNew(clip_rect);
// }

// void _TransformDisplayItemSetNew(DisplayItemRef handle,
//   double col1row1, double col2row1,
//   double col3row1, double col4row1,
//   double col1row2, double col2row2,
//   double col3row2, double col4row2,
//   double col1row3, double col2row3,
//   double col3row3, double col4row3,
//   double col1row4, double col2row4,
//   double col3row4, double col4row4) {
  
//   gfx::Transform transform(col1row1, col2row1,
//    col3row1, col4row1,
//    col1row2, col2row2,
//    col3row2, col4row2,
//    col1row3, col2row3,
//    col3row3, col4row3,
//    col1row4, col2row4,
//    col3row4, col4row4);
//   cc::TransformDisplayItem* item = reinterpret_cast<cc::TransformDisplayItem *>(handle);
//   item->SetNew(transform);
// }

void _CompositorInitialize(int single_threaded) {
  //DLOG(INFO) << "_CompositorInitialize";
  base::CommandLine::Init(0, nullptr);
//   if (single_threaded) {
//     scoped_refptr<base::SingleThreadTaskRunner> main_task_runner = base::ThreadTaskRunnerHandle::Get();
//     DCHECK(main_task_runner);
//     g_deps.Pointer()->Set(new SingleThreadedCompositorDependencies(main_task_runner));//, single_threaded == 0 ? false : true));
// #if defined(OS_LINUX)  
//     gfx::InitializeThreadedX11();
// #endif  
//     gl::init::InitializeGLOneOff();
//   } else {
    application::ApplicationThread* app_thread = application::ApplicationThread::current();
    DCHECK(app_thread);
    //DLOG(INFO) << "_CompositorInitialize: app_thread = " << app_thread;
    //g_deps.Pointer()->Set(app_thread);
 // }
}

PaintShaderRef _PaintShaderCreateColor(int r, int g, int b, int a) {
  SkColor color = SkColorSetARGB(a, r, g, b);
  return new PaintShader(cc::PaintShader::MakeColor(color));
}

PaintShaderRef _PaintShaderCreateLinearGradient(
      const float* px,
      const float* py,
      const int* inputColors,
      const float* fpos,
      int count,
      int shader_tile_mode) {
  SkPoint points[count];
  SkColor colors[count];
  //SkScalar pos[count];
  
  for (int i = 0; i < count; ++i) {
    points[i].set(px[i], py[i]);
    colors[i] = static_cast<SkColor>(inputColors[i]);
  }      

  return new PaintShader(cc::PaintShader::MakeLinearGradient(
    points, 
    colors, 
    fpos, 
    count,
    static_cast<SkShader::TileMode>(shader_tile_mode)));
}

PaintShaderRef _PaintShaderCreateRadialGradient(
      float center_x,
      float center_y,
      float radius,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode) {

  SkPoint center = SkPoint::Make(center_x, center_y);
  SkColor colors[color_count];
  
  for (int i = 0; i < color_count; ++i) {
    colors[i] = SkColorSetARGB(a[i], r[i], g[i], b[i]);
  }

  return new PaintShader(cc::PaintShader::MakeRadialGradient(
    center, 
    radius,
    colors,
    pos,
    color_count,
    static_cast<SkShader::TileMode>(shader_tile_mode)));
}

PaintShaderRef _PaintShaderCreateTwoPointConicalGradient(
      float start_x,
      float start_y,
      float start_radius,
      float end_x,
      float end_y,
      float end_radius,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode) {
        
  SkPoint start = SkPoint::Make(start_x, start_y);
  SkPoint end = SkPoint::Make(start_x, start_y);
  SkColor colors[color_count];
  
  for (int i = 0; i < color_count; ++i) {
    colors[i] = SkColorSetARGB(a[i], r[i], g[i], b[i]);
  }

  return new PaintShader(cc::PaintShader::MakeTwoPointConicalGradient(
      start, 
      start_radius,
      end,
      end_radius,
      colors,
      pos,
      color_count,
      static_cast<SkShader::TileMode>(shader_tile_mode)));
}

PaintShaderRef _PaintShaderCreateSweepGradient(
      float cx,
      float cy,
      int* r,
      int* g,
      int* b,
      int* a,
      float* pos,
      int color_count,
      int shader_tile_mode,
      float start_degrees,
      float end_degrees) {
  
  SkColor colors[color_count];
  
  for (int i = 0; i < color_count; ++i) {
    colors[i] = SkColorSetARGB(a[i], r[i], g[i], b[i]);
  }

  return new PaintShader(cc::PaintShader::MakeSweepGradient(
    cx, 
    cy, 
    colors, 
    pos, 
    color_count,
    static_cast<SkShader::TileMode>(shader_tile_mode),
    start_degrees,
    end_degrees));
}

PaintShaderRef _PaintShaderCreateImage(
  ImageRef image,
  int shader_tile_mode_x,
  int shader_tile_mode_y,
  // local_matrix
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {

  SkImage* sk_img = reinterpret_cast<SkiaImage*>(image)->handle();
  cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
                        .set_id(cc::PaintImage::GetNextId()) // TODO: fix
                        .set_image(sk_ref_sp(sk_img), cc::PaintImage::GetNextContentId())
                        .TakePaintImage();

  SkMatrix local = SkMatrix::MakeAll(
      scale_x,
      skew_x,
      trans_x,
      skew_y,
      scale_y,
      trans_y,
      persp0,
      persp1,
      persp2);
  
  return new PaintShader(cc::PaintShader::MakeImage(
    paint_image, 
    static_cast<SkShader::TileMode>(shader_tile_mode_x),
    static_cast<SkShader::TileMode>(shader_tile_mode_y),
    &local));
}

PaintShaderRef _PaintShaderCreateImageFromBitmap(
  BitmapRef bitmap,
  int shader_tile_mode_x,
  int shader_tile_mode_y,
  // local_matrix
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {

  SkBitmap* sk_bitmap = reinterpret_cast<SkBitmap *>(bitmap);
  cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
                        .set_id(cc::PaintImage::GetNextId()) // TODO: fix
                        .set_image(SkImage::MakeFromBitmap(*sk_bitmap), cc::PaintImage::GetNextContentId())
                        .TakePaintImage();

  SkMatrix local = SkMatrix::MakeAll(
      scale_x,
      skew_x,
      trans_x,
      skew_y,
      scale_y,
      trans_y,
      persp0,
      persp1,
      persp2);
  
  return new PaintShader(cc::PaintShader::MakeImage(
    paint_image, 
    static_cast<SkShader::TileMode>(shader_tile_mode_x),
    static_cast<SkShader::TileMode>(shader_tile_mode_y),
    &local));

}

PaintShaderRef _PaintShaderCreatePaintRecord(
      PaintRecordRef record,
      float tile_x,
      float tile_y,
      float tile_w,
      float tile_h,
      int shader_tile_mode_x,
      int shader_tile_mode_y,
      // local_matrix
      double scale_x,
      double skew_x,
      double trans_x,
      double skew_y,
      double scale_y,
      double trans_y,
      double persp0,
      double persp1,
      double persp2) {
  
  SkRect tile = SkRect::MakeXYWH(tile_x, tile_y, tile_w, tile_h);
  SkMatrix local = SkMatrix::MakeAll(
      scale_x,
      skew_x,
      trans_x,
      skew_y,
      scale_y,
      trans_y,
      persp0,
      persp1,
      persp2);
  
  return new PaintShader(cc::PaintShader::MakePaintRecord(
    sk_ref_sp(reinterpret_cast<PaintRecord*>(record)->handle()),
    tile,
    static_cast<SkShader::TileMode>(shader_tile_mode_x),
    static_cast<SkShader::TileMode>(shader_tile_mode_y),
    &local));
}

void _PaintShaderDestroy(PaintShaderRef shader) {
  delete reinterpret_cast<PaintShader *>(shader);
}

PaintFlagsRef _PaintFlagsCreate() {
  return new PaintFlags();
}

void _PaintFlagsDestroy(PaintFlagsRef flags) {
  delete reinterpret_cast<PaintFlags *>(flags);
}

PaintRef _PaintFlagsToSkiaPaint(PaintFlagsRef flags) {
  SkPaint paint = reinterpret_cast<PaintFlags *>(flags)->ref().ToSkPaint();
  return new SkPaint(paint);
}

int _PaintFlagsIsSimpleOpacity(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().IsSimpleOpacity() ? 1 : 0;
}

int _PaintFlagsGetStyleFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getStyle();
}

int _PaintFlagsGetBlendModeFlag(PaintFlagsRef flags) {
  return static_cast<int>(reinterpret_cast<PaintFlags *>(flags)->const_ref().getBlendMode());
}

uint8_t _PaintFlagsGetAlphaFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getAlpha();
}

void _PaintFlagsGetColorFlag(PaintFlagsRef flags, uint8_t* r, uint8_t* g, uint8_t* b, uint8_t* a) {
  SkColor color = reinterpret_cast<PaintFlags *>(flags)->const_ref().getColor();
  *a = SkColorGetA(color);
  *r = SkColorGetR(color);
  *g = SkColorGetG(color);
  *b = SkColorGetB(color);
}

int _PaintFlagsGetAntiAliasFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isAntiAlias();
}

int _PaintFlagsGetVerticalTextFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isVerticalText();
}

int _PaintFlagsGetSubpixelTextFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isSubpixelText();
}

int _PaintFlagsGetLCDRenderTextFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isLCDRenderText();
}

int _PaintFlagsGetHintingFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getHinting();
}

int _PaintFlagsGetAutohintedFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isAutohinted();
}

int _PaintFlagsGetDitherFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().isDither();
}

int _PaintFlagsGetTextEncodingFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getTextEncoding();
}

float _PaintFlagsGetTextSizeFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getTextSize();
}

int _PaintFlagsGetFilterQualityFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getFilterQuality();
}

float _PaintFlagsGetStrokeWidthFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getStrokeWidth();
}

float _PaintFlagsGetStrokeMiterFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getStrokeMiter();
}

int _PaintFlagsGetStrokeCapFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getStrokeCap();
}

int _PaintFlagsGetStrokeJoinFlag(PaintFlagsRef flags) {
  return reinterpret_cast<PaintFlags *>(flags)->const_ref().getStrokeJoin();
}

TypefaceRef _PaintFlagsGetTypefaceFlag(PaintFlagsRef flags) {
  SkiaTypeface* handle = new SkiaTypeface();
  handle->set(reinterpret_cast<PaintFlags *>(flags)->const_ref().getTypeface());
  return handle;
}

ColorFilterRef _PaintFlagsGetColorFilterFlag(PaintFlagsRef flags) {
  SkiaColorFilter* handle = new SkiaColorFilter();
  handle->set(reinterpret_cast<PaintFlags *>(flags)->const_ref().getColorFilter());
  return handle;
}

MaskFilterRef _PaintFlagsGetMaskFilterFlag(PaintFlagsRef flags) {
   SkiaMaskFilter* handle = new SkiaMaskFilter();
   handle->set(reinterpret_cast<PaintFlags *>(flags)->const_ref().getMaskFilter());
   return handle;
}

PaintShaderRef _PaintFlagsGetShaderFlag(PaintFlagsRef flags) {
  if (reinterpret_cast<PaintFlags *>(flags)->const_ref().HasShader()) {
    return new PaintShader(sk_ref_sp(reinterpret_cast<PaintFlags *>(flags)->const_ref().getShader()));
  }
  return nullptr;
}

PathEffectRef _PaintFlagsGetPathEffectFlag(PaintFlagsRef flags) {
  PathEffect* handle = new PathEffect();
  handle->set(reinterpret_cast<PaintFlags *>(flags)->const_ref().getPathEffect());
  return handle;
}

PaintFilterRef _PaintFlagsGetImageFilterFlag(PaintFlagsRef flags) {
  return new PaintFilter(sk_ref_sp(reinterpret_cast<PaintFlags *>(flags)->const_ref().getImageFilter().get()));
}

DrawLooperRef _PaintFlagsGetLooperFlag(PaintFlagsRef flags) {
  SkiaDrawLooper* handle = new SkiaDrawLooper();
  handle->set(reinterpret_cast<PaintFlags *>(flags)->const_ref().getLooper());
  return handle;
}

void _PaintFlagsSetStyleFlag(PaintFlagsRef flags, int style) {
  cc::PaintFlags::Style paint_style = cc::PaintFlags::kFill_Style;
  if (style == 1) { 
    paint_style = cc::PaintFlags::kStroke_Style;
  } else if (style) {
    paint_style = cc::PaintFlags::kStrokeAndFill_Style;
  }
  reinterpret_cast<PaintFlags *>(flags)->ref().setStyle(paint_style);
}

void _PaintFlagsSetBlendModeFlag(PaintFlagsRef flags, int blend_mode) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setBlendMode(static_cast<SkBlendMode>(blend_mode));
}
  
void _PaintFlagsSetAlphaFlag(PaintFlagsRef flags, uint8_t alpha) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setAlpha(alpha);
}

void _PaintFlagsSetColorFlag(PaintFlagsRef flags, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
  SkColor color = SkColorSetARGB(a, r, g, b);
  reinterpret_cast<PaintFlags *>(flags)->ref().setColor(color);
}

void _PaintFlagsSetAntiAliasFlag(PaintFlagsRef flags, int aa) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setAntiAlias(aa == 1 ? true : false); 
}

void _PaintFlagsSetVerticalTextFlag(PaintFlagsRef flags, int vertical) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setVerticalText(vertical == 1 ? true : false);
}

void _PaintFlagsSetSubpixelTextFlag(PaintFlagsRef flags, int subpixel_text) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setSubpixelText(subpixel_text == 1 ? true : false);
}

void _PaintFlagsSetLCDRenderTextFlag(PaintFlagsRef flags, int lcd_text) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setLCDRenderText(lcd_text == 1 ? true : false);
}

void _PaintFlagsSetHintingFlag(PaintFlagsRef flags, int hinting) {
  cc::PaintFlags::Hinting paint_hinting = cc::PaintFlags::kNormal_Hinting;
  if (hinting == 0) {
    paint_hinting = cc::PaintFlags::kNo_Hinting;
  } else if (hinting == 1) {
    paint_hinting = cc::PaintFlags::kSlight_Hinting;
  } else if (hinting == 3) {
    paint_hinting = cc::PaintFlags::kFull_Hinting;
  }
  reinterpret_cast<PaintFlags *>(flags)->ref().setHinting(paint_hinting);
}

void _PaintFlagsSetAutohintedFlag(PaintFlagsRef flags, int use_auto_hinter) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setAutohinted(use_auto_hinter == 1 ? true : false);
}

void _PaintFlagsSetDitherFlag(PaintFlagsRef flags, int dither) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setDither(dither == 1 ? true : false);
}

void _PaintFlagsSetTextEncodingFlag(PaintFlagsRef flags, int encoding) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setTextEncoding(static_cast<cc::PaintFlags::TextEncoding>(encoding));
}

void _PaintFlagsSetTextSizeFlag(PaintFlagsRef flags, float text_size) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setTextSize(text_size);
}

void _PaintFlagsSetFilterQualityFlag(PaintFlagsRef flags, int quality) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setFilterQuality(static_cast<SkFilterQuality>(quality));
}

void _PaintFlagsSetStrokeWidthFlag(PaintFlagsRef flags, float width) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setStrokeWidth(width);
}

void _PaintFlagsSetStrokeMiterFlag(PaintFlagsRef flags, float miter) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setStrokeMiter(miter);
}

void _PaintFlagsSetStrokeCapFlag(PaintFlagsRef flags, int cap) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setStrokeCap(static_cast<cc::PaintFlags::Cap>(cap));
}

void _PaintFlagsSetStrokeJoinFlag(PaintFlagsRef flags, int join) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setStrokeJoin(static_cast<cc::PaintFlags::Join>(join));
}

void _PaintFlagsSetTypefaceFlag(PaintFlagsRef flags, TypefaceRef typeface) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setTypeface(reinterpret_cast<SkiaTypeface *>(typeface)->own());
}

void _PaintFlagsSetColorFilterFlag(PaintFlagsRef flags, ColorFilterRef color_filter) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setColorFilter(reinterpret_cast<SkiaColorFilter *>(color_filter)->own());
}

void _PaintFlagsSetMaskFilterFlag(PaintFlagsRef flags, MaskFilterRef mask) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setMaskFilter(reinterpret_cast<SkiaMaskFilter *>(mask)->own());
}

void _PaintFlagsSetShaderFlag(PaintFlagsRef flags, PaintShaderRef shader) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setShader(reinterpret_cast<PaintShader *>(shader)->own());
}

void _PaintFlagsSetPathEffectFlag(PaintFlagsRef flags, PathEffectRef effect) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setPathEffect(reinterpret_cast<PathEffect *>(effect)->own());
}

void _PaintFlagsSetImageFilterFlag(PaintFlagsRef flags, PaintFilterRef filter) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setImageFilter(reinterpret_cast<PaintFilter *>(filter)->own());
}

void _PaintFlagsSetLooperFlag(PaintFlagsRef flags, DrawLooperRef looper) {
  reinterpret_cast<PaintFlags *>(flags)->ref().setLooper(reinterpret_cast<SkiaDrawLooper *>(looper)->own());
}

DisplayItemListRef _DisplayItemListCreate(int display_list_usage_hint) {
  //DLOG(INFO) << "_DisplayItemListCreate";
  //cc::DisplayItemListSettings settings;
  //settings.use_cached_picture = use_cached_picture ? true : false;
  _DisplayItemList* display_list = new _DisplayItemList(base::MakeRefCounted<cc::DisplayItemList>(static_cast<cc::DisplayItemList::UsageHint>(display_list_usage_hint)));
  return display_list;
}

void _DisplayItemListDestroy(DisplayItemListRef list) {
  //DLOG(INFO) << "_DisplayItemListDestroy";
  delete reinterpret_cast<_DisplayItemList *>(list);
}

int _DisplayItemListTotalOpCount(DisplayItemListRef list) {
  return reinterpret_cast<_DisplayItemList *>(list)->TotalOpCount();
}

void _DisplayItemListStartPaint(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->StartPaint();
}

void _DisplayItemListEndPaintOfPairedBegin(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->EndPaintOfPairedBegin();
}

void _DisplayItemListEndPaintOfPairedBeginWithRect(DisplayItemListRef list, int rx, int ry, int rw, int rh) {
  gfx::Rect rect(rx, ry, rw, rh);
  reinterpret_cast<_DisplayItemList *>(list)->EndPaintOfPairedBegin(rect);
}

void _DisplayItemListEndPaintOfPairedEnd(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->EndPaintOfPairedEnd();
}

void _DisplayItemListEndPaintOfUnpaired(DisplayItemListRef list, int rx, int ry, int rw, int rh) {
  gfx::Rect rect(rx, ry, rw, rh);
  reinterpret_cast<_DisplayItemList *>(list)->EndPaintOfUnpaired(rect);
}

void _DisplayItemListFinalize(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->Finalize();
}

PaintRecordRef _DisplayItemListReleaseAsRecord(DisplayItemListRef list) {
  sk_sp<cc::PaintRecord> handle = reinterpret_cast<_DisplayItemList *>(list)->ReleaseAsRecord();
  return new PaintRecord(std::move(handle));
}

void _DisplayItemListPushClipPath(DisplayItemListRef list, PathRef path, int clip_op, int antialias) {
   reinterpret_cast<_DisplayItemList *>(list)->ClipPath(
      reinterpret_cast<SkiaPath*>(path)->ref(),
      static_cast<SkClipOp>(clip_op),
      antialias == 1 ? true : false);
}

void _DisplayItemListPushClipRect(DisplayItemListRef list, float rx, float ry, float rw, float rh, int clip_op, int antialias) {
  SkRect rect = SkRect::MakeXYWH(rx, ry, rw, rh);
  reinterpret_cast<_DisplayItemList *>(list)->ClipRect(
      rect,
      static_cast<SkClipOp>(clip_op),
      antialias == 1 ? true : false);
}

void _DisplayItemListPushClipRRect(DisplayItemListRef list, float x, float y, float w, float h, int clip_op, int antialias) {
  SkRRect rr;
  rr.setRect(SkRect::MakeXYWH(x, y, w, h));
  reinterpret_cast<_DisplayItemList *>(list)->ClipRRect(
      rr,
      static_cast<SkClipOp>(clip_op),
      antialias == 1 ? true : false);
}

void _DisplayItemListPushConcat(DisplayItemListRef list, 
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {

  SkMatrix mat = SkMatrix::MakeAll(
    scale_x, skew_x, trans_x, 
    skew_y, scale_y, trans_y,
    persp0, persp1, persp2);

  reinterpret_cast<_DisplayItemList *>(list)->Concat(mat);
}

void _DisplayItemListPushCustomData(DisplayItemListRef list, uint32_t id) {
  reinterpret_cast<_DisplayItemList *>(list)->RecordCustomData(id);
}

void _DisplayItemListPushDrawColor(DisplayItemListRef list, int r, int g , int b, int a, int blend_mode) {
  SkColor color = SkColorSetARGB(a, r, g, b);
  reinterpret_cast<_DisplayItemList *>(list)->DrawColor(
    color,
    static_cast<SkBlendMode>(blend_mode));
}

void _DisplayItemListPushDrawDRRect(DisplayItemListRef list, float ix, float iy, float iw, float ih, float ox, float oy, float ow, float oh, PaintFlagsRef flags) {
  DCHECK(flags);

  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkRRect inner_rect, outer_rect;
  const cc::PaintFlags& local_flags = reinterpret_cast<PaintFlags *>(flags)->const_ref();
  
  inner_rect.setRect(SkRect::MakeXYWH(ix, iy, iw, ih));
  outer_rect.setRect(SkRect::MakeXYWH(ox, oy, ow, oh));

  display_list->DrawDRRect(
    outer_rect, 
    inner_rect,
    local_flags);
}   

void _DisplayItemListPushDrawBitmap(DisplayItemListRef list, BitmapRef bitmap, float left, float top, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkBitmap* sk_bitmap = reinterpret_cast<SkBitmap *>(bitmap);
  const cc::PaintFlags* local_flags = flags ? reinterpret_cast<PaintFlags *>(flags)->const_ptr() : nullptr;
  display_list->DrawBitmap(
    *sk_bitmap,
    left,
    top,
    local_flags);
}

void _DisplayItemListPushDrawImage(DisplayItemListRef list, ImageRef image, float left, float top, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkImage* sk_img = reinterpret_cast<SkiaImage*>(image)->handle();
  const cc::PaintFlags* local_flags = flags ? reinterpret_cast<PaintFlags *>(flags)->const_ptr() : nullptr;
  cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
                        .set_id(cc::PaintImage::GetNextId()) // TODO: fix
                        .set_image(sk_ref_sp(sk_img), cc::PaintImage::GetNextContentId())
                        .TakePaintImage();  
  display_list->DrawImage(
    paint_image,
    left,
    top,
    local_flags);
}

void _DisplayItemListPushDrawImageRect(DisplayItemListRef list, ImageRef image, float sx, float sy, float sw, float sh, float dx, float dy, float dw, float dh, int paint_canvas_src_rect_constraint, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);  
  SkImage* sk_img = reinterpret_cast<SkiaImage*>(image)->handle();
  const cc::PaintFlags* local_flags = flags ? reinterpret_cast<PaintFlags *>(flags)->const_ptr() : nullptr;
  cc::PaintImage paint_image = cc::PaintImageBuilder::WithDefault()
                        .set_id(cc::PaintImage::GetNextId()) // TODO: fix
                        .set_image(sk_ref_sp(sk_img), cc::PaintImage::GetNextContentId())
                        .TakePaintImage();
  SkRect src = SkRect::MakeXYWH(sx, sy, sw, sh);
  SkRect dst = SkRect::MakeXYWH(dx, dy, dw, dh);
  display_list->DrawImageRect(
    paint_image,
    src,
    dst,
    local_flags,
    static_cast<cc::PaintCanvas::SrcRectConstraint>(paint_canvas_src_rect_constraint));
}

void _DisplayItemListPushDrawIRect(DisplayItemListRef list, int x, int y, int w, int h, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkIRect src = SkIRect::MakeXYWH(x, y, w, h);
  display_list->DrawIRect(src, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawLine(DisplayItemListRef list, float x0, float y0, float x1, float y1, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  display_list->DrawLine(x0, y0, x1, y1, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawOval(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkRect oval = SkRect::MakeXYWH(x, y, w ,h);
  display_list->DrawOval(oval, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawPath(DisplayItemListRef list, PathRef path, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  const SkPath& sk_path = reinterpret_cast<SkiaPath *>(path)->ref();
  display_list->DrawPath(sk_path, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawRecord(DisplayItemListRef list, PaintRecordRef record) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  display_list->DrawRecord(
    sk_ref_sp(reinterpret_cast<PaintRecord *>(record)->handle()));
}

void _DisplayItemListPushDrawRect(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags) {
  DCHECK(flags);
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkRect rect = SkRect::MakeXYWH(x, y, w ,h);
  display_list->DrawRect(rect, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawRRect(DisplayItemListRef list, float x, float y, float w, float h, PaintFlagsRef flags) {
  DCHECK(flags);
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  SkRRect rect;
  rect.setRect(SkRect::MakeXYWH(x, y, w ,h));
  display_list->DrawRRect(rect, reinterpret_cast<PaintFlags *>(flags)->const_ref());
}

void _DisplayItemListPushDrawTextBlob(DisplayItemListRef list, PaintTextBlobRef blob, float x, float y, PaintFlagsRef flags) {
  DCHECK(flags);
  PaintTextBlob* paint_text_blob = reinterpret_cast<PaintTextBlob *>(blob);
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  //cc::PaintFlags& ccflags = reinterpret_cast<PaintFlags *>(flags)->ref();
  // NOTE: the reference to PaintFlags is not working.. FIX
  //cc::PaintFlags local_flags(*reinterpret_cast<cc::PaintFlags *>(flags));
  cc::PaintFlags local_flags;//(ccflags);
  local_flags.setStyle(cc::PaintFlags::kFill_Style);
  local_flags.setAntiAlias(true);
  local_flags.setSubpixelText(false);
  local_flags.setLCDRenderText(false);
  local_flags.setHinting(cc::PaintFlags::kNormal_Hinting);
  
  display_list->DrawTextBlob(
    paint_text_blob->ref(),
    x,
    y,
    local_flags);

}

void _DisplayItemListPushNoop(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->Noop();
}

void _DisplayItemListPushRestore(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->Restore();
}

void _DisplayItemListPushRotate(DisplayItemListRef list, float degrees) {
  reinterpret_cast<_DisplayItemList *>(list)->Rotate(degrees);
}

void _DisplayItemListPushSave(DisplayItemListRef list) {
  reinterpret_cast<_DisplayItemList *>(list)->Save();
}

void _DisplayItemListPushSaveLayer(DisplayItemListRef list, PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  const cc::PaintFlags* local_flags = flags ? reinterpret_cast<PaintFlags *>(flags)->const_ptr() : nullptr;
  display_list->SaveLayer(nullptr, local_flags);//display_list->flags());
}

void _DisplayItemListPushSaveLayerBounds(DisplayItemListRef list, 
  float x, 
  float y, 
  float w, 
  float h, 
  PaintFlagsRef flags) {
  _DisplayItemList* display_list = reinterpret_cast<_DisplayItemList *>(list);
  const cc::PaintFlags* local_flags = flags ? reinterpret_cast<PaintFlags *>(flags)->const_ptr() : nullptr;
  SkRect rect = SkRect::MakeXYWH(x, y, w, h); 
  display_list->SaveLayer(&rect, local_flags);
}

void _DisplayItemListPushSaveLayerAlpha(DisplayItemListRef list, uint8_t alpha, int preserve_lcd_text_requests) {//, int* x, int* y, int* w, int* h, int* rect_is_set) {
  reinterpret_cast<_DisplayItemList *>(list)->SaveLayerAlpha(nullptr, alpha, preserve_lcd_text_requests == 0 ? false : true);
}

void _DisplayItemListPushSaveLayerAlphaBounds(DisplayItemListRef list,
  float x, 
  float y, 
  float w, 
  float h,
  uint8_t alpha, 
  int preserve_lcd_text_requests) {

  SkRect rect = SkRect::MakeXYWH(x, y, w, h);
  reinterpret_cast<_DisplayItemList *>(list)->SaveLayerAlpha(&rect, alpha, preserve_lcd_text_requests == 0 ? false : true);
}

void _DisplayItemListPushScale(DisplayItemListRef list, float x, float y) {
  reinterpret_cast<_DisplayItemList *>(list)->Scale(x, y);
}

void _DisplayItemListPushSetMatrix(DisplayItemListRef list,
  double scale_x,
  double skew_x,
  double trans_x,
  double skew_y,
  double scale_y,
  double trans_y,
  double persp0,
  double persp1,
  double persp2) {
  
  SkMatrix mat = SkMatrix::MakeAll(
    scale_x, skew_x, trans_x, 
    skew_y, scale_y, trans_y,
    persp0, persp1, persp2);

  reinterpret_cast<_DisplayItemList *>(list)->SetMatrix(mat);
}

void _DisplayItemListPushTranslate(DisplayItemListRef list, float x, float y) {
  reinterpret_cast<_DisplayItemList *>(list)->Translate(x, y);
}

void _DisplayItemImageRasterWithFlags() {
  DCHECK(false);
}

void _DisplayItemImageRectRasterWithFlags() {
  DCHECK(false);
}

void _PaintRecordPlayback(PaintRecordRef handle, CanvasRef canvas) {
  reinterpret_cast<PaintRecord *>(handle)->handle()->Playback(reinterpret_cast<SkiaCanvas *>(canvas)->handle());
}

void _PaintRecordPlaybackParams(PaintRecordRef handle, CanvasRef canvas, MatrixRef mat) {
  cc::PlaybackParams params(nullptr, *reinterpret_cast<SkMatrix*>(mat));
  reinterpret_cast<PaintRecord *>(handle)->handle()->Playback(reinterpret_cast<SkiaCanvas *>(canvas)->handle(), params);
}

void _PaintRecordDestroy(PaintRecordRef handle) {
  delete reinterpret_cast<PaintRecord *>(handle);
}

// DisplayItemRef _DisplayItemListCreateAndAppendItem(DisplayItemListRef list, int type) {
//   cc::DisplayItemList* display_list = reinterpret_cast<cc::DisplayItemList *>(list);
//   cc::DisplayItem* item = nullptr;
//   switch (type) {
//     case DisplayItemTypeClip:
//       item = display_list->CreateAndAppendItem<cc::ClipDisplayItem>();
//       break;
//     case DisplayItemTypeEndClip:
//       item = display_list->CreateAndAppendItem<cc::EndClipDisplayItem>();
//       break;
//     case DisplayItemTypeClipPath:
//       item = display_list->CreateAndAppendItem<cc::ClipPathDisplayItem>();
//       break;
//     case DisplayItemTypeEndClipPath:
//       item = display_list->CreateAndAppendItem<cc::EndClipPathDisplayItem>();
//       break;
//     case DisplayItemTypeCompositing:
//       item = display_list->CreateAndAppendItem<cc::CompositingDisplayItem>();
//       break;
//     case DisplayItemTypeEndCompositing:
//       item = display_list->CreateAndAppendItem<cc::EndCompositingDisplayItem>();
//       break;
//     case DisplayItemTypeFilter:
//       item = display_list->CreateAndAppendItem<cc::FilterDisplayItem>();
//       break;
//     case DisplayItemTypeEndFilter:
//       item = display_list->CreateAndAppendItem<cc::EndFilterDisplayItem>();
//       break;
//     case DisplayItemTypeDrawing:
//       item = display_list->CreateAndAppendItem<cc::DrawingDisplayItem>();
//       break;
//     case DisplayItemTypeFloatClip:
//       item = display_list->CreateAndAppendItem<cc::FloatClipDisplayItem>();
//       break;
//     case DisplayItemTypeEndFloatClip:
//       item = display_list->CreateAndAppendItem<cc::EndFloatClipDisplayItem>();
//       break;
//     case DisplayItemTypeTransform:
//       item = display_list->CreateAndAppendItem<cc::TransformDisplayItem>();
//       break;
//     case DisplayItemTypeEndTransform:
//       item = display_list->CreateAndAppendItem<cc::EndTransformDisplayItem>();
//       break;
//   }
//   return item;
// }

ContextProviderRef _ContextProviderCreate(
  int alphaSize,
  int blueSize,
  int greenSize,
  int redSize,
  int depthSize,
  int stencilSize,
  int samples,
  int sampleBuffers,
  int bufferPreserved,
  int bindGeneratesResource,
  int failIfMajorPerfCaveat,
  int loseContextWhenOutOfMemory,
  int contextType,
#if defined(OS_LINUX)
  XID widget,
#elif defined(OS_WIN)
  HWND widget,
#endif
  int offscreen) {
  DCHECK(false);
  
  application::ApplicationThread* deps = application::ApplicationThread::current();
  
  gpu::ContextCreationAttribs attribs;
  attribs.alpha_size = alphaSize;
  attribs.blue_size = blueSize;
  attribs.green_size = greenSize;
  attribs.red_size = redSize;
  attribs.depth_size = depthSize;
  attribs.stencil_size = stencilSize;
  attribs.samples = samples;
  attribs.sample_buffers = sampleBuffers;
  attribs.buffer_preserved = bufferPreserved ? true : false;
  attribs.bind_generates_resource = bindGeneratesResource ? true : false;
  attribs.fail_if_major_perf_caveat = failIfMajorPerfCaveat ? true : false;
 // attribs.lose_context_when_out_of_memory = loseContextWhenOutOfMemory ? true : false;
  //attribs.context_type = gpu::ContextType::CONTEXT_TYPE_OPENGLES2;//gles2::CONTEXT_TYPE_OPENGLES2;//contextType;
  // the client should be running over a 'current' message loop, before we get here
  //base::MessageLoop* current = base::MessageLoop::current();
  //DCHECK(current);
  //if(!current)
  // return nullptr;

  _ContextProvider* provider = new _ContextProvider();
  
 if (offscreen) {
  provider->handle = InProcessContextProvider::CreateOffscreen(
     deps->GetGpuMemoryBufferManager(),
     deps->GetImageFactory(), false);

 } else {
  provider->handle = InProcessContextProvider::Create(
    attribs,
    deps->GetGpuMemoryBufferManager(),
    deps->GetImageFactory(),
    widget,
    "UICompositor",
    false);
  }

  return provider;
}

void _ContextProviderDestroy(ContextProviderRef provider) {
  DCHECK(false);
  delete reinterpret_cast<_ContextProvider *>(provider);
}

int _ContextProviderBindToCurrentThread(ContextProviderRef provider) {
  return reinterpret_cast<_ContextProvider *>(provider)->handle->BindToCurrentThread() == gpu::ContextResult::kSuccess ? 1 : 0;
}

// void _ContextProviderDetachFromThread(ContextProviderRef provider) {
//   reinterpret_cast<_ContextProvider *>(provider)->handle->DetachFromThread();
// }

// void _ContextProviderInvalidateGrContext(ContextProviderRef provider, uint32_t state) {
//   reinterpret_cast<_ContextProvider *>(provider)->handle->InvalidateGrContext(state);
// }

// void _ContextProviderDeleteCachedResources(ContextProviderRef provider) {
//   reinterpret_cast<_ContextProvider *>(provider)->handle->DeleteCachedResources();
// }

// void _ContextProviderSetupLock(ContextProviderRef provider) {
//   reinterpret_cast<_ContextProvider *>(provider)->handle->SetupLock();
// }

OutputSurfaceRef _OutputSurfaceCreate(ContextProviderRef provider, ContextProviderRef worker) {
  //if (type == OutputSurfaceTypeDirect) { // we only support direct for now
 scoped_refptr<InProcessContextProvider> context_provider = reinterpret_cast<_ContextProvider *>(provider)->handle;
 DirectOutputSurface* surface = new DirectOutputSurface(context_provider); //g_deps.Pointer()->Get()->CreateDirectOutputSurface(context_provider);
 return surface;
 //}
 //return nullptr;
}

void _OutputSurfaceDestroy(OutputSurfaceRef surface) {
  delete reinterpret_cast<viz::OutputSurface *>(surface);
}

// int _OutputSurfaceBindToClient(OutputSurfaceRef surface) {
//   NOTREACHED(); // "we" shouldnt be called
//   //return surface->handle->BindToClient();
//   return 0;
// }

// void _OutputSurfaceDetachFromClient(OutputSurfaceRef surface) {
//   return reinterpret_cast<_OutputSurface *>(surface)->handle->DetachFromClient();
// }

void _OutputSurfaceEnsureBackbuffer(OutputSurfaceRef surface) {
  return reinterpret_cast<viz::OutputSurface *>(surface)->EnsureBackbuffer();
}

void _OutputSurfaceDiscardBackbuffer(OutputSurfaceRef surface) {
  return reinterpret_cast<viz::OutputSurface *>(surface)->DiscardBackbuffer();
}

void _OutputSurfaceReshape(OutputSurfaceRef surface, 
  int width, int height, float scaleFactor,
  int has_alpha, int use_stencil) {
 
  // TODO: see if theres a need to provide this from source
  gfx::ColorSpace rgb = gfx::ColorSpace::CreateSRGB();  
  
  return reinterpret_cast<viz::OutputSurface *>(surface)->Reshape(
    gfx::Size(width, height), 
    scaleFactor,
    rgb,
    has_alpha ? true : false,
    use_stencil ? true : false);
}

// void _OutputSurfaceSurfaceSize(OutputSurfaceRef surface, int* width, int* height) {
//   gfx::Size size = reinterpret_cast<_OutputSurface *>(surface)->handle->SurfaceSize();
//   *width = size.width();
//   *height = size.height();
// }

// float _OutputSurfaceDeviceScaleFactor(OutputSurfaceRef surface) {
//   return reinterpret_cast<_OutputSurface *>(surface)->handle->device_scale_factor();
// }

// void _OutputSurfaceForceReclaimResources(OutputSurfaceRef surface) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->ForceReclaimResources();
// }

void _OutputSurfaceBindFramebuffer(OutputSurfaceRef surface) {
  reinterpret_cast<viz::OutputSurface *>(surface)->BindFramebuffer();
}

// void _OutputSurfaceOnSwapBuffersComplete(OutputSurfaceRef surface) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->OnSwapBuffersComplete();
// }

// void _OutputSurfaceUpdateSmoothnessTakesPriority(OutputSurfaceRef surface, int preferSmoothness) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->UpdateSmoothnessTakesPriority(preferSmoothness ? true : false);
// }

// int _OutputSurfaceHasClient(OutputSurfaceRef surface) {
//   return reinterpret_cast<_OutputSurface *>(surface)->handle->HasClient() ? 1 : 0;
// }

void _OutputSurfaceGetOverlayCandidateValidator(OutputSurfaceRef surface) {
  reinterpret_cast<viz::OutputSurface *>(surface)->GetOverlayCandidateValidator();
}

int _OutputSurfaceIsDisplayedAsOverlayPlane(OutputSurfaceRef surface) {
  return reinterpret_cast<viz::OutputSurface *>(surface)->IsDisplayedAsOverlayPlane();
}

uint32_t _OutputSurfaceGetOverlayTextureId(OutputSurfaceRef surface) {
  return reinterpret_cast<viz::OutputSurface *>(surface)->GetOverlayTextureId();
}

// void _OutputSurfaceDidLoseOutputSurface(OutputSurfaceRef surface) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->DidLoseOutputSurface();
// }

// void _OutputSurfaceSetMemoryPolicy(OutputSurfaceRef surface) {

// }

// void _OutputSurfaceInvalidate(OutputSurfaceRef surface) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->Invalidate();
// }

// void _OutputSurfaceSetWorkerContextShouldAggressivelyFreeResources(OutputSurfaceRef surface, int isVisible) {
//   reinterpret_cast<_OutputSurface *>(surface)->handle->SetWorkerContextShouldAggressivelyFreeResources(isVisible ? true : false);
// }

int _OutputSurfaceSurfaceIsSuspendForRecycle(OutputSurfaceRef surface) {
  return reinterpret_cast<viz::OutputSurface *>(surface)->SurfaceIsSuspendForRecycle();
}

void _DirectOutputSurfaceSwapBuffers(OutputSurfaceRef surface, CompositorFrameRef frame) {
  //reinterpret_cast<_OutputSurface *>(surface)->handle->SwapBuffers(reinterpret_cast<_ompositorFrame *>(frame)->handle.get());
}

CompositorFrameRef _CompositorFrameCreate() {
  return new _ompositorFrame(new viz::CompositorFrame());
}

void _CompositorFrameDestroy(CompositorFrameRef frame) {
  delete reinterpret_cast<_ompositorFrame *>(frame);
}

void _CompositorFrameSetMetadata(CompositorFrameRef frame) {

}

// LayerTreeHostRef _LayerTreeHostCreateThreaded(
//   void* payload,
//   AnimationHostRef animator_host,
//   CLayerTreeHostSingleThreadClientCbs callbacks) {
//  cc::LayerTreeSettings settings;
//   std::unique_ptr<CompositorLayerTreeHostClient> client =
//     std::unique_ptr<CompositorLayerTreeHostClient>(new CompositorLayerTreeHostClient(payload, callbacks));

//  // the client should be running over a 'current' message loop, before we get here
//  //base::MessageLoop* current = base::MessageLoop::current();
//  //if(!current)
// //  return nullptr;

//  settings.layers_always_allowed_lcd_text = true;
//  settings.use_occlusion_for_tile_prioritization = true;
//  //settings.renderer_settings.refresh_rate = 60.0;
//  settings.main_frame_before_activation_enabled = false;

//  //settings.renderer_settings.partial_swap_enabled = true;
// //#if defined(OS_WIN)
// // settings.renderer_settings.finish_rendering_on_resize = true;
// //#endif
// //
//   //settings.use_property_trees = true;
//   settings.use_zero_copy = true;//IsUIZeroCopyEnabled();
//  // settings.renderer_settings.use_rgba_4444_textures = true;
//   settings.use_partial_raster = !settings.use_zero_copy;
//   //settings.use_image_texture_targets =
//   //g_deps.Pointer()->Get()->GetImageTextureTargets();
//   //settings.image_decode_tasks_enabled = false;
//   //settings.use_compositor_animation_timelines = true;

// //#if !defined(OS_ANDROID)
//   // TODO(sohanjg): Revisit this memory usage in tile manager.
// //  cc::ManagedMemoryPolicy policy(
// //      512 * 1024 * 1024, gpu::MemoryAllocation::CUTOFF_ALLOW_NICE_TO_HAVE,
//  //     settings.memory_policy_.num_resources_limit);
// //  settings.memory_policy_ = policy;
// //#endif

//  scoped_refptr<base::SingleThreadTaskRunner> compositor_thread_task_runner =
//   g_deps.Pointer()->Get()->GetCompositorImplThreadTaskRunner();
//  scoped_refptr<base::SingleThreadTaskRunner>
//   main_thread_compositor_task_runner =
//   g_deps.Pointer()->Get()->GetCompositorMainThreadTaskRunner();
//  //viz::SharedBitmapManager* shared_bitmap_manager =
// //g_deps.Pointer()->Get()->GetSharedBitmapManager();
// // gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager =
//  // g_deps.Pointer()->Get()->GetGpuMemoryBufferManager();
//  cc::TaskGraphRunner* task_graph_runner =
//   g_deps.Pointer()->Get()->GetTaskGraphRunner();

//  //std::unique_ptr<viz::BeginFrameSource> external_begin_frame_source;
//  //if (settings.use_external_begin_frame_source) {
//   //external_begin_frame_source =
//   // compositor_deps_->CreateExternalBeginFrameSource(widget_->routing_id());
//  //}

//  cc::LayerTreeHost::InitParams params;
//  params.client = client.get();
//  //params.shared_bitmap_manager = shared_bitmap_manager;
//  //params.gpu_memory_buffer_manager = gpu_memory_buffer_manager;
//  params.settings = &settings;
//  params.task_graph_runner = task_graph_runner;
//  params.main_task_runner = main_thread_compositor_task_runner;
//  params.mutator_host = reinterpret_cast<_AnimationHost *>(animator_host)->handle();
//  //params.external_begin_frame_source = std::move(external_begin_frame_source);
 
//  //gfx::BufferUsage usage =
//  //     settings.use_partial_raster
//  //         ? gfx::BufferUsage::GPU_READ_PU_READ_WRITE_PERSISTENT
//  //         : gfx::BufferUsage::GPU_READ_PU_READ_WRITE;

// //   for (size_t format = 0;
// //       format < static_cast<size_t>(gfx::BufferFormat::LAST) + 1; format++) {
// //     DCHECK_GT(settings.use_image_texture_targets.size(), format);
// //     settings.use_image_texture_targets[format] =
// //         g_deps.Pointer()->Get()->GetImageTextureTarget(
// //             static_cast<gfx::BufferFormat>(format), usage);
// //  }

//  DCHECK(compositor_thread_task_runner.get());
//  //std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateThreaded(compositor_thread_task_runner, &params);
//  std::unique_ptr<cc::LayerTreeHost> ptr = std::unique_ptr<cc::LayerTreeHost>(g_deps.Pointer()->Get()->CreateLayerTreeHostThreaded(&params, compositor_thread_task_runner));
//  // TODO: we need to specify error codes and be more specific about errors happening on shims
//  if(!ptr) {
//   return nullptr;
//  }

//  return new _LayerTreeHost(std::move(ptr), std::move(client));
// }

LayerTreeHostRef _LayerTreeHostCreate(
  void* payload, 
  AnimationHostRef animator_host,
  CLayerTreeHostSingleThreadClientCbs callbacks,
  int /*bool*/ is_single_threaded,
  int /*bool*/ single_thread_proxy_scheduler,
  int /*bool*/ main_frame_before_activation_enabled,
  int /*bool*/ using_synchronous_renderer_compositor,
  int /*bool*/ enable_early_damage_check,
  int damaged_frame_limit,
  int /*bool*/ enable_latency_recovery,
  int /*bool*/ can_use_lcd_text,
  int /*bool*/ gpu_rasterization_forced,
  int gpu_rasterization_msaa_sample_count,
  float gpu_rasterization_skewport_target_time_in_seconds,
  int /*bool*/ create_low_res_tiling,
  int /*bool*/ use_stream_video_draw_quad,
  int64_t scrollbar_fade_delay,
  int64_t scrollbar_fade_duration,
  int64_t scrollbar_thinning_duration,
  int /*bool*/ scrollbar_flash_after_any_scroll_update,
  int /*bool*/ scrollbar_flash_when_mouse_enter,
  uint8_t solid_color_scrollbar_color_a,
  uint8_t solid_color_scrollbar_color_r,
  uint8_t solid_color_scrollbar_color_g,
  uint8_t solid_color_scrollbar_color_b,
  int /*bool*/ timeout_and_draw_when_animation_checkerboards,
  int /*bool*/ layer_transforms_should_scale_layer_contents,
  int /*bool*/ layers_always_allowed_lcd_text,
  float minimum_contents_scale,
  float low_res_contents_scale_factor,
  float top_controls_show_threshold,
  float top_controls_hide_threshold,
  double background_animation_rate,
  int default_tile_size_width,
  int default_tile_size_height,
  int max_untiled_layer_size_width,
  int max_untiled_layer_size_height,
  int max_gpu_raster_tile_size_width,
  int max_gpu_raster_tile_size_height,
  int minimum_occlusion_tracking_size_width,
  int minimum_occlusion_tracking_size_height,
  int tiling_interest_area_padding,
  float skewport_target_time_in_seconds,
  int skewport_extrapolation_limit_in_screen_pixels,
  int max_memory_for_prepaint_percentage,
  int /*bool*/ use_zero_copy,
  int /*bool*/ use_partial_raster,
  int /*bool*/ enable_elastic_overscroll,
  int /*bool*/ ignore_root_layer_flings,
  int scheduled_raster_task_limit,
  int /*bool*/ use_occlusion_for_tile_prioritization,
  int /*bool*/ use_layer_lists,
  int max_staging_buffer_usage_in_bytes,
  int memory_policy_bytes_limit_when_visible,
  int memory_policy_priority_cutoff_when_visible,
  int decoded_image_working_set_budget_bytes,
  int max_preraster_distance_in_screen_pixels,
  int /*bool*/ use_rgba_4444,
  int /*bool*/ unpremultiply_and_dither_low_bit_depth_tiles,
  int /*bool*/ enable_mask_tiling,
  int /*bool*/ enable_checker_imaging,
  int min_image_bytes_to_checker,
  int /*bool*/ only_checker_images_with_gpu_raster,
  int /*bool*/ enable_surface_synchronization,
  int /*bool*/ is_layer_tree_for_subframe,
  int /*bool*/ disallow_non_exact_resource_reuse,
  int /*bool*/ wait_for_all_pipeline_stages_before_draw,
  int /*bool*/ commit_to_active_tree,
  int /*bool*/ enable_oop_rasterization,
  int /*bool*/ enable_image_animation_resync,
  int /*bool*/ enable_edge_anti_aliasing,
  int /*bool*/ always_request_presentation_time,
  int /*bool*/ use_painted_device_scale_factor) {

  std::unique_ptr<CompositorLayerTreeHostClient> client =
    std::unique_ptr<CompositorLayerTreeHostClient>(new CompositorLayerTreeHostClient(payload, callbacks));

 //g_deps.Pointer()->Set(new CompositorDependencies(base::ThreadTaskRunnerHandle::Get()));
 cc::LayerTreeSettings settings;
 settings.single_thread_proxy_scheduler = single_thread_proxy_scheduler;
 settings.main_frame_before_activation_enabled = main_frame_before_activation_enabled;
 settings.using_synchronous_renderer_compositor = using_synchronous_renderer_compositor;
 settings.enable_early_damage_check = enable_early_damage_check;
 settings.damaged_frame_limit = damaged_frame_limit;
 settings.enable_latency_recovery = enable_latency_recovery;
 settings.can_use_lcd_text = can_use_lcd_text;
 settings.gpu_rasterization_forced = gpu_rasterization_forced;
 settings.gpu_rasterization_msaa_sample_count = gpu_rasterization_msaa_sample_count;
 settings.gpu_rasterization_skewport_target_time_in_seconds = gpu_rasterization_skewport_target_time_in_seconds;
 settings.create_low_res_tiling = create_low_res_tiling;
 settings.use_stream_video_draw_quad = use_stream_video_draw_quad;
 settings.scrollbar_fade_delay = base::TimeDelta::FromMicroseconds(scrollbar_fade_delay);
 settings.scrollbar_fade_duration = base::TimeDelta::FromMicroseconds(scrollbar_fade_duration);
 settings.scrollbar_thinning_duration = base::TimeDelta::FromMicroseconds(scrollbar_thinning_duration); 
 settings.scrollbar_flash_after_any_scroll_update = scrollbar_flash_after_any_scroll_update;
 settings.scrollbar_flash_when_mouse_enter = scrollbar_flash_when_mouse_enter;
 settings.solid_color_scrollbar_color = SkColorSetARGB(solid_color_scrollbar_color_a, solid_color_scrollbar_color_r, solid_color_scrollbar_color_g, solid_color_scrollbar_color_b);
 settings.timeout_and_draw_when_animation_checkerboards = timeout_and_draw_when_animation_checkerboards;
 settings.layer_transforms_should_scale_layer_contents = layer_transforms_should_scale_layer_contents;
 settings.layers_always_allowed_lcd_text = layers_always_allowed_lcd_text;
 settings.minimum_contents_scale = minimum_contents_scale;
 settings.low_res_contents_scale_factor = low_res_contents_scale_factor;
 settings.top_controls_show_threshold = top_controls_show_threshold;
 settings.top_controls_hide_threshold = top_controls_hide_threshold;
 settings.background_animation_rate = background_animation_rate;
 settings.default_tile_size = gfx::Size(default_tile_size_width, default_tile_size_height);
 settings.max_untiled_layer_size = gfx::Size(max_untiled_layer_size_width, max_untiled_layer_size_height);
 settings.max_gpu_raster_tile_size = gfx::Size(max_gpu_raster_tile_size_width, max_gpu_raster_tile_size_height);
 settings.minimum_occlusion_tracking_size = gfx::Size(minimum_occlusion_tracking_size_width, minimum_occlusion_tracking_size_height);
 settings.tiling_interest_area_padding = tiling_interest_area_padding;
 settings.skewport_target_time_in_seconds = skewport_target_time_in_seconds;
 settings.skewport_extrapolation_limit_in_screen_pixels = skewport_extrapolation_limit_in_screen_pixels;
 settings.max_memory_for_prepaint_percentage = max_memory_for_prepaint_percentage;
 settings.use_zero_copy = use_zero_copy;
 settings.use_partial_raster = use_partial_raster;
 settings.enable_elastic_overscroll = enable_elastic_overscroll;
 settings.ignore_root_layer_flings = ignore_root_layer_flings;
 settings.scheduled_raster_task_limit = scheduled_raster_task_limit;
 settings.use_occlusion_for_tile_prioritization = use_occlusion_for_tile_prioritization;
 settings.use_layer_lists = use_layer_lists;
 settings.max_staging_buffer_usage_in_bytes = max_staging_buffer_usage_in_bytes;
 settings.memory_policy.bytes_limit_when_visible = memory_policy_bytes_limit_when_visible;
 settings.memory_policy.priority_cutoff_when_visible = static_cast<gpu::MemoryAllocation::PriorityCutoff>(memory_policy_priority_cutoff_when_visible);
 settings.decoded_image_working_set_budget_bytes = decoded_image_working_set_budget_bytes;
 settings.max_preraster_distance_in_screen_pixels = max_preraster_distance_in_screen_pixels;
 settings.use_rgba_4444 = use_rgba_4444;
 settings.unpremultiply_and_dither_low_bit_depth_tiles = unpremultiply_and_dither_low_bit_depth_tiles;
 settings.enable_mask_tiling = enable_mask_tiling;
 settings.enable_checker_imaging = enable_checker_imaging;
 settings.min_image_bytes_to_checker = min_image_bytes_to_checker;
 settings.only_checker_images_with_gpu_raster = only_checker_images_with_gpu_raster;
 settings.enable_surface_synchronization = enable_surface_synchronization;
 settings.is_layer_tree_for_subframe = is_layer_tree_for_subframe;
 settings.disallow_non_exact_resource_reuse = disallow_non_exact_resource_reuse;
 settings.wait_for_all_pipeline_stages_before_draw = wait_for_all_pipeline_stages_before_draw;
 settings.commit_to_active_tree = commit_to_active_tree;
 settings.enable_oop_rasterization = enable_oop_rasterization;
 settings.enable_image_animation_resync = enable_image_animation_resync;
 settings.enable_edge_anti_aliasing = enable_edge_anti_aliasing;
 settings.always_request_presentation_time = always_request_presentation_time;
 settings.use_painted_device_scale_factor = use_painted_device_scale_factor;

 application::ApplicationThread* deps = application::ApplicationThread::current();
 //DLOG(INFO) << "_LayerTreeHostCreate: (app_thread) 0 = " << deps;
 DCHECK(deps->message_loop()->task_runner()->BelongsToCurrentThread());
 scoped_refptr<base::SingleThreadTaskRunner> compositor_thread_task_runner =
  deps->GetCompositorImplThreadTaskRunner();
// //DLOG(INFO) << "_LayerTreeHostCreate(): g_deps.Pointer()->Get()->GetCompositorMainThreadTaskRunner()";  
 //scoped_refptr<base::SingleThreadTaskRunner>
 // main_thread_compositor_task_runner =
 // g_deps.Pointer()->Get()->GetCompositorMainThreadTaskRunner();
 //viz::SharedBitmapManager* shared_bitmap_manager =
 // g_deps.Pointer()->Get()->GetSharedBitmapManager();
// gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager =
//  g_deps.Pointer()->Get()->GetGpuMemoryBufferManager();
 cc::TaskGraphRunner* task_graph_runner =
  deps->GetTaskGraphRunner();

 //std::unique_ptr<viz::BeginFrameSource> external_begin_frame_source;
 //if (settings.use_external_begin_frame_source) {
  //external_begin_frame_source =
  // compositor_deps_->CreateExternalBeginFrameSource(widget_->routing_id());
 //}

 cc::LayerTreeHost::InitParams params;
 params.client = client.get();
 //params.shared_bitmap_manager = shared_bitmap_manager;
 //params.gpu_memory_buffer_manager = gpu_memory_buffer_manager;
 params.settings = &settings;
 params.task_graph_runner = task_graph_runner;
 params.main_task_runner = deps->GetCompositorMainThreadTaskRunner();//base::ThreadTaskRunnerHandle::Get();//main_thread_compositor_task_runner;
 params.mutator_host = reinterpret_cast<_AnimationHost *>(animator_host)->handle();
 //params.external_begin_frame_source = std::move(external_begin_frame_source);
 //std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateSingleThreaded(client.get(), &params);
 //std::unique_ptr<cc::LayerTreeHost> ptr;
 //if (is_single_threaded) {
 //  ptr.reset(g_deps.Pointer()->Get()->compositor_helper()->CreateLayerTreeHostSingleThreaded(&params, client.get()));
 //} else {
 //DLOG(INFO) << "_LayerTreeHostCreate: (app_thread) 1 = " << deps;  
 std::unique_ptr<cc::LayerTreeHost> ptr = cc::LayerTreeHost::CreateThreaded(compositor_thread_task_runner, &params);
 //ptr.reset(deps->compositor_helper()->CreateLayerTreeHostThreaded(&params, compositor_thread_task_runner));
 //}
 // TODO: we need to specify error codes and be more specific about errors happening on shims
 DCHECK(ptr);

 //DLOG(INFO) << "_LayerTreeHostCreate: (app_thread) 2 = " << deps << " layer_tree_host = " << ptr.get();

 return new _LayerTreeHost(std::move(ptr), std::move(client));
}

void _LayerTreeHostDestroy(LayerTreeHostRef tree) {
 delete reinterpret_cast<_LayerTreeHost *>(tree);
}

// void _LayerTreeHostSetClientPeer(LayerTreeHostRef tree, void* payload) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->client->set_client_peer(payload);
// }

void _LayerTreeHostWillBeginMainFrame(LayerTreeHostRef tree) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->WillBeginMainFrame();
}

void _LayerTreeHostDidBeginMainFrame(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidBeginMainFrame();
}

void _LayerTreeHostBeginMainFrame(LayerTreeHostRef tree,
  uint64_t source_id,
  uint64_t sequence_number,
  double frame_time, 
  double deadline, 
  double interval) {
 viz::BeginFrameArgs args = viz::BeginFrameArgs::Create(BEGINFRAME_FROM_HERE,
    // TODO: this probably will not be in a proper format.. check time format compability
    source_id,
    sequence_number,
    base::TimeTicks::FromInternalValue(frame_time),
    base::TimeTicks::FromInternalValue(deadline),
    base::TimeDelta::FromMicroseconds(interval),
    viz::BeginFrameArgs::NORMAL);
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->BeginMainFrame(args);
}

void _LayerTreeHostBeginMainFrameNotExpectedSoon(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->BeginMainFrameNotExpectedSoon();
}

void _LayerTreeHostAnimateLayers(LayerTreeHostRef tree, double monotonic_frame_begin_time) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->AnimateLayers(base::TimeTicks::FromInternalValue(monotonic_frame_begin_time));
}

void _LayerTreeHostDidStopFlinging(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidStopFlinging();
}

void _LayerTreeHostRequestMainFrameUpdate(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->RequestMainFrameUpdate();
}

void _LayerTreeHostFinishCommitOnImplThread(LayerTreeHostRef tree) {
  NOTREACHED() << "LayerTreeHostFinishCommitOnImplThread not implemented";
}

void _LayerTreeHostWillCommit(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->WillCommit();
}

void _LayerTreeHostCommitComplete(LayerTreeHostRef tree) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->CommitComplete();
}

void _LayerTreeHostReleaseLayerTreeFrameSink(LayerTreeHostRef tree) {
  _LayerTreeHost* tree_state = reinterpret_cast<_LayerTreeHost *>(tree);
  tree_state->handle->ReleaseLayerTreeFrameSink();
}

void _LayerTreeHostRequestPresentationTimeForNextFrame(LayerTreeHostRef tree, void* peer, CLayerTreeHostRequestPresentationCallback cb) {
  _LayerTreeHost* tree_state = reinterpret_cast<_LayerTreeHost *>(tree);
  tree_state->request_presentation_callback = cb;
  tree_state->request_presentation_state = peer;
  tree_state->handle->RequestPresentationTimeForNextFrame(
    base::BindOnce(
      &_LayerTreeHost::OnRequestPresentation, 
      base::Unretained(tree_state)));
}

// void _LayerTreeHostSetOutputSurface(LayerTreeHostRef tree, OutputSurfaceRef output_surface) {
//   DCHECK(output_surface);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetOutputSurface(output_surface->handle.Pass());
// }

// OutputSurfaceRef _LayerTreeHostReleaseOutputSurface(LayerTreeHostRef tree) {
//  std::unique_ptr<viz::OutputSurface> surface = reinterpret_cast<_LayerTreeHost *>(tree)->handle->ReleaseOutputSurface();
//  return new _OutputSurface(std::move(surface));
// }

// void _LayerTreeHostRequestNewOutputSurface(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->RequestNewOutputSurface();
// }

// void _LayerTreeHostDidInitializeOutputSurface(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidInitializeOutputSurface();
// }

// void _LayerTreeHostDidFailToInitializeOutputSurface(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidFailToInitializeOutputSurface();
// }

// void _LayerTreeHostDidLoseOutputSurface(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidLoseOutputSurface();
// }

// int _LayerTreeHostOutputSurfaceLost(LayerTreeHostRef tree) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->output_surface_lost() ? 1 : 0;
// }

void _LayerTreeHostDidCommitAndDrawFrame(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidCommitAndDrawFrame();
}

// void _LayerTreeHostDidCompleteSwapBuffers(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidCompleteSwapBuffers();
// }

int _LayerTreeHostUpdateLayers(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->UpdateLayers() ? 1 : 0;
}

void _LayerTreeHostDidCompletePageScaleAnimation(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->DidCompletePageScaleAnimation();
}

void _LayerTreeHostNotifyInputThrottledUntilCommit(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->NotifyInputThrottledUntilCommit();
}

void _LayerTreeHostLayoutAndUpdateLayers(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->LayoutAndUpdateLayers();
}

void _LayerTreeHostComposite(LayerTreeHostRef tree, int64_t frame_begin_time, int raster) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->Composite(base::TimeTicks::FromInternalValue(frame_begin_time), raster == 1 ? true : false);
}

// void _LayerTreeHostFinishAllRendering(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->FinishAllRendering();
// }

void _LayerTreeHostSetDeferCommits(LayerTreeHostRef tree, int defer_commits) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetDeferCommits(defer_commits ? true : false);
}

int _LayerTreeHostSourceFrameNumber(LayerTreeHostRef tree) {
  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->SourceFrameNumber();
}

void _LayerTreeHostRequestBeginMainFrameNotExpected(LayerTreeHostRef reference, int new_state) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->RequestBeginMainFrameNotExpected(new_state != 0);
}

void _LayerTreeHostGetViewportVisibleRect(LayerTreeHostRef tree, int* x, int* y, int* width, int* height) {
  gfx::Rect rect = reinterpret_cast<_LayerTreeHost *>(tree)->handle->viewport_visible_rect();
  *x = rect.x();
  *y = rect.y();
  *width = rect.width();
  *height = rect.height();
}

void _LayerTreeHostSetViewportVisibleRect(LayerTreeHostRef tree, int x, int y, int width, int height) {
  gfx::Rect rect(x, y, width, height);
  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetViewportVisibleRect(rect);
}

// int _LayerTreeHostMetaInformationSequenceNumber(LayerTreeHostRef tree) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->meta_information_sequence_number();
// }

// void _LayerTreeHostIncrementMetaInformationSequenceNumber(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->IncrementMetaInformationSequenceNumber();
// }

void _LayerTreeHostSetNeedsDisplayOnAllLayers(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsDisplayOnAllLayers();
}

void _LayerTreeHostSetNeedsAnimate(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsAnimate();
}

void _LayerTreeHostSetNeedsUpdateLayers(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsUpdateLayers();
}

void _LayerTreeHostSetNeedsCommit(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsCommit();
}

void _LayerTreeHostSetNeedsCommitWithForcedRedraw(LayerTreeHostRef tree) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsCommitWithForcedRedraw();
}

void _LayerTreeHostSetNeedsFullTreeSync(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsFullTreeSync();
}

// void _LayerTreeHostSetNeedsMetaInfoRecomputation(LayerTreeHostRef tree, int needs_meta_info_recomputation) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsMetaInfoRecomputation(needs_meta_info_recomputation ? true : false);
// }

// void _LayerTreeHostSetNeedsRedraw(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsRedraw();
// }

void _LayerTreeHostSetNeedsRedrawRect(LayerTreeHostRef tree, int x, int y, int width, int height) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsRedrawRect(gfx::Rect(x, y, width, height));
}

int _LayerTreeHostCommitRequested(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->CommitRequested() ? 1 : 0;
}

// int _LayerTreeHostBeginMainFrameRequested(LayerTreeHostRef tree) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->BeginMainFrameRequested() ? 1 : 0;
// }

void _LayerTreeHostSetNextCommitWaitsForActivation(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNextCommitWaitsForActivation();
}

// void _LayerTreeHostSetNextCommitForcesRedraw(LayerTreeHostRef tree) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNextCommitForcesRedraw();
// }

// void _LayerTreeHostSetAnimationEvents(LayerTreeHostRef tree, AnimationEventRef* events, int event_count) {
//  std::unique_ptr<cc::AnimationEventsVector> animations(new cc::AnimationEventsVector);
//  for(int i = 0; i < event_count; ++i) {
//    DCHECK(events[i]);
//    animations->push_back(events[i]->event);
//  }
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetAnimationEvents(std::move(animations));
// }

void _LayerTreeHostSetRootLayer(LayerTreeHostRef tree, LayerRef root) {
 //DCHECK(reinterpret_cast<_Layer *>(root)->owned()); // should be the owned type (created by LayerCreate)
 //reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetRootLayer(reinterpret_cast<_Layer *>(root)->handle);
  //g_deps.Pointer()->Get()->compositor_helper()->SetRootLayer(reinterpret_cast<_LayerTreeHost *>(tree)->handle.get(), reinterpret_cast<_Layer *>(root)->handle);
 blink::WebLayer* blink_layer = reinterpret_cast<blink::WebLayer *>(root);
 cc::Layer* ccLayer = blink_layer->CcLayer();
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetRootLayer(ccLayer);
}

void _LayerTreeHostClearRootLayer(LayerTreeHostRef tree) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetRootLayer(scoped_refptr<cc::Layer>());
}

LayerRef _LayerTreeHostRootLayer(LayerTreeHostRef tree) {
 cc::Layer* layer = reinterpret_cast<_LayerTreeHost *>(tree)->handle->root_layer();
 if(!layer)
  return nullptr;
 return new _Layer(layer);
}

int _LayerTreeHostHasPendingPageScaleAnimation(LayerTreeHostRef tree) {
  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasPendingPageScaleAnimation() ? 1 : 0;
}

LayerRef _LayerTreeHostOverscrollElasticityLayer(LayerTreeHostRef tree) {
 cc::Layer* layer = const_cast<cc::Layer *>(reinterpret_cast<_LayerTreeHost *>(tree)->handle->overscroll_elasticity_layer());
 if(!layer)
  return nullptr;

 return new _Layer(layer);
}

LayerRef _LayerTreeHostPageScaleLayer(LayerTreeHostRef tree) {
 cc::Layer* layer = const_cast<cc::Layer *>(reinterpret_cast<_LayerTreeHost *>(tree)->handle->page_scale_layer());
 if(!layer)
  return nullptr;

 return new _Layer(layer);
}

void _LayerTreeHostGetDeviceViewportSize(LayerTreeHostRef tree, int* w, int* h) {
  gfx::Size viewport_size = reinterpret_cast<_LayerTreeHost *>(tree)->handle->device_viewport_size();
  *w = viewport_size.width();
  *h = viewport_size.height();
}

void _LayerTreeHostSetViewportSizeAndScale(LayerTreeHostRef tree, int w, int h, float scale,
   uint32_t lsid_parent,
   uint32_t lsid_child,
   uint64_t lsid_token_high,
   uint64_t lsid_token_low) {
  base::UnguessableToken token;
  if (lsid_token_high !=0 && lsid_token_low != 0) {
    token = base::UnguessableToken::Deserialize(lsid_token_high, lsid_token_low);
  }
  viz::LocalSurfaceId id(lsid_parent, lsid_child, std::move(token));
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetViewportSizeAndScale(gfx::Size(w, h), scale, id);
}

float _LayerTreeHostGetRecordingScaleFactor(LayerTreeHostRef tree) {
  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->recording_scale_factor();
}

void _LayerTreeHostSetRecordingScaleFactor(LayerTreeHostRef tree, float factor) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetRecordingScaleFactor(factor);
}

// void _LayerTreeHostRegisterViewportLayers(LayerTreeHostRef tree,
//   LayerRef overscroll_elasticity_layer,
//   LayerRef page_scale_layer,
//   LayerRef inner_viewport_container_layer,
//   LayerRef outer_viewport_container_layer,
//   LayerRef inner_viewport_scroll_layer,
//   LayerRef outer_viewport_scroll_layer) {

//   cc::LayerTreeHost::ViewportLayers viewport;
//   viewport.overscroll_elasticity = overscroll_elasticity_layer ? reinterpret_cast<_Layer *>(overscroll_elasticity_layer)->handle : nullptr;
//   viewport.page_scale = page_scale_layer ? reinterpret_cast<_Layer *>(page_scale_layer)->handle : nullptr;
//   viewport.inner_viewport_container = inner_viewport_container_layer ? reinterpret_cast<_Layer *>(inner_viewport_container_layer)->handle : nullptr;
//   viewport.outer_viewport_container = outer_viewport_container_layer ? reinterpret_cast<_Layer *>(outer_viewport_container_layer)->handle : nullptr;
//   viewport.inner_viewport_scroll = inner_viewport_scroll_layer ? reinterpret_cast<_Layer *>(inner_viewport_scroll_layer)->handle : nullptr;
//   viewport.outer_viewport_scroll = outer_viewport_scroll_layer ? reinterpret_cast<_Layer *>(outer_viewport_scroll_layer)->handle : nullptr;

//   reinterpret_cast<_LayerTreeHost *>(tree)->handle->RegisterViewportLayers(viewport);
// }

void _LayerTreeHostRegisterViewportLayers(LayerTreeHostRef tree,
  LayerRef overscroll_elasticity_layer,
  LayerRef page_scale_layer,
  LayerRef inner_viewport_container_layer,
  LayerRef outer_viewport_container_layer,
  LayerRef inner_viewport_scroll_layer,
  LayerRef outer_viewport_scroll_layer) {

  cc::LayerTreeHost::ViewportLayers viewport_layers;
  cc::Layer* overscroll_elasticity = nullptr;
  cc::Layer* page_scale = nullptr;
  cc::Layer* inner_viewport_container = nullptr;
  cc::Layer* outer_viewport_container = nullptr;
  cc::Layer* inner_viewport_scroll = nullptr;
  cc::Layer* outer_viewport_scroll = nullptr;

  if (overscroll_elasticity_layer) {
    overscroll_elasticity = reinterpret_cast<blink::WebLayer *>(overscroll_elasticity_layer)->CcLayer();
    DCHECK(overscroll_elasticity);
  }
  
  if (page_scale_layer) {
    page_scale = reinterpret_cast<blink::WebLayer *>(page_scale_layer)->CcLayer();
    DCHECK(page_scale);
  }
  
  if (inner_viewport_container_layer) {
    inner_viewport_container = reinterpret_cast<blink::WebLayer *>(inner_viewport_container_layer)->CcLayer();
    DCHECK(inner_viewport_container);
  }

  if (outer_viewport_container_layer) {
    outer_viewport_container = reinterpret_cast<blink::WebLayer *>(outer_viewport_container_layer)->CcLayer();
    DCHECK(outer_viewport_container);
  }
  
  if (inner_viewport_scroll_layer) {
    inner_viewport_scroll = reinterpret_cast<blink::WebLayer *>(inner_viewport_scroll_layer)->CcLayer();
    DCHECK(inner_viewport_scroll);
  }
  
  if (outer_viewport_scroll_layer) {
    outer_viewport_scroll = reinterpret_cast<blink::WebLayer *>(outer_viewport_scroll_layer)->CcLayer();
    DCHECK(outer_viewport_scroll);
  }

  viewport_layers.overscroll_elasticity = overscroll_elasticity;
  viewport_layers.page_scale = page_scale;
  viewport_layers.inner_viewport_container = inner_viewport_container;
  viewport_layers.outer_viewport_container = outer_viewport_container;
  viewport_layers.inner_viewport_scroll = inner_viewport_scroll;
  viewport_layers.outer_viewport_scroll = outer_viewport_scroll;
    
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->RegisterViewportLayers(viewport_layers);
}

LayerRef _LayerTreeHostInnerViewportScrollLayer(LayerTreeHostRef tree) {
 cc::Layer* layer = reinterpret_cast<_LayerTreeHost *>(tree)->handle->inner_viewport_scroll_layer();
 if(!layer)
  return nullptr;

 return new _Layer(layer);
}

LayerRef _LayerTreeHostOuterViewportScrollLayer(LayerTreeHostRef tree) {
 cc::Layer* layer = reinterpret_cast<_LayerTreeHost *>(tree)->handle->outer_viewport_scroll_layer();
 if(!layer)
  return nullptr;

 return new _Layer(layer);
}

void _LayerTreeHostRegisterSelection(LayerTreeHostRef tree,
  int s1_boundtype,
  int s1_edgetop_x,
  int s1_edgetop_y,
  int s1_edgebottom_x,
  int s1_edgebottom_y,
  int s1_layerid,
  int s1_hidden,
  int s2_boundtype,
  int s2_edgetop_x,
  int s2_edgetop_y,
  int s2_edgebottom_x,
  int s2_edgebottom_y,
  int s2_layerid,
  int s2_hidden) {//,
  //int is_editable,
  //int is_empty_text_form_control) {
    cc::LayerSelection selection;
    selection.start.type = static_cast<gfx::SelectionBound::Type>(s1_boundtype);
    selection.start.edge_top = gfx::Point(s1_edgetop_x, s1_edgetop_y);
    selection.start.edge_bottom = gfx::Point(s1_edgebottom_x, s1_edgebottom_y);
    selection.start.layer_id = s1_layerid;
    selection.start.hidden = s1_hidden == 0 ? false : true;
    selection.end.type = static_cast<gfx::SelectionBound::Type>(s2_boundtype);
    selection.end.edge_top = gfx::Point(s2_edgetop_x, s2_edgetop_y);
    selection.end.edge_bottom = gfx::Point(s2_edgebottom_x, s2_edgebottom_y);
    selection.end.layer_id = s2_layerid;
    selection.end.hidden = s2_hidden == 0 ? false : true;
    //selection.is_editable = is_editable == 0 ? false : true;
    //selection.is_empty_text_form_control = is_empty_text_form_control == 0 ? false : true;
    reinterpret_cast<_LayerTreeHost *>(tree)->handle->RegisterSelection(selection);
}

int _LayerTreeHostHasGpuRasterizationTrigger(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->has_gpu_rasterization_trigger() ? 1 : 0;
}

void _LayerTreeHostSetHasGpuRasterizationTrigger(LayerTreeHostRef tree, int has_gpu_rasterization_trigger) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetHasGpuRasterizationTrigger(has_gpu_rasterization_trigger != 0);
}

void _LayerTreeHostSetLayerTreeMutator(LayerTreeHostRef tree, LayerTreeMutatorRef mutator) {
  std::unique_ptr<cc::LayerTreeMutator> client(reinterpret_cast<cc::LayerTreeMutator *>(mutator));
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetLayerTreeMutator(std::move(client));
}

void _LayerTreeHostSetNeedsRecalculateRasterScales(LayerTreeHostRef tree) {
  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetNeedsRecalculateRasterScales(); 
}

int _LayerTreeHostGetHaveScrollEventHandlers(LayerTreeHostRef reference) {
  return reinterpret_cast<_LayerTreeHost *>(reference)->handle->have_scroll_event_handlers();
}

void _LayerTreeHostSetHaveScrollEventHandlers(LayerTreeHostRef reference, int have) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetHaveScrollEventHandlers(have != 0);
}

// void _LayerTreeHostSetTopControlsHeight(LayerTreeHostRef tree, float height, int shrink) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetTopControlsHeight(height, shrink ? true : false);
// }

// void _LayerTreeHostSetTopControlsShownRatio(LayerTreeHostRef tree, float ratio) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetTopControlsShownRatio(ratio);
// }

void _LayerTreeHostDeviceViewportSize(LayerTreeHostRef tree, int* width, int* height) {
 gfx::Size size = reinterpret_cast<_LayerTreeHost *>(tree)->handle->device_viewport_size();
 *width = size.width();
 *height = size.height();
}

// void _LayerTreeHostSetViewportSize(LayerTreeHostRef tree, int width, int height) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetViewportSize(gfx::Size(width, height));
// }

// void _LayerTreeHostApplyPageScaleDeltaFromImplSide(LayerTreeHostRef tree, float page_scale_delta) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->ApplyPageScaleDeltaFromImplSide(page_scale_delta);
// }

void _LayerTreeHostSetPageScaleFactorAndLimits(LayerTreeHostRef tree,
                                 float page_scale_factor,
                                 float min_page_scale_factor,
                                 float max_page_scale_factor) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetPageScaleFactorAndLimits(page_scale_factor, min_page_scale_factor, max_page_scale_factor);
}

float _LayerTreeHostPageScaleFactor(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->page_scale_factor();
}

void _LayerTreeHostElasticOverscroll(LayerTreeHostRef tree, float* x, float* y) {
 gfx::Vector2dF vec = reinterpret_cast<_LayerTreeHost *>(tree)->handle->elastic_overscroll();
 *x = vec.x();
 *y = vec.y();
}

void _LayerTreeHostSetBackgroundColor(LayerTreeHostRef tree, uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
 SkColor color = SkColorSetARGB(a, r, g, b);
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->set_background_color(color);
}

void _LayerTreeHostBackgroundColor(LayerTreeHostRef tree, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b) {
 SkColor color = reinterpret_cast<_LayerTreeHost *>(tree)->handle->background_color();
 *a = SkColorGetA(color);
 *r = SkColorGetR(color);
 *g = SkColorGetG(color);
 *b = SkColorGetB(color);
}

// void _LayerTreeHostSetHasTransparentBackground(LayerTreeHostRef tree, int transparent) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->set_has_transparent_background(transparent ? true : false);
// }

void _LayerTreeHostSetVisible(LayerTreeHostRef tree, int visible) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetVisible(visible ? true : false);
}

int _LayerTreeHostIsVisible(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->IsVisible() ? 1 : 0;
}

// void _LayerTreeHostSetThrottleFrameProduction(LayerTreeHostRef tree, int throttle) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetThrottleFrameProduction(throttle ? true : false);
// }

void _LayerTreeHostStartPageScaleAnimation(LayerTreeHostRef tree,
  int offset_x,
  int offset_y,
  int use_anchor,
  float scale,
  double duration) {

 reinterpret_cast<_LayerTreeHost *>(tree)->handle->StartPageScaleAnimation(gfx::Vector2d(offset_x, offset_y),
  use_anchor ? true : false,
  scale,
  base::TimeDelta::FromMicroseconds(duration));
}

void _LayerTreeHostApplyScrollAndScale(LayerTreeHostRef tree) {
 cc::ScrollAndScaleSet info;
 // TODO: we are trowing the information out.. fix it
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->ApplyScrollAndScale(&info);
}

void _LayerTreeHostSetTransform(LayerTreeHostRef tree,
  double col1row1, double col2row1,
  double col3row1, double col4row1,
  double col1row2, double col2row2,
  double col3row2, double col4row2,
  double col1row3, double col2row3,
  double col3row3, double col4row3,
  double col1row4, double col2row4,
  double col3row4, double col4row4) {
 NOTREACHED() << "LayerTreeHostSetTransform not implemented";;
// gfx::Transform transform(col1row1, col2row1,
//   col3row1, col4row1,
//   col1row2, col2row2,
//   col3row2, col4row2,
//   col1row3, col2row3,
//   col3row3, col4row3,
//   col1row4, col2row4,
//   col3row4, col4row4);
// reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetImplTransform(transform);
}

// void _LayerTreeHostSetDeviceScaleFactor(LayerTreeHostRef tree, float scale) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetDeviceScaleFactor(scale);
// }

float _LayerTreeHostDeviceScaleFactor(LayerTreeHostRef tree) {
  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->device_scale_factor();
}

//void _LayerTreeHostSetPaintedDeviceScaleFactor(LayerTreeHostRef tree, float painted_device_scale_factor) {
// reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetPaintedDeviceScaleFactor(painted_device_scale_factor);
//}

//void _LayerTreeHostUpdateTopControlsState(LayerTreeHostRef tree, int top_controls_state_constraints, int top_controls_state_current, int animate) {
// reinterpret_cast<_LayerTreeHost *>(tree)->handle->UpdateTopControlsState(cc::TopControlsState(top_controls_state_constraints), cc::TopControlsState(top_controls_state_current), animate ? 1 : 0);
//}

// AnimationRegistrarRef _LayerTreeHostAnimationRegistrar(LayerTreeHostRef tree) {
//  cc::AnimationRegistrar* registrar = reinterpret_cast<_LayerTreeHost *>(tree)->handle->animation_registrar();

//  if(!registrar)
//   return nullptr;

//  return new _AnimationRegistrar(registrar);
// }

int _LayerTreeHostInPaintLayerContents(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->in_paint_layer_contents() ? 1 : 0;
}

AnimationHostRef _LayerTreeHostAnimationHost(LayerTreeHostRef tree) {
 cc::AnimationHost* host = reinterpret_cast<cc::AnimationHost *>(reinterpret_cast<_LayerTreeHost *>(tree)->handle->mutator_host());
 if(!host)
  return nullptr;

 // TODO: one of the reasons why we need to get rid of wrappers!
 // stupid allocation for a simple getter
 return new _AnimationHost(host);
}

// int _LayerTreeHostUsingSharedMemoryResources(LayerTreeHostRef tree) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->UsingSharedMemoryResources() ? 1 : 0;
// }

int _LayerTreeHostId(LayerTreeHostRef tree) {
 return reinterpret_cast<_LayerTreeHost *>(tree)->handle->GetId();
}

// void _LayerTreeHostInsertSwapPromiseMonitor(LayerTreeHostRef tree, SwapPromiseMonitorRef monitor) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->InsertSwapPromiseMonitor(reinterpret_cast<_SwapPromiseMonitor *>(monitor)->handle.get());
// }

// void _LayerTreeHostRemoveSwapPromiseMonitor(LayerTreeHostRef tree, SwapPromiseMonitorRef monitor) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->RemoveSwapPromiseMonitor(reinterpret_cast<_SwapPromiseMonitor *>(monitor)->handle.get());
// }

void _LayerTreeHostQueueSwapPromise(LayerTreeHostRef tree, SwapPromiseRef swap_promise) {
 cc::SwapPromise* inner_promise = reinterpret_cast<_SwapPromise *>(swap_promise)->handle.release();
 std::unique_ptr<cc::SwapPromise> owned_promise(inner_promise); 
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->QueueSwapPromise(std::move(owned_promise));
}

// void _LayerTreeHostBreakSwapPromises(LayerTreeHostRef tree, int DidNotSwapReason) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->BreakSwapPromises(cc::SwapPromise::DidNotSwapReason(DidNotSwapReason));
// }

// void _LayerTreeHostSetSurfaceIdNamespace(LayerTreeHostRef tree, uint32_t id_namespace) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->set_surface_id_namespace(id_namespace);
// }

// void _LayerTreeHostCreateSurfaceSequence(LayerTreeHostRef tree, uint32_t* id_namespace, uint32_t* sequence) {
//  cc::SurfaceSequence seq = reinterpret_cast<_LayerTreeHost *>(tree)->handle->CreateSurfaceSequence();
//  *id_namespace = seq.id_namespace;
//  *sequence = seq.sequence;
// }

// void _LayerTreeHostSetChildrenNeedBeginFrames(LayerTreeHostRef tree, int children_need_begin_frames) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetChildrenNeedBeginFrames(children_need_begin_frames ? 1 : 0);
// }

// void _LayerTreeHostSendBeginFramesToChildren(
//   LayerTreeHostRef tree,  
//   uint64_t source_id,
//   uint64_t sequence_number, 
//   double frame_time, 
//   double deadline, 
//   double interval) {
//  viz::BeginFrameArgs args = viz::BeginFrameArgs::Create(BEGINFRAME_FROM_HERE,
//     // TODO: this probably will not be in a proper format.. check time format compability
//     source_id,
//     sequence_number,
//     base::TimeTicks::FromInternalValue(frame_time),
//     base::TimeTicks::FromInternalValue(deadline),
//     base::TimeDelta::FromMicroseconds(interval),
//     viz::BeginFrameArgs::NORMAL);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SendBeginFramesToChildren(args);
// }

PropertyTreesRef _LayerTreeHostPropertyTrees(LayerTreeHostRef tree) {
 cc::PropertyTrees* trees = reinterpret_cast<_LayerTreeHost *>(tree)->handle->property_trees();
 return new _PropertyTrees(trees);
}

// void _LayerTreeHostSetAuthoritativeVsyncInterval(LayerTreeHostRef tree, double interval) {
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetAuthoritativeVSyncInterval(base::TimeDelta::FromMicroseconds(interval));
// }

LayerRef _LayerTreeHostLayerById(LayerTreeHostRef tree, int id) {
 cc::Layer* layer = reinterpret_cast<_LayerTreeHost *>(tree)->handle->LayerById(id);

 if (!layer)
  return nullptr;
 // return a "not owned" layer
 return new _Layer(layer);
}

// int _LayerTreeHostNeedsMetaInfoRecomputation(LayerTreeHostRef tree) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->needs_meta_info_recomputation() ? 1 : 0;
// }

void _LayerTreeHostRegisterLayer(LayerTreeHostRef tree, LayerRef layer) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->RegisterLayer(reinterpret_cast<_Layer *>(layer)->layer());
}

void _LayerTreeHostUnregisterLayer(LayerTreeHostRef tree, LayerRef layer) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->UnregisterLayer(reinterpret_cast<_Layer *>(layer)->layer());
}

// int _LayerTreeHostIsLayerInTree(LayerTreeHostRef tree, int layer_id, int tree_type) {
//  cc::LayerTreeType type = (tree_type == LayerTreeTypeActive ? cc::LayerTreeType::ACTIVE : cc::LayerTreeType::PENDING);
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->IsLayerInTree(layer_id, type) ? 1: 0;
// }

void _LayerTreeHostSetMutatorsNeedCommit(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetMutatorsNeedCommit();
}

void _LayerTreeHostSetMutatorsNeedRebuildPropertyTrees(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetMutatorsNeedRebuildPropertyTrees();
}

// TODO: this is disabled for now until we implement a way to pass a array of filter operations
// from swift to C
// void _LayerTreeHostSetLayerFilterMutated(LayerTreeHostRef tree, int layer_id,
//   int tree_type,
//   int* filters) {
//  //reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetLayerFilterMutated();
// }

// void _LayerTreeHostSetLayerOpacityMutated(LayerTreeHostRef tree, int layer_id,
//   int tree_type,
//   float opacity) {
//  cc::LayerTreeType type = (tree_type == LayerTreeTypeActive ? cc::LayerTreeType::ACTIVE : cc::LayerTreeType::PENDING);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetLayerOpacityMutated(layer_id, type, opacity);
// }

//void _LayerTreeHostSetLayerTransformMutated(LayerTreeHostRef tree,
// int layer_id,
// int tree_type,
// double col1row1, double col2row1,
//  double col3row1, double col4row1,
//  double col1row2, double col2row2,
//  double col3row2, double col4row2,
//  double col1row3, double col2row3,
//  double col3row3, double col4row3,
//  double col1row4, double col2row4,
//  double col3row4, double col4row4) {
//  cc::LayerTreeType type = (tree_type == LayerTreeTypeActive ? cc::LayerTreeType::ACTIVE : cc::LayerTreeType::PENDING);
//  gfx::Transform transform(col1row1, col2row1,
//    col3row1, col4row1,
//    col1row2, col2row2,
//    col3row2, col4row2,
//    col1row3, col2row3,
//    col3row3, col4row3,
//    col1row4, col2row4,
//    col3row4, col4row4);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetLayerTransformMutated(layer_id, type, transform);
// }

// void _LayerTreeHostSetLayerScrollOffsetMutated(LayerTreeHostRef tree,
//   int layer_id,
//   int tree_type,
//   double offset_x, double offset_y) {
//  cc::LayerTreeType type = (tree_type == LayerTreeTypeActive ? cc::LayerTreeType::ACTIVE : cc::LayerTreeType::PENDING);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->SetLayerScrollOffsetMutated(layer_id, type, gfx::ScrollOffset(offset_x, offset_x));
// }

// void _LayerTreeHostLayerTransformIsPotentiallyAnimatingChanged(LayerTreeHostRef tree,
//   int layer_id,
//   int tree_type,
//   int is_animating) {
//  cc::LayerTreeType type = (tree_type == LayerTreeTypeActive ? cc::LayerTreeType::ACTIVE : cc::LayerTreeType::PENDING);
//  reinterpret_cast<_LayerTreeHost *>(tree)->handle->LayerTransformIsPotentiallyAnimatingChanged(layer_id, type, is_animating ? true : false);
// }

void _LayerTreeHostScrollOffsetAnimationFinished(LayerTreeHostRef tree) {
 reinterpret_cast<_LayerTreeHost *>(tree)->handle->ScrollOffsetAnimationFinished();
}

void _LayerTreeHostGetLocalSurfaceId(
        LayerTreeHostRef reference,
        uint32_t* parent,
        uint32_t* child,
        uint64_t* high,
        uint64_t* low) {
  
  const viz::LocalSurfaceId& id = reinterpret_cast<_LayerTreeHost *>(reference)->handle->local_surface_id();
  *parent = id.parent_sequence_number();
  *child = id.child_sequence_number();
  *high = id.embed_token().GetHighForSerialization();
  *low = id.embed_token().GetLowForSerialization();
}

void _LayerTreeHostSetLocalSurfaceId(
        LayerTreeHostRef reference, 
        uint32_t parent,
        uint32_t child,
        uint64_t high,
        uint64_t low) {
  viz::LocalSurfaceId id(parent, child, base::UnguessableToken::Deserialize(high, low));
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetLocalSurfaceId(id);
}

void _LayerTreeHostSetRasterColorSpace(LayerTreeHostRef reference, 
  uint8_t primaries,
  uint8_t transfer,
  uint8_t matrix,
  uint8_t range,
  int64_t icc_profile) {
  //DLOG(INFO) << "_LayerTreeHostSetRasterColorSpace";
  gfx::ColorSpace color_space {
    static_cast<gfx::ColorSpace::PrimaryID>(primaries), 
    static_cast<gfx::ColorSpace::TransferID>(transfer), 
    static_cast<gfx::ColorSpace::MatrixID>(matrix), 
    static_cast<gfx::ColorSpace::RangeID>(range),
    icc_profile
  };
  //gfx::ColorSpace color_space = gfx::ColorSpace::CreateSRGB();
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetRasterColorSpace(color_space);
}

//void _LayerTreeHostGetRasterColorSpace(LayerTreeHostRef reference,
//  uint8_t* primaries,
//  uint8_t* transfer,
//  uint8_t* matrix,
//  uint8_t* range) {
  
//  const gfx::ColorSpace& cs = reinterpret_cast<_LayerTreeHost *>(reference)->handle->raster_color_space();
//  *primaries = cs.primaries;
//  *transfer = cs.transfer;
//  *matrix = cs.matrix;
//  *range = cs.range;
//}

void _LayerTreeHostSetLayerTreeFrameSink(LayerTreeHostRef reference, LayerTreeFrameSinkRef framesink) {
  std::unique_ptr<cc::LayerTreeFrameSink> frame_sink(reinterpret_cast<cc::LayerTreeFrameSink*>(framesink));
  //g_deps.Pointer()->Get()->compositor_helper()->SetLayerTreeFrameSink(reinterpret_cast<_LayerTreeHost *>(reference)->handle.get(), std::move(frame_sink));
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetLayerTreeFrameSink(std::move(frame_sink));
}

void _LayerTreeHostQueueImageDecode(LayerTreeHostRef reference, void* peer, ImageRef image, void(*callback)(void*, int)) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->compositor_helper()->QueueImageDecode(
    reinterpret_cast<_LayerTreeHost *>(reference)->handle.get(), 
    peer,
    reinterpret_cast<SkiaImage*>(image)->handle(),
    callback);
}

void _LayerTreeHostSetOverscrollBehavior(LayerTreeHostRef reference, int x_behavior, int y_behavior) {
  cc::OverscrollBehavior overscroll_behavior(
    static_cast<cc::OverscrollBehavior::OverscrollBehaviorType>(x_behavior), 
    static_cast<cc::OverscrollBehavior::OverscrollBehaviorType>(y_behavior));
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetOverscrollBehavior(overscroll_behavior);
}

void _LayerTreeHostSetEventListenerProperties(LayerTreeHostRef reference, int event_class, int event_properties) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetEventListenerProperties(
      static_cast<cc::EventListenerClass>(event_class),
      static_cast<cc::EventListenerProperties>(event_properties));
}

void _LayerTreeHostRequestNewLocalSurfaceId(LayerTreeHostRef reference) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->RequestNewLocalSurfaceId();
}

// void _LayerTreeHostDidNavigate(LayerTreeHostRef reference) {
//   reinterpret_cast<_LayerTreeHost *>(reference)->handle->DidNavigate();
// }

void _LayerTreeHostClearCachesOnNextCommit(LayerTreeHostRef reference) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->ClearCachesOnNextCommit();
}

//void _LayerTreeHostQueueSwapPromise(LayerTreeHostRef reference, SwapPromiseRef swap_promise) {
//  reinterpret_cast<_LayerTreeHost *>(reference)->handle->QueueSwapPromise(*reinterpret_cast<cc::SwapPromisse *>(swap_promise));
//}

// void _LayerTreeHostGetScrollOffsetForAnimation(LayerTreeHostRef tree, int layer_id, double* x, double* y) {
//  gfx::ScrollOffset offset = reinterpret_cast<_LayerTreeHost *>(tree)->handle->GetScrollOffsetForAnimation(ElementId(layer_id));
//  *x = offset.x();
//  *y = offset.y();
// }

// int _LayerTreeHostScrollOffsetAnimationWasInterrupted(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->ScrollOffsetAnimationWasInterrupted(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostIsAnimatingFilterProperty(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->IsAnimatingFilterProperty(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostIsAnimatingOpacityProperty(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->IsAnimatingOpacityProperty(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostIsAnimatingTransformProperty(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->IsAnimatingTransformProperty(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasPotentiallyRunningFilterAnimation(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasPotentiallyRunningFilterAnimation(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasPotentiallyRunningOpacityAnimation(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasPotentiallyRunningOpacityAnimation(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasPotentiallyRunningTransformAnimation(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasPotentiallyRunningTransformAnimation(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasOnlyTranslationTransforms(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasOnlyTranslationTransforms(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostMaximumTargetScale(LayerTreeHostRef tree, LayerRef layer, float* max_scale) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->MaximumTargetScale(GetLayer(layer), max_scale) ? 1: 0;
// }

// int _LayerTreeHostAnimationStartScale(LayerTreeHostRef tree, LayerRef layer, float* start_scale) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->AnimationStartScale(GetLayer(layer), start_scale) ? 1: 0;
// }

// int _LayerTreeHostHasAnyAnimationTargetingProperty(LayerTreeHostRef tree, LayerRef layer, int property) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasAnyAnimationTargetingProperty(GetLayer(layer), cc::Animation::TargetProperty(property)) ? 1: 0;
// }

// int _LayerTreeHostAnimationsPreserveAxisAlignment(LayerTreeHostRef tree, LayerRef layer) {
//  return reinterpret_cast<_LayerTreeHost *>(tree)->handle->AnimationsPreserveAxisAlignment(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasAnyAnimation(LayerTreeHostRef tree, LayerRef layer) {
//   return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasAnyAnimation(GetLayer(layer)) ? 1: 0;
// }

// int _LayerTreeHostHasActiveAnimation(LayerTreeHostRef tree, LayerRef layer) {
//   return reinterpret_cast<_LayerTreeHost *>(tree)->handle->HasActiveAnimation(GetLayer(layer)) ? 1: 0;
// }

void _LayerTreeHostHelperSynchronouslyComposite(LayerTreeHostRef reference, int raster, SwapPromiseRef swap_promise) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->compositor_helper()->SynchronouslyComposite(
    reinterpret_cast<_LayerTreeHost *>(reference)->handle.get(), 
    raster != 0, 
    swap_promise ? 
      std::move(reinterpret_cast<_SwapPromise *>(swap_promise)->handle) : 
      std::unique_ptr<cc::SwapPromise>());
}

void _LayerTreeHostHelperBeginMainFrame(
  LayerTreeHostRef reference,
  uint64_t source_id,
  uint64_t sequence_number,
  int64_t frame_time, 
  int64_t deadline, 
  int64_t interval) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  viz::BeginFrameArgs args = viz::BeginFrameArgs::Create(BEGINFRAME_FROM_HERE,
    source_id,
    sequence_number,
    base::TimeTicks::FromInternalValue(frame_time),
    base::TimeTicks::FromInternalValue(deadline),
    base::TimeDelta::FromMicroseconds(interval),
    viz::BeginFrameArgs::NORMAL);
  deps->GetWebMainThreadScheduler()->WillBeginFrame(args);
}

void _LayerTreeHostHelperBeginMainFrameNotExpectedSoon(LayerTreeHostRef reference) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->GetWebMainThreadScheduler()->BeginFrameNotExpectedSoon();
}

void _LayerTreeHostHelperBeginMainFrameNotExpectedUntil(LayerTreeHostRef reference, int64_t time) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->GetWebMainThreadScheduler()->BeginMainFrameNotExpectedUntil(base::TimeTicks::FromInternalValue(time));
}

void _LayerTreeHostHelperRequestNewLayerTreeFrameSink(LayerTreeHostRef reference, void* peer, void (*callback)(void*)) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->compositor_helper()->RequestNewLayerTreeFrameSink(reinterpret_cast<_LayerTreeHost *>(reference)->handle.get(), peer, callback);
}

void _LayerTreeHostHelperDidCommitFrameToCompositor(LayerTreeHostRef reference) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  deps->GetWebMainThreadScheduler()->DidCommitFrameToCompositor();
}

void _LayerTreeHostSetContentSourceId(LayerTreeHostRef reference, uint32_t id) {
  reinterpret_cast<_LayerTreeHost *>(reference)->handle->SetContentSourceId(id);
}

//class _TextureLayerClientImpl : public cc::TextureLayerClient {
//public:
//  _TextureLayerClientImpl() {}
//  ~_TextureLayerClientImpl() override {}
//    bool PrepareTextureMailbox(
//      cc::TextureMailbox* mailbox,
//      scoped_ptr<cc::SingleReleaseCallback>* release_callback,
//      bool use_shared_memory) override {
//        return false;
//      }
//};

// Layer

LayerRef _LayerCreateDefault() {
  _Layer* layer = new _Layer(0, nullptr);
  layer->create_layer(true);
  return layer;
}


LayerRef _LayerCreate(int type, void* client, CLayerClientCallbacks cbs) {
 //DLOG(INFO) << "_LayerCreate: type = " << type;
 LayerRef result = nullptr;
  //SolidColorLayer         = 0
  //NinePatchLayer          = 1
  //PictureLayer            = 2
 
 //if (type == 0 || type == 1) {
//   result = new _Layer(type, nullptr, false);
// } else {
//   result = new _Layer(type, nullptr, false);
 //}
 _Layer* layer = new _Layer(type, nullptr);
 result = layer;
 if (type == 2 || type == 3) { // PictureLayer or TextureLayer
  //int id = GetLayer(result)->id();
  layer->set_client(new _LayerClientImpl(client, -1, cbs));
  layer->create_layer(false);
 } else {
  layer->create_layer(false);
 }
 return result;
}

void _LayerDestroy(LayerRef layer) {
 //LOG(INFO) << "destroying layer";
 delete reinterpret_cast<_Layer *>(layer);
 layer = nullptr;
}

int64_t _LayerId(LayerRef layer) {
  return GetLayer(layer)->id();
}

uint64_t _LayerGetElementId(LayerRef layer) {
  return GetLayer(layer)->element_id().ToInternalValue();
}

void _LayerSetElementId(LayerRef layer, uint64_t id) {
  GetLayer(layer)->SetElementId(cc::ElementId(id));
}

int64_t _LayerType(LayerRef layer) {
  int64_t type = reinterpret_cast<_Layer *>(layer)->type();
  if(type != -1) {
    return type;
  }

  return -1;
}

LayerRef _LayerRootLayer(LayerRef layer) {
  cc::Layer* ptr = nullptr;
  ptr = GetLayer(layer)->RootLayer();
  if(!ptr)
    return nullptr;
  // return a not owned layer
  return new _Layer(ptr);
}

LayerRef _LayerParent(LayerRef layer) {
  cc::Layer* ptr = nullptr;
  ptr = GetLayer(layer)->parent();
  if(!ptr)
    return nullptr;
  // return a not owned layer
  return new _Layer(ptr);
}

void _LayerAddChild(LayerRef layer, LayerRef child) {
  //DCHECK(child->owned());
  GetLayer(layer)->AddChild(reinterpret_cast<_Layer *>(child)->handle);
}

void _LayerInsertChild(LayerRef layer, LayerRef child, int index) {
  //DCHECK(child->owned());
  GetLayer(layer)->InsertChild(reinterpret_cast<_Layer *>(child)->handle, index);
}

void _LayerReplaceChild(LayerRef layer, LayerRef ref, LayerRef repl) {
 //DCHECK(repl->owned());
 GetLayer(layer)->ReplaceChild(reinterpret_cast<_Layer *>(ref)->layer(), reinterpret_cast<_Layer *>(repl)->handle);
}

void _LayerRemoveFromParent(LayerRef layer) {
 GetLayer(layer)->RemoveFromParent();
}

void _LayerRemoveAllChildren(LayerRef layer) {
  GetLayer(layer)->RemoveAllChildren();
}

void _LayerSetTrilinearFiltering(LayerRef layer, int value) {
  GetLayer(layer)->SetTrilinearFiltering(value);
}

int _LayerGetTrilinearFiltering(LayerRef layer) {
  return GetLayer(layer)->trilinear_filtering() ? 1 : 0;
}

void _LayerSetCacheRenderSurface(LayerRef layer, int value) {
  GetLayer(layer)->SetCacheRenderSurface(value);
}

int _LayerGetCacheRenderSurface(LayerRef layer) {
  return GetLayer(layer)->cache_render_surface() ? 1 : 0;
}

void _LayerSetChildren(LayerRef layer, LayerRef* children, int count) {
 cc::LayerList list;
 for (int i = 0; i < count; ++i) {
   list.push_back(reinterpret_cast<_Layer **>(children)[i]->handle);
 }
 GetLayer(layer)->SetChildren(list);
}

int _LayerHasAncestor(LayerRef layer, const LayerRef ancestor) {
 cc::Layer* handle = GetLayer(ancestor);
 return GetLayer(layer)->HasAncestor(handle) ? 1 : 0;
}

void _LayerChildren(LayerRef layer) {
 //GetLayer(layer)->children();
}

LayerRef _LayerChildAt(LayerRef layer, int index) {
 cc::Layer* child = GetLayer(layer)->child_at(index);
 if (!child)
  return nullptr;

 return new _Layer(child);
}

void _LayerRequestCopyOfOutput(LayerRef layer, CopyOutputRequestRef output_request) {
 GetLayer(layer)->RequestCopyOfOutput(std::move(reinterpret_cast<_opyOutputRequest *>(output_request)->handle));
}

int _LayerHasCopyRequest(LayerRef layer) {
 return GetLayer(layer)->HasCopyRequest() ? 1 : 0;
}

void _LayerSetBackgroundColor(LayerRef layer, uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
 SkColor color = SkColorSetARGB(a, r, g, b);
 GetLayer(layer)->SetBackgroundColor(color);
}

void _LayerBackgroundColor(LayerRef layer, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b) {
 SkColor color = GetLayer(layer)->background_color();
 *a = SkColorGetA(color);
 *r = SkColorGetR(color);
 *g = SkColorGetG(color);
 *b = SkColorGetB(color);
}

void _LayerSafeOpaqueBackgroundColor(LayerRef layer, uint8_t* r, uint8_t* g, uint8_t* b) {
 SkColor color = GetLayer(layer)->SafeOpaqueBackgroundColor();
 *r = SkColorGetR(color);
 *g = SkColorGetG(color);
 *b = SkColorGetB(color);
}

void _LayerSetBounds(LayerRef layer, int width, int height) {
 GetLayer(layer)->SetBounds(gfx::Size(width, height));
}

void _LayerBounds(LayerRef layer, int* width, int* height) {
 gfx::Size bounds = GetLayer(layer)->bounds();
 *width = bounds.width();
 *height = bounds.height();
}

void _LayerSetMasksToBounds(LayerRef layer, int masks_to_bounds) {
 GetLayer(layer)->SetMasksToBounds(masks_to_bounds ? true : false);
}

int _LayerMasksToBounds(LayerRef layer) {
 return GetLayer(layer)->masks_to_bounds() ? 1 : 0;
}

void _LayerSetMaskLayer(LayerRef layer, LayerRef mask) {
 cc::Layer* handle = GetLayer(mask);
 GetLayer(layer)->SetMaskLayer(handle);
}

LayerRef _LayerMaskLayer(LayerRef layer) {
 cc::Layer* handle = GetLayer(layer)->mask_layer();
 if (!handle)
  return nullptr;

 return new _Layer(handle);
}

int _LayerDrawsContent(LayerRef layer) {
  return GetLayer(layer)->DrawsContent();
}

void _LayerGetVisibleLayerRect(LayerRef layer, int* x, int* y, int* w, int* h) {
  gfx::Rect r = GetLayer(layer)->visible_layer_rect_for_testing();
  *x = r.x();
  *y = r.y();
  *w = r.width();
  *h = r.height();
}

void _LayerSetNeedsDisplayRect(LayerRef layer, int x, int y, int width, int height) {
 GetLayer(layer)->SetNeedsDisplayRect(gfx::Rect(x, y, width, height));
}

void _LayerSetNeedsDisplay(LayerRef layer) {
 GetLayer(layer)->SetNeedsDisplay();
}

void _LayerSetOpacity(LayerRef layer, float opacity) {
 GetLayer(layer)->SetOpacity(opacity);
}

float _LayerOpacity(LayerRef layer) {
  return GetLayer(layer)->opacity();
}

float _LayerGetEffectiveOpacity(LayerRef layer) {
  return GetLayer(layer)->EffectiveOpacity();
}

// int _LayerOpacityIsAnimating(LayerRef layer) {
//  return GetLayer(layer)->OpacityIsAnimating() ? 1 : 0;
// }

// int _LayerHasPotentiallyRunningOpacityAnimation(LayerRef layer) {
//  return GetLayer(layer)->HasPotentiallyRunningOpacityAnimation() ? 1 : 0;
// }

void _LayerOpacityCanAnimateOnImplThread(LayerRef layer) {
 GetLayer(layer)->OpacityCanAnimateOnImplThread();
}

void _LayerSetBlendMode(LayerRef layer, int blend_mode) {
 GetLayer(layer)->SetBlendMode(static_cast<SkBlendMode>(blend_mode));
}

int _LayerBlendMode(LayerRef layer) {
 return static_cast<int>(GetLayer(layer)->blend_mode());
}

// int _LayerUsesDefaultBlendMode(LayerRef layer) {
//  return GetLayer(layer)->uses_default_blend_mode() ? 1 : 0;
// }

void _LayerSetIsRootForIsolatedGroup(LayerRef layer, int root) {
 GetLayer(layer)->SetIsRootForIsolatedGroup(root ? 1 : 0);
}

int _LayerIsRootForIsolatedGroup(LayerRef layer) {
 return GetLayer(layer)->is_root_for_isolated_group() ? 1 : 0;
}

void _LayerSetFilters(LayerRef layer, int* filters) {
  NOTREACHED() << "LayerSetFilters not implemented";
 //GetLayer(layer)->SetFilters();
}

void _LayerFilters(LayerRef layer) {
  NOTREACHED() << "LayerFilters not implemented";
 //GetLayer(layer)->filters();
}

// int _LayerFilterIsAnimating(LayerRef layer) {
//  return GetLayer(layer)->FilterIsAnimating() ? 1 : 0;
// }

// int _LayerHasPotentiallyRunningFilterAnimation(LayerRef layer) {
//  return GetLayer(layer)->HasPotentiallyRunningFilterAnimation() ? 1 : 0;
// }

void _LayerSetBackgroundFilters(LayerRef layer) {
  NOTREACHED() << "LayerSetBackgroundFilters not implemented";
 //GetLayer(layer)->SetBackgroundFilters();
}

void _LayerBackgroundFilters(LayerRef layer) {
  NOTREACHED() << "BackgroundFilters not implemented";
 //GetLayer(layer)->background_filters();
}

void _LayerSetContentsOpaque(LayerRef layer, int contents_opaque) {
 GetLayer(layer)->SetContentsOpaque(contents_opaque ? true : false);
}

int _LayerContentsOpaque(LayerRef layer) {
 return GetLayer(layer)->contents_opaque() ? 1 : 0;
}

void _LayerSetPosition(LayerRef layer, float x, float y) {
 GetLayer(layer)->SetPosition(gfx::PointF(x, y));
}

void _LayerPosition(LayerRef layer, float* x, float* y) {
 gfx::PointF point = GetLayer(layer)->position();
 *x = point.x();
 *y = point.y();
}

void _LayerSetIsContainerForFixedPositionLayers(LayerRef layer, int container_fixed) {
 GetLayer(layer)->SetIsContainerForFixedPositionLayers(container_fixed ? true : false);
}

int _LayerIsContainerForFixedPositionLayers(LayerRef layer) {
 return GetLayer(layer)->IsContainerForFixedPositionLayers() ? 1 : 0;
}

// void _LayerFixedContainerSizeDelta(LayerRef layer, float* x, float* y) {
//  gfx::Vector2dF vec = GetLayer(layer)->FixedContainerSizeDelta();
//  *x = vec.x();
//  *y = vec.y();
// }

void _LayerSetPositionConstraint(LayerRef layer) {
 NOTREACHED() << "LayerSetPositionConstraint not implemented";
 //GetLayer(layer)->SetPositionConstraint();
}

void _LayerPositionConstraint(LayerRef layer) {
 NOTREACHED() << "LayerPositionConstraint( not implemented";
 //GetLayer(layer)->position_constraint();
}

void _LayerSetTransform(LayerRef layer,
  double col1row1, double col2row1,
  double col3row1, double col4row1,
  double col1row2, double col2row2,
  double col3row2, double col4row2,
  double col1row3, double col2row3,
  double col3row3, double col4row3,
  double col1row4, double col2row4,
  double col3row4, double col4row4) {

  gfx::Transform transform(col1row1, col2row1,
        col3row1, col4row1,
        col1row2, col2row2,
        col3row2, col4row2,
        col1row3, col2row3,
        col3row3, col4row3,
        col1row4, col2row4,
        col3row4, col4row4);

 GetLayer(layer)->SetTransform(transform);
}

void _LayerTransform(LayerRef layer,
  double* col1row1, double* col2row1,
  double* col3row1, double* col4row1,
  double* col1row2, double* col2row2,
  double* col3row2, double* col4row2,
  double* col1row3, double* col2row3,
  double* col3row3, double* col4row3,
  double* col1row4, double* col2row4,
  double* col3row4, double* col4row4) {

 SkMatrix44 matrix = GetLayer(layer)->transform().matrix();

 *col1row1 = matrix.get(0, 0);
 *col1row2 = matrix.get(1, 0);
 *col1row3 = matrix.get(2, 0);
 *col1row4 = matrix.get(3, 0);

 *col2row1 = matrix.get(0, 1);
 *col2row2 = matrix.get(1, 1);
 *col2row3 = matrix.get(2, 1);
 *col2row4 = matrix.get(3, 1);

 *col3row1 = matrix.get(0, 2);
 *col3row2 = matrix.get(1, 2);
 *col3row3 = matrix.get(2, 2);
 *col3row4 = matrix.get(3, 2);

 *col4row1 = matrix.get(0, 3);
 *col4row2 = matrix.get(1, 3);
 *col4row3 = matrix.get(2, 3);
 *col4row4 = matrix.get(3, 3);
}

// int _LayerTransformIsAnimating(LayerRef layer) {
//  return GetLayer(layer)->TransformIsAnimating() ? 1 : 0;
// }

// int _LayerTransformIsInvertible(LayerRef layer) {
//  return GetLayer(layer)->transform_is_invertible() ? 1 : 0;
// }

// int _LayerHasPotentiallyRunningTransformAnimation(LayerRef layer) {
//  return GetLayer(layer)->HasPotentiallyRunningTransformAnimation() ? 1 : 0;
// }

// int _LayerHasOnlyTranslationTransforms(LayerRef layer) {
//  return GetLayer(layer)->HasOnlyTranslationTransforms() ? 1 : 0;
// }

// int _LayerAnimationsPreserveAxisAlignment(LayerRef layer) {
//  return GetLayer(layer)->AnimationsPreserveAxisAlignment() ? 1 : 0;
// }

// int _LayerMaximumTargetScale(LayerRef layer, float* max_scale) {
//  return GetLayer(layer)->MaximumTargetScale(max_scale) ? 1 : 0;
// }

// int _LayerAnimationStartScale(LayerRef layer, float* start_scale) {
//  return GetLayer(layer)->AnimationStartScale(start_scale) ? 1 : 0;
// }

void _LayerSetTransformOrigin(LayerRef layer, float x, float y, float z) {
 GetLayer(layer)->SetTransformOrigin(gfx::Point3F(x, y, z));
}

void _LayerTransformOrigin(LayerRef layer, float* x, float* y, float* z) {
 gfx::Point3F point = GetLayer(layer)->transform_origin();
 *x = point.x();
 *y = point.y();
 *z = point.z();
}

// int _LayerHasAnyAnimationTargetingProperty(LayerRef layer, int target_property) {
//  return GetLayer(layer)->HasAnyAnimationTargetingProperty(static_cast<cc::TargetProperty::Type>(target_property)) ? 1 : 0;
// }

// int _LayerScrollOffsetAnimationWasInterrupted(LayerRef layer) {
//  return GetLayer(layer)->ScrollOffsetAnimationWasInterrupted() ? 1 : 0;
// }

void _LayerSetScrollParent(LayerRef layer, LayerRef parent) {
 GetLayer(layer)->SetScrollParent(GetLayer(parent));
}

LayerRef _LayerScrollParent(LayerRef layer) {
 cc::Layer* parent = GetLayer(layer)->scroll_parent();
 if (!parent)
  return nullptr;

 return new _Layer(parent);
}

// void _LayerAddScrollChild(LayerRef layer, LayerRef child) {
//  GetLayer(layer)->AddScrollChild(GetLayer(child));
// }

// void _LayerRemoveScrollChild(LayerRef layer, LayerRef child) {
//  GetLayer(layer)->RemoveScrollChild(GetLayer(child));
// }

void _LayerScrollChildren(LayerRef layer) {
  NOTREACHED() << "LayerScrollChildren not implemented";
 //GetLayer(layer)->scroll_children();
}

void _LayerSetClipParent(LayerRef layer, LayerRef ancestor) {
 GetLayer(layer)->SetClipParent(GetLayer(ancestor));
}

LayerRef _LayerClipParent(LayerRef layer) {
 cc::Layer* handle = GetLayer(layer)->clip_parent();
 if (!handle)
  return nullptr;

 return new _Layer(handle);
}

// void _LayerAddClipChild(LayerRef layer, LayerRef clip_child) {
//  GetLayer(layer)->AddClipChild(GetLayer(clip_child));
// }

// void _LayerRemoveClipChild(LayerRef layer, LayerRef clip_child) {
//  GetLayer(layer)->RemoveClipChild(GetLayer(clip_child));
// }

void _LayerClipChildren(LayerRef layer) {
 NOTREACHED() << "LayerClipChildren not implemented";
 //GetLayer(layer)->clip_children();
}

// void _LayerDrawTransform(LayerRef layer,
//   double* col1row1, double* col2row1,
//   double* col3row1, double* col4row1,
//   double* col1row2, double* col2row2,
//   double* col3row2, double* col4row2,
//   double* col1row3, double* col2row3,
//   double* col3row3, double* col4row3,
//   double* col1row4, double* col2row4,
//   double* col3row4, double* col4row4) {

//  gfx::Transform transform = GetLayer(layer)->DrawTransform();
//  SkMatrix44 matrix = transform.matrix();

//  *col1row1 = matrix.get(0, 0);
//  *col1row2 = matrix.get(1, 0);
//  *col1row3 = matrix.get(2, 0);
//  *col1row4 = matrix.get(3, 0);

//  *col2row1 = matrix.get(0, 1);
//  *col2row2 = matrix.get(1, 1);
//  *col2row3 = matrix.get(2, 1);
//  *col2row4 = matrix.get(3, 1);

//  *col3row1 = matrix.get(0, 2);
//  *col3row2 = matrix.get(1, 2);
//  *col3row3 = matrix.get(2, 2);
//  *col3row4 = matrix.get(3, 2);

//  *col4row1 = matrix.get(0, 3);
//  *col4row2 = matrix.get(1, 3);
//  *col4row3 = matrix.get(2, 3);
//  *col4row4 = matrix.get(3, 3);
// }

void _LayerScreenSpaceTransform(LayerRef layer,
  double* col1row1, double* col2row1,
  double* col3row1, double* col4row1,
  double* col1row2, double* col2row2,
  double* col3row2, double* col4row2,
  double* col1row3, double* col2row3,
  double* col3row3, double* col4row3,
  double* col1row4, double* col2row4,
  double* col3row4, double* col4row4) {

 gfx::Transform transform = GetLayer(layer)->ScreenSpaceTransform();
 SkMatrix44 matrix = transform.matrix();

 *col1row1 = matrix.get(0, 0);
 *col1row2 = matrix.get(1, 0);
 *col1row3 = matrix.get(2, 0);
 *col1row4 = matrix.get(3, 0);

 *col2row1 = matrix.get(0, 1);
 *col2row2 = matrix.get(1, 1);
 *col2row3 = matrix.get(2, 1);
 *col2row4 = matrix.get(3, 1);

 *col3row1 = matrix.get(0, 2);
 *col3row2 = matrix.get(1, 2);
 *col3row3 = matrix.get(2, 2);
 *col3row4 = matrix.get(3, 2);

 *col4row1 = matrix.get(0, 3);
 *col4row2 = matrix.get(1, 3);
 *col4row3 = matrix.get(2, 3);
 *col4row4 = matrix.get(3, 3);
}

void _LayerSetNumUnclippedDescendants(LayerRef layer, int descendants) {
 GetLayer(layer)->set_num_unclipped_descendants(descendants);
}

int _LayerNumUnclippedDescendants(LayerRef layer) {
 return GetLayer(layer)->num_unclipped_descendants();
}

void _LayerSetScrollOffset(LayerRef layer, float offset_x, float offset_y) {
 GetLayer(layer)->SetScrollOffset(gfx::ScrollOffset(offset_x, offset_y));
}

// void _LayerSetScrollCompensationAdjustment(LayerRef layer, float offset_x, float offset_y) {
//  GetLayer(layer)->SetScrollCompensationAdjustment(gfx::Vector2d(offset_x, offset_y));
// }

// void _LayerScrollCompensationAdjustment(LayerRef layer, float* offset_x, float* offset_y) {
//  gfx::Vector2dF vec = GetLayer(layer)->ScrollCompensationAdjustment();
//  *offset_x = vec.x();
//  *offset_y = vec.y();
// }

void _LayerScrollOffset(LayerRef layer, float* offset_x, float* offset_y) {
 gfx::ScrollOffset offset = GetLayer(layer)->scroll_offset();
 *offset_x = offset.x();
 *offset_y = offset.y();
}

void _LayerSetScrollOffsetFromImplSide(LayerRef layer, float offset_x, float offset_y) {
 GetLayer(layer)->SetScrollOffsetFromImplSide(gfx::ScrollOffset(offset_x, offset_y));
}

// void _LayerSetScrollClipLayerId(LayerRef layer, int clip_layer_id) {
//  GetLayer(layer)->SetScrollClipLayerId(clip_layer_id);
// }

int _LayerScrollable(LayerRef layer) {
 return GetLayer(layer)->scrollable() ? 1 : 0;
}

void _LayerSetUserScrollable(LayerRef layer, int horizontal, int vertical) {
 GetLayer(layer)->SetUserScrollable(horizontal ? true : false, vertical ? true : false);
}

int _LayerUserScrollableHorizontal(LayerRef layer) {
 return GetLayer(layer)->user_scrollable_horizontal() ? 1 : 0;
}

int _LayerUserScrollableVertical(LayerRef layer) {
 return GetLayer(layer)->user_scrollable_vertical() ? 1 : 0;
}

// void _LayerSetShouldScrollOnMainThread(LayerRef layer, int should_scroll) {
//  GetLayer(layer)->SetShouldScrollOnMainThread(should_scroll ? true : false);
// }

int _LayerShouldScrollOnMainThread(LayerRef layer) {
 return GetLayer(layer)->should_scroll_on_main_thread() ? true : false;
}

// void _LayerSetHaveWheelEventHandlers(LayerRef layer, int have_wheel) {
//  GetLayer(layer)->SetHaveWheelEventHandlers(have_wheel ? true : false);
// }

// int _LayerHaveWheelEventHandlers(LayerRef layer) {
//  return GetLayer(layer)->have_wheel_event_handlers() ? 1 : 0;
// }

// void _LayerSetHaveScrollEventHandlers(LayerRef layer, int have_scroll) {
//  GetLayer(layer)->SetHaveScrollEventHandlers(have_scroll ? true : false);
// }

// int _LayerHaveScrollEventHandlers(LayerRef layer) {
//  return GetLayer(layer)->have_scroll_event_handlers() ? 1 : 0;
// }

void _LayerSetNonFastScrollableRegion(LayerRef layer, int x, int y, int width, int height) {
 cc::Region region(gfx::Rect(x, y, width, height));
 GetLayer(layer)->SetNonFastScrollableRegion(region);
}

void _LayerNonFastScrollableRegion(LayerRef layer, int* x, int* y, int* width, int* height) {
 gfx::Rect rect = GetLayer(layer)->non_fast_scrollable_region().bounds();
 *x = rect.x();
 *y = rect.y();
 *width = rect.width();
 *height = rect.height();
}

// void _LayerSetTouchEventHandlerRegion(LayerRef layer, int x, int y, int width, int height) {
//  cc::Region region(gfx::Rect(x, y, width, height));
//  GetLayer(layer)->SetTouchEventHandlerRegion(region);
// }

// void _LayerTouchEventHandlerRegion(LayerRef layer, int* x, int* y, int* width, int* height) {
//  gfx::Rect rect = GetLayer(layer)->touch_event_handler_region().bounds();
//  *x = rect.x();
//  *y = rect.y();
//  *width = rect.width();
//  *height = rect.height();
// }

// void _LayerSetScrollBlocksOn(LayerRef layer, int scroll_blocks_on) {
//  GetLayer(layer)->SetScrollBlocksOn(ScrollBlocksOn(scroll_blocks_on));
// }

// int _LayerScrollBlocksOn(LayerRef layer) {
//  return GetLayer(layer)->scroll_blocks_on();
// }

void _LayerSetDidScrollCallback(LayerRef layer) {
 NOTREACHED() << "LayerSetDidScrollCallback not implemented";
 //GetLayer(layer)->set_did_scroll_callback();
}

int _LayerForceRenderSurface(LayerRef layer) {
 return GetLayer(layer)->force_render_surface_for_testing() ? 1 : 0;
}

void _LayerSetForceRenderSurface(LayerRef layer, int force_render_surface) {
 GetLayer(layer)->SetForceRenderSurfaceForTesting(force_render_surface ? true : false);
}

// void _LayerScrollDelta(LayerRef layer, float* delta_x, float* delta_y) {
//  gfx::Vector2dF vec = GetLayer(layer)->ScrollDelta();
//  *delta_x = vec.x();
//  *delta_y = vec.y();
// }

void _LayerCurrentScrollOffset(LayerRef layer, float* offset_x, float* offset_y) {
 gfx::ScrollOffset offset = GetLayer(layer)->CurrentScrollOffset();
 *offset_x = offset.x();
 *offset_y = offset.y();
}

void _LayerSetDoubleSided(LayerRef layer, int double_sided) {
 GetLayer(layer)->SetDoubleSided(double_sided ? true : false);
}

int _LayerDoubleSided(LayerRef layer) {
 return GetLayer(layer)->double_sided() ? 1 : 0;
}

void _LayerSetShouldFlattenTransform(LayerRef layer, int should_flatten) {
 GetLayer(layer)->SetShouldFlattenTransform(should_flatten ? true : false);
}

int _LayerShouldFlattenTransform(LayerRef layer) {
 return GetLayer(layer)->should_flatten_transform() ? 1 : 0;
}

int _LayerIs3dSorted(LayerRef layer) {
 return GetLayer(layer)->Is3dSorted() ? 1 : 0;
}

void _LayerSetUseParentBackfaceVisibility(LayerRef layer, int parent_backface_visibility) {
 GetLayer(layer)->SetUseParentBackfaceVisibility(parent_backface_visibility ? true : false);
}

int _LayerUseParentBackfaceVisibility(LayerRef layer) {
 return GetLayer(layer)->use_parent_backface_visibility() ? 1 : 0;
}

void _LayerSetLayerTreeHost(LayerRef layer, LayerTreeHostRef host) {
 //DCHECK(host->owned);
 GetLayer(layer)->SetLayerTreeHost(reinterpret_cast<_LayerTreeHost *>(host)->handle.get());
}

// int _LayerHasDelegatedContent(LayerRef layer) {
//  return GetLayer(layer)->HasDelegatedContent() ? 1 : 0;
// }

// int _LayerHasContributingDelegatedRenderPasses(LayerRef layer) {
//  return GetLayer(layer)->HasContributingDelegatedRenderPasses() ? 1 : 0;
// }

void _LayerSetIsDrawable(LayerRef layer, int is_drawable) {
 GetLayer(layer)->SetIsDrawable(is_drawable ? true : false);
}

void _LayerSetHideLayerAndSubtree(LayerRef layer, int hide) {
 GetLayer(layer)->SetHideLayerAndSubtree(hide ? true : false);
}

int _LayerHideLayerAndSubtree(LayerRef layer) {
 return GetLayer(layer)->hide_layer_and_subtree() ? 1 : 0;
}

// void _LayerSetReplicaLayer(LayerRef layer, LayerRef replica) {
//  GetLayer(layer)->SetReplicaLayer(GetLayer(replica));
// }

// LayerRef _LayerReplicaLayer(LayerRef layer) {
//  cc::Layer* replica = GetLayer(layer)->replica_layer();
//  if(!replica)
//   return nullptr;

//  return new _Layer(replica);
// }

// int _LayerHasMask(LayerRef layer) {
//  return GetLayer(layer)->HasMask() ? 1 : 0;
// }

// int _LayerHasReplica(LayerRef layer) {
//  return GetLayer(layer)->has_replica() ? 1 : 0;
// }

// int _LayerReplicaHasMask(LayerRef layer) {
//  return GetLayer(layer)->replica_has_mask() ? 1 : 0;
// }

int _LayerNumDescendantsThatDrawContent(LayerRef layer) {
 return GetLayer(layer)->NumDescendantsThatDrawContent();
}

// void _LayerSavePaintProperties(LayerRef layer) {
//  GetLayer(layer)->SavePaintProperties();
// }

int _LayerUpdate(LayerRef layer) {
 return GetLayer(layer)->Update() ? 1 : 0;
}

// void _LayerSetIsMask(LayerRef layer, int is_mask) {
//  GetLayer(layer)->SetIsMask(is_mask ? true : false);
// }

// int _LayerIsSuitableForGpuRasterization(LayerRef layer) {
//  return GetLayer(layer)->IsSuitableForGpuRasterization() ? 1 : 0;
// }

void _LayerSetLayerClient(LayerRef layer) {
 NOTREACHED() << "LayerSetLayerClient not implemented";
 //GetLayer(layer)->SetLayerClient();
}

void _LayerPushPropertiesTo(LayerRef layer, LayerRef other) {
  NOTREACHED() << "LayerPushPropertiesTo not implemented";
 //GetLayer(layer)->PushPropertiesTo(GetLayer(other));
}

LayerTreeHostRef _LayerLayerTreeHost(LayerRef layer) {
 cc::LayerTreeHost* host = GetLayer(layer)->layer_tree_host();
 if(!host)
  return nullptr;

 return new _LayerTreeHost(host);
}

// int _LayerAddAnimation(LayerRef layer, AnimationRef animation) {
//  return GetLayer(layer)->AddAnimation(animation->handle.Pass()) ? 1 : 0;
// }

// void _LayerPauseAnimation(LayerRef layer, int animation_id, double time_offset) {
//  GetLayer(layer)->PauseAnimation(animation_id, time_offset);
// }

// void _LayerRemoveAnimation(LayerRef layer, int animation_id) {
//  GetLayer(layer)->RemoveAnimation(animation_id);
// }

// void _LayerRemoveAnimationByProperty(LayerRef layer, int animation_id, int target_property) {
//  GetLayer(layer)->RemoveAnimation(animation_id, cc::Animation::TargetProperty(target_property));
// }

// // LayerAnimationControllerRef _LayerLayerAnimationController(LayerRef layer) {
// //  cc::LayerAnimationController* controller = GetLayer(layer)->layer_animation_controller();
// //  return new _LayerAnimationController(controller);
// // }

// void _LayerSetLayerAnimationDelegate(LayerRef layer, void* peer, CLayerAnimationDelegateCallbacks callbacks) {
//  _LayerAnimationDelegate* delegate = new _LayerAnimationDelegate(peer, callbacks);
//  layer->own_animation_delegate(delegate);
//  GetLayer(layer)->set_layer_animation_delegate(delegate);
// }

// int _LayerHasActiveAnimation(LayerRef layer) {
//  return GetLayer(layer)->HasActiveAnimation() ? 1 : 0;
// }

// void _LayerRegisterForAnimations(LayerRef layer, AnimationRegistrarRef registrar) {
//  GetLayer(layer)->RegisterForAnimations(registrar->handle);
// }

// void _LayerAddLayerAnimationEventObserver(LayerRef layer, LayerAnimationEventObserverRef observer) {
//  GetLayer(layer)->AddLayerAnimationEventObserver(observer->handle);
// }

// void _LayerRemoveLayerAnimationEventObserver(LayerRef layer, LayerAnimationEventObserverRef observer) {
//  GetLayer(layer)->RemoveLayerAnimationEventObserver(observer->handle);
// }

void _LayerGetPicture(LayerRef layer) {
 //GetLayer(layer)->GetPicture();
 NOTREACHED() << "LayerGetPicture not implemented";
}

int _LayerToScrollbarLayer(LayerRef layer) {
 NOTREACHED() << "LayerToScrollbarLayer not implemented";
 //cc::ScrollbarLayerInterface iface = GetLayer(layer)->ToScrollbarLayer();
 //return iface.ScrollLayerId();
 return -1;
}

void _LayerPaintProperties(LayerRef layer) {
 NOTREACHED() << "LayerPaintProperties not implemented";
 //GetLayer(layer)->paint_properties();
}

void _LayerSetNeedsPushProperties(LayerRef layer) {
 GetLayer(layer)->SetNeedsPushProperties();
}

// int _LayerNeedsPushProperties(LayerRef layer) {
//  return GetLayer(layer)->needs_push_properties() ? 1 : 0;
// }

// int _LayerDescendantNeedsPushProperties(LayerRef layer) {
//  return GetLayer(layer)->descendant_needs_push_properties() ? 1 : 0;
// }

void _LayerSet3dSortingContextId(LayerRef layer, int id) {
 GetLayer(layer)->Set3dSortingContextId(id);
}

int _LayerSortingContextId(LayerRef layer) {
 return GetLayer(layer)->sorting_context_id();
}

void _LayerSetPropertyTreeSequenceNumber(LayerRef layer, int sequence_number) {
 GetLayer(layer)->set_property_tree_sequence_number(sequence_number);
}

void _LayerSetTransformTreeIndex(LayerRef layer, int index) {
 GetLayer(layer)->SetTransformTreeIndex(index);
}

int _LayerTransformTreeIndex(LayerRef layer) {
 return GetLayer(layer)->transform_tree_index();
}

void _LayerSetClipTreeIndex(LayerRef layer, int index) {
 GetLayer(layer)->SetClipTreeIndex(index);
}

int _LayerClipTreeIndex(LayerRef layer) {
 return GetLayer(layer)->clip_tree_index();
}

void _LayerSetEffectTreeIndex(LayerRef layer, int index) {
 GetLayer(layer)->SetEffectTreeIndex(index);
}

int _LayerEffectTreeIndex(LayerRef layer) {
 return GetLayer(layer)->effect_tree_index();
}

void _LayerSetOffsetToTransformParent(LayerRef layer, float offset_x, float offset_y) {
 GetLayer(layer)->set_offset_to_transform_parent(gfx::Vector2dF(offset_x, offset_y));
}

void _LayerOffsetToTransformParent(LayerRef layer, float* offset_x, float* offset_y) {
 gfx::Vector2dF vec = GetLayer(layer)->offset_to_transform_parent();
 *offset_x = vec.x();
 *offset_y = vec.y();
}

// void _LayerVisibleRectFromPropertyTrees(LayerRef layer, int* x, int* y, int* width, int* height) {
//  gfx::Rect rect = GetLayer(layer)->visible_rect_from_property_trees();
//  *x = rect.x();
//  *y = rect.y();
//  *width = rect.width();
//  *height = rect.height();
// }

// void _LayerSetVisibleRectFromPropertyTrees(LayerRef layer, int x, int y, int width, int height) {
//  GetLayer(layer)->set_visible_rect_from_property_trees(gfx::Rect(x, y, width, height));
// }

// void _LayerClipRectInTargetSpaceFromPropertyTrees(LayerRef layer, int* x, int* y, int* width, int* height) {
//  gfx::Rect rect = GetLayer(layer)->clip_rect_in_target_space_from_property_trees();
//  *x = rect.x();
//  *y = rect.y();
//  *width = rect.width();
//  *height = rect.height();
// }

// void _LayerSetClipRectInTargetSpaceFromPropertyTrees(LayerRef layer, int x, int y, int width, int height) {
//  GetLayer(layer)->set_clip_rect_in_target_space_from_property_trees(gfx::Rect(x, y, width, height));
// }

void _LayerSetShouldFlattenTransformFromPropertyTree(LayerRef layer, int should_flatten) {
 GetLayer(layer)->set_should_flatten_transform_from_property_tree(should_flatten ? true : false);
}

int _LayerShouldFlattenTransformFromPropertyTree(LayerRef layer) {
 return GetLayer(layer)->should_flatten_transform_from_property_tree() ? 1 : 0;
}

// void _LayerVisibleLayerRect(LayerRef layer, int* x, int* y, int* width, int* height) {
//  gfx::Rect rect = GetLayer(layer)->visible_layer_rect();
//  *x = rect.x();
//  *y = rect.y();
//  *width = rect.width();
//  *height = rect.height();
// }

void _LayerSetVisibleLayerRect(LayerRef layer, int x, int y, int width, int height) {
 GetLayer(layer)->set_visible_layer_rect(gfx::Rect(x, y, width, height));
}

// void _LayerClipRect(LayerRef layer, int* x, int* y, int* width, int* height) {
//  gfx::Rect rect = GetLayer(layer)->clip_rect();
//  *x = rect.x();
//  *y = rect.y();
//  *width = rect.width();
//  *height = rect.height();
// }

// void _LayerSetClipRect(LayerRef layer, int x, int y, int width, int height) {
//  GetLayer(layer)->set_clip_rect(gfx::Rect(x, y, width, height));
// }

// int _LayerHasRenderSurface(LayerRef layer) {
//  return GetLayer(layer)->has_render_surface() ? 1 : 0;
// }

void _LayerSetFrameTimingRequests(LayerRef layer) {
  NOTREACHED() << "LayerSetFrameTimingRequests not implemented";
 //GetLayer(layer)->SetFrameTimingRequests();
}

void _LayerFrameTimingRequests(LayerRef layer) {
  NOTREACHED() << "LayerFrameTimingRequests not implemented";
 //GetLayer(layer)->FrameTimingRequests();
}

void _LayerDidBeginTracing(LayerRef layer) {
  NOTREACHED() << "LayerDidBeginTracing not implemented";
 //GetLayer(layer)->DidBeginTracing();
}

// void _LayerSetNumLayerOrDescendantWithCopyRequest(LayerRef layer, int layers) {
//  GetLayer(layer)->set_num_layer_or_descendant_with_copy_request(layers);
// }

// int _LayerNumLayerOrDescendantsWithCopyRequest(LayerRef layer) {
//  return GetLayer(layer)->num_layer_or_descendants_with_copy_request();
// }

// void _LayerSetVisited(LayerRef layer, int visited) {
//  GetLayer(layer)->set_visited(visited ? true : false);
// }

// int _LayerVisited(LayerRef layer) {
//  return GetLayer(layer)->visited() ? 1 : 0;
// }

// void _LayerSetLayerOrDescendantIsDrawn(LayerRef layer, int is_drawn) {
//  GetLayer(layer)->set_layer_or_descendant_is_drawn(is_drawn ? true : false);
// }

// int _LayerLayerOrDescendantIsDrawn(LayerRef layer) {
//  return GetLayer(layer)->layer_or_descendant_is_drawn() ? 1 : 0;
// }

// void _LayerSetSortedForRecursion(LayerRef layer, int sorted) {
//  GetLayer(layer)->set_sorted_for_recursion(sorted ? true : false);
// }

// int _LayerSortedForRecursion(LayerRef layer) {
//  return GetLayer(layer)->sorted_for_recursion() ? true : false;
// }

// void _LayerScrollOffsetForAnimation(LayerRef layer, double* offset_x, double* offset_y) {
//  gfx::ScrollOffset offset = GetLayer(layer)->ScrollOffsetForAnimation();
//  *offset_x = offset.x();
//  *offset_y = offset.y();
// }

void _LayerFilterOperations(LayerRef layer) {
  NOTREACHED() << "LayerFilterOperations not implemented";
 // GetLayer(layer)->filters();
}

void _LayerSetFilterOperations(LayerRef layer) {
  NOTREACHED() << "LayerSetFilterOperations not implemented";
 // GetLayer(layer)->SetFilters();
}

void _LayerOnFilterAnimated(LayerRef layer, int* filters) {
  NOTREACHED() << "LayerOnFilterAnimated not implemented";
 // GetLayer(layer)->OnFilterAnimated();
}


// void _LayerOnOpacityAnimated(LayerRef layer, float opacity) {
//  GetLayer(layer)->OnOpacityAnimated(opacity);
// }

// void _LayerOnTransformAnimated(LayerRef layer,
//   double col1row1, double col2row1,
//   double col3row1, double col4row1,
//   double col1row2, double col2row2,
//   double col3row2, double col4row2,
//   double col1row3, double col2row3,
//   double col3row3, double col4row3,
//   double col1row4, double col2row4,
//   double col3row4, double col4row4) {

//   gfx::Transform transform(col1row1, col2row1,
//       col3row1, col4row1,
//       col1row2, col2row2,
//       col3row2, col4row2,
//       col1row3, col2row3,
//       col3row3, col4row3,
//       col1row4, col2row4,
//       col3row4, col4row4);
//  GetLayer(layer)->OnTransformAnimated(transform);
// }

// void _LayerOnScrollOffsetAnimated(LayerRef layer, double x_offset, double y_offset) {
//  GetLayer(layer)->OnScrollOffsetAnimated(gfx::ScrollOffset(x_offset, y_offset));
// }

// void _LayerOnAnimationWaitingForDeletion(LayerRef layer) {
//  GetLayer(layer)->OnAnimationWaitingForDeletion();
// }

// void _LayerOnTransformIsPotentiallyAnimatingChanged(LayerRef layer, int is_animating) {
//  GetLayer(layer)->OnTransformIsPotentiallyAnimatingChanged(is_animating ? true : false);
// }

// int _LayerIsActive(LayerRef layer) {
//  return GetLayer(layer)->IsActive() ? 0 : 1;
// }

int _TextureLayerFlipped(LayerRef reference) {
  return GetLayerAs<cc::TextureLayer>(reference)->flipped() ? 1 : 0;
}

void _TextureLayerSetFlipped(LayerRef reference, int flipped) {
  GetLayerAs<cc::TextureLayer>(reference)->SetFlipped(flipped);
}

int _TextureLayerIsSnapped(LayerRef reference) {
  return GetLayerAs<cc::TextureLayer>(reference)->IsSnapped() ? 1 : 0;
}

void _TextureLayerClearClient(LayerRef reference) {
  GetLayerAs<cc::TextureLayer>(reference)->ClearClient();
}

void _TextureLayerClearTexture(LayerRef reference) {
  GetLayerAs<cc::TextureLayer>(reference)->ClearTexture();
}

void _TextureLayerSetUV(LayerRef reference, float tlx, float tly, float brx, float bry) {
  GetLayerAs<cc::TextureLayer>(reference)->SetUV(gfx::PointF(tlx, tly), gfx::PointF(brx, bry));
}

void _TextureLayerSetNearestNeighbor(LayerRef reference, int nearest_neighbor) {
  GetLayerAs<cc::TextureLayer>(reference)->SetNearestNeighbor(nearest_neighbor != 0);
}

void _TextureLayerSetVertexOpacity(LayerRef reference, float bottom_left, float top_left, float top_right, float bottom_right) {
  GetLayerAs<cc::TextureLayer>(reference)->SetVertexOpacity(bottom_left, top_left, top_right, bottom_right);
}

void _TextureLayerSetPremultipliedAlpha(LayerRef reference, int premulalpha) {
  GetLayerAs<cc::TextureLayer>(reference)->SetPremultipliedAlpha(premulalpha != 0);
}

void _TextureLayerSetBlendBackgroundColor(LayerRef reference, int blend) {
  GetLayerAs<cc::TextureLayer>(reference)->SetBlendBackgroundColor(blend != 0);
}

void _TextureLayerSetTransferableResource(LayerRef reference, TransferableResourceRef resource) {

}

int _InputHandlerGetScrollOffsetForLayer(InputHandlerRef reference, int layerId, float* x, float* y) {
  gfx::ScrollOffset offset;
  bool ok = reinterpret_cast<cc::InputHandler *>(reference)->GetScrollOffsetForLayer(layerId, &offset);
  *x = offset.x();
  *y = offset.y();
  return ok ? 1 : 0;
}

int _InputHandlerScrollLayerTo(InputHandlerRef reference, int layerId, float offset_x, float offset_y) {
  gfx::ScrollOffset offset(offset_x, offset_y);
  return reinterpret_cast<cc::InputHandler *>(reference)->ScrollLayerTo(layerId, offset) ? 1 : 0;
}

struct KeyframeModelHolder {
  KeyframeModelHolder(std::unique_ptr<cc::KeyframeModel> _ptr): ptr(std::move(_ptr)), owned(true) {}
  std::unique_ptr<cc::KeyframeModel> ptr;
  bool owned;

  inline cc::KeyframeModel* handle() const {
    DCHECK(owned);
    return ptr.get();
  }
};

class NativeFloatAnimationCurve : public cc::FloatAnimationCurve {
public:
  NativeFloatAnimationCurve(void* state, FloatAnimationCurveCallbacks callbacks):
   state_(state),
   callbacks_(callbacks) {}
  
  ~NativeFloatAnimationCurve() override {}

  base::TimeDelta Duration() const override {
    return base::TimeDelta::FromMilliseconds(callbacks_.GetDuration(state_));
  }
  
  std::unique_ptr<AnimationCurve> Clone() const override {
    return std::unique_ptr<AnimationCurve>(new NativeFloatAnimationCurve(state_, callbacks_));
  }

  float GetValue(base::TimeDelta t) const {
    return callbacks_.GetValue(state_, t.ToInternalValue());
  }

private:
  void* state_;
  FloatAnimationCurveCallbacks callbacks_;
};

class NativeTransformAnimationCurve : public cc::TransformAnimationCurve {
public:
  NativeTransformAnimationCurve(void* state, TransformAnimationCurveCallbacks callbacks):
   state_(state),
   callbacks_(callbacks) {}
  
  ~NativeTransformAnimationCurve() override {}

  base::TimeDelta Duration() const override {
    int64_t value = callbacks_.GetDuration(state_);
    return base::TimeDelta::FromMilliseconds(value);
  }
    
  std::unique_ptr<AnimationCurve> Clone() const override {
    return std::unique_ptr<AnimationCurve>(new NativeTransformAnimationCurve(state_, callbacks_));
  }

  cc::TransformOperations GetValue(base::TimeDelta t) const override {
    TransformOperationsRef ref = callbacks_.GetValue(state_, t.ToInternalValue());
    return *reinterpret_cast<cc::TransformOperations *>(ref);
  }

  bool AnimatedBoundsForBox(const gfx::BoxF& box,
                            gfx::BoxF* bounds) const {
    float x;
    float y;
    float z;
    float w;
    float h;
    float d;
    int rc = callbacks_.GetAnimatedBoundsForBox(state_, 
      box.x(), box.y(), box.z(), box.width(), box.height(), box.depth(),
      &x, &y ,&z, &w, &h, &d);
    if (rc) {
      bounds->set_x(x);
      bounds->set_y(y);
      bounds->set_z(z);
      bounds->set_width(w);
      bounds->set_height(h);
      bounds->set_depth(d);
    }
    return rc;
  }

  bool IsTranslation() const {
    return callbacks_.GetIsTranslation(state_);
  }

  bool PreservesAxisAlignment() const {
    return callbacks_.GetPreservesAxisAlignment(state_);
  }

  bool AnimationStartScale(bool forward_direction,
                           float* start_scale) const {
    return callbacks_.GetAnimationStartScale(state_, forward_direction ? 1 : 0, start_scale);
  }

  bool MaximumTargetScale(bool forward_direction,
                          float* max_scale) const {
    return callbacks_.GetMaximumTargetScale(state_, forward_direction ? 1 : 0, max_scale);
  }

private:
  void* state_;
  TransformAnimationCurveCallbacks callbacks_;
};

KeyframeModelRef _KeyframeModelCreate(AnimationCurveRef curve, int id, int group, int property) {
  std::unique_ptr<cc::AnimationCurve> curve_ptr(reinterpret_cast<cc::AnimationCurve *>(curve));
  std::unique_ptr<cc::KeyframeModel> ptr = cc::KeyframeModel::Create(
      std::move(curve_ptr), 
      id,
      group, 
      property);
  return new KeyframeModelHolder(std::move(ptr));
}

void _KeyframeModelDestroy(KeyframeModelRef model) {
  KeyframeModelHolder* ref = reinterpret_cast<KeyframeModelHolder *>(model);
  //if (ref->owned) {
  //  ref->ptr.reset();
  //}
  delete ref;
}

int _KeyframeModelIsFinishedAt(KeyframeModelRef model, int64_t monotonic_time) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->IsFinishedAt(base::TimeTicks::FromInternalValue(monotonic_time));
}

int  _KeyframeModelId(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->id();
}

int _KeyframeModelGroup(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->group();
}

int _KeyframeModelTargetProperty(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->target_property_id();
}

int _KeyframeModelRunState(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->run_state());
}

void _KeyframeModelSetRunState(KeyframeModelRef model, int run_state, int64_t monotonic_time) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->SetRunState(static_cast<cc::KeyframeModel::RunState>(run_state), base::TimeTicks::FromInternalValue(monotonic_time));
}

double _KeyframeModelIterations(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->iterations();
}

void _KeyframeModelSetIterations(KeyframeModelRef model, double iterations) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_iterations(iterations);
}

double _KeyframeModelIterationStart(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->iteration_start();
}

void _KeyframeModelSetIterationStart(KeyframeModelRef model, double iteration_start) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_iteration_start(iteration_start);
}

int64_t _KeyframeModelStartTime(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->start_time().ToInternalValue();
}

void _KeyframeModelSetStartTime(KeyframeModelRef model, int64_t value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_start_time(base::TimeTicks::FromInternalValue(value));
}

int64_t _KeyframeModelTimeOffset(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->time_offset().ToInternalValue();
}

void _KeyframeModelSetTimeOffset(KeyframeModelRef model, int64_t value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_time_offset(base::TimeDelta::FromInternalValue(value));
}

int _KeyframeModelDirection(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->direction());
}

void _KeyframeModelSetDirection(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_direction(static_cast<cc::KeyframeModel::Direction>(value));
}

int _KeyframeModelFillMode(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->fill_mode());
}

void _KeyframeModelSetFillMode(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_fill_mode(static_cast<cc::KeyframeModel::FillMode>(value));
}

double _KeyframeModelPlaybackRate(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->playback_rate();
}

void _KeyframeModelSetPlaybackRate(KeyframeModelRef model, double value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_playback_rate(value);
}

AnimationCurveRef _KeyframeModelAnimationCurve(KeyframeModelRef model) {
  return reinterpret_cast<KeyframeModelHolder *>(model)->handle()->curve();
}

int _KeyframeModelNeedsSynchronizedStartTime(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->needs_synchronized_start_time());
}

void _KeyframeModelSetNeedsSynchronizedStartTime(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_needs_synchronized_start_time(static_cast<bool>(value));
}

int _KeyframeModelReceivedFinishedEvent(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->received_finished_event());
}

void _KeyframeModelSetReceivedFinishedEvent(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_received_finished_event(static_cast<bool>(value));
}

int _KeyframeModelIsControllingInstance(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->is_controlling_instance());
}

void _KeyframeModelSetIsControllingInstance(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_is_controlling_instance_for_test(static_cast<bool>(value));
}

int _KeyframeModelIsImplOnly(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->is_impl_only());
}

void _KeyframeModelSetIsImplOnly(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->SetIsImplOnly();
}

int _KeyframeModelAffectsActiveElements(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->affects_active_elements());
}

void _KeyframeModelSetAffectsActiveElements(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_affects_active_elements(static_cast<bool>(value));
}

int _KeyframeModelAffectsPendingElements(KeyframeModelRef model) {
  return static_cast<int>(reinterpret_cast<KeyframeModelHolder *>(model)->handle()->affects_pending_elements());
}

void _KeyframeModelSetAffectsPendingElements(KeyframeModelRef model, int value) {
  reinterpret_cast<KeyframeModelHolder *>(model)->handle()->set_affects_pending_elements(static_cast<bool>(value));
}

void _KeyframeEffectDestroy(KeyframeEffectRef reference) {
  delete reinterpret_cast<cc::KeyframeEffect *>(reference);
}

int _KeyframeEffectGetId(KeyframeEffectRef reference) {
  return static_cast<int>(reinterpret_cast<cc::KeyframeEffect *>(reference)->id());
}

int _KeyframeEffectHasBoundElementAnimations(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->has_bound_element_animations() ? 1 : 0;
}

int _KeyframeEffectGetElementId(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->element_id().ToInternalValue();
}

int _KeyframeEffectHasAnyKeyframeModel(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->has_any_keyframe_model() ? 1 : 0;
}

int _KeyframeEffectScrollOffsetAnimationWasInterrupted(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->scroll_offset_animation_was_interrupted() ? 1 : 0;
}

int _KeyframeEffectGetNeedsPushProperties(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->needs_push_properties() ? 1 : 0;
}

void _KeyframeEffectSetNeedsPushProperties(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->SetNeedsPushProperties();
}

int _KeyframeEffectAnimationsPreserveAxisAlignment(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->AnimationsPreserveAxisAlignment() ? 1 : 0;
}

int _KeyframeEffectIsTicking(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->is_ticking() ? 1 : 0;
}

int _KeyframeEffectHasTickingKeyframeModel(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->HasTickingKeyframeModel() ? 1 : 0;
}

int _KeyframeEffectTickingKeyframeModelsCount(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->TickingKeyframeModelsCount();
}

int _KeyframeEffectHasNonDeletedKeyframeModel(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->HasNonDeletedKeyframeModel() ? 1 : 0;
}

void _KeyframeEffectBindElementAnimations(KeyframeEffectRef reference, ElementAnimationsRef elementAnimations) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->BindElementAnimations(reinterpret_cast<CCElementAnimations *>(elementAnimations)->ptr());
}

void _KeyframeEffectUnbindElementAnimations(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->UnbindElementAnimations();
}

int _KeyframeEffectHasAttachedElement(KeyframeEffectRef reference) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->has_attached_element() ? 1 : 0;
}

void _KeyframeEffectAttachElement(KeyframeEffectRef reference, int elementId) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->AttachElement(cc::ElementId(elementId));
}

void _KeyframeEffectDetachElement(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->DetachElement();
}

void _KeyframeEffectTick(KeyframeEffectRef reference, int64_t monotonicTime, void* state, AnimationTimeProviderCallback tickProvider) {
  AnimationTimeProvider provider(state, tickProvider);
  reinterpret_cast<cc::KeyframeEffect *>(reference)->Tick(base::TimeTicks::FromInternalValue(monotonicTime), &provider);
}

void _KeyframeEffectRemoveFromTicking(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->RemoveFromTicking();
}

void _KeyframeEffectUpdateState(KeyframeEffectRef reference, int startReadyKeyframeModels, AnimationEventsRef events) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->UpdateState(startReadyKeyframeModels == 0 ? false : true, reinterpret_cast<cc::AnimationEvents *>(events));
}

void _KeyframeEffectUpdateTickingState(KeyframeEffectRef reference, int type) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->UpdateTickingState(type == 0 ? cc::UpdateTickingType::NORMAL : cc::UpdateTickingType::FORCE);
}

void _KeyframeEffectAddKeyframeModel(KeyframeEffectRef reference, KeyframeModelRef model) {
  KeyframeModelHolder* model_ref = reinterpret_cast<KeyframeModelHolder *>(model);
  model_ref->owned = false;
  std::unique_ptr<cc::KeyframeModel> to_move(model_ref->ptr.release());
  reinterpret_cast<cc::KeyframeEffect *>(reference)->AddKeyframeModel(std::move(to_move));
  //model_ref->ptr = std::unique_ptr<cc::KeyframeModel>();
}

void _KeyframeEffectPauseKeyframeModel(KeyframeEffectRef reference, int id, double timeOffset) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->PauseKeyframeModel(id, timeOffset);
}

void _KeyframeEffectRemoveKeyframeModel(KeyframeEffectRef reference, int id) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->RemoveKeyframeModel(id);
}

void _KeyframeEffectAbortKeyframeModel(KeyframeEffectRef reference, int id) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->AbortKeyframeModel(id);
}

void _KeyframeEffectAbortKeyframeModels(KeyframeEffectRef reference, int target, int needsCompletion) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->AbortKeyframeModels(static_cast<cc::TargetProperty::Type>(target), needsCompletion);
}

void _KeyframeEffectActivateKeyframeEffects(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->ActivateKeyframeEffects();
}

void _KeyframeEffectActivateKeyframeModelAdded(KeyframeEffectRef reference) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->KeyframeModelAdded();
}

int _KeyframeEffectNotifyKeyframeModelStarted(KeyframeEffectRef reference, AnimationEventRef event) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->NotifyKeyframeModelStarted(*reinterpret_cast<cc::AnimationEvent *>(event)) ? 1 : 0;
}

int _KeyframeEffectNotifyKeyframeModelFinished(KeyframeEffectRef reference, AnimationEventRef event) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->NotifyKeyframeModelFinished(*reinterpret_cast<cc::AnimationEvent *>(event)) ? 1 : 0;
}

void _KeyframeEffectNotifyKeyframeModelTakeover(KeyframeEffectRef reference, AnimationEventRef event) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->NotifyKeyframeModelTakeover(*reinterpret_cast<cc::AnimationEvent *>(event));
}

int _KeyframeEffectNotifyKeyframeModelAborted(KeyframeEffectRef reference, AnimationEventRef event) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->NotifyKeyframeModelAborted(*reinterpret_cast<cc::AnimationEvent *>(event)) ? 1 : 0;
}

int _KeyframeEffectHasOnlyTranslationTransforms(KeyframeEffectRef reference, int type) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->HasOnlyTranslationTransforms(static_cast<cc::ElementListType>(type)) ? 1 : 0;
}

int _KeyframeEffectAnimationStartScale(KeyframeEffectRef reference, int type, float* scale) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->AnimationStartScale(static_cast<cc::ElementListType>(type), scale) ? 1 : 0;
}

int _KeyframeEffectMaximumTargetScale(KeyframeEffectRef reference, int type, float* scale) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->MaximumTargetScale(static_cast<cc::ElementListType>(type), scale) ? 1 : 0;
}

int _KeyframeEffectIsPotentiallyAnimatingProperty(KeyframeEffectRef reference, int targetProperty, int type) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->IsPotentiallyAnimatingProperty(static_cast<cc::TargetProperty::Type>(targetProperty), static_cast<cc::ElementListType>(type)) ? 1 : 0;
}

int _KeyframeEffectIsCurrentlyAnimatingProperty(KeyframeEffectRef reference, int targetProperty, int type) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->IsCurrentlyAnimatingProperty(static_cast<cc::TargetProperty::Type>(targetProperty), static_cast<cc::ElementListType>(type)) ? 1 : 0;
}

KeyframeModelRef _KeyframeEffectGetKeyframeModel(KeyframeEffectRef reference, int targetProperty) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->GetKeyframeModel(static_cast<cc::TargetProperty::Type>(targetProperty));
}

KeyframeModelRef _KeyframeEffectGetKeyframeModelById(KeyframeEffectRef reference, int keyframeModelId) {
  return reinterpret_cast<cc::KeyframeEffect *>(reference)->GetKeyframeModelById(keyframeModelId);
}

void _KeyframeEffectGetPropertyAnimationState(KeyframeEffectRef reference, int* pendingStateCurrentlyRunning, int* pendingStatePotentiallyAnimating, int* activeStateCurrentlyRunning , int* activeStatePotentiallyAnimating) {
 cc::PropertyAnimationState pendingState;
 cc::PropertyAnimationState activeState;
 reinterpret_cast<cc::KeyframeEffect *>(reference)->GetPropertyAnimationState(&pendingState, &activeState);
 *pendingStateCurrentlyRunning = static_cast<int>(pendingState.currently_running.to_ulong());
 *pendingStatePotentiallyAnimating = static_cast<int>(pendingState.potentially_animating.to_ulong());
 *activeStateCurrentlyRunning = static_cast<int>(activeState.currently_running.to_ulong());
 *activeStatePotentiallyAnimating = static_cast<int>(activeState.potentially_animating.to_ulong());
}

void _KeyframeEffectMarkAbortedKeyframeModelsForDeletion(KeyframeEffectRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->MarkAbortedKeyframeModelsForDeletion(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _KeyframeEffectPurgeKeyframeModelsMarkedForDeletion(KeyframeEffectRef reference, int implOnly) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->PurgeKeyframeModelsMarkedForDeletion(implOnly);
}

void _KeyframeEffectPushNewKeyframeModelsToImplThread(KeyframeEffectRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->PushNewKeyframeModelsToImplThread(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _KeyframeEffectRemoveKeyframeModelsCompletedOnMainThread(KeyframeEffectRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->RemoveKeyframeModelsCompletedOnMainThread(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _KeyframeEffectPushPropertiesTo(KeyframeEffectRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->PushPropertiesTo(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _KeyframeEffectSetAnimation(KeyframeEffectRef reference, AnimationRef animation) {
  reinterpret_cast<cc::KeyframeEffect *>(reference)->SetAnimation(reinterpret_cast<cc::Animation *>(animation));
}

void _KeyframeEffectListDestroy(KeyframeEffectListRef reference) {
  // not(never) owned
  //delete reinterpret_cast<cc::KeyframeEffectsList *>(reference);
}

void _ElementAnimationsDestroy(ElementAnimationsRef reference) {
  delete reinterpret_cast<CCElementAnimations *>(reference);
}

int _ElementAnimationsIsEmpty(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->IsEmpty() ? 1 : 0;
}

uint64_t _ElementAnimationsGetElementId(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->element_id().ToInternalValue();
}

void _ElementAnimationsSetElementId(ElementAnimationsRef reference, uint64_t id) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->SetElementId(cc::ElementId(id));
}

AnimationHostRef _ElementAnimationsGetAnimationHost(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->animation_host();
}

void _ElementAnimationsSetAnimationHost(ElementAnimationsRef reference, AnimationHostRef animHost) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->SetAnimationHost(reinterpret_cast<cc::AnimationHost *>(animHost));  
}

void _ElementAnimationsGetScrollOffsetForAnimation(ElementAnimationsRef reference, float* x, float* y) {
  gfx::ScrollOffset offset = reinterpret_cast<CCElementAnimations *>(reference)->ptr()->ScrollOffsetForAnimation();
  *x = offset.x();
  *y = offset.y();
}

KeyframeEffectListRef _ElementAnimationsKeyframeEffectListGet(ElementAnimationsRef reference) {
  return const_cast<cc::ElementAnimations::KeyframeEffectsList *>(&reinterpret_cast<CCElementAnimations *>(reference)->ptr()->keyframe_effects_list());
}

int _ElementAnimationsHasTickingKeyframeEffect(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->HasTickingKeyframeEffect() ? 1 : 0;
}

int _ElementAnimationsHasAnyKeyframeModel(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->HasAnyKeyframeModel() ? 1 : 0;
}

int _ElementAnimationsHasElementInActiveList(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->has_element_in_active_list() ? 1 : 0;
}

int _ElementAnimationsHasElementInPendingList(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->has_element_in_pending_list() ? 1 : 0;
}

int _ElementAnimationsHasElementInAnyList(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->has_element_in_any_list() ? 1 : 0;
}

int _ElementAnimationsAnimationsPreserveAxisAlignment(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->AnimationsPreserveAxisAlignment() ? 1 : 0;
}

int _ElementAnimationsScrollOffsetAnimationWasInterrupted(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->ScrollOffsetAnimationWasInterrupted() ? 1 : 0;
}

int _ElementAnimationsGetNeedsPushProperties(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->needs_push_properties() ? 1 : 0;
}

void _ElementAnimationsSetNeedsPushProperties(ElementAnimationsRef reference) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->SetNeedsPushProperties();
}

void _ElementAnimationsInitAffectedElementTypes(ElementAnimationsRef reference) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->InitAffectedElementTypes();
}

void _ElementAnimationsClearAffectedElementTypes(ElementAnimationsRef reference) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->ClearAffectedElementTypes();
}

void _ElementAnimationsElementRegistered(ElementAnimationsRef reference, uint64_t elementId, int type) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->ElementRegistered(cc::ElementId(elementId), static_cast<cc::ElementListType>(type));
}

void _ElementAnimationsElementUnregistered(ElementAnimationsRef reference, uint64_t elementId, int type) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->ElementUnregistered(cc::ElementId(elementId), static_cast<cc::ElementListType>(type));
}

void _ElementAnimationsAddKeyframeEffect(ElementAnimationsRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->AddKeyframeEffect(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _ElementAnimationsRemoveKeyframeEffect(ElementAnimationsRef reference, KeyframeEffectRef effect) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->RemoveKeyframeEffect(reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _ElementAnimationsPushPropertiesTo(ElementAnimationsRef reference, ElementAnimationsRef animations) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->PushPropertiesTo(reinterpret_cast<CCElementAnimations *>(animations)->ref());
}

int _ElementAnimationsHasAnyAnimationTargetingProperty(ElementAnimationsRef reference, int property) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->HasAnyAnimationTargetingProperty(static_cast<cc::TargetProperty::Type>(property)) ? 1 : 0;
}

int _ElementAnimationsIsPotentiallyAnimatingProperty(ElementAnimationsRef reference, int property, int type) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->IsPotentiallyAnimatingProperty(static_cast<cc::TargetProperty::Type>(property), static_cast<cc::ElementListType>(type)) ? 1 : 0;
}

int _ElementAnimationsIsCurrentlyAnimatingProperty(ElementAnimationsRef reference, int property, int type) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->IsCurrentlyAnimatingProperty(static_cast<cc::TargetProperty::Type>(type), static_cast<cc::ElementListType>(type));
}

void _ElementAnimationsNotifyAnimationStarted(ElementAnimationsRef reference, AnimationEventRef event) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyAnimationStarted(*reinterpret_cast<cc::AnimationEvent *>(event));
}

void _ElementAnimationsNotifyAnimationFinished(ElementAnimationsRef reference, AnimationEventRef event) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyAnimationFinished(*reinterpret_cast<cc::AnimationEvent *>(event));
}

void _ElementAnimationsNotifyAnimationAborted(ElementAnimationsRef reference, AnimationEventRef event) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyAnimationAborted(*reinterpret_cast<cc::AnimationEvent *>(event));
}

//void _ElementAnimationsNotifyAnimationPropertyUpdate(ElementAnimationsRef reference, AnimationEventRef event) {
//  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyAnimationPropertyUpdate(*reinterpret_cast<cc::AnimationEvent *>(event));
//}

void _ElementAnimationsNotifyAnimationTakeover(ElementAnimationsRef reference, AnimationEventRef event) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyAnimationTakeover(*reinterpret_cast<cc::AnimationEvent *>(event));
}

void _ElementAnimationsSetHasElementInActiveList(ElementAnimationsRef reference, int hasElementInActiveList) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->set_has_element_in_active_list(hasElementInActiveList == 0 ? false : true);
}

void _ElementAnimationsSetHasElementInPendingList(ElementAnimationsRef reference, int hasElementInPendingList) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->set_has_element_in_pending_list(hasElementInPendingList == 0 ? false : true);
}

// int _ElementAnimationsTransformAnimationBoundsForBox(ElementAnimationsRef reference, 
//   float bx, float by, float bz, float bw, float bh, float bdepth,
//   float* x, float* y, float* z, float* w, float* h, float* depth) {
//   gfx::BoxF input(bx, by, bz, bw, bh, bdepth);
//   gfx::BoxF output;
//   bool r = reinterpret_cast<CCElementAnimations *>(reference)->ptr()->TransformAnimationBoundsForBox(input, &output);
//   if (r) {
//     *x = output.x();
//     *y = output.y();
//     *z = output.z();
//     *w = output.width();
//     *h = output.height();
//     *depth = output.depth();
//   }
//   return r;
// }

int _ElementAnimationsHasOnlyTranslationTransforms(ElementAnimationsRef reference, int type) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->HasOnlyTranslationTransforms(static_cast<cc::ElementListType>(type)) ? 1 : 0;
}

int _ElementAnimationsAnimationStartScale(ElementAnimationsRef reference, int type, float* scale) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->AnimationStartScale(static_cast<cc::ElementListType>(type), scale) ? 1 : 0;
}

int _ElementAnimationsMaximumTargetScale(ElementAnimationsRef reference, int type, float* scale) {
  return reinterpret_cast<CCElementAnimations *>(reference)->ptr()->MaximumTargetScale(static_cast<cc::ElementListType>(type), scale) ? 1 : 0;
}

void _ElementAnimationsUpdateClientAnimationState(ElementAnimationsRef reference) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->UpdateClientAnimationState();
}

void _ElementAnimationsNotifyClientFloatAnimated(ElementAnimationsRef reference, float opacity, int target, KeyframeModelRef model) {
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyClientFloatAnimated(opacity, target, reinterpret_cast<cc::KeyframeModel*>(model));
}

void _ElementAnimationsNotifyClientScrollOffsetAnimated(
    ElementAnimationsRef reference, 
    float scrollOffsetX,
    float scrollOffsetY,
    int target,
    KeyframeModelRef model) {
  gfx::ScrollOffset scroll_offset(scrollOffsetX, scrollOffsetY);    
  reinterpret_cast<CCElementAnimations *>(reference)->ptr()->NotifyClientScrollOffsetAnimated(scroll_offset, target, reinterpret_cast<cc::KeyframeModel*>(model));
}

PaintTextBlobRef _PaintTextBlobCreate(const uint16_t* glyphs, size_t glyph_count, const float* px, const float* py, int plen, PaintFlagsRef flags) {
  //cc::PaintFlags local_flags(*reinterpret_cast<cc::PaintFlags *>(flags));
  const cc::PaintFlags& local_flags = reinterpret_cast<PaintFlags *>(flags)->const_ref();

  //local_flags.setStyle(cc::PaintFlags::kFill_Style);
  //local_flags.setAntiAlias(true);
  //local_flags.setSubpixelText(false);
  //local_flags.setLCDRenderText(false);
  //local_flags.setHinting(cc::PaintFlags::kNormal_Hinting);

  SkTArray<SkScalar> pos_vec;
  for (int i = 0; i < plen; ++i) {
    pos_vec.push_back(static_cast<SkScalar>(px[i]));
    pos_vec.push_back(static_cast<SkScalar>(py[i]));
  }
  //sk_sp<SkFontMgr> fm(SkFontMgr::RefDefault());  
  //SkFontStyle font_style = SkFontStyle::Normal();
  //sk_sp<SkTypeface> fTypeface = fm->legacyMakeTypeface("Arial", font_style);
  SkPaint paint = local_flags.ToSkPaint();
  //SkPaint paint;
  //paint.setTypeface(fTypeface);
  //const char* text = "Hello World";
  //SkTDArray<uint16_t> glyph_vec;
  //size_t len = strlen(text);
  //for (size_t i = 0; i < glyph_count; ++i) {
  //  glyph_vec.append(glyphs[i]);
  //}
  //glyph_vec.append(paint.textToGlyphs(text, len, nullptr));
  //paint.textToGlyphs(text, len, glyph_vec.begin());
  
  SkTextBlobBuilder builder;

  //paint.setTextEncoding(SkPaint::kGlyphID_TextEncoding);

  const SkTextBlobBuilder::RunBuffer& run = builder.allocRunPos(paint, glyph_count, nullptr);//allocRun(paint, glyph_count, 10, 10,
                                                    //          nullptr);
  //const SkTextBlobBuilder::RunBuffer& run = builder.allocRun(paint, glyph_count, nullptr); 
  //memcpy(run.glyphs, glyph_vec.begin(), glyph_vec.count() * sizeof(uint16_t)); 
  memcpy(run.glyphs, glyphs, glyph_count * sizeof(uint16_t));
  memcpy(run.pos, pos_vec.begin(), pos_vec.count() * sizeof(SkScalar));

  //std::vector<cc::PaintTypeface> typefaces;
  //typefaces.push_back(cc::PaintTypeface::FromSkTypeface(fTypeface));
  PaintTextBlob* result = new PaintTextBlob(base::MakeRefCounted<cc::PaintTextBlob>(builder.make(), std::vector<cc::PaintTypeface>()));//std::move(typefaces)));
  return result;
}

// PaintTextBlobRef _PaintTextBlobCreate(const uint16_t* glyphs, size_t glyph_count, const float* px, const float* py, int plen, PaintFlagsRef flags) {
//   //DLOG(INFO) << "_PaintTextBlobCreate (begin): glyphs: " << glyph_count << " points: " << plen;
//   cc::PaintFlags local_flags;//local_flags(*reinterpret_cast<cc::PaintFlags *>(flags));

//   local_flags.setStyle(cc::PaintFlags::kFill_Style);
//   local_flags.setAntiAlias(true);
//   local_flags.setSubpixelText(false);
//   local_flags.setLCDRenderText(false);
//   local_flags.setHinting(cc::PaintFlags::kNormal_Hinting);

//   std::vector<cc::PaintTypeface> typefaces;
  
//   SkPoint pos[plen];
//   for (int i = 0; i < plen; ++i) {
//     pos[i] = SkPoint::Make(px[i], py[i]);
//   }
//   SkTextBlobBuilder builder;

//   //static_assert(sizeof(*glyphs) == sizeof(*run_buffer.glyphs), "");
  
//   //static_assert(sizeof(*pos) == 2 * sizeof(*run_buffer.pos), "");
//   //sk_sp<SkFontMgr> fm(SkFontMgr::RefDefault());  
//   //DCHECK(fm);
//   //SkFontStyle font_style = SkFontStyle::Normal();
//   //sk_sp<SkTypeface> fTypeface = fm->legacyMakeTypeface("Arial", font_style);
//   // DCHECK(fTypeface);
//   // // make textblob
//   // SkPaint paint;
//   // paint.setTypeface(fTypeface);
//   // const char* text = "Hello blob!";
//   // SkTDArray<uint16_t> glyph_vec;
//   // size_t len = strlen(text);
//   // glyph_vec.append(paint.textToGlyphs(text, len, nullptr));
//   // paint.textToGlyphs(text, len, glyph_vec.begin());

//   // SkTextBlobBuilder builder;

//   // paint.setTextEncoding(SkPaint::kGlyphID_TextEncoding);
//   // const SkTextBlobBuilder::RunBuffer& run = builder.allocRun(paint, glyph_vec.count(), 10, 10,
//   //                                                            nullptr);
//   // memcpy(run.glyphs, glyph_vec.begin(), glyph_vec.count() * sizeof(uint16_t));
//   //cc::PaintTypeface typeface = cc::PaintTypeface::TestTypeface();

//   blink::FontDescription font_description;
//   font_description.SetComputedSize(12.0);
//   font_description.SetLocale(blink::LayoutLocale::Get("en"));
//   font_description.SetGenericFamily(blink::FontDescription::kStandardFamily);

//   blink::Font font = blink::Font(font_description);
//   font.Update(nullptr);
  
//   const blink::SimpleFontData* font_data = font.PrimaryFont();
//   DCHECK(font_data);
//   const blink::FontPlatformData& platform_font = font_data->PlatformData();
    
//   SkPaint paint = local_flags.ToSkPaint();
//   paint.setTypeface(sk_ref_sp(platform_font.Typeface()));

//   //SkTDArray<uint16_t> glyph_vec;
//   //glyph_vec.append(paint.textToGlyphs(text, len, nullptr))
//   paint.setTextEncoding(SkPaint::kGlyphID_TextEncoding);
//   const SkTextBlobBuilder::RunBuffer& run_buffer = builder.allocRunPos(paint, glyph_count, nullptr);
//   memcpy(run_buffer.glyphs, glyphs, glyph_count * sizeof(uint16_t));
//   memcpy(run_buffer.pos, pos, plen * sizeof(pos));
  
//   typefaces.push_back(platform_font.GetPaintTypeface());//cc::PaintTypeface::FromSkTypeface(fTypeface));
//   PaintTextBlob* result = new PaintTextBlob(base::MakeRefCounted<cc::PaintTextBlob>(builder.make(), std::move(typefaces)));
//   //DLOG(INFO) << "_PaintTextBlobCreate (end): PaintTextBlob = " << result;
//   return result;
// }

void _PaintTextBlobDestroy(PaintTextBlobRef handle) {
  PaintTextBlob* ref = reinterpret_cast<PaintTextBlob *>(handle);
  delete ref;
}

void _PaintFilterDestroy(PaintFilterRef handle) {
  delete reinterpret_cast<PaintFilter *>(handle);
}

int _TransformOperationGetType(TransformOperationRef handle) {
  return static_cast<int>(reinterpret_cast<cc::TransformOperation *>(handle)->type);
}

TransformOperationsRef _TransformOperationsCreate() {
  return new cc::TransformOperations();
}

void _TransformOperationsDestroy(TransformOperationsRef handle) {
  delete reinterpret_cast<cc::TransformOperations *>(handle);
}

int _TransformOperationsIsTranslation(TransformOperationsRef handle) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->IsTranslation();
}

int _TransformOperationsPreservesAxisAlignment(TransformOperationsRef handle) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->PreservesAxisAlignment();
}

int _TransformOperationsIsIdentity(TransformOperationsRef handle) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->IsIdentity();
}

int _TransformOperationsCount(TransformOperationsRef handle) {
  return static_cast<int>(reinterpret_cast<cc::TransformOperations *>(handle)->size());
}

TransformOperationRef _TransformOperationsGet(TransformOperationsRef handle, int index) {
  cc::TransformOperation& op = reinterpret_cast<cc::TransformOperations *>(handle)->at(index);
  return &op;
}

Matrix44Ref _TransformOperationsApply(TransformOperationsRef handle) {
  gfx::Transform transform = reinterpret_cast<cc::TransformOperations *>(handle)->Apply();
  return new SkMatrix44(transform.matrix());
}

TransformOperationsRef _TransformOperationsBlend(TransformOperationsRef handle, TransformOperationsRef other, float progress) {
  return new cc::TransformOperations(reinterpret_cast<cc::TransformOperations *>(handle)->Blend(*reinterpret_cast<cc::TransformOperations *>(other), progress));
}

int _TransformOperationsMatchesTypes(TransformOperationsRef handle, TransformOperationsRef other) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->MatchesTypes(*reinterpret_cast<cc::TransformOperations *>(other));
}

int _TransformOperationsCanBlendWith(TransformOperationsRef handle, TransformOperationsRef other) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->CanBlendWith(*reinterpret_cast<cc::TransformOperations *>(other));
}

int _TransformOperationsScaleComponent(TransformOperationsRef handle, float* scale) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->ScaleComponent(scale);
}

void _TransformOperationsAppendTranslate(TransformOperationsRef handle, float x, float y, float z) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendTranslate(x, y, z);
}

void _TransformOperationsAppendRotate(TransformOperationsRef handle, float x, float y, float z, float degrees) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendRotate(x, y, z, degrees);
}

void _TransformOperationsAppendScale(TransformOperationsRef handle, float x, float y, float z) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendScale(x, y, z);
}

void _TransformOperationsAppendSkew(TransformOperationsRef handle, float x, float y) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendSkew(x, y);
}

void _TransformOperationsAppendPerspective(TransformOperationsRef handle, float depth) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendPerspective(depth);
}

void _TransformOperationsAppendMatrix(TransformOperationsRef handle, Matrix44Ref matrix) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendMatrix(gfx::Transform(*reinterpret_cast<SkMatrix44 *>(matrix)));
}

void _TransformOperationsAppendIdentity(TransformOperationsRef handle) {
  reinterpret_cast<cc::TransformOperations *>(handle)->AppendIdentity();
}

void _TransformOperationsAppend(TransformOperationsRef handle, TransformOperationRef op) {
  reinterpret_cast<cc::TransformOperations *>(handle)->Append(*reinterpret_cast<cc::TransformOperation *>(op));
}

int _TransformApproximatelyEqual(TransformOperationsRef handle, TransformOperationsRef other, float tolerance) {
  return reinterpret_cast<cc::TransformOperations *>(handle)->ApproximatelyEqual(*reinterpret_cast<cc::TransformOperations *>(other), tolerance);
}


// AnimationEvents

int _AnimationEventGetType(AnimationEventRef handle) {
  return static_cast<int>(reinterpret_cast<cc::AnimationEvent *>(handle)->type);
}

uint64_t _AnimationEventGetElementId(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->element_id.ToInternalValue();
}

int _AnimationEventGetGroupId(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->group_id;
}

int _AnimationEventGetTargetProperty(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->target_property;
}

int64_t _AnimationEventGetMonotonicTime(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->monotonic_time.ToInternalValue();
}

int _AnimationEventIsImplOnly(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->is_impl_only;
}

float _AnimationEventGetOpacity(AnimationEventRef handle) {
  return reinterpret_cast<cc::AnimationEvent *>(handle)->opacity;
}

Matrix44Ref _AnimationEventGetTransform(AnimationEventRef handle) {
  return &reinterpret_cast<cc::AnimationEvent *>(handle)->transform.matrix();
}

FilterOperationsRef _AnimationEventGetFilterOperations(AnimationEventRef handle) {
  return &reinterpret_cast<cc::AnimationEvent *>(handle)->filters;
}

int _AnimationEventsIsEmpty(AnimationEventsRef handle) {
  return reinterpret_cast<cc::AnimationEvents *>(handle)->IsEmpty();
}

int _FilterOperationGetType(FilterOperationRef handle) {
  return reinterpret_cast<cc::FilterOperation *>(handle)->type();
}

float _FilterOperationGetAmount(FilterOperationRef handle) {
  return reinterpret_cast<cc::FilterOperation *>(handle)->amount();
}

void _FilterOperationSetAmount(FilterOperationRef handle, float value) {
  reinterpret_cast<cc::FilterOperation *>(handle)->set_amount(value);
}

float _FilterOperationGetOuterThreshold(FilterOperationRef handle) {
  return reinterpret_cast<cc::FilterOperation *>(handle)->outer_threshold();
}

void _FilterOperationSetOuterThreshold(FilterOperationRef handle, float value) {
  reinterpret_cast<cc::FilterOperation *>(handle)->set_outer_threshold(value);
}

void _FilterOperationGetDropShadowOffset(FilterOperationRef handle, int* x, int* y) {
  gfx::Point p = reinterpret_cast<cc::FilterOperation *>(handle)->drop_shadow_offset();
  *x = p.x();
  *y = p.y();
}

void _FilterOperationSetDropShadowOffset(FilterOperationRef handle, int x, int y) {
  reinterpret_cast<cc::FilterOperation *>(handle)->set_drop_shadow_offset(gfx::Point(x, y));
}

void _FilterOperationGetDropShadowColor(FilterOperationRef handle, uint8_t* a, uint8_t* r, uint8_t* g, uint8_t* b) {
  SkColor color = reinterpret_cast<cc::FilterOperation *>(handle)->drop_shadow_color();
  *a = SkColorGetA(color);
  *r = SkColorGetR(color);
  *g = SkColorGetG(color);
  *b = SkColorGetB(color);
}

void _FilterOperationSetDropShadowColor(FilterOperationRef handle, uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
  SkColor color = SkColorSetARGB(a, r, g, b);
  reinterpret_cast<cc::FilterOperation *>(handle)->set_drop_shadow_color(color);
} 

PaintFilterRef _FilterOperationGetImageFilter(FilterOperationRef handle) {
  return new PaintFilter(sk_ref_sp(reinterpret_cast<cc::FilterOperation *>(handle)->image_filter().get()));
}

void _FilterOperationSetImageFilter(FilterOperationRef handle, PaintFilterRef filter) {
  reinterpret_cast<cc::FilterOperation *>(handle)->set_image_filter(sk_ref_sp(reinterpret_cast<PaintFilter *>(filter)->handle()));
}

void _FilterOperationGetColorMatrix(
  FilterOperationRef handle, 
  int *m0, int *m1, int *m2, int *m3,
  int *m4, int *m5, int *m6, int *m7,
  int *m8, int *m9, int *m10, int *m11,
  int *m12, int *m13, int *m14, int *m15,
  int *m16, int *m17, int *m18, int *m19) {
  const cc::FilterOperation::Matrix& m = reinterpret_cast<cc::FilterOperation *>(handle)->matrix();
  *m0 = m[0];
  *m1 = m[1];
  *m2 = m[2];
  *m3 = m[3];
  *m4 = m[4];
  *m5 = m[5];
  *m6 = m[6];
  *m7 = m[7];
  *m8 = m[8];
  *m9 = m[9];
  *m10 = m[10];
  *m11 = m[11];
  *m12 = m[12];
  *m13 = m[13];
  *m14 = m[14];
  *m15 = m[15];
  *m16 = m[16];
  *m17 = m[17];
  *m18 = m[18];
  *m19 = m[19];
}

void _FilterOperationSetColorMatrix(
    FilterOperationRef handle,
    int m0, int m1, int m2, int m3,
    int m4, int m5, int m6, int m7,
    int m8, int m9, int m10, int m11,
    int m12, int m13, int m14, int m15,
    int m16, int m17, int m18, int m19) {
  cc::FilterOperation::Matrix m;
  m[0] = m0;
  m[1] = m1;
  m[2] = m2;
  m[3] = m3;
  m[4] = m4;
  m[5] = m5;
  m[6] = m6;
  m[7] = m7;
  m[8] = m8;
  m[9] = m9;
  m[10] = m10;
  m[11] = m11;
  m[12] = m12;
  m[13] = m13;
  m[14] = m14;
  m[15] = m15;
  m[16] = m16;
  m[17] = m17;
  m[18] = m18;
  m[19] = m19;

  reinterpret_cast<cc::FilterOperation *>(handle)->set_matrix(m);
}

int _FilterOperationGetZoomInset(FilterOperationRef handle) {
  return reinterpret_cast<cc::FilterOperation *>(handle)->zoom_inset();
}

void _FilterOperationSetZoomInset(FilterOperationRef handle, int inset) {
  reinterpret_cast<cc::FilterOperation *>(handle)->set_zoom_inset(inset);
}

void _FilterOperationGetShape(FilterOperationRef handle, int** x, int** y, int** w, int** h, int* count) {
  const cc::FilterOperation::ShapeRects& rects = reinterpret_cast<cc::FilterOperation *>(handle)->shape();
  for (size_t i = 0; i < rects.size(); i++) {
    gfx::Rect rect = rects[i];
    (*x)[i] = rect.x();
    (*y)[i] = rect.y();
    (*w)[i] = rect.width();
    (*h)[i] = rect.height();
  }
  *count = rects.size();
}

void _FilterOperationGetShapeCount(FilterOperationRef handle, int* count) {
  *count = reinterpret_cast<cc::FilterOperation *>(handle)->shape().size();
}

void _FilterOperationGetShapeNoCount(FilterOperationRef handle, int** x, int** y, int** w, int** h) {
  const cc::FilterOperation::ShapeRects& rects = reinterpret_cast<cc::FilterOperation *>(handle)->shape();
  for (size_t i = 0; i < rects.size(); i++) {
    gfx::Rect rect = rects[i];
    (*x)[i] = rect.x();
    (*y)[i] = rect.y();
    (*w)[i] = rect.width();
    (*h)[i] = rect.height();
  }
}

void _FilterOperationSetShape(FilterOperationRef handle, int* x, int* y, int* w, int* h, int count) {
  cc::FilterOperation::ShapeRects rects;
  for (int i = 0; i < count; i++) {
    gfx::Rect r(x[i], y[i], w[i], h[i]);
    rects.push_back(r);
  }
  reinterpret_cast<cc::FilterOperation *>(handle)->set_shape(rects);
}

FilterOperationRef _FilterOperationCreateWithAmount(int type, float amount) {
  switch (type) {
    case cc::FilterOperation::GRAYSCALE:
      return new cc::FilterOperation(cc::FilterOperation::CreateGrayscaleFilter(amount));
    case cc::FilterOperation::SEPIA:
      return new cc::FilterOperation(cc::FilterOperation::CreateSepiaFilter(amount));
    case cc::FilterOperation::SATURATE:
      return new cc::FilterOperation(cc::FilterOperation::CreateSaturateFilter(amount));
    case cc::FilterOperation::HUE_ROTATE:
      return new cc::FilterOperation(cc::FilterOperation::CreateHueRotateFilter(amount));
    case cc::FilterOperation::INVERT:
      return new cc::FilterOperation(cc::FilterOperation::CreateInvertFilter(amount));
    case cc::FilterOperation::BRIGHTNESS:
      return new cc::FilterOperation(cc::FilterOperation::CreateBrightnessFilter(amount));
    case cc::FilterOperation::CONTRAST:
      return new cc::FilterOperation(cc::FilterOperation::CreateContrastFilter(amount));
    case cc::FilterOperation::OPACITY:
      return new cc::FilterOperation(cc::FilterOperation::CreateOpacityFilter(amount));
    case cc::FilterOperation::SATURATING_BRIGHTNESS:
      return new cc::FilterOperation(cc::FilterOperation::CreateSaturatingBrightnessFilter(amount));
    default:
      return nullptr;  
  }
  return nullptr;
}

FilterOperationRef _FilterOperationCreateWithShape(int type, int* x, int* y, int* w, int* h, int count, float innerThreshold, float outerThreshold) {
  if (type == cc::FilterOperation::ALPHA_THRESHOLD) {
    cc::FilterOperation::ShapeRects shape;
    for (int i = 0; i < count; i++) {
      shape.push_back(gfx::Rect(x[i], y[i], w[i], h[i]));
    }
    return new cc::FilterOperation(cc::FilterOperation::CreateAlphaThresholdFilter(
      shape,
      innerThreshold,
      outerThreshold));
  }
  return nullptr;
}

FilterOperationRef _FilterOperationCreateWithOffset(int type, 
  int x, int y, 
  float deviation,
  uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
  
  if (type == cc::FilterOperation::DROP_SHADOW) {
    return new cc::FilterOperation(cc::FilterOperation::CreateDropShadowFilter(gfx::Point(x, y), deviation, SkColorSetARGB(a,r,g,b)));
  }
  
  return nullptr;
}

FilterOperationRef _FilterOperationCreateWithInset(int type, float amount, int inset) {
  if (type == cc::FilterOperation::ZOOM) {
    return new cc::FilterOperation(cc::FilterOperation::CreateZoomFilter(amount, inset));
  }
  return nullptr;
}

FilterOperationRef _FilterOperationCreateWithMatrix(int type,
  int m0, int m1, int m2, int m3,
  int m4, int m5, int m6, int m7,
  int m8, int m9, int m10, int m11,
  int m12, int m13, int m14, int m15,
  int m16, int m17, int m18, int m19) {
  if (type == cc::FilterOperation::COLOR_MATRIX) {
    cc::FilterOperation::Matrix m;
    m[0] = m0;
    m[1] = m1;
    m[2] = m2;
    m[3] = m3;
    m[4] = m4;
    m[5] = m5;
    m[6] = m6;
    m[7] = m7;
    m[8] = m8;
    m[9] = m9;
    m[10] = m10;
    m[11] = m11;
    m[12] = m12;
    m[13] = m13;
    m[14] = m14;
    m[15] = m15;
    m[16] = m16;
    m[17] = m17;
    m[18] = m18;
    m[19] = m19;
    return new cc::FilterOperation(cc::FilterOperation::CreateColorMatrixFilter(m));
  }
  return nullptr;
}

FilterOperationRef _FilterOperationCreateWithFilter(int type, PaintFilterRef filter) {
  if (type == cc::FilterOperation::REFERENCE) {
    PaintFilter* pf = reinterpret_cast<PaintFilter *>(filter);
    return new cc::FilterOperation(cc::FilterOperation::CreateReferenceFilter(sk_ref_sp(pf->handle())));
  }
  return nullptr;
}

FilterOperationsRef _FilterOperationsCreate() {
  return new cc::FilterOperations(); 
}

void _FilterOperationsDestroy(FilterOperationsRef reference) {
  delete reinterpret_cast<cc::FilterOperations *>(reference);
}

int _FilterOperationsGetCount(FilterOperationsRef reference) {
  return reinterpret_cast<cc::FilterOperations *>(reference)->size();
}

int _FilterOperationsHasFilterThatMovesPixels(FilterOperationsRef reference) {
  return reinterpret_cast<cc::FilterOperations *>(reference)->HasFilterThatMovesPixels() ? 1 : 0;
}

int _FilterOperationsHasFilterThatAffectsOpacity(FilterOperationsRef reference) {
  return reinterpret_cast<cc::FilterOperations *>(reference)->HasFilterThatAffectsOpacity() ? 1 : 0;
}

int _FilterOperationsHasReferenceFilter(FilterOperationsRef reference) {
  return reinterpret_cast<cc::FilterOperations *>(reference)->HasReferenceFilter() ? 1 : 0;
}

FilterOperationRef _FilterOperationsGet(FilterOperationsRef reference, int index) {
  const cc::FilterOperation& op = reinterpret_cast<cc::FilterOperations *>(reference)->at(index);
  return const_cast<cc::FilterOperation *>(&op);
}

void _FilterOperationsAppend(FilterOperationsRef reference, FilterOperationRef filter) {
  reinterpret_cast<cc::FilterOperations *>(reference)->Append(*reinterpret_cast<cc::FilterOperation *>(filter));
}

void _FilterOperationsClear(FilterOperationsRef reference) {
  reinterpret_cast<cc::FilterOperations *>(reference)->Clear();
}

void _FilterOperationsMapRect(FilterOperationsRef reference, 
  int rx, int ry, int rw, int rh, 
  float scaleX, float skewX, float transX,
  float skewY, float scaleY, float transY,
  float pers0, float pers1, float pers2,
  int* x, int* y, int* w, int* h) {
  gfx::Rect input_rect(rx, ry, rw, rh);
  SkMatrix input_matrix = SkMatrix::MakeAll(
    scaleX, skewX, transX, skewY, scaleY, transY, pers0, pers1, pers2);
  gfx::Rect r = reinterpret_cast<cc::FilterOperations *>(reference)->MapRect(input_rect, input_matrix);
  *x = r.x();
  *y = r.y();
  *w = r.width();
  *h = r.height();
}

void _FilterOperationsMapRectReverse(FilterOperationsRef reference, 
  int rx, int ry, int rw, int rh, 
  float scaleX, float skewX, float transX,
  float skewY, float scaleY, float transY,
  float pers0, float pers1, float pers2,
  int* x, int* y, int* w, int* h) {
  gfx::Rect input_rect(rx, ry, rw, rh);
  SkMatrix input_matrix = SkMatrix::MakeAll(
    scaleX, skewX, transX, skewY, scaleY, transY, pers0, pers1, pers2);
 
  gfx::Rect r = reinterpret_cast<cc::FilterOperations *>(reference)->MapRectReverse(input_rect, input_matrix);
  *x = r.x();
  *y = r.y();
  *w = r.width();
  *h = r.height();
}

FilterOperationsRef _FilterOperationsBlend(FilterOperationsRef reference, FilterOperationsRef from, float progress) {
  return new cc::FilterOperations(reinterpret_cast<cc::FilterOperations *>(reference)->Blend(*reinterpret_cast<cc::FilterOperations *>(from), progress));
}

AnimationCurveRef _AnimationCurveCreateFloatAnimation(void* state, FloatAnimationCurveCallbacks callbacks) {
  return new NativeFloatAnimationCurve(state, callbacks);
}

AnimationCurveRef _AnimationCurveCreateTransformAnimation(void* state, TransformAnimationCurveCallbacks callbacks) {
  return new NativeTransformAnimationCurve(state, callbacks);
}

int64_t _AnimationCurveGetDuration(AnimationCurveRef reference) {
  return reinterpret_cast<cc::AnimationCurve *>(reference)->Duration().ToInternalValue();
}

int _AnimationCurveGetType(AnimationCurveRef reference) {
  return reinterpret_cast<cc::AnimationCurve *>(reference)->Type();
}

AnimationCurveRef _AnimationCurveClone(AnimationCurveRef reference) {
  std::unique_ptr<cc::AnimationCurve> owned_ptr = reinterpret_cast<cc::AnimationCurve *>(reference)->Clone();
  return owned_ptr.release();
}

void _AnimationCurveDestroy(AnimationCurveRef reference) {
  delete reinterpret_cast<cc::AnimationCurve *>(reference);
}

AnimationHostRef _AnimationHostCreate() {
  std::unique_ptr<cc::AnimationHost> animation_host = cc::AnimationHost::CreateMainInstance();
  // its only considered "owned" if created through here
  _AnimationHost* handle = new _AnimationHost(std::move(animation_host));
  return handle;
}

void _AnimationHostDestroy(AnimationHostRef handle) {
  _AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle);
  delete host;
}

void _AnimationHostAddAnimationTimeline(AnimationHostRef handle, AnimationTimelineRef timeline) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->AddAnimationTimeline(reinterpret_cast<_AnimationTimeline *>(timeline)->handle_ref_counted());
}

void _AnimationHostRemoveAnimationTimeline(AnimationHostRef handle, AnimationTimelineRef timeline) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->RemoveAnimationTimeline(reinterpret_cast<_AnimationTimeline *>(timeline)->handle_ref_counted());
}

AnimationTimelineRef _AnimationHostGetTimelineById(AnimationHostRef handle, int id) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  cc::AnimationTimeline* maybe_timeline = host->GetTimelineById(id);
  if (maybe_timeline) {
    return new _AnimationTimeline(maybe_timeline);
  }
  return nullptr;
}

//void _AnimationHostClearTimelines(AnimationHostRef handle) {
//  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
//  host->ClearTimelines();
//}

void _AnimationHostRegisterKeyframeEffectForElement(AnimationHostRef handle, uint64_t element_id, KeyframeEffectRef effect) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->RegisterKeyframeEffectForElement(cc::ElementId(element_id), reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _AnimationHostUnregisterKeyframeEffectForElement(AnimationHostRef handle, uint64_t element_id, KeyframeEffectRef effect) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->UnregisterKeyframeEffectForElement(cc::ElementId(element_id), reinterpret_cast<cc::KeyframeEffect *>(effect));
}

void _AnimationHostSetNeedsCommit(AnimationHostRef handle) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->SetNeedsCommit();
}

void _AnimationHostSetNeedsPushProperties(AnimationHostRef handle) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  host->SetNeedsPushProperties();
}

int _AnimationHostGetNeedsPushProperties(AnimationHostRef handle) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  return host->needs_push_properties() ? 1 : 0;
}

int _AnimationHostSupportsScrollAnimations(AnimationHostRef handle) {
  cc::AnimationHost* host = reinterpret_cast<_AnimationHost *>(handle)->handle();
  return host->SupportsScrollAnimations() ? 1 : 0;
}

void _AnimationDestroy(AnimationRef handle) {
  delete reinterpret_cast<_Animation *>(handle);
}

int _AnimationGetId(AnimationRef handle) {
  return reinterpret_cast<_Animation *>(handle)->handle()->id();
}

void _AnimationSetAnimationDelegate(AnimationRef handle, void *peer, CAnimationDelegate delegate) {
  reinterpret_cast<_Animation *>(handle)->set_delegate(peer, delegate);
}

int _AnimationIsElementAttached(AnimationRef handle, uint64_t id) {
  return reinterpret_cast<_Animation *>(handle)->handle()->IsElementAttached(cc::ElementId(id)) == 0 ? false : true;
}

int _AnimationGetElementIdOfKeyframeEffect(AnimationRef handle, uint64_t keyframe_effect_id, uint64_t* elem_id) {
  cc::ElementId id = reinterpret_cast<_Animation *>(handle)->handle()->element_id_of_keyframe_effect(keyframe_effect_id);
  if (id == cc::ElementId(cc::kInvalidElementId)) {
    return 0;
  }
  *elem_id = id.ToInternalValue();
  return 1;
}

AnimationHostRef _AnimationGetAnimationHost(AnimationRef handle) {
  cc::AnimationHost* host = reinterpret_cast<_Animation *>(handle)->handle()->animation_host();
  if (host) {
    // TODO: really stupid allocation, just to return a associated reference
    // given AnimationHost is not ref-counted, we could just deal with 
    // the 'raw' cc::AnimationHost, theres no need for a wrapper who owns the reference
    return new _AnimationHost(host);
  }
  return nullptr;
}

void _AnimationSetAnimationHost(AnimationRef handle, AnimationHostRef host) {
  reinterpret_cast<_Animation *>(handle)->handle()->SetAnimationHost(
    reinterpret_cast<_AnimationHost *>(host)->handle());
}

int _AnimationHasAnimationHost(AnimationRef handle) {
  return reinterpret_cast<_Animation *>(handle)->handle()->has_animation_host() ? 1 : 0;
}

AnimationTimelineRef _AnimationGetAnimationTimeline(AnimationRef handle) {
  // TODO: get rid of stupid allocation
  return new _AnimationTimeline(reinterpret_cast<_Animation *>(handle)->handle()->animation_timeline());
}

void _AnimationSetAnimationTimeline(AnimationRef handle, AnimationTimelineRef timeline) {
  reinterpret_cast<_Animation *>(handle)->handle()->SetAnimationTimeline(reinterpret_cast<_AnimationTimeline *>(timeline)->handle());
}

int _AnimationHasElementAnimations(AnimationRef handle) {
  return reinterpret_cast<_Animation *>(handle)->handle()->has_element_animations() ? 1 : 0;
}

void _AnimationAttachElementForKeyframeEffect(AnimationRef handle, uint64_t element_id, uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->AttachElementForKeyframeEffect(cc::ElementId(element_id), keyframe_effect_id);
}

void _AnimationDetachElementForKeyframeEffect(AnimationRef handle, uint64_t element_id, uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->DetachElementForKeyframeEffect(cc::ElementId(element_id), keyframe_effect_id);
}

void _AnimationDetachElement(AnimationRef handle) {
  reinterpret_cast<_Animation *>(handle)->handle()->DetachElement();
}

void _AnimationAddKeyframeModelForKeyframeEffect(AnimationRef handle, KeyframeModelRef model, uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->AddKeyframeModelForKeyframeEffect(
      std::unique_ptr<cc::KeyframeModel>(reinterpret_cast<cc::KeyframeModel *>(model)),
      cc::KeyframeEffectId(keyframe_effect_id));
}
 
void _AnimationPauseKeyframeModelForKeyframeEffect(AnimationRef handle, 
  int keyframe_model_id, 
  double time_offset, 
  uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->PauseKeyframeModelForKeyframeEffect(
    keyframe_model_id,
    time_offset,
    cc::KeyframeEffectId(keyframe_effect_id));
}

void _AnimationRemoveKeyframeModelForKeyframeEffect(AnimationRef handle, int keyframe_model_id, uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->RemoveKeyframeModelForKeyframeEffect(
      keyframe_model_id,
      cc::KeyframeEffectId(keyframe_effect_id));
}
 
void _AnimationAbortKeyframeModelForKeyframeEffect(AnimationRef handle, int keyframe_model_id, uint64_t keyframe_effect_id) {
  reinterpret_cast<_Animation *>(handle)->handle()->AbortKeyframeModelForKeyframeEffect(
    keyframe_model_id,
    cc::KeyframeEffectId(keyframe_effect_id));
}
 
void _AnimationAbortKeyframeModels(AnimationRef handle, int target_property, int needs_completion) {
  reinterpret_cast<_Animation *>(handle)->handle()->AbortKeyframeModels(
    static_cast<cc::TargetProperty::Type>(target_property),
    needs_completion == 0 ? false : true);
}

void _AnimationPushPropertiesTo(AnimationRef handle, AnimationRef other) {
  reinterpret_cast<_Animation *>(handle)->handle()->PushPropertiesTo(reinterpret_cast<_Animation *>(other)->handle());
}

void _AnimationUpdateState(AnimationRef handle, int start_ready_keyframe_models, AnimationEventsRef events) { 
  reinterpret_cast<_Animation *>(handle)->handle()->UpdateState(start_ready_keyframe_models, reinterpret_cast<cc::AnimationEvents*>(events));
}

void _AnimationTick(AnimationRef handle, int64_t monotonic_time) {
  reinterpret_cast<_Animation *>(handle)->handle()->Tick(base::TimeTicks::FromInternalValue(monotonic_time));
}

void _AnimationAddToTicking(AnimationRef handle) {
  reinterpret_cast<_Animation *>(handle)->handle()->AddToTicking();
}

void _AnimationKeyframeModelRemovedFromTicking(AnimationRef handle) { 
  reinterpret_cast<_Animation *>(handle)->handle()->KeyframeModelRemovedFromTicking();
}

void _AnimationNotifyKeyframeModelStarted(AnimationRef handle, AnimationEventRef event) { 
  reinterpret_cast<_Animation *>(handle)->handle()->NotifyKeyframeModelStarted(*reinterpret_cast<cc::AnimationEvent*>(event));
}

void _AnimationNotifyKeyframeModelFinished(AnimationRef handle, AnimationEventRef event) { 
  reinterpret_cast<_Animation *>(handle)->handle()->NotifyKeyframeModelFinished(*reinterpret_cast<cc::AnimationEvent*>(event));
}

void _AnimationNotifyKeyframeModelAborted(AnimationRef handle, AnimationEventRef event) {
  reinterpret_cast<_Animation *>(handle)->handle()->NotifyKeyframeModelAborted(*reinterpret_cast<cc::AnimationEvent*>(event));
}

void _AnimationNotifyKeyframeModelTakeover(AnimationRef handle, AnimationEventRef event) {
  reinterpret_cast<_Animation *>(handle)->handle()->NotifyKeyframeModelTakeover(*reinterpret_cast<cc::AnimationEvent*>(event));
}

uint64_t _AnimationTickingKeyframeModelsCount(AnimationRef handle) { 
  return reinterpret_cast<_Animation *>(handle)->handle()->TickingKeyframeModelsCount();
}

void _AnimationSetNeedsPushProperties(AnimationRef handle) {
  reinterpret_cast<_Animation *>(handle)->handle()->SetNeedsPushProperties();
}

void _AnimationActivateKeyframeEffects(AnimationRef handle) {
  reinterpret_cast<_Animation *>(handle)->handle()->ActivateKeyframeEffects();
}

KeyframeModelRef _AnimationGetKeyframeModelForKeyframeEffect(
  AnimationRef handle, int target_property, uint64_t keyframe_effect_id) {
  return reinterpret_cast<_Animation *>(handle)->handle()->GetKeyframeModelForKeyframeEffect(
      static_cast<cc::TargetProperty::Type>(target_property),
      static_cast<cc::KeyframeEffectId>(keyframe_effect_id));
}

void _AnimationSetNeedsCommit(AnimationRef handle) {
  reinterpret_cast<_Animation *>(handle)->handle()->SetNeedsCommit();
}

int _AnimationIsWorkletAnimation(AnimationRef handle) {
  return reinterpret_cast<_Animation *>(handle)->handle()->IsWorkletAnimation(); 
}

void _AnimationAddKeyframeEffect(AnimationRef handle, KeyframeEffectRef effect) {
  reinterpret_cast<_Animation *>(handle)->handle()->AddKeyframeEffect(std::unique_ptr<cc::KeyframeEffect>(reinterpret_cast<cc::KeyframeEffect *>(effect)));
}

KeyframeEffectRef _AnimationGetKeyframeEffectById(AnimationRef handle, uint64_t keyframe_effect_id) {
 return reinterpret_cast<_Animation *>(handle)->handle()->GetKeyframeEffectById(keyframe_effect_id);
}

uint64_t _AnimationNextKeyframeEffectId(AnimationRef handle) {
  return reinterpret_cast<_Animation *>(handle)->handle()->NextKeyframeEffectId();
}

AnimationRef _SingleKeyframeEffectAnimationCreate(int id) {
  return new _Animation(cc::SingleKeyframeEffectAnimation::Create(id));
}

uint64_t _SingleKeyframeEffectAnimationGetElementId(AnimationRef handle) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  return anim_handle->element_id().ToInternalValue();
}

//KeyframeEffectRef _SingleKeyframeEffectAnimationGetKeyframeEffect(AnimationRef handle) {
  // we need to use this kind of reference, cause its marked as 'friend class'
  // on SingleKeyframeEffectAnimation so it have access to the private 'GetKeyframeEffect()' method 
//  scoped_refptr<cc::SingleKeyframeEffectAnimation> anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe_ref_counted();
//  return anim_handle->GetKeyframeEffect();
//}

void _SingleKeyframeEffectAnimationAttachElement(AnimationRef handle, uint64_t id) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  return anim_handle->AttachElement(cc::ElementId(id));
}

void _SingleKeyframeEffectAddKeyframeModel(AnimationRef handle, KeyframeModelRef model) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  KeyframeModelHolder* model_ref = reinterpret_cast<KeyframeModelHolder *>(model);
  model_ref->owned = false;
  std::unique_ptr<cc::KeyframeModel> to_move(model_ref->ptr.release());
  anim_handle->AddKeyframeModel(std::move(to_move));
}

void _SingleKeyframeEffectAnimationPauseKeyframeModel(AnimationRef handle, int keyframeModelId, double timeOffset) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  anim_handle->PauseKeyframeModel(keyframeModelId, timeOffset);
}

void _SingleKeyframeEffectAnimationRemoveKeyframeModel(AnimationRef handle, int keyframeModelId) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  anim_handle->RemoveKeyframeModel(keyframeModelId);
}

void _SingleKeyframeEffectAnimationAbortKeyframeModel(AnimationRef handle, int keyframeModelId) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  anim_handle->AbortKeyframeModel(keyframeModelId);
}

KeyframeModelRef _SingleKeyframeEffectAnimationGetKeyframeModel(AnimationRef handle, int target_property) {
  cc::SingleKeyframeEffectAnimation* anim_handle = reinterpret_cast<_Animation *>(handle)->as_single_keyframe();
  return anim_handle->GetKeyframeModel(static_cast<cc::TargetProperty::Type>(target_property));
}

// AnimationTimeline

AnimationTimelineRef _AnimationTimelineCreate(int id) {
  return new _AnimationTimeline(cc::AnimationTimeline::Create(id));
}

void _AnimationTimelineDestroy(AnimationTimelineRef handle) {
  delete reinterpret_cast<_AnimationTimeline *>(handle);
}

void _AnimationTimelineAttachAnimation(AnimationTimelineRef handle, AnimationRef anim) {
  reinterpret_cast<_AnimationTimeline *>(handle)->handle()->AttachAnimation(reinterpret_cast<_Animation *>(anim)->handle_ref_counted());
}

void _AnimationTimelineDetachAnimation(AnimationTimelineRef handle, AnimationRef anim) {
  reinterpret_cast<_AnimationTimeline *>(handle)->handle()->DetachAnimation(reinterpret_cast<_Animation *>(anim)->handle_ref_counted());
}

// // it will route the calls
// class HostFrameSinkClientWrapper : public viz::HostFrameSinkClient {
// public:
//   HostFrameSinkClientWrapper(void* peer, HostFrameSinkClientCallbacks callbacks): 
//     peer_(peer),
//     callbacks_(callbacks) {}

//   ~HostFrameSinkClientWrapper() override {}

//   void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override {
//     callbacks_.OnFirstSurfaceActivation(
//       peer_,
//       surface_info.id().frame_sink_id().client_id(),
//       surface_info.id().frame_sink_id().sink_id(),
//       surface_info.id().local_surface_id().parent_sequence_number(),
//       surface_info.id().local_surface_id().child_sequence_number(),
//       surface_info.id().local_surface_id().embed_token().GetHighForSerialization(),
//       surface_info.id().local_surface_id().embed_token().GetLowForSerialization(),
//       surface_info.device_scale_factor(),
//       surface_info.size_in_pixels().width(),
//       surface_info.size_in_pixels().height());
//   }
  
//   void OnFrameTokenChanged(uint32_t frame_token) override {
//     callbacks_.OnFrameTokenChanged(peer_, frame_token);
//   }

// private:
//   void* peer_;
//   HostFrameSinkClientCallbacks callbacks_;
// };

// class HostFrameSinkManagerWrapper {
// public:
//   HostFrameSinkManagerWrapper(): handle_(std::make_unique<viz::HostFrameSinkManager>()){}
//   ~HostFrameSinkManagerWrapper() {}

//   viz::HostFrameSinkManager* handle() const {
//     return handle_.get();
//   }

//   viz::HostFrameSinkClient* client() const {
//     return client_.get();
//   }

//   void set_client(std::unique_ptr<HostFrameSinkClientWrapper> client) {
//     client_ = std::move(client);
//   }

// private:
//   std::unique_ptr<viz::HostFrameSinkManager> handle_;
//   std::unique_ptr<HostFrameSinkClientWrapper> client_;
// };


LayerTreeFrameSinkRef _LayerTreeFrameSinkCreateDirect(
  uint32_t frame_sink_client_id, 
  uint32_t frame_sink_sink_id, 
  HostFrameSinkManagerRef hostframe_sink_manager,
  FrameSinkManagerRef frame_sink_manager,
  DisplayRef display,
  ContextProviderRef context_provider) {
  
  application::ApplicationThread* deps = application::ApplicationThread::current();

  viz::FrameSinkId frameSinkId(frame_sink_client_id, frame_sink_sink_id);

  _ContextProvider* provider = reinterpret_cast<_ContextProvider *>(context_provider);

  gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager = deps->GetGpuMemoryBufferManager();
  gpu::ImageFactory* image_factory = deps->GetImageFactory();
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner = g_deps.Pointer()->Get()->GetCompositorMainThreadTaskRunner();
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner = g_deps.Pointer()->Get()->GetCompositorImplThreadTaskRunner();
  
  // get the main thread or compositor thread, depending if is single_threaded
  scoped_refptr<base::SingleThreadTaskRunner> task_runner = deps->compositor_helper()->GetCompositorThreadTaskRunner();

  if (!provider->shared_worker_context_provider) {
    provider->shared_worker_context_provider = InProcessContextProvider::CreateOffscreen(
        gpu_memory_buffer_manager, image_factory, true);
  }

  return deps->compositor_helper()->CreateDirectLayerTreeFrameSink(// new viz::DirectLayerTreeFrameSink(
    frameSinkId,
    reinterpret_cast<HostFrameSinkManagerWrapper *>(hostframe_sink_manager)->handle(),
    reinterpret_cast<FrameSinkManagerImplWrapper *>(frame_sink_manager)->handle(),
    reinterpret_cast<viz::Display *>(display),
    //nullptr /*display_client*/,
    provider->handle,
    provider->shared_worker_context_provider,
    task_runner,
    gpu_memory_buffer_manager);
}

void _LayerTreeFrameSinkDestroy(LayerTreeFrameSinkRef handle) {
  delete reinterpret_cast<cc::LayerTreeFrameSink *>(handle);
}


HostFrameSinkManagerRef _HostFrameSinkManagerCreate() {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  return deps->compositor_helper()->CreateHostFrameSinkManagerWrapper();
  //return new HostFrameSinkManagerWrapper();
}

void _HostFrameSinkManagerDestroy(HostFrameSinkManagerRef reference) {
  delete reinterpret_cast<HostFrameSinkManagerWrapper *>(reference);
}
  
void _HostFrameSinkManagerRegisterFrameSinkId(HostFrameSinkManagerRef reference, uint32_t clientId, uint32_t sinkId, void* clientPtr, struct HostFrameSinkClientCallbacks clientCbs) {
  viz::FrameSinkId frameSinkId(clientId, sinkId);
  std::unique_ptr<HostFrameSinkClientWrapper> client_wrapper(new HostFrameSinkClientWrapper(clientPtr, clientCbs));

  HostFrameSinkManagerWrapper* manager = reinterpret_cast<HostFrameSinkManagerWrapper *>(reference);
  manager->set_client(std::move(client_wrapper));
  manager->RegisterFrameSinkId(frameSinkId);
}
 
void _HostFrameSinkManagerSetFrameSinkDebugLabel(HostFrameSinkManagerRef reference, uint32_t clientId, uint32_t sinkId, const char* labelCstr) {
  viz::FrameSinkId frameSinkId(clientId, sinkId);
  std::string debug_label(labelCstr);
  reinterpret_cast<HostFrameSinkManagerWrapper *>(reference)->SetFrameSinkDebugLabel(frameSinkId, debug_label);
}

 
int _HostFrameSinkManagerRegisterFrameSinkHierarchy(
      HostFrameSinkManagerRef reference, 
      uint32_t parentClientId, uint32_t parentSinkId,
      uint32_t childClientId, uint32_t childSinkId) {
  viz::FrameSinkId parentFrameSinkId(parentClientId, parentSinkId);
  viz::FrameSinkId childFrameSinkId(childClientId, childSinkId);       
  return reinterpret_cast<HostFrameSinkManagerWrapper *>(reference)->RegisterFrameSinkHierarchy(parentFrameSinkId, childFrameSinkId);
}

void _HostFrameSinkManagerUnregisterFrameSinkHierarchy(
        HostFrameSinkManagerRef reference, 
        uint32_t parentClientId, uint32_t parentSinkId,
        uint32_t childClientId, uint32_t childSinkId) {
  viz::FrameSinkId parentFrameSinkId(parentClientId, parentSinkId);
  viz::FrameSinkId childFrameSinkId(childClientId, childSinkId);
  reinterpret_cast<HostFrameSinkManagerWrapper *>(reference)->UnregisterFrameSinkHierarchy(parentFrameSinkId, childFrameSinkId);
}
  
void _HostFrameSinkManagerInvalidateFrameSinkId(
        HostFrameSinkManagerRef reference, 
        uint32_t clientId, uint32_t sinkId) {
 viz::FrameSinkId frameSinkId(clientId, sinkId);
 reinterpret_cast<HostFrameSinkManagerWrapper *>(reference)->InvalidateFrameSinkId(frameSinkId);
}

void _HostFrameSinkManagerSetLocalManager(HostFrameSinkManagerRef reference, FrameSinkManagerRef frameSinkManager) {
  reinterpret_cast<HostFrameSinkManagerWrapper *>(reference)->SetLocalManager(reinterpret_cast<FrameSinkManagerImplWrapper *>(frameSinkManager)->handle()); 
}

FrameSinkManagerRef _FrameSinkManagerImplCreate() {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  return deps->compositor_helper()->CreateFrameSinkManagerImpl();
}

void _FrameSinkManagerImplDestroy(FrameSinkManagerRef reference) {
  delete reinterpret_cast<FrameSinkManagerImplWrapper *>(reference);
}

void _FrameSinkManagerImplRegisterBeginFrameSource(FrameSinkManagerRef reference, BeginFrameSourceRef begin_frame, uint32_t clientId, uint32_t sinkId) {
  viz::FrameSinkId frameSinkId(clientId, sinkId);
  reinterpret_cast<FrameSinkManagerImplWrapper *>(reference)->RegisterBeginFrameSource(reinterpret_cast<viz::BeginFrameSource *>(begin_frame), frameSinkId);
}

void _FrameSinkManagerImplSetLocalClient(FrameSinkManagerRef reference, HostFrameSinkManagerRef hostFrameReference) {
   reinterpret_cast<FrameSinkManagerImplWrapper *>(reference)->SetLocalClient(reinterpret_cast<HostFrameSinkManagerWrapper *>(hostFrameReference));
}

BeginFrameSourceRef _BeginFrameSourceCreateDelayBased(int64_t microseconds) {
  //scoped_refptr<base::SingleThreadTaskRunner> task_runner = g_deps.Pointer()->Get()->GetCompositorImplThreadTaskRunner();
  // get the main thread or compositor thread, depending if is single_threaded
  application::ApplicationThread* deps = application::ApplicationThread::current();
  scoped_refptr<base::SingleThreadTaskRunner> task_runner = deps->compositor_helper()->GetCompositorThreadTaskRunner();

  DCHECK(task_runner);
  std::unique_ptr<viz::DelayBasedTimeSource> time_source(new viz::DelayBasedTimeSource(task_runner.get()));
  time_source->SetTimebaseAndInterval(base::TimeTicks(),
                                      base::TimeDelta::FromMicroseconds(microseconds));
  return new viz::DelayBasedBeginFrameSource(std::move(time_source), viz::BeginFrameSource::kNotRestartableId);
}

BeginFrameSourceRef _BeginFrameSourceCreateBackToBack() {
  application::ApplicationThread* deps = application::ApplicationThread::current();
//  scoped_refptr<base::SingleThreadTaskRunner> task_runner = g_deps.Pointer()->Get()->GetCompositorImplThreadTaskRunner();
  // get the main thread or compositor thread, depending if is single_threaded
  scoped_refptr<base::SingleThreadTaskRunner> task_runner = deps->compositor_helper()->GetCompositorThreadTaskRunner();

  DCHECK(task_runner);
  std::unique_ptr<viz::DelayBasedTimeSource> time_source(new viz::DelayBasedTimeSource(task_runner.get()));
  return new viz::BackToBackBeginFrameSource(std::move(time_source));
}

void _BeginFrameSourceDestroy(BeginFrameSourceRef reference) {
  delete reinterpret_cast<viz::BeginFrameSource *>(reference);
}

DisplayRef _DisplayCreate(uint32_t clientId, uint32_t sinkId, OutputSurfaceRef output_surface, BeginFrameSourceRef begin_frame) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  viz::FrameSinkId frameSinkId(clientId, sinkId);
  viz::RendererSettings renderer_settings;
  viz::BeginFrameSource* beginFrameSource = reinterpret_cast<viz::BeginFrameSource *>(begin_frame);

  DirectOutputSurface* surface_handle = reinterpret_cast<DirectOutputSurface *>(output_surface);

  std::unique_ptr<DirectOutputSurface> display_output_surface(surface_handle);

  //scoped_refptr<base::SingleThreadTaskRunner> task_runner = g_deps.Pointer()->Get()->GetCompositorImplThreadTaskRunner(); // base::ThreadTaskRunnerHandle::Get();
  // get the main thread or compositor thread, depending if is single_threaded
  scoped_refptr<base::SingleThreadTaskRunner> task_runner = deps->compositor_helper()->GetCompositorThreadTaskRunner();
  
  viz::SharedBitmapManager* shared_bitmap_manager = deps->GetSharedBitmapManager();

  auto scheduler = std::make_unique<viz::DisplayScheduler>(
      beginFrameSource, task_runner.get(),
      display_output_surface->capabilities().max_frames_pending);

  return new viz::Display( // g_deps.Pointer()->Get()->CreateDisplay(
      shared_bitmap_manager, renderer_settings, frameSinkId,
      std::move(display_output_surface), std::move(scheduler),
      task_runner);
}

void _DisplayDestroy(DisplayRef reference) {
  delete reinterpret_cast<viz::Display *>(reference);
}

void _DisplaySetVisible(DisplayRef reference, int visible) {
  reinterpret_cast<viz::Display *>(reference)->SetVisible(visible == 0 ? false : true);
}

void _DisplayResize(DisplayRef reference, int w, int h) {
  gfx::Size size(w, h);
  reinterpret_cast<viz::Display *>(reference)->Resize(size);
}

void _DisplaySetColorMatrix(DisplayRef reference, Matrix44Ref mat) {
  reinterpret_cast<viz::Display *>(reference)->SetColorMatrix(*reinterpret_cast<SkMatrix44 *>(mat));
}

void _DisplaySetColorSpace(DisplayRef reference, int blending_type, int device_type) {
   if (blending_type == 0 && device_type == 0) {
     gfx::ColorSpace blending_cs = gfx::ColorSpace::CreateSRGB();
     gfx::ColorSpace device_cs = gfx::ColorSpace::CreateSRGB();
     reinterpret_cast<viz::Display *>(reference)->SetColorSpace(blending_cs, device_cs);
   } else {
     LOG(ERROR) << "color space for type blending = " << blending_type << " and device = " << device_type << " not known. ColorSpace on Display was not changed";
   }
}

#if defined(OS_LINUX)
XID _GpuSurfaceTrackerAddSurfaceNativeWidget(XID widget) {
#if defined(OS_ANDROID)
  gpu::GpuSurfaceTracker* tracker = gpu::GpuSurfaceTracker::Get();
  XID surface_handle = tracker->AddSurfaceForNativeWidget(
        gpu::GpuSurfaceTracker::SurfaceRecord(
            widget
//#if defined(OS_ANDROID)
            // We have to provide a surface too, but we don't have one.  For
            // now, we don't proide it, since nobody should ask anyway.
            // If we ever provide a valid surface here, then GpuSurfaceTracker
            // can be more strict about enforcing it.
            ,
            nullptr
//#endif
            ));
  return surface_handle;
#else
  return widget;
#endif
  
}
#elif defined(OS_WIN)
HWND _GpuSurfaceTrackerAddSurfaceNativeWidget(HWND widget) {
  return widget;
}
#endif

class InProcessContextProviderState {
public:
 scoped_refptr<InProcessContextProvider> handle;

  InProcessContextProviderState(scoped_refptr<InProcessContextProvider> ref):
   handle(ref) {}
  ~InProcessContextProviderState() {}
};


InProcessContextProviderRef InProcessContextProviderCreate(
#if defined(OS_LINUX)
  XID window,
#elif defined(OS_WIN)
  HWND window,
#endif
  int32_t alpha_size, 
  int32_t blue_size, 
  int32_t green_size, 
  int32_t red_size, 
  int32_t depth_size, 
  int32_t stencil_size, 
  int32_t samples, 
  int32_t sample_buffers) {

  application::ApplicationThread* deps = application::ApplicationThread::current();
  
  gpu::ContextCreationAttribs attribs;
  attribs.alpha_size = alpha_size;
  attribs.blue_size = blue_size;
  attribs.green_size = green_size;
  attribs.red_size = red_size;
  attribs.depth_size = depth_size;
  attribs.stencil_size = stencil_size;
  attribs.samples = samples;
  attribs.sample_buffers = sample_buffers;
  attribs.fail_if_major_perf_caveat = false;
  attribs.bind_generates_resource = false;

  gpu::ImageFactory* image_factory = deps->GetImageFactory();
  gpu::GpuMemoryBufferManager* buffer_manager = deps->GetGpuMemoryBufferManager();
  
  scoped_refptr<InProcessContextProvider> handle = InProcessContextProvider::Create(
    attribs,
    buffer_manager,
    image_factory,
    window,
    "UICompositor",
    false);

  return new InProcessContextProviderState(handle);
}

InProcessContextProviderRef InProcessContextProviderCreateOffscreen(
  #if defined(OS_LINUX)
  XID window
#elif defined(OS_WIN)
  HWND window
#endif
) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  gpu::ImageFactory* image_factory = deps->GetImageFactory();
  gpu::GpuMemoryBufferManager* buffer_manager = deps->GetGpuMemoryBufferManager();

  scoped_refptr<InProcessContextProvider> handle = InProcessContextProvider::CreateOffscreen(
    buffer_manager,
    image_factory,
    false);

  return new InProcessContextProviderState(handle);
}

void InProcessContextProviderDestroy(InProcessContextProviderRef provider) {
  delete reinterpret_cast<InProcessContextProviderState *>(provider);
}

void InProcessContextProviderBindToCurrentThread(InProcessContextProviderRef provider) {
  reinterpret_cast<InProcessContextProviderState *>(provider)->handle->BindToCurrentThread();
}

CopyOutputRequestRef _CopyOutputRequestCreateWithBitmapRequest(void* state, LayerTreeHostRef tree, void(*callback)(void*, BitmapRef)) {
  application::ApplicationThread* deps = application::ApplicationThread::current();
  std::unique_ptr<viz::CopyOutputRequest> handle = deps->compositor_helper()->CreateCopyOutputRequestWithBitmapRequest(
    state,
    reinterpret_cast<_LayerTreeHost *>(tree)->handle.get(),
    callback);
  return new _opyOutputRequest(std::move(handle));
}

void _CopyOutputRequestDestroy(CopyOutputRequestRef reference) {
  delete reinterpret_cast<_opyOutputRequest *>(reference);
}

SwapPromiseRef _SwapPromiseCreateLatency(
  LayerTreeHostRef layer_tree_host,
  int64_t trace_id,
  const char* trace_name,
  int64_t ukm_source_id,
  int coalesced,
  int began,
  int terminated,
  int source_event_type,
  float scroll_update_delta,
  float pred_scroll_update_delta,
  int component_count,
  const int* typearr,
  const int64_t* evtarr) {//,
  //void* state, 
  //void(*cb)(void*, int, int, double)) {

  ui::LatencyInfo latency_info(trace_id, terminated != 0);
  latency_info.set_source_event_type(static_cast<ui::SourceEventType>(source_event_type));
  latency_info.set_trace_id(trace_id);
  latency_info.set_ukm_source_id(ukm_source_id);
  if (coalesced == 1) {
    latency_info.set_coalesced();
  }

  latency_info.set_scroll_update_delta(scroll_update_delta);
  latency_info.set_predicted_scroll_update_delta(pred_scroll_update_delta);
  
  for (int i = 0; i < component_count; i++) {
    latency_info.AddLatencyNumberWithTimestamp(
      static_cast<ui::LatencyComponentType>(typearr[i]),
      base::TimeTicks::FromInternalValue(evtarr[i]));
  }

  return _SwapPromise::CreateLatency(latency_info);
}

SwapPromiseRef _SwapPromiseCreateAlwaysDraw(
        LayerTreeHostRef layer_tree_host,
        int64_t trace_id,
        const char* trace_name,
        int64_t ukm_source_id,
        int coalesced,
        int began,
        int terminated,
        int source_event_type,
        float scroll_update_delta,
        float pred_scroll_update_delta,
        int component_count,
        const int* typearr,
        const int64_t* evtarr,
        void* state, 
        void(*cb)(void*, int, int, double)) {
  ui::LatencyInfo latency_info(trace_id, terminated != 0);
  latency_info.set_source_event_type(static_cast<ui::SourceEventType>(source_event_type));
  latency_info.set_trace_id(trace_id);
  latency_info.set_ukm_source_id(ukm_source_id);
  if (coalesced == 1) {
    latency_info.set_coalesced();
  }

  latency_info.set_scroll_update_delta(scroll_update_delta);
  latency_info.set_predicted_scroll_update_delta(pred_scroll_update_delta);
  
  for (int i = 0; i < component_count; i++) {
    latency_info.AddLatencyNumberWithTimestamp(
      static_cast<ui::LatencyComponentType>(typearr[i]),
      base::TimeTicks::FromInternalValue(evtarr[i]));
  }
  

  return _SwapPromise::CreateAlwaysDraw(
    std::move(latency_info),
    state,
    cb,
    reinterpret_cast<_LayerTreeHost *>(layer_tree_host)->handle->GetTaskRunnerProvider()->MainThreadTaskRunner());
}

SwapPromiseRef _SwapPromiseCreateReportTime(
  LayerTreeHostRef layer_tree_host, void* state) {
  return _SwapPromise::CreateReportTime(
    state, 
    reinterpret_cast<_LayerTreeHost *>(layer_tree_host)->handle->GetTaskRunnerProvider()->MainThreadTaskRunner());
}

void _SwapPromiseDestroy(SwapPromiseRef ref) {
  delete reinterpret_cast<_SwapPromise *>(ref); 
}

// we need this or we will have a lifetime problem with
// the pointer to the latency info the monitor uses

struct _LatencyInfoSwapPromiseMonitor {
  ui::LatencyInfo latency_info;
  std::unique_ptr<LatencyInfoSwapPromiseMonitor> handle;

  _LatencyInfoSwapPromiseMonitor(
    ui::LatencyInfo latency,
    std::unique_ptr<LatencyInfoSwapPromiseMonitor> ptr): 
     latency_info(std::move(latency)),
     handle(std::move(ptr)) {}

  _LatencyInfoSwapPromiseMonitor(
    ui::LatencyInfo latency): 
     latency_info(std::move(latency)) {}
};

SwapPromiseMonitorRef _SwapPromiseMonitorCreateLatency(
    LayerTreeHostRef layer_tree_host,
    int64_t trace_id,
    const char* trace_name,
    int64_t ukm_source_id,
    int coalesced,
    int began,
    int terminated,
    int source_event_type,
    float scroll_update_delta,
    float pred_scroll_update_delta,
    int component_count,
    const int* typearr,
    const int64_t* evtarr) {
  ui::LatencyInfo latency_info(trace_id, terminated != 0);
  latency_info.set_source_event_type(static_cast<ui::SourceEventType>(source_event_type));
  latency_info.set_trace_id(trace_id);
  latency_info.set_ukm_source_id(ukm_source_id);
  if (coalesced == 1) {
    latency_info.set_coalesced();
  }
  latency_info.set_scroll_update_delta(scroll_update_delta);
  latency_info.set_predicted_scroll_update_delta(pred_scroll_update_delta);
  
  for (int i = 0; i < component_count; i++) {
    latency_info.AddLatencyNumberWithTimestamp(
      static_cast<ui::LatencyComponentType>(typearr[i]),
      base::TimeTicks::FromInternalValue(evtarr[i]));
  }

  _LatencyInfoSwapPromiseMonitor* result = new _LatencyInfoSwapPromiseMonitor(std::move(latency_info));

  result->handle = std::make_unique<LatencyInfoSwapPromiseMonitor>(
    &result->latency_info,
    reinterpret_cast<_LayerTreeHost *>(layer_tree_host)->handle->GetSwapPromiseManager(),
    nullptr);

  return result;
}

void _SwapPromiseMonitorDestroy(SwapPromiseMonitorRef ref) {
  delete reinterpret_cast<_LatencyInfoSwapPromiseMonitor*>(ref);
}