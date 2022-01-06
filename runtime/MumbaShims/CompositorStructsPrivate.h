// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_COMPOSITOR_STRUCTS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_COMPOSITOR_STRUCTS_H_

#include <stdlib.h>

#include "Globals.h"
#include "CompositorCallbacks.h"
#include "CompositorFrameSinkCallbacks.h"
#include "SkiaShims.h"
#include "CompositorShims.h"
#include "CompositorHelper.h"
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
#include "cc/layers/video_layer.h"
#include "cc/layers/texture_layer.h"
#include "cc/layers/texture_layer_client.h"
#include "cc/paint/paint_shader.h"
#include "cc/paint/paint_recorder.h"
#include "cc/paint/paint_image_builder.h"
#include "cc/paint/filter_operations.h"
#include "cc/paint/filter_operation.h"
#include "cc/trees/latency_info_swap_promise_monitor.h"
#include "gpu/ipc/common/gpu_surface_tracker.h"
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
//#include "ui/gl/gl_surface.h"
//#include "ui/gl/gl_context_glx.h"
//#include "ui/gl/gl_image_glx.h"
//#include "ui/gl/gl_surface_glx.h"
//#include "ui/gl/gl_share_group.h"
//#include "ui/gl/init/gl_factory.h"
//#include "ui/gl/gl_implementation.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/skia/include/core/SkRefCnt.h"
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
#include "third_party/skia/include/core/SkPictureRecorder.h"
#include "third_party/skia/include/gpu/gl/GrGLInterface.h"
#include "third_party/skia/include/effects/SkBlurDrawLooper.h"
#include "third_party/skia/include/effects/SkLayerDrawLooper.h"
#include "third_party/skia/include/effects/SkBlurMaskFilter.h"
#include "third_party/skia/include/core/SkDrawable.h"
#include "third_party/skia/src/core/SkXfermodePriv.h"
#include "third_party/blink/public/platform/web_layer.h"
#include "third_party/blink/public/platform/web_layer_tree_view.h"

struct _LayerTreeHost {
 std::unique_ptr<cc::LayerTreeHost> handle;
 cc::LayerTreeHost* raw;
 std::unique_ptr<CompositorLayerTreeHostClient> client;
 bool owned;
 CLayerTreeHostRequestPresentationCallback request_presentation_callback;
 void* request_presentation_state;

 _LayerTreeHost(std::unique_ptr<cc::LayerTreeHost> ptr, std::unique_ptr<CompositorLayerTreeHostClient> cli):
    handle(std::move(ptr)),
    client(std::move(cli)),
    owned(true),
    request_presentation_callback(nullptr),
    request_presentation_state(nullptr) {}

 _LayerTreeHost(cc::LayerTreeHost* ptr): raw(ptr), owned(false), request_presentation_callback(nullptr), request_presentation_state(nullptr) {}

 void OnRequestPresentation(base::TimeTicks a, base::TimeDelta b, uint32_t c) {
   //DLOG(INFO) << "\n\n _LayerTreeHost::OnRequestPresentation: callback? " << request_presentation_callback << " \n\n";
   if (request_presentation_callback) {
     request_presentation_callback(request_presentation_state, a.ToInternalValue(), b.InMilliseconds(), c);
   }
 }

};

class _TextureLayerClientImpl;

class _LayerAnimationDelegate;

class _LayerClientImpl;

class _DisplayItemList {
public:
  _DisplayItemList(scoped_refptr<cc::DisplayItemList> handle, bool avoid_meta_ops = false);
  _DisplayItemList(cc::DisplayItemList* handle, bool avoid_meta_ops = false);
  _DisplayItemList(cc::PaintRecorder* paint_recorder, bool avoid_meta_ops = true);
  _DisplayItemList(cc::PaintCanvas* canvas, bool avoid_meta_ops = true);
  _DisplayItemList();
  ~_DisplayItemList();

  cc::DisplayItemList& handle();
  bool has_canvas();
  cc::RecordPaintCanvas& canvas();
  int TotalOpCount();
  void StartPaint();
  void EndPaintOfPairedBegin();
  void EndPaintOfPairedBegin(gfx::Rect& rect);
  void EndPaintOfPairedEnd();
  void EndPaintOfUnpaired(gfx::Rect& rect);
  void Finalize();
  sk_sp<cc::PaintRecord> ReleaseAsRecord();
  void ClipPath(const SkPath& path, SkClipOp op, bool antialias);
  void ClipRect(const SkRect& rect, SkClipOp op, bool antialias);
  void ClipRRect(const SkRRect& rrect, SkClipOp op, bool antialias);
  void Concat(const SkMatrix& matrix);
  void RecordCustomData(uint32_t id);
  void DrawColor(SkColor color, SkBlendMode blend_mode);
  void DrawDRRect(const SkRRect& outer,
                  const SkRRect& inner,
                  const cc::PaintFlags& flags);
  void DrawImage(const cc::PaintImage& image,
                 SkScalar left,
                 SkScalar top,
                 const cc::PaintFlags* flags);
  void DrawImageRect(const cc::PaintImage& image,
                     const SkRect& src,
                     const SkRect& dst,
                     const cc::PaintFlags* flags,
                     cc::PaintCanvas::SrcRectConstraint constraint);
  void DrawBitmap(const SkBitmap& bitmap,
                  SkScalar left,
                  SkScalar top,
                  const cc::PaintFlags* flags);
  void DrawIRect(const SkIRect& rect, const cc::PaintFlags& flags);
  void DrawLine(SkScalar x0,
                SkScalar y0,
                SkScalar x1,
                SkScalar y1,
                const cc::PaintFlags& flags);
  void DrawOval(const SkRect& oval, const cc::PaintFlags& flags);
  void DrawPath(const SkPath& path, const cc::PaintFlags& flags);
  void DrawRecord(sk_sp<const cc::PaintRecord> record);
  void DrawRect(const SkRect& rect, const cc::PaintFlags& flags);
  void DrawRRect(const SkRRect& rrect, const cc::PaintFlags& flags);
  void DrawTextBlob(const scoped_refptr<cc::PaintTextBlob>& blob,
                    SkScalar x,
                    SkScalar y,
                    const cc::PaintFlags& flags);
  void Noop();
  void Restore();
  void Rotate(SkScalar degrees);
  void Save();
  void SaveLayer(const SkRect* bounds, const cc::PaintFlags* flags);
  void SaveLayerAlpha(
    const SkRect* bounds,
    uint8_t alpha,
    bool preserve_lcd_text_requests);
  void Scale(SkScalar sx, SkScalar sy);
  void SetMatrix(const SkMatrix& matrix);
  void Translate(SkScalar dx, SkScalar dy);

private:
  friend class _LayerClientImpl;
  
  // bool flags_was_set_;
  
  // cc::PaintFlags flags_;
  // cc::PaintFlags no_flags_;
  base::Lock canvas_lock_;
  base::Lock display_item_lock_;
  cc::RecordPaintCanvas* canvas_;
  scoped_refptr<cc::DisplayItemList> handle_;
  cc::DisplayItemList* ptr_;
  bool avoid_meta_ops_;

  DISALLOW_COPY_AND_ASSIGN(_DisplayItemList);
};

class _LayerClientImpl : public cc::ContentLayerClient,
                         public cc::TextureLayerClient {
public:
  _LayerClientImpl(void* client, int layer_id, CLayerClientCallbacks cbs):
   texture_client_(nullptr) {
    callbacks_.paintContentsToDisplayList = cbs.paintContentsToDisplayList;
    callbacks_.paintableRegion = cbs.paintableRegion;
    callbacks_.prepareTransferableResource = cbs.prepareTransferableResource;
    callbacks_.fillsBoundsCompletely = cbs.fillsBoundsCompletely;
    callbacks_.getApproximateUnsharedMemoryUsage = cbs.getApproximateUnsharedMemoryUsage;
    client_ = client;
    layer_id_ = layer_id;
  }
  ~_LayerClientImpl() override {}

  void set_texture_client(cc::TextureLayerClient* texture_client) {
    texture_client_ = texture_client;
  }

  // scoped_refptr<cc::DisplayItemList> PaintContentsToDisplayList(
  //     cc::ContentLayerClient::PaintingControlSetting painting_status) override {
  //     //gfx::Rect local_bounds(bounds().size());
  //     //gfx::Rect invalidation(
  //     //  gfx::IntersectRects(damaged_region_.bounds(), local_bounds));
  //     //DCHECK(clip.Contains(invalidation));
  //     cc::DisplayItemListSettings settings;
  //     settings.use_cached_picture = false;
  //     scoped_refptr<cc::DisplayItemList> display_list = cc::DisplayItemList::Create(clip, settings);

  //       callbacks_.paintLayer(client_, display_list.get(), clip.x(), clip.y(), clip.width(), clip.height(),
  //         PaintingControlSettingToInt(painting_status));

  //     display_list->Finalize();
  //     return display_list;
  // }

   scoped_refptr<cc::DisplayItemList> PaintContentsToDisplayList(
       cc::ContentLayerClient::PaintingControlSetting painting_status) override {
     //gfx::Rect local_bounds(bounds().size());
     //gfx::Rect invalidation(
     //  gfx::IntersectRects(paint_region_.bounds(), local_bounds));
     //paint_region_.Clear();
     //scoped_refptr<cc::DisplayItemList> handle = base::MakeRefCounted<cc::DisplayItemList>();
     //_DisplayItemList* display_list = new _DisplayItemList();
     //display_list->handle_ = handle;
     // if (delegate_) {
     //   delegate_->OnPaintLayer(PaintContext(display_list.get(),
     //                                        device_scale_factor_, invalidation,
     //                                        GetCompositor()->is_pixel_canvas()));
     // }
    
     _DisplayItemList* display_list = 
       reinterpret_cast<_DisplayItemList*>(callbacks_.paintContentsToDisplayList(client_, PaintingControlSettingToInt(painting_status)));

     // TODO: checar se usa cache no código
     //       senão temos que finalizer aqui

     //handle->Finalize();
     scoped_refptr<cc::DisplayItemList> handle = display_list->handle_;
    
     // for (const auto& mirror : mirrors_)
     //   mirror->dest()->SchedulePaint(invalidation);
   
     delete display_list;

//     //DLOG(INFO) << "DEVOLVENDO uma DisplayList com um totalOpCount = " << handle->TotalOpCount();
    
     return handle;
   }

  // scoped_refptr<cc::DisplayItemList> PaintContentsToDisplayList(
  //     cc::ContentLayerClient::PaintingControlSetting painting_status) override {
    
  //   if (layer_id_ == 1) {
  //     auto list = base::MakeRefCounted<cc::DisplayItemList>();
  //     gfx::Point offset(8, 9);
  //     gfx::Rect layer_rect(100, 100);
  //     cc::PaintFlags blue_flags;
  //     blue_flags.setColor(SK_olorBLUE);
  //     cc::PaintFlags red_paint;
  //     red_paint.setColor(SK_olorRED);
  

  //     list->StartPaint();
  //     list->push<cc::SaveOp>();
  //     list->push<cc::TranslateOp>(static_cast<float>(offset.x()),
  //                         static_cast<float>(offset.y()));
  //     list->push<cc::DrawRectOp>(SkRect::MakeLTRB(0.f, 0.f, 60.f, 60.f), red_paint);
  //     list->push<cc::DrawRectOp>(SkRect::MakeLTRB(50.f, 50.f, 75.f, 75.f), blue_flags);
  //     list->push<cc::RestoreOp>();
  //     list->EndPaintOfUnpaired(gfx::Rect(offset, layer_rect.size()));
  //     list->Finalize();

  //     return list;
  //   } else {
  //     return PaintContentsToDisplayListInternal(painting_status);
  //   }
  // }

  gfx::Rect PaintableRegion() override {
    int x = 0, y = 0, w = 0, h = 0;
    callbacks_.paintableRegion(client_, &x, &y, &w, &h);
    return gfx::Rect(x, y, w, h);
  }

  // If true the layer may skip clearing the background before rasterizing,
  // because it will cover any uncleared data with content.
  bool FillsBoundsCompletely() const override {
    return callbacks_.fillsBoundsCompletely(client_) ? true : false;
  }

  // Returns an estimate of the current memory usage within this object,
  // excluding memory shared with painting artifacts (i.e.,
  // DisplayItemList). Should be invoked after PaintContentsToDisplayList,
  // so that the result includes data cached internally during painting.
  size_t GetApproximateUnsharedMemoryUsage() const override {
    return callbacks_.getApproximateUnsharedMemoryUsage(client_);
  }

  // bool PrepareTextureMailbox(
  //     cc::TextureMailbox* mailbox,
  //     std::unique_ptr<cc::SingleReleaseCallback>* release_callback,
  //     bool use_shared_memory) override {
  //   return callbacks_.prepareTextureMailbox(client_) ? true : false;
  // }

  bool PrepareTransferableResource(
      cc::SharedBitmapIdRegistrar* bitmap_registar,
      viz::TransferableResource* transferable_resource,
      std::unique_ptr<viz::SingleReleaseCallback>* release_callback) override {
    //DLOG(INFO) << "\n\nPrepareTransferableResource";
    // if theres a secondary client registered, fallback to it
    if (texture_client_) {
      //DLOG(INFO) << "PrepareTransferableResource: texture_client_ from canvas is here";
      return texture_client_->PrepareTransferableResource(bitmap_registar, transferable_resource, release_callback);
    }
    //DLOG(INFO) << "PrepareTransferableResource: NO texture_client_ from canvas.";
    return callbacks_.prepareTransferableResource(client_, bitmap_registar, transferable_resource, release_callback) ? true : false;
  }

private:
  void* client_;
  int layer_id_;
  cc::TextureLayerClient* texture_client_;
  CLayerClientCallbacks callbacks_;
  DISALLOW_COPY_AND_ASSIGN(_LayerClientImpl);
};


class _Layer {
public:
 scoped_refptr<cc::Layer> handle;

 _Layer(int64_t type,
    _LayerClientImpl* cclient)://,
    //bool isdefault):
   content_client_(cclient),
   type_(type),
   owned_(false){
     //create_layer(isdefault);
   }

 _Layer(cc::Layer* ptr,
        int64_t type,
     _LayerClientImpl* cclient):
    raw_(ptr),
    content_client_(cclient),
    type_(type),
    owned_(false){
  }

_Layer(cc::Layer* ptr): raw_(ptr), type_(-1), owned_(false) {}

 int type() const { return type_; }
 cc::Layer* layer() const { return owned_? handle.get() : raw_; }
 bool owned() const { return owned_; }
 void set_owned(bool owned) { owned_ = owned; }
 void own_animation_delegate(_LayerAnimationDelegate* delegate) { animation_delegate_.reset(delegate); }
 _LayerClientImpl* layer_client() const {
  return content_client_.get();
 }
 void set_client(_LayerClientImpl* cclient) {
   content_client_.reset(cclient);
 }

 void create_layer(bool isdefault) {
  //cc::LayerSettings settings;
  if (isdefault) {
    //DLOG(INFO) << "creating default layer";
    handle = cc::Layer::Create();
    DCHECK(handle.get());
  } else {
    //DLOG(INFO) << "creating layer for type " << type_;
    if (type_ == 0) {
      handle = cc::SolidColorLayer::Create();
      DCHECK(handle.get());
    } else if (type_ == 1) {
      handle = cc::NinePatchLayer::Create();
      DCHECK(handle.get());
    } else if (type_ == 2) {
      DCHECK(content_client_);
      handle = cc::PictureLayer::Create(content_client_.get());
      DCHECK(handle.get());
    } else if (type_ == 3) {
      //DLOG(INFO) << "creating texture layer..";
      handle = cc::TextureLayer::CreateForMailbox(content_client_.get());
      DCHECK(handle.get());
    } else if (type_ == 4) {
      handle = cc::SurfaceLayer::Create();
      DCHECK(handle.get());
    } else if (type_ == 5){
      DCHECK(false);
      //handle = cc::VideoLayer::Create();
    } else { // fallback to picture layer
      DCHECK(content_client_);
      handle = cc::PictureLayer::Create(content_client_.get());
      DCHECK(handle.get());
    }
  }
  owned_ = true;
 }

private:

 cc::Layer* raw_;
 std::unique_ptr<_LayerClientImpl> content_client_;
 std::unique_ptr<_LayerAnimationDelegate> animation_delegate_;
 int64_t type_;
 bool owned_;

private:
  DISALLOW_COPY_AND_ASSIGN(_Layer);
};

class _AnimationHost {
public:
 _AnimationHost(cc::AnimationHost* ptr): handle_(ptr), owned_(false) {}
 _AnimationHost(std::unique_ptr<cc::AnimationHost> ptr): owned_handle_(std::move(ptr)), handle_(nullptr), owned_(true) {}
 bool owned() const { return owned_; }
 cc::AnimationHost* handle() const {
   return owned_ ? owned_handle_.get() : handle_;
 }

 std::unique_ptr<cc::AnimationHost> owned_handle_;

private:
  cc::AnimationHost* handle_;
  bool owned_;
};

class _AnimationDelegate : public cc::AnimationDelegate {
public:
  _AnimationDelegate(void* peer, CAnimationDelegate delegate): peer_(peer), delegate_(delegate) {}
  ~_AnimationDelegate() {}

  void NotifyAnimationStarted(base::TimeTicks monotonic_time,
                              int target_property,
                              int group) override {
    delegate_.NotifyAnimationStarted(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }

  void NotifyAnimationFinished(base::TimeTicks monotonic_time,
                               int target_property,
                               int group) override {
    delegate_.NotifyAnimationFinished(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }

  void NotifyAnimationAborted(base::TimeTicks monotonic_time,
                              int target_property,
                              int group) override {

    delegate_.NotifyAnimationAborted(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }
  
  void NotifyAnimationTakeover(
      base::TimeTicks monotonic_time,
      int target_property,
      base::TimeTicks animation_start_time,
      std::unique_ptr<cc::AnimationCurve> curve) override {
     cc::AnimationCurve* curve_rawptr = curve.release();
     delegate_.NotifyAnimationTakeover(
      peer_, 
      monotonic_time.ToInternalValue(), 
      target_property, 
      animation_start_time.ToInternalValue(),
      curve_rawptr);
  }

private:
  void* peer_; 
  CAnimationDelegate delegate_;
};

struct _opyOutputRequest {
 std::unique_ptr<viz::CopyOutputRequest> handle;
 _opyOutputRequest(viz::CopyOutputRequest* req): handle(req) {}
 _opyOutputRequest(std::unique_ptr<viz::CopyOutputRequest> req): handle(std::move(req)) {}
};

class _Animation {
public:
 _Animation(cc::Animation* ptr): handle_(ptr) {}
 _Animation(scoped_refptr<cc::Animation> ptr): handle_(std::move(ptr)) {}

 cc::Animation* handle() const {
   return handle_.get();
 } 

 scoped_refptr<cc::Animation> handle_ref_counted() const {
   return handle_;
 } 

 cc::SingleKeyframeEffectAnimation* as_single_keyframe() const {
  return static_cast<cc::SingleKeyframeEffectAnimation*>(handle_.get());
 }

 scoped_refptr<cc::SingleKeyframeEffectAnimation> as_single_keyframe_ref_counted() const {
   return scoped_refptr<cc::SingleKeyframeEffectAnimation>(as_single_keyframe());
 }

 void set_delegate(void* peer, CAnimationDelegate delegate) {
   delegate_.reset(new _AnimationDelegate(peer, delegate));
   handle_->set_animation_delegate(delegate_.get());
 }

private:
  scoped_refptr<cc::Animation> handle_;
  std::unique_ptr<_AnimationDelegate> delegate_;
};

class _AnimationTimeline {
public:
 _AnimationTimeline(cc::AnimationTimeline* ptr): handle_(ptr) {}
 _AnimationTimeline(scoped_refptr<cc::AnimationTimeline> ptr): handle_(std::move(ptr)) {}

 cc::AnimationTimeline* handle() const {
   return handle_.get();
 } 

 scoped_refptr<cc::AnimationTimeline> handle_ref_counted() const {
   return handle_;
 } 

private:
  scoped_refptr<cc::AnimationTimeline> handle_;
};

class _LayerAnimationDelegate : public cc::AnimationDelegate {
public:
  _LayerAnimationDelegate(void* peer, CLayerAnimationDelegateCallbacks callbacks):peer_(peer), callbacks_(callbacks) {}
  ~_LayerAnimationDelegate() override {}

  void NotifyAnimationStarted(base::TimeTicks monotonic_time,
                             int target_property,
                             int group) override {
    callbacks_.CLayerAnimationDelegateNotifyAnimationStarted(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }
 
  void NotifyAnimationFinished(base::TimeTicks monotonic_time,
                              int target_property,
                              int group) override {
    callbacks_.CLayerAnimationDelegateNotifyAnimationFinished(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }

  void NotifyAnimationAborted(base::TimeTicks monotonic_time,
                             int target_property,
                             int group) override {
    callbacks_.CLayerAnimationDelegateNotifyAnimationAborted(peer_, monotonic_time.ToInternalValue(), target_property, group);
  }

  void NotifyAnimationTakeover(
      base::TimeTicks monotonic_time,
      int target_property,
      base::TimeTicks animation_start_time,
      std::unique_ptr<cc::AnimationCurve> curve) override {
    callbacks_.CLayerAnimationDelegateNotifyAnimationTakeover(peer_, 
      monotonic_time.ToInternalValue(), 
      target_property, 
      animation_start_time.ToInternalValue(),
      curve.get());
  }

private:
  void* peer_;
  CLayerAnimationDelegateCallbacks callbacks_;
};

// struct _LayerAnimationController {
//  scoped_refptr<cc::LayerAnimationController> handle;
//  _LayerAnimationController(cc::LayerAnimationController* controller): handle(controller) {}
// };

struct _LayerAnimation {
 scoped_refptr<cc::Animation> handle;

 _LayerAnimation(cc::Animation* animation): handle(animation) {}
};

struct _ompositorFrame {
 std::unique_ptr<viz::CompositorFrame> handle;

 _ompositorFrame(viz::CompositorFrame* frame): handle(frame) {}

};

struct _ContextProvider {
  //scoped_refptr<cc::ContextProvider> handle;
  //scoped_refptr<viz::ContextProvider> handle;
  
  // FOR NOW: but we need to fix this to accept
  // remote/IPC rendering
  scoped_refptr<InProcessContextProvider> handle;

  scoped_refptr<InProcessContextProvider> shared_worker_context_provider;
};

class PaintRecord {
public:
 PaintRecord(sk_sp<cc::PaintRecord> handle): 
  handle_(std::move(handle)) {}

 ~PaintRecord() {
   handle_ = nullptr;
 }
 cc::PaintRecord* handle() { return handle_.get(); }
 sk_sp<cc::PaintRecord> ref() const { return handle_; }

private: 
 sk_sp<cc::PaintRecord> handle_;

 DISALLOW_COPY_AND_ASSIGN(PaintRecord);
};

class PaintTextBlob {
public:
  PaintTextBlob(scoped_refptr<cc::PaintTextBlob> handle): handle_(handle) {}
  ~PaintTextBlob() {}

  const scoped_refptr<cc::PaintTextBlob>& ref() const { return handle_; }
  cc::PaintTextBlob* handle() { return handle_.get(); }

private:

  scoped_refptr<cc::PaintTextBlob> handle_;

  DISALLOW_COPY_AND_ASSIGN(PaintTextBlob);
};


// struct _AnimationRegistrar {
//   cc::AnimationRegistrar* handle;

//  _AnimationRegistrar(cc::AnimationRegistrar* ptr): handle(ptr) {}
// };

struct _PropertyTrees {
  cc::PropertyTrees* handle;
 _PropertyTrees(cc::PropertyTrees* ptr): handle(ptr) {}
};

struct _AnimationEvent {
  cc::AnimationEvent event;

  _AnimationEvent(cc::AnimationEvent::Type event_type, 
                  cc::ElementId element_id, 
                  int group_id,
                  int target_property,
                  base::TimeTicks monotonic_time): event(event_type, element_id, group_id, target_property, monotonic_time) {

  }
};

class SkiaCanvas {
public:
 SkiaCanvas(): skcanvas_(skia::CreatePlatformCanvas(0, 0, false)) {}
 
#if defined(OS_LINUX)
 SkiaCanvas(SkBitmap* bitmap) {
   skcanvas_ = skia::CreatePlatformCanvasWithPixels(
        bitmap->width(), 
        bitmap->height(), 
        bitmap->alphaType() == kOpaque_SkAlphaType,
        reinterpret_cast<uint8_t*>(bitmap->getPixels()),
        skia::RETURN_NULL_ON_FAILURE);
 }
#elif defined(OS_WIN)
 // TODO see the side effect of this
 SkiaCanvas(SkBitmap* bitmap) {
   skcanvas_ = skia::CreatePlatformCanvasWithSharedSection(
    bitmap->width(), 
    bitmap->height(), 
    bitmap->alphaType() == kOpaque_SkAlphaType,
    nullptr,
    skia::RETURN_NULL_ON_FAILURE);
 }
 SkiaCanvas(SkBitmap* bitmap, HANDLE shared_section) {
  skcanvas_ = skia::CreatePlatformCanvasWithSharedSection(
    bitmap->width(), 
    bitmap->height(), 
    bitmap->alphaType() == kOpaque_SkAlphaType,
    shared_section,
    skia::RETURN_NULL_ON_FAILURE);
 }
#endif
 
 
 SkiaCanvas(SkCanvas* canvas): skcanvas_(canvas) {
 }

 ~SkiaCanvas(){}

 SkCanvas* handle() const { return skcanvas_.get(); }

private:

 std::unique_ptr<SkCanvas> skcanvas_;

 DISALLOW_COPY_AND_ASSIGN(SkiaCanvas);
};

class SkiaPicture {
public:
 explicit SkiaPicture(sk_sp<SkPicture> picture): skpicture_(std::move(picture)) {}
 SkiaPicture(SkPicture* picture): skpicture_(picture) {}
 ~SkiaPicture() {}

 const sk_sp<SkPicture>& handle() const { return skpicture_; }

 sk_sp<SkPicture> own() { return std::move(skpicture_); }

private:
 SkiaPicture(){}

 sk_sp<SkPicture> skpicture_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaPicture);
};

// void _ClipDisplayItemSetNew(DisplayItemRef handle, int cx, int cy, int cw, int ch) {
//  gfx::Rect clip_rect(cx, cy, cw, ch);
//  std::vector<SkRRect> rounded_clip_rects;
//  cc::ClipDisplayItem* item = reinterpret_cast<cc::ClipDisplayItem *>(handle);
//  //gfx::Rect clip_rect,
//  // const std::vector<SkRRect>& rounded_clip_rects
//  item->SetNew(clip_rect, rounded_clip_rects);
// }

class SkiaImage {
public:
 SkiaImage(SkImage* image): skimage_(image)  {}
 SkiaImage(sk_sp<SkImage> image): skimage_(std::move(image))  {}
 SkiaImage(float width, float height) {
    empty_bitmap_.allocN32Pixels(width, height);
    empty_bitmap_.eraseARGB(255, 255, 255, 0);
    skimage_ = SkImage::MakeFromBitmap(empty_bitmap_);
 }
 ~SkiaImage() {}

 SkImage* handle() const { return skimage_.get(); }

 sk_sp<SkImage> ref() const {
  return skimage_;
 }

private:
 SkBitmap empty_bitmap_;
 sk_sp<SkImage> skimage_;

 DISALLOW_COPY_AND_ASSIGN(SkiaImage);
};

class SkiaPath {
public:
 SkiaPath(): skpath_(new SkPath)  {}
 ~SkiaPath() {}

 const SkPath& ref() const { return *skpath_; }
 SkPath* handle() { return skpath_.get(); }

private:

 std::unique_ptr<SkPath> skpath_;

 DISALLOW_COPY_AND_ASSIGN(SkiaPath);
};

class SkiaDrawFilter {
public:
 SkiaDrawFilter(){}
 SkiaDrawFilter(SkDrawFilter* filter): skfilter_(filter) {}
 ~SkiaDrawFilter() {}

 SkDrawFilter* handle() const { return skfilter_.get(); }

private:
 
 sk_sp<SkDrawFilter> skfilter_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaDrawFilter);
};

class SkiaDrawLooper {
public:
 SkiaDrawLooper(){}
 SkiaDrawLooper(SkDrawLooper* looper): sklooper_(looper) {}
 SkiaDrawLooper(sk_sp<SkDrawLooper> looper): sklooper_(std::move(looper)) {}
 ~SkiaDrawLooper() {}

 SkDrawLooper* handle() const { return sklooper_.get(); }
 sk_sp<SkDrawLooper> own() { return std::move(sklooper_); }
 void set(const sk_sp<SkDrawLooper>& looper) { 
   sklooper_ = looper;
 }

private:

 sk_sp<SkDrawLooper> sklooper_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaDrawLooper);
};

class SkiaMaskFilter {
public:
 SkiaMaskFilter(){}
 SkiaMaskFilter(SkMaskFilter* mask_filter): skmask_filter_(mask_filter) {}
 SkiaMaskFilter(sk_sp<SkMaskFilter> mask_filter): skmask_filter_(std::move(mask_filter)) {}
 ~SkiaMaskFilter() {}

 SkMaskFilter* handle() const { return skmask_filter_.get(); }
 sk_sp<SkMaskFilter> own() { return std::move(skmask_filter_); }
 void set(const sk_sp<SkMaskFilter>& mask_filter) { 
   skmask_filter_ = mask_filter; 
 }
 

private:

 sk_sp<SkMaskFilter> skmask_filter_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaMaskFilter);
};

class SkiaColorFilter {
public:
 SkiaColorFilter(){}
 SkiaColorFilter(SkColorFilter* color_filter): skcolor_filter_(color_filter) {}
 SkiaColorFilter(sk_sp<SkColorFilter> color_filter): skcolor_filter_(std::move(color_filter)) {}
 ~SkiaColorFilter() {}

 SkColorFilter* handle() const { return skcolor_filter_.get(); }
 sk_sp<SkColorFilter> own() { return std::move(skcolor_filter_); }
 void set(const sk_sp<SkColorFilter>& color_filter) {
  skcolor_filter_ = color_filter;
 }
 
private:
 
 sk_sp<SkColorFilter> skcolor_filter_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaColorFilter);
};

class SkiaPictureRecorder {
public:
 SkiaPictureRecorder():skpicture_recorder_(new SkPictureRecorder) {}
 ~SkiaPictureRecorder() {}

 SkPictureRecorder* handle() const { return skpicture_recorder_.get(); }

private:

 std::unique_ptr<SkPictureRecorder> skpicture_recorder_;

 DISALLOW_COPY_AND_ASSIGN(SkiaPictureRecorder);
};

class SkiaShader {
public:
 explicit SkiaShader(SkShader* shader): skshader_(shader) {}
 SkiaShader(sk_sp<SkShader> shader): skshader_(std::move(shader)) {}
 
 ~SkiaShader() {}

 SkShader* handle() const { return skshader_.get(); }
 sk_sp<SkShader> own() { return std::move(skshader_); }

private:
 SkiaShader(){}

 sk_sp<SkShader> skshader_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaShader);
};

class SkiaTypeface {
public:
 explicit SkiaTypeface(SkTypeface* typeface): sktypeface_(typeface) {
  DCHECK(typeface);
 }
 SkiaTypeface(sk_sp<SkTypeface> typeface): sktypeface_(std::move(typeface)) {}
  SkiaTypeface(){}

 ~SkiaTypeface() {}

 SkTypeface* handle() const { return sktypeface_.get(); }
 sk_sp<SkTypeface> own() { return std::move(sktypeface_); }
 void set(const sk_sp<SkTypeface>& typeface) {
  sktypeface_ = sk_sp<SkTypeface>(typeface);
 }

private:

 sk_sp<SkTypeface> sktypeface_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaTypeface);
};

class SkiaPathEffect {
public:
  SkiaPathEffect(sk_sp<SkPathEffect> patheffect): skpatheffect_(std::move(patheffect)) {}
  ~SkiaPathEffect() {}

  const sk_sp<SkPathEffect>& handle() const { return skpatheffect_; }
  sk_sp<SkPathEffect> own() { return std::move(skpatheffect_); }

private:
  sk_sp<SkPathEffect> skpatheffect_;
  DISALLOW_COPY_AND_ASSIGN(SkiaPathEffect);
};

class SkiaGLInterface {
public:
 SkiaGLInterface(sk_sp<const GrGLInterface> skgrglinterface): skgrglinterface_(std::move(skgrglinterface)) {}
 ~SkiaGLInterface() {}

 GrGLInterface const* handle() const { return skgrglinterface_.get(); }
 sk_sp<const GrGLInterface> own() { return std::move(skgrglinterface_); }

private:
 SkiaGLInterface(){}

 sk_sp<const GrGLInterface> skgrglinterface_;
 
 DISALLOW_COPY_AND_ASSIGN(SkiaGLInterface);
};

class SkDrawableImpl : public SkDrawable {
public:
  SkDrawableImpl(void* peer, CDrawableCallbacks callbacks): callback_(callbacks), peer_(peer) {}
  ~SkDrawableImpl() override {}

 SkRect onGetBounds() override {
   int x, y, w, h;
   callback_.CDrawableOnGetBounds(peer_, &x, &y, &w, &h);
   return SkRect::MakeXYWH(x, y, w, h);
 }

 void onDraw(SkCanvas* canvas) override {
   //sk_sp<SkCanvas> refcanvas = skia::SharePtr(canvas);
   SkiaCanvas lcanvas(canvas);//refcanvas.Pass());
   callback_.CDrawableOnDraw(peer_, &lcanvas);
 }
    
 SkPicture* onNewPictureSnapshot() override {
   return reinterpret_cast<SkPicture *>(callback_.CDrawableOnNewPictureSnapshot(peer_));
 }

private: 
  CDrawableCallbacks callback_;
  
  void* peer_;
  
  DISALLOW_COPY_AND_ASSIGN(SkDrawableImpl);
};


class PaintFilter {
public:
  PaintFilter(sk_sp<cc::PaintFilter> filter): skfilter_(std::move(filter)) {}
  ~PaintFilter() {}

  const sk_sp<cc::PaintFilter>& ref() const { return skfilter_; }
  cc::PaintFilter* handle() const { return skfilter_.get(); }
  sk_sp<cc::PaintFilter> own() { return std::move(skfilter_); }

private:
  sk_sp<cc::PaintFilter> skfilter_;
  DISALLOW_COPY_AND_ASSIGN(PaintFilter);
};

class PathEffect {
public:
  PathEffect() {}
  PathEffect(sk_sp<SkPathEffect> handle): handle_(std::move(handle)) {}
  ~PathEffect() {}

  SkPathEffect* handle() { return handle_.get(); }
  sk_sp<SkPathEffect> own() { return std::move(handle_); }

  void set(const sk_sp<SkPathEffect>& handle) {
    handle_ = handle;
  }

private:
 sk_sp<SkPathEffect> handle_;
 DISALLOW_COPY_AND_ASSIGN(PathEffect);
};

class PaintShader {
public:
 //explicit PaintShader(SkShader* shader): handle_(shader) {}
 PaintShader(sk_sp<cc::PaintShader> shader): handle_(std::move(shader)) {}
 ~PaintShader() {}

 cc::PaintShader* handle() const { return handle_.get(); }
 sk_sp<cc::PaintShader> own() { return std::move(handle_); }

private:

 sk_sp<cc::PaintShader> handle_;
 
 DISALLOW_COPY_AND_ASSIGN(PaintShader);
};

class PaintFlags {
public:
  PaintFlags(){}
 ~PaintFlags() {}
 
 const cc::PaintFlags& const_ref() const { return flags_; }
 cc::PaintFlags& ref() { return flags_; }

 const cc::PaintFlags* const_ptr() const { return &flags_; }

private:

 cc::PaintFlags flags_;
 
 DISALLOW_COPY_AND_ASSIGN(PaintFlags);
};

class CCElementAnimations {
public:
  CCElementAnimations(scoped_refptr<cc::ElementAnimations> ref): ref_(ref) {}
  
  ~CCElementAnimations() {
    ref_ = nullptr;
  }

  scoped_refptr<cc::ElementAnimations> ref() {
    return ref_;
  }

  // less expensive, when we just want to call the inner handle
  // given this object already 'owns' the ref counted ptr
  cc::ElementAnimations* ptr() const {
    return ref_.get();
  }

private:
  scoped_refptr<cc::ElementAnimations> ref_;
};

class AnimationTimeProvider : public cc::KeyframeEffect::AnimationTimeProvider {
public:
  AnimationTimeProvider(void *state, AnimationTimeProviderCallback callback): 
    state_(state),
    callback_(callback) {}
  base::TimeTicks GetTimeForKeyframeModel(const cc::KeyframeModel& model) const override {
    DCHECK(callback_);
    return base::TimeTicks::FromInternalValue(callback_(state_, const_cast<cc::KeyframeModel *>(&model)));
  }
private:
  void* state_;
  AnimationTimeProviderCallback callback_;
};

#endif
