// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/compositor/direct_output_surface.h"

#include "core/shared/common/compositor/in_process_context_provider.h"
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
#include "cc/paint/paint_image_builder.h"
#include "gpu/command_buffer/client/gles2_implementation.h"
#include "gpu/command_buffer/client/raster_implementation_gles.h"
#include "gpu/command_buffer/client/shared_memory_limits.h"
#include "gpu/ipc/gl_in_process_context.h"
#include "gpu/skia_bindings/grcontext_for_gles2_interface.h"
#include "third_party/skia/include/gpu/GrContext.h"
#include "third_party/skia/include/gpu/gl/GrGLInterface.h"


DirectOutputSurface::DirectOutputSurface(
    scoped_refptr<InProcessContextProvider> context_provider)
    : viz::OutputSurface(context_provider), weak_ptr_factory_(this) {
  
  capabilities_.flipped_output_surface = true;
}

DirectOutputSurface::~DirectOutputSurface() {}

void DirectOutputSurface::BindToClient(viz::OutputSurfaceClient* client) {
  LOG(INFO) << "DirectOutputSurface::BindToClient";
  client_ = client;
}

void DirectOutputSurface::EnsureBackbuffer() {}
void DirectOutputSurface::DiscardBackbuffer() {}
void DirectOutputSurface::BindFramebuffer() {
  LOG(INFO) << "DirectOutputSurface::BindFramebuffer";
  context_provider()->ContextGL()->BindFramebuffer(GL_FRAMEBUFFER, 0);
}
void DirectOutputSurface::SetDrawRectangle(const gfx::Rect& rect) {}
void DirectOutputSurface::Reshape(const gfx::Size& size,
              float device_scale_factor,
              const gfx::ColorSpace& color_space,
              bool has_alpha,
              bool use_stencil) {
  LOG(INFO) << "DirectOutputSurface::Reshape";
  context_provider()->ContextGL()->ResizeCHROMIUM(
      size.width(), size.height(), device_scale_factor,
      gl::GetGLColorSpace(color_space), has_alpha);
}
void DirectOutputSurface::SwapBuffers(viz::OutputSurfaceFrame frame) {
  LOG(INFO) << "DirectOutputSurface::SwapBuffers: this = " << this;
  DCHECK(context_provider_.get());
  if (frame.sub_buffer_rect) {
    LOG(INFO) << "DirectOutputSurface::SwapBuffers: frame.sub_buffer_rect != NULL PartialSwapBuffers(*frame.sub_buffer_rect)";
    context_provider_->ContextSupport()->PartialSwapBuffers(
        *frame.sub_buffer_rect);
  } else {
    LOG(INFO) << "DirectOutputSurface::SwapBuffers: frame.sub_buffer_rect == NULL Swap()";
    context_provider_->ContextSupport()->Swap();
  }
  gpu::gles2::GLES2Interface* gl = context_provider_->ContextGL();
  gpu::SyncToken sync_token;
  gl->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());

  context_provider_->ContextSupport()->SignalSyncToken(
      sync_token, base::BindOnce(&DirectOutputSurface::OnSwapBuffersComplete,
                                  weak_ptr_factory_.GetWeakPtr(), ++swap_id_));
}
uint32_t DirectOutputSurface::GetFramebufferCopyTextureFormat() {
  auto* gl = static_cast<InProcessContextProvider*>(context_provider());
  return gl->GetCopyTextureInternalFormat();
}
viz::OverlayCandidateValidator* DirectOutputSurface::GetOverlayCandidateValidator()
    const {
  return nullptr;
}
bool DirectOutputSurface::IsDisplayedAsOverlayPlane() const { return false; }
unsigned DirectOutputSurface::GetOverlayTextureId() const { return 0; }
gfx::BufferFormat DirectOutputSurface::GetOverlayBufferFormat() const {
  return gfx::BufferFormat::RGBX_8888;
}
bool DirectOutputSurface::SurfaceIsSuspendForRecycle() const { return false; }
bool DirectOutputSurface::HasExternalStencilTest() const { return false; }
void DirectOutputSurface::ApplyExternalStencil() {}
#if BUILDFLAG(ENABLE_VULKAN)
gpu::VulkanSurface* DirectOutputSurface::GetVulkanSurface() { 
  LOG(INFO) << "DirectOutputSurface::GetVulkanSurface";
  return nullptr; 
}
#endif

void DirectOutputSurface::OnSwapBuffersComplete(uint64_t swap_id) {
  LOG(INFO) << "DirectOutputSurface::OnSwapBuffersComplete";
  client_->DidReceiveSwapBuffersAck(swap_id);
  client_->DidReceivePresentationFeedback(swap_id,
                                          gfx::PresentationFeedback());
}
