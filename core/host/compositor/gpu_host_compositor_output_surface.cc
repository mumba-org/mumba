// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/compositor/gpu_host_compositor_output_surface.h"

#include <utility>

#include "build/build_config.h"
#include "components/viz/service/display/output_surface_client.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/display_embedder/compositor_overlay_candidate_validator.h"
#include "core/host/compositor/reflector_impl.h"
#include "core/host/compositor/reflector_texture.h"
#include "core/host/application/application_window_host.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/swap_buffers_complete_params.h"
#include "gpu/ipc/client/command_buffer_proxy_impl.h"
#include "services/ui/public/cpp/gpu/context_provider_command_buffer.h"
#include "ui/gl/gl_utils.h"

namespace host {

GpuHostCompositorOutputSurface::GpuHostCompositorOutputSurface(
    scoped_refptr<ui::ContextProviderCommandBuffer> context,
    const UpdateVSyncParametersCallback& update_vsync_parameters_callback,
    std::unique_ptr<viz::CompositorOverlayCandidateValidator>
        overlay_candidate_validator)
    : HostCompositorOutputSurface(std::move(context),
                                  update_vsync_parameters_callback,
                                  std::move(overlay_candidate_validator)),
      latency_info_cache_(this) {
  if (capabilities_.uses_default_gl_framebuffer) {
    capabilities_.flipped_output_surface =
        context_provider()->ContextCapabilities().flips_vertically;
  }
  capabilities_.supports_stencil =
      context_provider()->ContextCapabilities().num_stencil_bits > 0;
}

GpuHostCompositorOutputSurface::~GpuHostCompositorOutputSurface() {
  // Reset GetCommandBufferProxy() callbacks to avoid calling those callbacks
  // from dtor of the base class.
  GetCommandBufferProxy()->SetSwapBuffersCompletionCallback(
      gpu::CommandBufferProxyImpl::SwapBuffersCompletionCallback());
  GetCommandBufferProxy()->SetUpdateVSyncParametersCallback(
      UpdateVSyncParametersCallback());
  GetCommandBufferProxy()->SetPresentationCallback(
      gpu::CommandBufferProxyImpl::PresentationCallback());
}

void GpuHostCompositorOutputSurface::SetNeedsVSync(bool needs_vsync) {
#if defined(OS_WIN)
  GetCommandBufferProxy()->SetNeedsVSync(needs_vsync);
#else
  NOTREACHED();
#endif  // defined(OS_WIN)
}

void GpuHostCompositorOutputSurface::OnGpuSwapBuffersCompleted(
    const gpu::SwapBuffersCompleteParams& params) {
  if (!params.ca_layer_params.is_empty)
    client_->DidReceiveCALayerParams(params.ca_layer_params);
  if (!params.texture_in_use_responses.empty())
    client_->DidReceiveTextureInUseResponses(params.texture_in_use_responses);
  client_->DidReceiveSwapBuffersAck(params.swap_response.swap_id);
  latency_info_cache_.OnSwapBuffersCompleted(params.swap_response);
}

void GpuHostCompositorOutputSurface::LatencyInfoCompleted(
    const std::vector<ui::LatencyInfo>& latency_info) {
  ApplicationWindowHost::OnGpuSwapBuffersCompleted(latency_info);
}

void GpuHostCompositorOutputSurface::OnReflectorChanged() {
  if (!reflector_) {
    reflector_texture_.reset();
  } else {
    reflector_texture_.reset(new ReflectorTexture(context_provider()));
    reflector_->OnSourceTextureMailboxUpdated(reflector_texture_->mailbox());
  }
  reflector_texture_defined_ = false;
}

void GpuHostCompositorOutputSurface::BindToClient(
    viz::OutputSurfaceClient* client) {
  DCHECK(client);
  DCHECK(!client_);
  client_ = client;

  // CommandBufferProxy() will always call below callbacks directly (no
  // PostTask), so it is safe to use base::Unretained(this).
  GetCommandBufferProxy()->SetSwapBuffersCompletionCallback(
      base::Bind(&GpuHostCompositorOutputSurface::OnGpuSwapBuffersCompleted,
                 base::Unretained(this)));
  GetCommandBufferProxy()->SetUpdateVSyncParametersCallback(
      update_vsync_parameters_callback_);
  GetCommandBufferProxy()->SetPresentationCallback(
      base::Bind(&GpuHostCompositorOutputSurface::OnPresentation,
                 base::Unretained(this)));
}

void GpuHostCompositorOutputSurface::EnsureBackbuffer() {}

void GpuHostCompositorOutputSurface::DiscardBackbuffer() {
  context_provider()->ContextGL()->DiscardBackbufferCHROMIUM();
}

void GpuHostCompositorOutputSurface::BindFramebuffer() {
  context_provider()->ContextGL()->BindFramebuffer(GL_FRAMEBUFFER, 0);
}

void GpuHostCompositorOutputSurface::Reshape(
    const gfx::Size& size,
    float device_scale_factor,
    const gfx::ColorSpace& color_space,
    bool has_alpha,
    bool use_stencil) {
  size_ = size;
  has_set_draw_rectangle_since_last_resize_ = false;
  context_provider()->ContextGL()->ResizeCHROMIUM(
      size.width(), size.height(), device_scale_factor,
      gl::GetGLColorSpace(color_space), has_alpha);
}

void GpuHostCompositorOutputSurface::SwapBuffers(
    viz::OutputSurfaceFrame frame) {

  if (latency_info_cache_.WillSwap(std::move(frame.latency_info)))
    GetCommandBufferProxy()->SetSnapshotRequested();

  gfx::Size surface_size = frame.size;
  if (reflector_) {
    if (frame.sub_buffer_rect && reflector_texture_defined_) {
      reflector_texture_->CopyTextureSubImage(*frame.sub_buffer_rect);
      reflector_->OnSourcePostSubBuffer(*frame.sub_buffer_rect, surface_size);
    } else {
      reflector_texture_->CopyTextureFullImage(surface_size);
      reflector_->OnSourceSwapBuffers(surface_size);
      reflector_texture_defined_ = true;
    }
  }

  set_draw_rectangle_for_frame_ = false;

  if (frame.sub_buffer_rect) {
    DCHECK(frame.content_bounds.empty());
    context_provider_->ContextSupport()->PartialSwapBuffers(
        *frame.sub_buffer_rect);
  } else if (!frame.content_bounds.empty()) {
    context_provider_->ContextSupport()->SwapWithBounds(frame.content_bounds);
  } else {
    context_provider_->ContextSupport()->Swap();
  }
}

uint32_t GpuHostCompositorOutputSurface::GetFramebufferCopyTextureFormat() {
  auto* gl = static_cast<ui::ContextProviderCommandBuffer*>(context_provider());
  return gl->GetCopyTextureInternalFormat();
}

bool GpuHostCompositorOutputSurface::IsDisplayedAsOverlayPlane() const {
  return false;
}

unsigned GpuHostCompositorOutputSurface::GetOverlayTextureId() const {
  return 0;
}

gfx::BufferFormat GpuHostCompositorOutputSurface::GetOverlayBufferFormat()
    const {
  return gfx::BufferFormat::RGBX_8888;
}

bool GpuHostCompositorOutputSurface::SurfaceIsSuspendForRecycle() const {
  return false;
}

#if defined(OS_MACOSX)
void GpuHostCompositorOutputSurface::SetSurfaceSuspendedForRecycle(
    bool suspended) {}
#endif

void GpuHostCompositorOutputSurface::SetDrawRectangle(
    const gfx::Rect& rect) {
  if (set_draw_rectangle_for_frame_)
    return;
  DCHECK(gfx::Rect(size_).Contains(rect));
  DCHECK(has_set_draw_rectangle_since_last_resize_ ||
         (gfx::Rect(size_) == rect));
  set_draw_rectangle_for_frame_ = true;
  has_set_draw_rectangle_since_last_resize_ = true;
  context_provider()->ContextGL()->SetDrawRectangleCHROMIUM(
      rect.x(), rect.y(), rect.width(), rect.height());
}

void GpuHostCompositorOutputSurface::OnPresentation(
    uint64_t swap_id,
    const gfx::PresentationFeedback& feedback) {
  DCHECK(client_);
  client_->DidReceivePresentationFeedback(swap_id, feedback);
}

gpu::CommandBufferProxyImpl*
GpuHostCompositorOutputSurface::GetCommandBufferProxy() {
  ui::ContextProviderCommandBuffer* provider_command_buffer =
      static_cast<ui::ContextProviderCommandBuffer*>(context_provider_.get());
  gpu::CommandBufferProxyImpl* command_buffer_proxy =
      provider_command_buffer->GetCommandBufferProxy();
  DCHECK(command_buffer_proxy);
  return command_buffer_proxy;
}

#if BUILDFLAG(ENABLE_VULKAN)
gpu::VulkanSurface* GpuHostCompositorOutputSurface::GetVulkanSurface() {
  NOTIMPLEMENTED();
  return nullptr;
}
#endif

}  // namespace host
