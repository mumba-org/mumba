// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_COMPOSITOR_GPU_BROWSER_COMPOSITOR_OUTPUT_SURFACE_H_
#define CONTENT_BROWSER_COMPOSITOR_GPU_BROWSER_COMPOSITOR_OUTPUT_SURFACE_H_

#include <memory>

#include "base/macros.h"
#include "build/build_config.h"
#include "core/host/compositor/host_compositor_output_surface.h"
#include "core/host/compositor/gpu_vsync_begin_frame_source.h"
#include "gpu/vulkan/buildflags.h"
#include "ui/gfx/swap_result.h"

namespace viz {
class CompositorOverlayCandidateValidator;
}

namespace gfx {
struct PresentationFeedback;
}

namespace gpu {
class CommandBufferProxyImpl;
struct SwapBuffersCompleteParams;
}

namespace ui {
class ContextProviderCommandBuffer;
}

namespace host {
class ReflectorTexture;

// Adapts a WebGraphicsContext3DCommandBufferImpl into a
// viz::OutputSurface that also handles vsync parameter updates
// arriving from the GPU process.
class GpuHostCompositorOutputSurface
    : public HostCompositorOutputSurface,
      public GpuVSyncControl,
      public viz::OutputSurface::LatencyInfoCache::Client {
 public:
  GpuHostCompositorOutputSurface(
      scoped_refptr<ui::ContextProviderCommandBuffer> context,
      const UpdateVSyncParametersCallback& update_vsync_parameters_callback,
      std::unique_ptr<viz::CompositorOverlayCandidateValidator>
          overlay_candidate_validator);

  ~GpuHostCompositorOutputSurface() override;

  // Called when a swap completion is sent from the GPU process.
  virtual void OnGpuSwapBuffersCompleted(
      const gpu::SwapBuffersCompleteParams& params);

  // HostCompositorOutputSurface implementation.
  void OnReflectorChanged() override;
#if defined(OS_MACOSX)
  void SetSurfaceSuspendedForRecycle(bool suspended) override;
#endif

  // viz::OutputSurface implementation.
  void BindToClient(viz::OutputSurfaceClient* client) override;
  void EnsureBackbuffer() override;
  void DiscardBackbuffer() override;
  void BindFramebuffer() override;
  void Reshape(const gfx::Size& size,
               float device_scale_factor,
               const gfx::ColorSpace& color_space,
               bool has_alpha,
               bool use_stencil) override;
  void SwapBuffers(viz::OutputSurfaceFrame frame) override;
  uint32_t GetFramebufferCopyTextureFormat() override;
  bool IsDisplayedAsOverlayPlane() const override;
  unsigned GetOverlayTextureId() const override;
  gfx::BufferFormat GetOverlayBufferFormat() const override;

  bool SurfaceIsSuspendForRecycle() const override;
  void SetDrawRectangle(const gfx::Rect& rect) override;

  // GpuVSyncControl implementation.
  void SetNeedsVSync(bool needs_vsync) override;
#if BUILDFLAG(ENABLE_VULKAN)
  gpu::VulkanSurface* GetVulkanSurface() override;
#endif

  // OutputSurface::LatencyInfoCache::Client implementation.
  void LatencyInfoCompleted(
      const std::vector<ui::LatencyInfo>& latency_info) override;

 protected:
  void OnPresentation(uint64_t swap_id,
                      const gfx::PresentationFeedback& feedback);
  gpu::CommandBufferProxyImpl* GetCommandBufferProxy();

  viz::OutputSurfaceClient* client_ = nullptr;
  std::unique_ptr<ReflectorTexture> reflector_texture_;
  bool reflector_texture_defined_ = false;
  bool set_draw_rectangle_for_frame_ = false;
  // True if the draw rectangle has been set at all since the last resize.
  bool has_set_draw_rectangle_since_last_resize_ = false;
  gfx::Size size_;
  LatencyInfoCache latency_info_cache_;

 private:
  DISALLOW_COPY_AND_ASSIGN(GpuHostCompositorOutputSurface);
};

}  // namespace host

#endif  // CONTENT_BROWSER_COMPOSITOR_GPU_BROWSER_COMPOSITOR_OUTPUT_SURFACE_H_
