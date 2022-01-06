// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/compositor/vulkan_host_compositor_output_surface.h"

#include "base/threading/thread_task_runner_handle.h"
#include "components/viz/service/display/output_surface_client.h"
#include "core/host/application/application_window_host_impl.h"
#include "gpu/vulkan/vulkan_surface.h"

namespace host {

VulkanHostCompositorOutputSurface::VulkanHostCompositorOutputSurface(
    scoped_refptr<viz::VulkanContextProvider> context,
    const UpdateVSyncParametersCallback& update_vsync_parameters_callback)
    : HostCompositorOutputSurface(std::move(context),
                                     update_vsync_parameters_callback),
      weak_ptr_factory_(this) {}

VulkanHostCompositorOutputSurface::~VulkanHostCompositorOutputSurface() {
  Destroy();
}

bool VulkanHostCompositorOutputSurface::Initialize(
    gfx::AcceleratedWidget widget) {
  DCHECK(!surface_);
  std::unique_ptr<gpu::VulkanSurface> surface(
      gpu::VulkanSurface::CreateViewSurface(widget));
  if (!surface->Initialize(vulkan_context_provider()->GetDeviceQueue(),
                           gpu::VulkanSurface::DEFAULT_SURFACE_FORMAT)) {
    return false;
  }
  surface_ = std::move(surface);

  return true;
}

void VulkanHostCompositorOutputSurface::Destroy() {
  if (surface_) {
    surface_->Destroy();
    surface_.reset();
  }
}

void VulkanHostCompositorOutputSurface::BindToClient(
    viz::OutputSurfaceClient* client) {
  DCHECK(client);
  DCHECK(!client_);
  client_ = client;
}

void VulkanHostCompositorOutputSurface::EnsureBackbuffer() {
  NOTIMPLEMENTED();
}

void VulkanHostCompositorOutputSurface::DiscardBackbuffer() {
  NOTIMPLEMENTED();
}

void VulkanHostCompositorOutputSurface::BindFramebuffer() {
  NOTIMPLEMENTED();
}

bool VulkanHostCompositorOutputSurface::IsDisplayedAsOverlayPlane() const {
  NOTIMPLEMENTED();
  return false;
}

unsigned VulkanHostCompositorOutputSurface::GetOverlayTextureId() const {
  NOTIMPLEMENTED();
  return 0;
}

gfx::BufferFormat VulkanHostCompositorOutputSurface::GetOverlayBufferFormat()
    const {
  NOTIMPLEMENTED();
  return gfx::BufferFormat::RGBX_8888;
}

bool VulkanHostCompositorOutputSurface::SurfaceIsSuspendForRecycle() const {
  NOTIMPLEMENTED();
  return false;
}

void VulkanHostCompositorOutputSurface::Reshape(
    const gfx::Size& size,
    float device_scale_factor,
    const gfx::ColorSpace& color_space,
    bool has_alpha,
    bool use_stencil) {
  NOTIMPLEMENTED();
}

void VulkanHostCompositorOutputSurface::SetDrawRectangle(
    const gfx::Rect& rect) {
  NOTREACHED();
}

uint32_t
VulkanHostCompositorOutputSurface::GetFramebufferCopyTextureFormat() {
  NOTIMPLEMENTED();
  return 0;
}

void VulkanHostCompositorOutputSurface::SwapBuffers(
    viz::OutputSurfaceFrame frame) {
  surface_->SwapBuffers();
  ++swap_id_;

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&VulkanHostCompositorOutputSurface::SwapBuffersAck,
                 weak_ptr_factory_.GetWeakPtr(), swap_id_));
}

void VulkanHostCompositorOutputSurface::SwapBuffersAck(uint64_t swap_id) {
  DCHECK(client_);
  client_->DidReceiveSwapBuffersAck(swap_id);
}

gpu::VulkanSurface* VulkanHostCompositorOutputSurface::GetVulkanSurface() {
  return surface_.get();
}

}  // namespace host
