// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/compositor/software_host_compositor_output_surface.h"

#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/viz/service/display/output_surface_client.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/display/software_output_device.h"
#include "core/host/application/application_window_host.h"
#include "ui/gfx/vsync_provider.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/latency/latency_info.h"

namespace host {

SoftwareHostCompositorOutputSurface::SoftwareHostCompositorOutputSurface(
    std::unique_ptr<viz::SoftwareOutputDevice> software_device,
    const UpdateVSyncParametersCallback& update_vsync_parameters_callback,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : HostCompositorOutputSurface(std::move(software_device),
                                     update_vsync_parameters_callback),
      task_runner_(std::move(task_runner)),
      weak_factory_(this) {}

SoftwareHostCompositorOutputSurface::
    ~SoftwareHostCompositorOutputSurface() {
}

void SoftwareHostCompositorOutputSurface::BindToClient(
    viz::OutputSurfaceClient* client) {
  DCHECK(client);
  DCHECK(!client_);
  client_ = client;
}

void SoftwareHostCompositorOutputSurface::EnsureBackbuffer() {
  software_device()->EnsureBackbuffer();
}

void SoftwareHostCompositorOutputSurface::DiscardBackbuffer() {
  software_device()->DiscardBackbuffer();
}

void SoftwareHostCompositorOutputSurface::BindFramebuffer() {
  // Not used for software surfaces.
  NOTREACHED();
}

void SoftwareHostCompositorOutputSurface::SetDrawRectangle(
    const gfx::Rect& draw_rectangle) {
  NOTREACHED();
}

void SoftwareHostCompositorOutputSurface::Reshape(
    const gfx::Size& size,
    float device_scale_factor,
    const gfx::ColorSpace& color_space,
    bool has_alpha,
    bool use_stencil) {
  software_device()->Resize(size, device_scale_factor);
}

void SoftwareHostCompositorOutputSurface::SwapBuffers(
    viz::OutputSurfaceFrame frame) {
  DCHECK(client_);
  base::TimeTicks swap_time = base::TimeTicks::Now();
  for (auto& latency : frame.latency_info) {
    latency.AddLatencyNumberWithTimestamp(
        ui::INPUT_EVENT_GPU_SWAP_BUFFER_COMPONENT, swap_time);
    latency.AddLatencyNumberWithTimestamp(
        ui::INPUT_EVENT_LATENCY_TERMINATED_FRAME_SWAP_COMPONENT, swap_time);
  }
  //NOTREACHED()<< "equivalent to RenderWidgetHostImpl::OnGpuSwapBuffersCompleted needed"; ;
   task_runner_->PostTask(
       FROM_HERE,
       base::BindOnce(&ApplicationWindowHost::OnGpuSwapBuffersCompleted,
                      frame.latency_info));

  gfx::VSyncProvider* vsync_provider = software_device()->GetVSyncProvider();
  if (vsync_provider) {
    vsync_provider->GetVSyncParameters(
        base::Bind(&SoftwareHostCompositorOutputSurface::UpdateVSyncCallback,
                   weak_factory_.GetWeakPtr()));
  }

  ++swap_id_;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &SoftwareHostCompositorOutputSurface::SwapBuffersCallback,
          weak_factory_.GetWeakPtr(), swap_id_));
}

void SoftwareHostCompositorOutputSurface::SwapBuffersCallback(
    uint64_t swap_id) {
  client_->DidReceiveSwapBuffersAck(swap_id);
  client_->DidReceivePresentationFeedback(
      swap_id,
      gfx::PresentationFeedback(base::TimeTicks::Now(), refresh_interval_, 0u));
}

void SoftwareHostCompositorOutputSurface::UpdateVSyncCallback(
    const base::TimeTicks timebase,
    const base::TimeDelta interval) {
  refresh_interval_ = interval;
  update_vsync_parameters_callback_.Run(timebase, interval);
}

bool SoftwareHostCompositorOutputSurface::IsDisplayedAsOverlayPlane() const {
  return false;
}

unsigned SoftwareHostCompositorOutputSurface::GetOverlayTextureId() const {
  return 0;
}

gfx::BufferFormat
SoftwareHostCompositorOutputSurface::GetOverlayBufferFormat() const {
  return gfx::BufferFormat::RGBX_8888;
}

bool SoftwareHostCompositorOutputSurface::SurfaceIsSuspendForRecycle()
    const {
  return false;
}

uint32_t
SoftwareHostCompositorOutputSurface::GetFramebufferCopyTextureFormat() {
  // Not used for software surfaces.
  NOTREACHED();
  return 0;
}

#if defined(OS_MACOSX)
void SoftwareHostCompositorOutputSurface::SetSurfaceSuspendedForRecycle(
    bool suspended) {
}
#endif

#if BUILDFLAG(ENABLE_VULKAN)
gpu::VulkanSurface* SoftwareHostCompositorOutputSurface::GetVulkanSurface() {
  NOTIMPLEMENTED();
  return nullptr;
}
#endif

}  // namespace host
