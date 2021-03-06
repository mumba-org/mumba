// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/gpu/gpu_client.h"

#include "core/host/gpu/host_gpu_memory_buffer_manager.h"
#include "core/host/gpu/gpu_process_host.h"
#include "core/shared/common/child_process_host_impl.h"
#include "core/host/host_thread.h"
#include "gpu/ipc/client/gpu_channel_host.h"
#include "gpu/ipc/common/gpu_memory_buffer_impl.h"
#include "gpu/ipc/common/gpu_memory_buffer_impl_shared_memory.h"

namespace host {

GpuClient::GpuClient(int render_process_id)
    : render_process_id_(render_process_id), weak_factory_(this) {
  bindings_.set_connection_error_handler(
      base::Bind(&GpuClient::OnError, base::Unretained(this)));
}

GpuClient::~GpuClient() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  bindings_.CloseAllBindings();
  OnError();
}

void GpuClient::Add(ui::mojom::GpuRequest request) {
  bindings_.AddBinding(this, std::move(request));
}

void GpuClient::OnError() {
  ClearCallback();
  if (!bindings_.empty())
    return;
  HostGpuMemoryBufferManager* gpu_memory_buffer_manager =
      HostGpuMemoryBufferManager::current();
  if (gpu_memory_buffer_manager)
    gpu_memory_buffer_manager->ProcessRemoved(render_process_id_);
}

void GpuClient::PreEstablishGpuChannel() {
  //DCHECK_CURRENTLY_ON(HostThread::UI);
  if (HostThread::CurrentlyOn(HostThread::IO)) {
    EstablishGpuChannel(EstablishGpuChannelCallback());
  } else {
    HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&GpuClient::EstablishGpuChannel, base::Unretained(this),
                     EstablishGpuChannelCallback()));
  }
}

void GpuClient::OnEstablishGpuChannel(
    mojo::ScopedMessagePipeHandle channel_handle,
    const gpu::GPUInfo& gpu_info,
    const gpu::GpuFeatureInfo& gpu_feature_info,
    GpuProcessHost::EstablishChannelStatus status) {
  DCHECK_EQ(channel_handle.is_valid(),
            status == GpuProcessHost::EstablishChannelStatus::SUCCESS);
  gpu_channel_requested_ = false;
  EstablishGpuChannelCallback callback = std::move(callback_);
  DCHECK(!callback_);

  if (status == GpuProcessHost::EstablishChannelStatus::GPU_HOST_INVALID) {
    // GPU process may have crashed or been killed. Try again.
    EstablishGpuChannel(std::move(callback));
    return;
  }
  if (callback) {
    // A request is waiting.
    std::move(callback).Run(render_process_id_, std::move(channel_handle),
                            gpu_info, gpu_feature_info);
    return;
  }
  if (status == GpuProcessHost::EstablishChannelStatus::SUCCESS) {
    // This is the case we pre-establish a channel before a request arrives.
    // Cache the channel for a future request.
    channel_handle_ = std::move(channel_handle);
    gpu_info_ = gpu_info;
    gpu_feature_info_ = gpu_feature_info;
  }
}

void GpuClient::OnCreateGpuMemoryBuffer(
    CreateGpuMemoryBufferCallback callback,
    const gfx::GpuMemoryBufferHandle& handle) {
  std::move(callback).Run(handle);
}

void GpuClient::ClearCallback() {
  if (!callback_)
    return;
  EstablishGpuChannelCallback callback = std::move(callback_);
  std::move(callback).Run(render_process_id_, mojo::ScopedMessagePipeHandle(),
                          gpu::GPUInfo(), gpu::GpuFeatureInfo());
  DCHECK(!callback_);
}

void GpuClient::EstablishGpuChannel(EstablishGpuChannelCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // At most one channel should be requested. So clear previous request first.
  ClearCallback();
  if (channel_handle_.is_valid()) {
    // If a channel has been pre-established and cached,
    //   1) if callback is valid, return it right away.
    //   2) if callback is empty, it's PreEstablishGpyChannel() being called
    //      more than once, no need to do anything.
    if (callback) {
      std::move(callback).Run(render_process_id_, std::move(channel_handle_),
                              gpu_info_, gpu_feature_info_);
      DCHECK(!channel_handle_.is_valid());
    }
    return;
  }
  GpuProcessHost* host = GpuProcessHost::Get();
  if (!host) {
    if (callback) {
      std::move(callback).Run(render_process_id_,
                              mojo::ScopedMessagePipeHandle(), gpu::GPUInfo(),
                              gpu::GpuFeatureInfo());
    }
    return;
  }
  callback_ = std::move(callback);
  if (gpu_channel_requested_)
    return;
  gpu_channel_requested_ = true;
  bool preempts = false;
  bool allow_view_command_buffers = false;
  bool allow_real_time_streams = false;
  host->EstablishGpuChannel(
      render_process_id_,
      common::ChildProcessHostImpl::ChildProcessUniqueIdToTracingProcessId(
          render_process_id_),
      preempts, allow_view_command_buffers, allow_real_time_streams,
      base::Bind(&GpuClient::OnEstablishGpuChannel,
                 weak_factory_.GetWeakPtr()));
}

void GpuClient::CreateJpegDecodeAccelerator(
    media::mojom::JpegDecodeAcceleratorRequest jda_request) {
  GpuProcessHost* host = GpuProcessHost::Get();
  if (host)
    host->gpu_service()->CreateJpegDecodeAccelerator(std::move(jda_request));
}

void GpuClient::CreateVideoEncodeAcceleratorProvider(
    media::mojom::VideoEncodeAcceleratorProviderRequest vea_provider_request) {
  GpuProcessHost* host = GpuProcessHost::Get();
  if (!host)
    return;
  host->gpu_service()->CreateVideoEncodeAcceleratorProvider(
      std::move(vea_provider_request));
}

void GpuClient::CreateGpuMemoryBuffer(
    gfx::GpuMemoryBufferId id,
    const gfx::Size& size,
    gfx::BufferFormat format,
    gfx::BufferUsage usage,
    ui::mojom::Gpu::CreateGpuMemoryBufferCallback callback) {
  DCHECK(HostGpuMemoryBufferManager::current());

  base::CheckedNumeric<int> bytes = size.width();
  bytes *= size.height();
  if (!bytes.IsValid()) {
    OnCreateGpuMemoryBuffer(std::move(callback), gfx::GpuMemoryBufferHandle());
    return;
  }

  HostGpuMemoryBufferManager::current()
      ->AllocateGpuMemoryBufferForChildProcess(
          id, size, format, usage, render_process_id_,
          base::BindOnce(&GpuClient::OnCreateGpuMemoryBuffer,
                         weak_factory_.GetWeakPtr(), std::move(callback)));
}

void GpuClient::DestroyGpuMemoryBuffer(gfx::GpuMemoryBufferId id,
                                       const gpu::SyncToken& sync_token) {
  DCHECK(HostGpuMemoryBufferManager::current());

  HostGpuMemoryBufferManager::current()->ChildProcessDeletedGpuMemoryBuffer(
      id, render_process_id_, sync_token);
}

}  // namespace host
