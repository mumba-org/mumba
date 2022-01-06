// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/compositor/host_frame_sink_manager_wrapper.h"

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


HostFrameSinkClientWrapper::HostFrameSinkClientWrapper(void* peer, HostFrameSinkClientCallbacks callbacks): 
    peer_(peer),
    callbacks_(callbacks) {

}

HostFrameSinkClientWrapper::~HostFrameSinkClientWrapper() {}

void HostFrameSinkClientWrapper::OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info){
  callbacks_.OnFirstSurfaceActivation(
    peer_,
    surface_info.id().frame_sink_id().client_id(),
    surface_info.id().frame_sink_id().sink_id(),
    surface_info.id().local_surface_id().parent_sequence_number(),
    surface_info.id().local_surface_id().child_sequence_number(),
    surface_info.id().local_surface_id().embed_token().GetHighForSerialization(),
    surface_info.id().local_surface_id().embed_token().GetLowForSerialization(),
    surface_info.device_scale_factor(),
    surface_info.size_in_pixels().width(),
    surface_info.size_in_pixels().height());
}
  
void HostFrameSinkClientWrapper::OnFrameTokenChanged(uint32_t frame_token) {
  callbacks_.OnFrameTokenChanged(peer_, frame_token);
}


HostFrameSinkManagerWrapper::HostFrameSinkManagerWrapper(): 
  handle_(std::make_unique<viz::HostFrameSinkManager>()),
  task_runner_(base::ThreadTaskRunnerHandle::Get()){

}

HostFrameSinkManagerWrapper::~HostFrameSinkManagerWrapper() {
  task_runner_ = nullptr;
}

void HostFrameSinkManagerWrapper::set_client(std::unique_ptr<HostFrameSinkClientWrapper> client) {
  client_ = std::move(client);
}

void HostFrameSinkManagerWrapper::RegisterFrameSinkId(const viz::FrameSinkId& frameSinkId) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::RegisterFrameSinkIdImpl,
      base::Unretained(this),
      frameSinkId));
  } else {
    RegisterFrameSinkIdImpl(frameSinkId);
  }
}

void HostFrameSinkManagerWrapper::SetFrameSinkDebugLabel(const viz::FrameSinkId& frameSinkId, const std::string& label) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::SetFrameSinkDebugLabelImpl,
      base::Unretained(this),
      frameSinkId,
      label));
  } else {
    SetFrameSinkDebugLabelImpl(frameSinkId, label);
  }
}

bool HostFrameSinkManagerWrapper::RegisterFrameSinkHierarchy(const viz::FrameSinkId& parent, const viz::FrameSinkId& child) {
  bool result = false;
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    base::WaitableEvent waiter{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::RegisterFrameSinkHierarchyImpl,
      base::Unretained(this),
      parent,
      child,
      base::Unretained(&waiter),
      base::Unretained(&result)));
    waiter.Wait();
  } else {
    RegisterFrameSinkHierarchyImpl(parent, child, nullptr, &result);
  }
  return result;
}

void HostFrameSinkManagerWrapper::UnregisterFrameSinkHierarchy(const viz::FrameSinkId& parent, const viz::FrameSinkId& child) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::UnregisterFrameSinkHierarchyImpl,
      base::Unretained(this),
      parent,
      child));
  } else {
    UnregisterFrameSinkHierarchyImpl(parent, child);
  }
}

void HostFrameSinkManagerWrapper::InvalidateFrameSinkId(const viz::FrameSinkId& frameSinkId) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::InvalidateFrameSinkIdImpl,
      base::Unretained(this),
      frameSinkId));
  } else {
    InvalidateFrameSinkIdImpl(frameSinkId);
  }
}

void HostFrameSinkManagerWrapper::SetLocalManager(viz::FrameSinkManagerImpl* frame_sink_manager) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&HostFrameSinkManagerWrapper::SetLocalManagerImpl,
      base::Unretained(this),
      base::Unretained(frame_sink_manager)));
  } else {
    SetLocalManagerImpl(frame_sink_manager);
  }
}

void HostFrameSinkManagerWrapper::RegisterFrameSinkIdImpl(const viz::FrameSinkId& frameSinkId) {
  handle_->RegisterFrameSinkId(frameSinkId, client_.get());
}

void HostFrameSinkManagerWrapper::SetFrameSinkDebugLabelImpl(const viz::FrameSinkId& frameSinkId, const std::string& label) {
  handle_->SetFrameSinkDebugLabel(frameSinkId, label);
}

void HostFrameSinkManagerWrapper::RegisterFrameSinkHierarchyImpl(
  const viz::FrameSinkId& parent, 
  const viz::FrameSinkId& child, 
  base::WaitableEvent* event,
  bool* out) {
  *out = handle_->RegisterFrameSinkHierarchy(parent, child);
  if (event) {
    event->Signal();
  }
}

void HostFrameSinkManagerWrapper::UnregisterFrameSinkHierarchyImpl(const viz::FrameSinkId& parent, const viz::FrameSinkId& child) {
  handle_->UnregisterFrameSinkHierarchy(parent, child);
}

void HostFrameSinkManagerWrapper::InvalidateFrameSinkIdImpl(const viz::FrameSinkId& frameSinkId) {
  handle_->InvalidateFrameSinkId(frameSinkId);
}

void HostFrameSinkManagerWrapper::SetLocalManagerImpl(viz::FrameSinkManagerImpl* frame_sink_manager) {
  handle_->SetLocalManager(frame_sink_manager);
}

