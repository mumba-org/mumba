// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/compositor/frame_sink_manager_impl_wrapper.h"

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


// it will route the calls
FrameSinkManagerImplWrapper::FrameSinkManagerImplWrapper(): 
  handle_(std::make_unique<viz::FrameSinkManagerImpl>()),
  task_runner_(base::ThreadTaskRunnerHandle::Get()){

}

FrameSinkManagerImplWrapper::~FrameSinkManagerImplWrapper() {
  task_runner_ = nullptr;
}

void FrameSinkManagerImplWrapper::RegisterBeginFrameSource(viz::BeginFrameSource* begin_frame, const viz::FrameSinkId& frameSinkId) {
  if (base::ThreadTaskRunnerHandle::Get() != task_runner_) {
    task_runner_->PostTask(FROM_HERE, 
      base::BindOnce(&FrameSinkManagerImplWrapper::RegisterBeginFrameSourceImpl,
      base::Unretained(this),
      base::Unretained(begin_frame),
      frameSinkId));
  } else {
    RegisterBeginFrameSourceImpl(begin_frame, frameSinkId);
  }
}

void FrameSinkManagerImplWrapper::RegisterBeginFrameSourceImpl(viz::BeginFrameSource* begin_frame, const viz::FrameSinkId& frameSinkId) {
  handle_->RegisterBeginFrameSource(begin_frame, frameSinkId);
}

void FrameSinkManagerImplWrapper::SetLocalClient(HostFrameSinkManagerWrapper* host) {
  handle_->SetLocalClient(host->handle());
}
