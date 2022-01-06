// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_COMPOSITOR_FRAME_SINK_IMPL_WRAPPER_H_
#define MUMBA_COMMON_COMPOSITOR_FRAME_SINK_IMPL_WRAPPER_H_

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread.h"
#include "cc/base/switches.h"
#include "cc/test/test_image_factory.h"
#include "cc/test/pixel_test_output_surface.h"
#include "cc/test/test_task_graph_runner.h"
#include "cc/trees/layer_tree_host_client.h"
#include "cc/layers/layer.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_host_single_thread_client.h"
#include "core/shared/common/content_export.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/frame_sinks/delay_based_time_source.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/test/test_shared_bitmap_manager.h"
#include "components/viz/service/display/display_scheduler.h"
#include "components/viz/service/display/output_surface_client.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/frame_sinks/direct_layer_tree_frame_sink.h"
#include "components/viz/test/test_gpu_memory_buffer_manager.h"
#include "gpu/command_buffer/common/context_creation_attribs.h"
#include "gpu/ipc/common/surface_handle.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/context_creation_attribs.h"
#include "ui/compositor/compositor_switches.h"
#include "ui/compositor/layer.h"
#include "ui/compositor/reflector.h"
#include "ui/compositor/test/in_process_context_provider.h"
#include "ui/display/display_switches.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gfx/switches.h"
#include "ui/gl/gl_implementation.h"
#include "ui/gl/gl_utils.h"
#include "ui/gl/test/gl_surface_test_support.h"

class HostFrameSinkManagerWrapper;

class CONTENT_EXPORT FrameSinkManagerImplWrapper {
public:
  FrameSinkManagerImplWrapper();
  ~FrameSinkManagerImplWrapper();
  
  viz::FrameSinkManagerImpl* handle() const {
    return handle_.get();
  }

  void RegisterBeginFrameSource(viz::BeginFrameSource* begin_frame, const viz::FrameSinkId& frameSinkId);
  void SetLocalClient(HostFrameSinkManagerWrapper* host);

private:

  void RegisterBeginFrameSourceImpl(viz::BeginFrameSource* begin_frame, const viz::FrameSinkId& frameSinkId);
  
  std::unique_ptr<viz::FrameSinkManagerImpl> handle_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

#endif