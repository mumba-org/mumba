// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_COMPOSITOR_HOST_FRAME_SINK_MANAGER_WRAPPER_H_
#define MUMBA_COMMON_COMPOSITOR_HOST_FRAME_SINK_MANAGER_WRAPPER_H_

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
#include "runtime/MumbaShims/CompositorFrameSinkCallbacks.h"


// it will route the calls
class CONTENT_EXPORT HostFrameSinkClientWrapper : public viz::HostFrameSinkClient {
public:
  HostFrameSinkClientWrapper(void* peer, HostFrameSinkClientCallbacks callbacks);
  ~HostFrameSinkClientWrapper();

  void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
  
  void OnFrameTokenChanged(uint32_t frame_token) override;

private:
  void* peer_;
  HostFrameSinkClientCallbacks callbacks_;
};

class CONTENT_EXPORT HostFrameSinkManagerWrapper {
public:
  HostFrameSinkManagerWrapper();
  ~HostFrameSinkManagerWrapper();

  viz::HostFrameSinkManager* handle() const {
    return handle_.get();
  }

  viz::HostFrameSinkClient* client() const {
    return client_.get();
  }

  void set_client(std::unique_ptr<HostFrameSinkClientWrapper> client);

  void RegisterFrameSinkId(const viz::FrameSinkId& frameSinkId);
  void SetFrameSinkDebugLabel(const viz::FrameSinkId& frameSinkId, const std::string& label);
  bool RegisterFrameSinkHierarchy(const viz::FrameSinkId& parent, const viz::FrameSinkId& child);
  void UnregisterFrameSinkHierarchy(const viz::FrameSinkId& parent, const viz::FrameSinkId& child);
  void InvalidateFrameSinkId(const viz::FrameSinkId& frameSinkId);
  void SetLocalManager(viz::FrameSinkManagerImpl* frame_sink_manager);

private:

  void RegisterFrameSinkIdImpl(const viz::FrameSinkId& frameSinkId);
  void SetFrameSinkDebugLabelImpl(const viz::FrameSinkId& frameSinkId, const std::string& label);
  void RegisterFrameSinkHierarchyImpl(
    const viz::FrameSinkId& parent, 
    const viz::FrameSinkId& child,
    base::WaitableEvent* event,
    bool* out);
  void UnregisterFrameSinkHierarchyImpl(const viz::FrameSinkId& parent, const viz::FrameSinkId& child);
  void InvalidateFrameSinkIdImpl(const viz::FrameSinkId& frameSinkId);
  void SetLocalManagerImpl(viz::FrameSinkManagerImpl* frame_sink);

  std::unique_ptr<viz::HostFrameSinkManager> handle_;
  std::unique_ptr<HostFrameSinkClientWrapper> client_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};


#endif