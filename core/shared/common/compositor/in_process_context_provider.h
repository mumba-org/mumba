// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_COMPOSITOR_IN_PROCESS_CONTEXT_PROVIDER_H_
#define MUMBA_COMMON_COMPOSITOR_IN_PROCESS_CONTEXT_PROVIDER_H_

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

class CONTENT_EXPORT InProcessContextProvider
    : public base::RefCountedThreadSafe<InProcessContextProvider>,
      public viz::ContextProvider,
      public viz::RasterContextProvider {
 public:
  static scoped_refptr<InProcessContextProvider> Create(
      const gpu::ContextCreationAttribs& attribs,
      gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
      gpu::ImageFactory* image_factory,
      gfx::AcceleratedWidget window,
      const std::string& debug_name,
      bool support_locking);

  // Uses default attributes for creating an offscreen context.
  static scoped_refptr<InProcessContextProvider> CreateOffscreen(
      gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
      gpu::ImageFactory* image_factory,
      bool support_locking);

  // viz::ContextProvider / viz::RasterContextProvider implementation.
  void AddRef() const override;
  void Release() const override;
  gpu::ContextResult BindToCurrentThread() override;
  const gpu::Capabilities& ContextCapabilities() const override;
  const gpu::GpuFeatureInfo& GetGpuFeatureInfo() const override;
  gpu::gles2::GLES2Interface* ContextGL() override;
  gpu::raster::RasterInterface* RasterInterface() override;
  gpu::ContextSupport* ContextSupport() override;
  class GrContext* GrContext() override;
  viz::ContextCacheController* CacheController() override;
  base::Lock* GetLock() override;
  void AddObserver(viz::ContextLostObserver* obs) override;
  void RemoveObserver(viz::ContextLostObserver* obs) override;

  // Gives the GL internal format that should be used for calling CopyTexImage2D
  // on the default framebuffer.
  uint32_t GetCopyTextureInternalFormat();

 private:
  friend class base::RefCountedThreadSafe<InProcessContextProvider>;

  InProcessContextProvider(
      const gpu::ContextCreationAttribs& attribs,
      gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
      gpu::ImageFactory* image_factory,
      gfx::AcceleratedWidget window,
      const std::string& debug_name,
      bool support_locking);
  ~InProcessContextProvider() override;

  void CheckValidThreadOrLockAcquired() const {
#if DCHECK_IS_ON()
    //if (support_locking_) {
    //  context_lock_.AssertAcquired();
    //} else {
      DCHECK(context_thread_checker_.CalledOnValidThread());
    //}
#endif
  }

  base::ThreadChecker main_thread_checker_;
  base::ThreadChecker context_thread_checker_;

  std::unique_ptr<gpu::GLInProcessContext> context_;
  std::unique_ptr<skia_bindings::GrContextForGLES2Interface> gr_context_;
  std::unique_ptr<gpu::raster::RasterInterface> raster_context_;
  std::unique_ptr<viz::ContextCacheController> cache_controller_;

  const bool support_locking_ ALLOW_UNUSED_TYPE;
  bool bind_tried_ = false;
  gpu::ContextResult bind_result_;

  gpu::ContextCreationAttribs attribs_;
  gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager_;
  gpu::ImageFactory* image_factory_;
  gfx::AcceleratedWidget window_;
  std::string debug_name_;

  base::Lock context_lock_;

  DISALLOW_COPY_AND_ASSIGN(InProcessContextProvider);
};

#endif