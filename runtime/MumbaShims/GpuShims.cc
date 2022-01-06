// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "GpuShims.h"
#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "ui/gl/gl_surface_glx.h"
//#include "components/viz/test/test_shared_bitmap_manager.h"
//#include "components/viz/test/test_gpu_memory_buffer_manager.h"
//#include "cc/test/test_image_factory.h"

//#include "ui/gl/test/gl_surface_test_support.h"

//#include "gpu/command_buffer/client/gl_in_process_context.h"
//#include "cc/test/test_image_factory.h"
//#include "cc/test/test_gpu_memory_buffer_manager.h"

//#include "CompositorHelper.h"

//warning: redeclaration

struct _GLXSurface {
 scoped_refptr<gl::GLSurfaceGLX> handle;
};

// GLInProcessContextRef _GLInProcessContextCreate(
//   InProcessCommandBufferServiceRef service,
//   GLXSurfaceRef surface,
//   int isOffscreen,
//   XID window,
//   int width,
//   int height,
//   GLInProcessContextRef shareContextHandle,
//   int useGlobalShareGroup,
//   int alphaSize,
//   int blueSize,
//   int greenSize,
//   int redSize,
//   int depthSize,
//   int stencilSize,
//   int samples,
//   int sampleBuffers,
//   int bufferPreserved,
//   int bindGeneratesResource,
//   int failIfMajorPerfCaveat,
//   int loseContextWhenOutOfMemory,
//   int contextType,
//   int gpuPreference,
//   int commandBufferSize,
//   int startTransferBufferSize,
//   int minTransferBufferSize,
//   int maxTransferBufferSize,
//   int mappedMemoryReclaimLimit,
//   GpuMemoryBufferManagerRef gpuMemoryBufferManager,
//   ImageFactoryRef imageFactory) {
//   DCHECK(surface);

//   gpu::gles2::ContextCreationAttribHelper attribs;
//   attribs.alpha_size = alphaSize;
//   attribs.blue_size = blueSize;
//   attribs.green_size = greenSize;
//   attribs.red_size = redSize;
//   attribs.depth_size = depthSize;
//   attribs.stencil_size = stencilSize;
//   attribs.samples = samples;
//   attribs.sample_buffers = sampleBuffers;
//   attribs.buffer_preserved = bufferPreserved ? true : false;
//   attribs.bind_generates_resource = bindGeneratesResource ? true : false;
//   attribs.fail_if_major_perf_caveat = failIfMajorPerfCaveat ? true : false;
//   attribs.lose_context_when_out_of_memory = loseContextWhenOutOfMemory ? true : false;
//   attribs.context_type = gpu::gles2::CONTEXT_TYPE_OPENGLES2;//contextType;

//   gpu::GLInProcessContextSharedMemoryLimits limits;

//   limits.command_buffer_size = commandBufferSize;
//   limits.start_transfer_buffer_size = startTransferBufferSize;
//   limits.min_transfer_buffer_size = minTransferBufferSize;
//   limits.max_transfer_buffer_size = maxTransferBufferSize;
//   limits.mapped_memory_reclaim_limit = mappedMemoryReclaimLimit;

//   gpu::GLInProcessContext* context = gpu::GLInProcessContext::Create(
//   nullptr,
//   surface->handle,
//   isOffscreen ? true : false,
//   window,
//   gfx::Size(width, height),
//   nullptr,
//   useGlobalShareGroup ? true : false,
//   attribs,
//   gfx::GpuPreference::PreferDiscreteGpu,
//   limits,
//   nullptr,
//   nullptr);
//   DCHECK(context);
//   return context;
// }

// void _GLInProcessContextDestroy(GLInProcessContextRef handle) {
//  gpu::GLInProcessContext* context = reinterpret_cast<gpu::GLInProcessContext*>(handle);
//  delete context;
// }

// GLES2ImplementationRef _GLInProcessContextGetGLES2Implementation(GLInProcessContextRef handle) {
//  gpu::GLInProcessContext* context = reinterpret_cast<gpu::GLInProcessContext*>(handle);
//  return context->GetImplementation();
// }

//void _GLES2ImplementationDestroy(GLES2ImplementationRef handle) {
 // do nothing (its owned by GLInProcessContext)
//}

ImageFactoryRef _TestImageFactoryCreate() {
  DCHECK(false);
  return nullptr;
  //return new cc::TestImageFactory();
}

void _TestImageFactoryDestroy(ImageFactoryRef handle) {
  DCHECK(false);
  //delete reinterpret_cast<cc::TestImageFactory*>(handle);
}

GpuMemoryBufferManagerRef _TestGpuMemoryManagerCreate() {
  DCHECK(false);
  return nullptr;
  //return new viz::TestGpuMemoryBufferManager();
}

void _TestGpuMemoryManagerDestroy(GpuMemoryBufferManagerRef handle) {
  DCHECK(false);
  //delete reinterpret_cast<viz::TestGpuMemoryBufferManager*>(handle);
}
