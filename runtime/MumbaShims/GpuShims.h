// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_GPU_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_GPU_SHIMS_H_

#include "Globals.h"

//#if (OS_LINUX)
//#include "X11Shims.h"
//#endif

//typedef void* GLInProcessContextRef;
typedef void* InProcessCommandBufferServiceRef;
typedef void* ImageFactoryRef;
typedef void* GLES2ImplementationRef;
typedef void* GpuMemoryBufferManagerRef;

// EXPORT GLInProcessContextRef _GLInProcessContextCreate(
//   InProcessCommandBufferServiceRef serviceHandle,
//   GLXSurfaceRef surfaceHandle,
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
//   ImageFactoryRef imageFactory);
// EXPORT void _GLInProcessContextDestroy(GLInProcessContextRef handle);
// EXPORT GLES2ImplementationRef _GLInProcessContextGetGLES2Implementation(GLInProcessContextRef handle);
// EXPORT void _GLES2ImplementationDestroy(GLES2ImplementationRef handle);

EXPORT ImageFactoryRef _TestImageFactoryCreate();
EXPORT void _TestImageFactoryDestroy(ImageFactoryRef handle);

EXPORT GpuMemoryBufferManagerRef _TestGpuMemoryManagerCreate();
EXPORT void _TestGpuMemoryManagerDestroy(GpuMemoryBufferManagerRef handle);

#endif
