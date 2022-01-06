// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_X11_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_X11_SHIMS_H_

#include "Globals.h"

#if defined(OS_LINUX)
#include <X11/X.h>
#include <X11/extensions/XInput2.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/randr.h>
#include <X11/extensions/Xrandr.h>
#include <X11/extensions/XInput.h>
#include <X11/extensions/shape.h>
#include <X11/XKBlib.h>
#include <glib.h>
//#include <GL/glx.h>
#endif

//typedef union _XEvent XEvent;
typedef unsigned long XSharedMemoryId;  // ShmSeg in the X headers.
typedef unsigned long XCursor;
typedef unsigned long XAtom;
typedef unsigned long XID;
typedef struct _XImage XImage;
typedef struct _XGC *GC;
typedef struct _XDisplay XDisplay;
typedef struct _XcursorImage XcursorImage;
typedef struct _GLibX11Source GLibX11Source;

//typedef union _XEvent XEvent;

typedef XEvent* XEventHandle;
typedef XDisplay* XDisplayHandle;
typedef GLibX11Source* GLibX11SourceHandle;
typedef struct _GLXContext* GLXContextRef;
typedef struct _GLXSurface* GLXSurfaceRef;
typedef struct _GLXImage* GLXImageRef;
typedef struct _GLShareGroup* GLShareGroupRef;
typedef void* GLXVSyncProviderRef;

const int GpuPreferencePreferIntegratedGpu = 0;
const int GpuPreferencePreferDiscreteGpu = 1;

typedef void (*GLibX11Callback)(void* ptr);
typedef void (*CSwapCompletionCallback)(int swap_result);
typedef void (*CSwapPresentationCallback)(int swap_result);

EXPORT void _X11_Init();
EXPORT XDisplayHandle _X11_GetXDisplay();
EXPORT void _X11_getint_ptr(int value, unsigned char** ptr);
EXPORT Window _X11_FindEventTarget(const XEvent* xev);
EXPORT GLibX11SourceHandle _X11_InitXSource(int fd, XDisplayHandle display, GLibX11Callback cb, void* payload);
EXPORT void _X11_DestroyXSource(GLibX11SourceHandle xsource);
EXPORT int _X11_onnectionNumber(XDisplayHandle display);
EXPORT void _X11_SetUseNativeFrame(XDisplayHandle display, XID window, int use_frame);


EXPORT GLShareGroupRef _GLShareGroupCreate();
EXPORT void _GLShareGroupDestroy(GLShareGroupRef shareGroup);
EXPORT void* _GLShareGroupGetHandle(GLShareGroupRef shareGroup);
EXPORT GLXContextRef _GLShareGroupGetContext(GLShareGroupRef shareGroup);
EXPORT GLXContextRef _GLShareGroupGetSharedContext(GLShareGroupRef shareGroup, GLXSurfaceRef surface);
EXPORT void _GLShareGroupSetSharedContext(GLShareGroupRef shareGroup, GLXContextRef context, GLXSurfaceRef surface);
EXPORT void _GLShareGroupAddContext(GLShareGroupRef shareGroup, GLXContextRef context);
EXPORT void _GLShareGroupRemoveContext(GLShareGroupRef shareGroup, GLXContextRef context);

// GLX

EXPORT GLXContextRef _GLXContextCreate(GLShareGroupRef shareGroup);
EXPORT void _GLXContextDestroy(GLXContextRef context);
EXPORT void* _GLXContextGetHandle(GLXContextRef context);
EXPORT int _GLXContextInitialize(GLXContextRef context, GLXSurfaceRef surface, int gpuPreference);
EXPORT int _GLXContextMakeCurrent(GLXContextRef context, GLXSurfaceRef surface);
EXPORT void _GLXContextReleaseCurrent(GLXContextRef context, GLXSurfaceRef surface);
EXPORT int _GLXContextIsCurrent(GLXContextRef context, GLXSurfaceRef surface);

EXPORT GLXImageRef _GLXImageCreate(int width, int height, int internalFormat);
EXPORT void _GLXImageDestroy(GLXImageRef image);
EXPORT int _GLXImageInitialize(GLXImageRef image, XID pixmap);
EXPORT void _GLXImageGetSize(GLXImageRef image, int* width, int* height);
EXPORT uint32_t _GLXImageGetInternalFormat(GLXImageRef image);
//EXPORT void _GLXImageDestroy(GLXImageRef image, int haveContext);
EXPORT int _GLXImageBindTexImage(GLXImageRef image, int target);
EXPORT void _GLXImageReleaseTexImage(GLXImageRef image, int target);
EXPORT int _GLXImageCopyTexImage(GLXImageRef image, int target);
EXPORT int _GLXImageCopyTexSubImage(GLXImageRef image,
  int target,
  int px,
  int py,
  int rx,
  int ry,
  int rw,
  int rh);
EXPORT int _GLXImageScheduleOverlayPlane(GLXImageRef image,
  XID widget,
  int zOrder,
  int transform,
  int bx,
  int by,
  int bw,
  int bh,
  float cx,
  float cy,
  float cw,
  float ch,
  int enable_blend);

EXPORT int _GLXSurfaceInitializeOneOff();
EXPORT GLXSurfaceRef _GLXSurfaceCurrent();
EXPORT GLXSurfaceRef _GLXSurfaceCreateView(XID window);
EXPORT GLXSurfaceRef _GLXSurfaceCreateOffscreen(int width, int height);
EXPORT void _GLXSurfaceFree(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceIsOffscreen(GLXSurfaceRef handle);
EXPORT void _GLXSurfaceGetSize(GLXSurfaceRef handle, int* width, int* height);
EXPORT void* _GLXSurfaceGetHandle(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceSupportsPostSubBuffer(GLXSurfaceRef handle);
EXPORT uint32_t _GLXSurfaceBackingFrameBufferObject(GLXSurfaceRef handle);
EXPORT void* _GLXSurfaceGetShareHandle(GLXSurfaceRef handle);
EXPORT void* _GLXSurfaceGetDisplay(GLXSurfaceRef handle);
EXPORT void* _GLXSurfaceGetConfig(GLXSurfaceRef handle);
//EXPORT uint32_t _GLXSurfaceGetFormat(GLXSurfaceRef handle);
EXPORT GLXVSyncProviderRef _GLXSurfaceGetVSyncProvider(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceInitialize(GLXSurfaceRef handle);
EXPORT void _GLXSurfaceDestroy(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceResize(GLXSurfaceRef handle, int width, int height, float scaleFactor, int has_alpha);
EXPORT int _GLXSurfaceRecreate(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceDeferDraws(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceSwapBuffers(GLXSurfaceRef handle);
EXPORT void _GLXSurfaceSwapBuffersAsync(GLXSurfaceRef handle, CSwapCompletionCallback callback);
EXPORT int _GLXSurfacePostSubBuffer(GLXSurfaceRef handle, int x, int y, int width, int height);
EXPORT void _GLXSurfacePostSubBufferAsync(GLXSurfaceRef handle, int x, int y, int width, int height, CSwapCompletionCallback callback);
EXPORT int _GLXSurfaceOnMakeCurrent(GLXSurfaceRef handle, GLXContextRef context);
//EXPORT void _GLXSurfaceNotifyWasBound(GLXSurfaceRef handle);
EXPORT int _GLXSurfaceSetBackbufferAllocation(GLXSurfaceRef handle, int allocation);
EXPORT void _GLXSurfaceSetFrontbufferAllocation(GLXSurfaceRef handle, int allocation);
EXPORT int _GLXSurfaceScheduleOverlayPlane(GLXSurfaceRef handle,
  int zOrder,
  int transform,
  GLXImageRef image,
  int bx,
  int by,
  int bw,
  int bh,
  float cx,
  float cy,
  float cw,
  float ch,
  int enable_blend);

EXPORT int _GLXSurfaceIsSurfaceless(GLXSurfaceRef handle);
//EXPORT void _GLXSurfaceOnSetSwapInterval(GLXSurfaceRef handle, int interval);

EXPORT GLXVSyncProviderRef _GLXVSyncProviderCreate();
EXPORT void _GLXVSyncProviderDestroy(GLXVSyncProviderRef provider);
EXPORT void _GLXVSyncProviderGetVSyncParameters(GLXVSyncProviderRef handle);

#endif
