// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "X11Shims.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
//#include "base/memory/scoped_ptr.h"
#include "base/memory/ref_counted.h"
#include "ui/base/x/x11_util.h"
#include "ui/gfx/x/x11_connection.h"
#include "ui/gfx/overlay_transform.h"
#include "ui/gfx/presentation_feedback.h"
#include "ui/gl/gl_surface.h"
#include "ui/gl/gl_context_glx.h"
#include "ui/gl/gl_image_glx.h"
#include "ui/gl/gl_surface_glx.h"
#include "ui/gl/gl_share_group.h"
#include "ui/gl/gl_bindings.h"
#include "ui/gl/init/gl_factory.h"
#include "ui/gl/gl_implementation.h"
#include "ui/gl/sync_control_vsync_provider.h"
#if defined(OS_LINUX)
#include <glib.h>
#endif

gfx::OverlayTransform ToOverlayTransform(int code) {
  switch (code) {
    case 0:
     return gfx::OVERLAY_TRANSFORM_INVALID;
    case 1:
     return gfx::OVERLAY_TRANSFORM_NONE;
    case 2:
     return gfx::OVERLAY_TRANSFORM_FLIP_HORIZONTAL;
    case 3:
     return gfx::OVERLAY_TRANSFORM_FLIP_VERTICAL;
    case 4:
     return gfx::OVERLAY_TRANSFORM_ROTATE_90;
    case 5:
     return gfx::OVERLAY_TRANSFORM_ROTATE_180;
    case 6:
     return gfx::OVERLAY_TRANSFORM_ROTATE_270;
    default:
     return gfx::OVERLAY_TRANSFORM_INVALID;
  }
}

int SwapResultToInt(gfx::SwapResult code){
  switch (code) {
    case gfx::SwapResult::SWAP_ACK:
      return 0;
    case gfx::SwapResult::SWAP_FAILED:
      return 1;
    case gfx::SwapResult::SWAP_NAK_RECREATE_BUFFERS:
      return 2;
    default:
      return 1;
  }
}

struct CallbackData {
 GLibX11Callback cb;
};

struct _GLibX11Source : public GSource {
  XDisplay* display;
  std::unique_ptr<GPollFD> poll_fd;
  CallbackData data;
  void* payload;
};

gboolean XSourcePrepare(GSource* source, gint* timeout_ms) {
  _GLibX11Source* gxsource = static_cast<_GLibX11Source*>(source);
  if (XPending(gxsource->display))
    *timeout_ms = 0;
  else
    *timeout_ms = -1;
  return FALSE;
}

gboolean XSourceCheck(GSource* source) {
  _GLibX11Source* gxsource = static_cast<_GLibX11Source*>(source);
  return XPending(gxsource->display);
}

gboolean XSourceDispatch(GSource* source,
                         GSourceFunc unused_func,
                         gpointer data) {
  CallbackData* cbdata = static_cast<CallbackData *>(data);
  _GLibX11Source* gxsource = static_cast<_GLibX11Source*>(source);
  cbdata->cb(gxsource->payload);
  return TRUE;
}

GSourceFuncs XSourceFuncs = {
  XSourcePrepare,
  XSourceCheck,
  XSourceDispatch,
  NULL
};

void _X11_Init() {}

XDisplayHandle _X11_GetXDisplay() {
  return gfx::GetXDisplay();
}

void _X11_getint_ptr(int value, unsigned char** ptr) {
  *ptr = (unsigned char *)&value;
}

Window _X11_FindEventTarget(const XEvent* xev) {
  Window target = xev->xany.window;
  if (xev->type == GenericEvent)
    target = static_cast<XIDeviceEvent*>(xev->xcookie.data)->event;
  return target;
}

GLibX11SourceHandle _X11_InitXSource(int fd, XDisplayHandle display, GLibX11Callback cb, void* payload) {  
  GLibX11SourceHandle x_source = static_cast<GLibX11SourceHandle>
      (g_source_new(&XSourceFuncs, sizeof(_GLibX11Source)));

  x_source->poll_fd.reset(new GPollFD());
  x_source->poll_fd->fd = fd;
  x_source->poll_fd->events = G_IO_IN;
  x_source->poll_fd->revents = 0;

  x_source->display = display;
  x_source->data.cb = cb;
  x_source->payload = payload;
  //glib_x_source->poll_fd = x_poll_.get();

  g_source_add_poll(x_source, x_source->poll_fd.get());
  g_source_set_can_recurse(x_source, TRUE);
  g_source_set_callback(x_source, NULL, &x_source->data, NULL);
  g_source_attach(x_source, g_main_context_default());

  return x_source;
}

void _X11_DestroyXSource(GLibX11SourceHandle xsource) {
  g_source_destroy(xsource);
  g_source_unref(xsource);
}

int _X11_onnectionNumber(XDisplayHandle display) {
  return ConnectionNumber(display);
}

void _X11_SetUseNativeFrame(XDisplayHandle display, XID window, int use_frame) {
  typedef struct {
    unsigned long flags;
    unsigned long functions;
    unsigned long decorations;
    long input_mode;
    unsigned long status;
  } MotifWmHints;

  MotifWmHints motif_hints;
  memset(&motif_hints, 0, sizeof(motif_hints));
  // Signals that the reader of the _MOTIF_WM_HINTS property should pay
  // attention to the value of |decorations|.
  motif_hints.flags = (1L << 1);
  motif_hints.decorations = use_frame;

  XAtom hint_atom = XInternAtom(display, "_MOTIF_WM_HINTS", false);
  XChangeProperty(display,
                  window,
                  hint_atom,
                  hint_atom,
                  32,
                  PropModeReplace,
                  reinterpret_cast<unsigned char*>(&motif_hints),
                  sizeof(MotifWmHints)/sizeof(long));
}

struct _GLXContext {
 scoped_refptr<gl::GLContextGLX> handle;
};

struct _GLXSurface {
 scoped_refptr<gl::GLSurface> handle;
};

struct _GLXImage {
 scoped_refptr<gl::GLImageGLX> handle;
};

struct _GLShareGroup {
 scoped_refptr<gl::GLShareGroup> handle;
};

//struct _GLXVSyncProvider {
// scoped_ptr<gfx::SyncControlVSyncProvider> handle;
 //_GLXVSyncProvider(gfx::SyncControlVSyncProvider* provider): handle(provider) {}
//};


GLShareGroupRef _GLShareGroupCreate() {
 auto* group = new _GLShareGroup();
 group->handle = new gl::GLShareGroup();
 return group;
}

void _GLShareGroupDestroy(GLShareGroupRef shareGroup) {
 delete shareGroup;
}

void* _GLShareGroupGetHandle(GLShareGroupRef shareGroup) {
 return shareGroup->handle->GetHandle();
}

GLXContextRef _GLShareGroupGetContext(GLShareGroupRef shareGroup) {
  auto* context = shareGroup->handle->GetContext();
  if (!context) {
    return nullptr;
  }
  GLXContextRef glx = new _GLXContext();
  glx->handle = static_cast<gl::GLContextGLX *>(context);
  return glx;
}

GLXContextRef _GLShareGroupGetSharedContext(GLShareGroupRef shareGroup, GLXSurfaceRef surface) {
  auto* context = shareGroup->handle->GetSharedContext(reinterpret_cast<gl::GLSurfaceGLX *>(surface));
  if (!context) {
    return nullptr;
  }
  GLXContextRef glx = new _GLXContext();
  glx->handle = static_cast<gl::GLContextGLX *>(context);
  return glx;
}

void _GLShareGroupSetSharedContext(GLShareGroupRef shareGroup, GLXContextRef context, GLXSurfaceRef surface) {
  if(context->handle.get() != nullptr) {
    shareGroup->handle->SetSharedContext(reinterpret_cast<gl::GLSurfaceGLX *>(surface), context->handle.get());
  }
}

void _GLShareGroupAddContext(GLShareGroupRef shareGroup, GLXContextRef context) {
  shareGroup->handle->AddContext(context->handle.get());
}

void _GLShareGroupRemoveContext(GLShareGroupRef shareGroup, GLXContextRef context) {
 shareGroup->handle->RemoveContext(context->handle.get());
}

GLXContextRef _GLXContextCreate(GLShareGroupRef shareGroup) {
 auto* context = new _GLXContext();
 context->handle = new gl::GLContextGLX(shareGroup->handle.get());
 return context;
}

void _GLXContextDestroy(GLXContextRef context) {
 delete context;
}

void* _GLXContextGetHandle(GLXContextRef context) {
  return context->handle->GetHandle();
}

int _GLXContextInitialize(GLXContextRef context, GLXSurfaceRef surface, int gpuPreference) {
  gl::GLContextAttribs attribs;
  return context->handle->Initialize(surface->handle.get(), attribs) ? 1 : 0;
}

int _GLXContextMakeCurrent(GLXContextRef context, GLXSurfaceRef surface) {
  return context->handle->MakeCurrent(surface->handle.get()) ? 1 : 0;
}

void _GLXContextReleaseCurrent(GLXContextRef context, GLXSurfaceRef surface) {
  context->handle->ReleaseCurrent(surface->handle.get());
}

int _GLXContextIsCurrent(GLXContextRef context, GLXSurfaceRef surface) {
  return context->handle->IsCurrent(surface->handle.get()) ? 1 : 0;
}

GLXImageRef _GLXImageCreate(int width, int height, int internalFormat) {
  auto* image = new _GLXImage();
  image->handle = new gl::GLImageGLX(gfx::Size(width, height), internalFormat);
  return image;
}

void _GLXImageDestroy(GLXImageRef image) {
 delete image;
}

int _GLXImageInitialize(GLXImageRef image, XID pixmap) {
 return image->handle->Initialize(pixmap) ? 1 : 0;
}

void _GLXImageGetSize(GLXImageRef image, int* width, int* height) {
 gfx::Size size = image->handle->GetSize();
 *width = size.width();
 *height = size.height();
}

uint32_t _GLXImageGetInternalFormat(GLXImageRef image) {
 return image->handle->GetInternalFormat();
}

// void _GLXImageDestroy(GLXImageRef image, int haveContext) {
//  image->handle->Destroy(haveContext ? true : false);
// }

int _GLXImageBindTexImage(GLXImageRef image, int target) {
 return image->handle->BindTexImage(target) ? 1 : 0;
}

void _GLXImageReleaseTexImage(GLXImageRef image, int target) {
 image->handle->ReleaseTexImage(target);
}

int _GLXImageCopyTexImage(GLXImageRef image, int target) {
 return image->handle->CopyTexImage(target) ? 1 : 0;
}

int _GLXImageCopyTexSubImage(GLXImageRef image,
  int target,
  int px,
  int py,
  int rx,
  int ry,
  int rw,
  int rh) {

  return image->handle->CopyTexSubImage(target, gfx::Point(px, py), gfx::Rect(rx, ry, rw, rh)) ? 1: 0;

}

int _GLXImageScheduleOverlayPlane(GLXImageRef image,
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
  int enable_blend) {

  return image->handle->ScheduleOverlayPlane(
    widget,
    zOrder,
    ToOverlayTransform(transform),
    gfx::Rect(bx, by, bw, bh),
    gfx::RectF(cx, cy, cw, ch),
    enable_blend ? true : false) ? 1 : 0;
}

void _GLXSurfaceSwapCallback(gfx::SwapResult result) {
  DCHECK(result == gfx::SwapResult::SWAP_ACK);
}

void _GLXSurfacePresentationCallback(const gfx::PresentationFeedback& feedback) {}


int _GLXSurfaceInitializeOneOff() {
  LOG(ERROR) << "Should not be calling this anymore, but _CompositorInitialize(). fix";
  base::CommandLine::Init(0, nullptr);
  // we are cheating right here
  // scoped_refptr<base::SingleThreadTaskRunner> task_runner(new base::TestSimpleTaskRunner);
  // base::ThreadTaskRunnerHandle task_runner_handle(task_runner);
  
  gfx::InitializeThreadedX11();
  int r = gl::init::InitializeGLOneOff();
  //int r = gl::GLSurfaceGLX::InitializeOneOff();
  return  r ? 1 : 0;
}

GLXSurfaceRef _GLXSurfaceCurrent() {
 gl::GLSurfaceGLX* surface = static_cast<gl::GLSurfaceGLX*>(gl::GLSurface::GetCurrent());
 if (surface == nullptr) {
   return nullptr;
 }
 auto* current = new _GLXSurface();
 current->handle = surface;
 return current;
}

GLXSurfaceRef _GLXSurfaceCreateView(XID window) {
 auto* surface = new _GLXSurface();
 surface->handle = gl::init::CreateViewGLSurface(window);
 DCHECK(surface->handle->Initialize());
 return surface;
}

GLXSurfaceRef _GLXSurfaceCreateOffscreen(int width, int height) {
  auto* surface = new _GLXSurface();
  surface->handle = gl::init::CreateOffscreenGLSurface(gfx::Size(width, height));
  return surface;
}

void _GLXSurfaceFree(GLXSurfaceRef surface) {
  delete surface;
}

int _GLXSurfaceIsOffscreen(GLXSurfaceRef surface) {
  return surface->handle->IsOffscreen() ? 1 : 0;
}

void _GLXSurfaceGetSize(GLXSurfaceRef surface, int* width, int* height) {
  gfx::Size size = surface->handle->GetSize();
  *width = size.width();
  *height = size.height();
}

void* _GLXSurfaceGetHandle(GLXSurfaceRef surface) {
  return surface->handle->GetHandle();
}

int _GLXSurfaceSupportsPostSubBuffer(GLXSurfaceRef surface) {
  return surface->handle->SupportsPostSubBuffer();
}

uint32_t _GLXSurfaceBackingFrameBufferObject(GLXSurfaceRef surface) {
  return surface->handle->GetBackingFramebufferObject();
}

void* _GLXSurfaceGetShareHandle(GLXSurfaceRef surface) {
  return surface->handle->GetShareHandle();
}

void* _GLXSurfaceGetDisplay(GLXSurfaceRef surface) {
  return surface->handle->GetDisplay();
}

void* _GLXSurfaceGetConfig(GLXSurfaceRef surface) {
  return surface->handle->GetConfig();
}

// uint32_t _GLXSurfaceGetFormat(GLXSurfaceRef surface) {
//   return surface->handle->GetFormat();
// }

GLXVSyncProviderRef _GLXSurfaceGetVSyncProvider(GLXSurfaceRef surface) {
  return surface->handle->GetVSyncProvider();
}

int _GLXSurfaceInitialize(GLXSurfaceRef surface) {
  return surface->handle->Initialize() ? 1 : 0;
}

void _GLXSurfaceDestroy(GLXSurfaceRef surface) {
  surface->handle->Destroy();
}

int _GLXSurfaceResize(GLXSurfaceRef surface, int width, int height, float scaleFactor, int has_alpha) {
 return surface->handle->Resize(gfx::Size(width, height), scaleFactor, gl::GLSurface::ColorSpace::UNSPECIFIED, has_alpha ? true : false) ? 1 : 0;
}

int _GLXSurfaceRecreate(GLXSurfaceRef surface) {
 return surface->handle->Recreate();
}

int _GLXSurfaceDeferDraws(GLXSurfaceRef surface) {
 return surface->handle->DeferDraws() ? 1 : 0;
}

int _GLXSurfaceSwapBuffers(GLXSurfaceRef surface) {
 return SwapResultToInt(surface->handle->SwapBuffers(base::BindRepeating(_GLXSurfacePresentationCallback)));
}

void _GLXSurfaceSwapBuffersAsync(GLXSurfaceRef surface, CSwapCompletionCallback callback) {
 surface->handle->SwapBuffersAsync(base::BindRepeating(_GLXSurfaceSwapCallback), base::BindRepeating(_GLXSurfacePresentationCallback));
}

int _GLXSurfacePostSubBuffer(GLXSurfaceRef surface, int x, int y, int width, int height) {
 return SwapResultToInt(surface->handle->PostSubBuffer(x, y, width, height, base::BindRepeating(_GLXSurfacePresentationCallback)));
}

void _GLXSurfacePostSubBufferAsync(GLXSurfaceRef surface, int x, int y, int width, int height, CSwapCompletionCallback callback) {
 surface->handle->PostSubBufferAsync(x, y, width, height, base::BindRepeating(_GLXSurfaceSwapCallback), base::BindRepeating(_GLXSurfacePresentationCallback));
}

int _GLXSurfaceOnMakeCurrent(GLXSurfaceRef surface, GLXContextRef context) {
 return surface->handle->OnMakeCurrent(context->handle.get()) ? 1 : 0;
}

// void _GLXSurfaceNotifyWasBound(GLXSurfaceRef surface) {
//  surface->handle->NotifyWasBound();
// }

int _GLXSurfaceSetBackbufferAllocation(GLXSurfaceRef surface, int allocation) {
 return surface->handle->SetBackbufferAllocation(allocation) ? 1 : 0;
}

void _GLXSurfaceSetFrontbufferAllocation(GLXSurfaceRef surface, int allocation) {
 surface->handle->SetFrontbufferAllocation(allocation);
}

int _GLXSurfaceScheduleOverlayPlane(GLXSurfaceRef surface,
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
  int enable_blend) {

  return surface->handle->ScheduleOverlayPlane(
    zOrder,
    ToOverlayTransform(transform),
    image->handle.get(),
    gfx::Rect(bx, by, bw, bh),
    gfx::RectF(cx, cy, cw, ch),
    enable_blend ? true : false) ? 1 : 0;

}

int _GLXSurfaceIsSurfaceless(GLXSurfaceRef surface) {
 return surface->handle->IsSurfaceless() ? 1 : 0;
}

// void _GLXSurfaceOnSetSwapInterval(GLXSurfaceRef surface, int interval) {
//  surface->handle->OnSetSwapInterval(interval);
// }

GLXVSyncProviderRef _GLXVSyncProviderCreate() {
  //return new _GLXVSyncProvider(new gfx::SyncControlVSyncProvider());
  NOTREACHED();
  return nullptr;
}

void _GLXVSyncProviderDestroy(GLXVSyncProviderRef provider) {
  //delete provider;
}

void _GLXVSyncProviderGetVSyncParameters(GLXVSyncProviderRef handle) {
  //DCHECK(handle);
  //return handle->GetVSyncParameters();
}
