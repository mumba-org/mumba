// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class GLXSurface {

  // TODO: this c binding should be a temporary thing
  // because its a dependency on the c++ ui:: namespace
  // we want to get rid of.
  // We are perfectly capable of using the GLX x11 api directly
  public var _handle: GLXSurfaceRef

  init(reference: GLXSurfaceRef) {
    _handle = reference
  }

  deinit {
    _GLXSurfaceFree(_handle)
  }


}

extension GLXSurface: GLSurface {

    public var isOffscreen: Bool {
      return Bool(_GLXSurfaceIsOffscreen(_handle))
    }

    public var size: IntSize {
      var width:Int32 = 0, height:Int32 = 0
      _GLXSurfaceGetSize(_handle, &width, &height)
      return IntSize(width: Int(width), height: Int(height))
    }

    public var reference: UnsafeMutableRawPointer {
      return _GLXSurfaceGetHandle(_handle)
    }

    public var supportsPostSubBuffer: Bool {
      return Bool(_GLXSurfaceSupportsPostSubBuffer(_handle))
    }

    public var backingFrameBufferObject: UInt32 {
      return _GLXSurfaceBackingFrameBufferObject(_handle)
    }

    public var shareHandle: UnsafeMutableRawPointer {
      return _GLXSurfaceGetShareHandle(_handle)
    }

    public var display: UnsafeMutableRawPointer {
      return _GLXSurfaceGetDisplay(_handle)
    }

    public var config: UnsafeMutableRawPointer {
      return _GLXSurfaceGetConfig(_handle)
    }

    // public var format: UInt {
    //   return UInt(_GLXSurfaceGetFormat(_handle))
    // }

    public var vsyncProvider: VSyncProvider? {
      let vsync = _GLXSurfaceGetVSyncProvider(_handle)
      if vsync == nil {
        return nil
      }
      return GLXVSyncProvider(reference: vsync!)
    }

    public static func current() -> GLSurface? {
      let surface = _GLXSurfaceCurrent()
      if surface == nil {
        return nil
      }
      return GLXSurface(reference: surface!)
    }

    public static func initializeOneOff() -> Bool {
      return Bool(_GLXSurfaceInitializeOneOff())
    }

    public static func createViewGLSurface(window: AcceleratedWidget) -> GLSurface {
      let reference = _GLXSurfaceCreateView(window)
      return GLXSurface(reference: reference!)
    }

    public static func createOffscreenGLSurface(size: IntSize) -> GLSurface {
      let reference = _GLXSurfaceCreateOffscreen(Int32(size.width), Int32(size.height))
      return GLXSurface(reference: reference!)
    }

    public func initialize() -> Bool {
      return Bool(_GLXSurfaceInitialize(_handle))
    }

    public func destroy() {
      _GLXSurfaceDestroy(_handle)
    }

    public func resize(size: IntSize, scaleFactor: Float, hasAlpha: Bool) -> Bool {
      return Bool(_GLXSurfaceResize(_handle, Int32(size.width), Int32(size.height), scaleFactor, hasAlpha.intValue))
    }

    public func recreate() -> Bool {
      return Bool(_GLXSurfaceRecreate(_handle))
    }

    public func deferDraws() -> Bool {
      return Bool(_GLXSurfaceDeferDraws(_handle))
    }

    public func swapBuffers() -> SwapResult {
      let r = _GLXSurfaceSwapBuffers(_handle)
      return SwapResult(rawValue: r)!
    }

    public func swapBuffersAsync(completion: SwapCompletionCallback) -> Bool {
      _GLXSurfaceSwapBuffersAsync(_handle, { (result: Int32) in

      })
      return true
    }

    public func postSubBuffer(x: Int, y: Int, width: Int, height: Int) -> SwapResult {
      let r = _GLXSurfacePostSubBuffer(_handle, Int32(x), Int32(y), Int32(width), Int32(height))
      return SwapResult(rawValue: r)!
    }

    public func postSubBufferAsync(x: Int,
                                   y: Int,
                                   width: Int,
                                   height: Int,
                                   callback: SwapCompletionCallback) -> Bool {
      _GLXSurfacePostSubBufferAsync(_handle, Int32(x), Int32(y), Int32(width), Int32(height),
      { (result: Int32) in

      }
     )
     return true
    }

    public func onMakeCurrent(context: GLContext) -> Bool {
      let glxContext = context as! GLXContext
      return Bool(_GLXSurfaceOnMakeCurrent(_handle, glxContext._handle))
    }

    // public func notifyWasBound() {
    //   _GLXSurfaceNotifyWasBound(_handle)
    // }

    public func setBackbufferAllocation(allocated: Bool) -> Bool {
      return Bool(_GLXSurfaceSetBackbufferAllocation(_handle, allocated.intValue))
    }

    public func setFrontbufferAllocation(allocated: Bool) {
      _GLXSurfaceSetFrontbufferAllocation(_handle, allocated.intValue)
    }

    public func scheduleOverlayPlane(zOrder: Int,
                                     transform: OverlayTransform,
                                     image: GLImage,
                                     boundsRect: IntRect,
                                     cropRect: FloatRect,
                                     enableBlend: Bool) -> Bool {
      let glxImage = image as! GLXImage

      return Bool(_GLXSurfaceScheduleOverlayPlane(_handle,
            Int32(zOrder),
            transform.rawValue,
            glxImage.reference,
            Int32(boundsRect.x),
            Int32(boundsRect.y),
            Int32(boundsRect.width),
            Int32(boundsRect.height),
            cropRect.x,
            cropRect.y,
            cropRect.width,
            cropRect.height,
            enableBlend.intValue))

    }

    public func isSurfaceless() -> Bool {
      return Bool(_GLXSurfaceIsSurfaceless(_handle))
    }

    // public func onSetSwapInterval(interval: Int) {
    //   _GLXSurfaceOnSetSwapInterval(_handle, Int32(interval))
    // }
}
