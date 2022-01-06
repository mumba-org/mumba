// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public typealias SwapCompletionCallback = (SwapResult) -> Void

public protocol GLSurface {

  static func current() -> GLSurface?
  static func initializeOneOff() -> Bool
  static func createViewGLSurface(window: AcceleratedWidget) -> GLSurface
  static func createOffscreenGLSurface(size: IntSize) -> GLSurface

  var isOffscreen: Bool { get }
  var size: IntSize { get }
  var reference: UnsafeMutableRawPointer { get }
  var supportsPostSubBuffer: Bool { get }
  var backingFrameBufferObject: UInt32 { get }
  var shareHandle: UnsafeMutableRawPointer { get }
  var display: UnsafeMutableRawPointer { get }
  var config: UnsafeMutableRawPointer { get }
 // var format: UInt { get }
  var vsyncProvider: VSyncProvider? { get }

  func initialize() -> Bool
  func destroy()
  func resize(size: IntSize, scaleFactor: Float, hasAlpha: Bool) -> Bool
  func recreate() -> Bool
  func deferDraws() -> Bool
  func swapBuffers() -> SwapResult
  func swapBuffersAsync(completion: SwapCompletionCallback) -> Bool
  func postSubBuffer(x: Int, y: Int, width: Int, height: Int) -> SwapResult
  func postSubBufferAsync(x: Int,
                          y: Int,
                          width: Int,
                          height: Int,
                          callback: SwapCompletionCallback) -> Bool
  func onMakeCurrent(context: GLContext) -> Bool
  func setBackbufferAllocation(allocated: Bool) -> Bool
  func setFrontbufferAllocation(allocated: Bool)
  func scheduleOverlayPlane(zOrder: Int,
                            transform: OverlayTransform,
                            image: GLImage,
                            boundsRect: IntRect,
                            cropRect: FloatRect,
                            enableBlend: Bool) -> Bool
  func isSurfaceless() -> Bool
}
