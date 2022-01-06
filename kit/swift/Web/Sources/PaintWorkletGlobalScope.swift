// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public protocol CSSPainter {
  var name: String { get }
  func paint(canvas: PaintCanvasRenderingContext2d, size: IntSize)
}

public class PaintWorkletGlobalScope {

  public var devicePixelRatio: Double {
    return PaintWorkletGlobalScopeGetDevicePixelRatio(reference)
  }

  private var callbacks: [PaintCallbackState] = []
  let reference: WorkletGlobalScopeRef
  let window: WebWindow

  internal init(reference: WorkletGlobalScopeRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }
  
  public func registerPaint(name: String, _ paintCallback: @escaping PaintCallback) {
    let state = PaintCallbackState(self, self.devicePixelRatio, paintCallback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    name.withCString { ncstr in
      PaintWorkletGlobalScopeRegisterPaintNative(reference, window.reference, ncstr, statePtr, { 
        // PaintRenderingContext2D*, PaintSize*, StylePropertyMapReadOnly*, CSSStyleValueVector*
        (cbState: UnsafeMutableRawPointer?, canvasRef: UnsafeMutableRawPointer?, paintSize: UnsafeMutableRawPointer?, styleProps: UnsafeMutableRawPointer?, cssStyleValuesRef: UnsafeRawPointer?) in
        let cb = unsafeBitCast(cbState, to: PaintCallbackState.self)
        var w: CInt = 0
        var h: CInt = 0
        PaintSizeGet(paintSize, &w, &h)
        let canvas = PaintCanvasRenderingContext2d(reference: canvasRef!, window: cb.parent!.window)
        let size = IntSize(width: Int(w), height: Int(h))
        cb.paintCallback!(canvas, size)
        //cb.dispose()
      })
    }
  }

  public func registerPaint(_ painter: CSSPainter) {
    let state = PaintCallbackState(self, self.devicePixelRatio, painter)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    painter.name.withCString { ncstr in
      PaintWorkletGlobalScopeRegisterPaintNative(reference, window.reference, ncstr, statePtr, { 
        // PaintRenderingContext2D*, PaintSize*, StylePropertyMapReadOnly*, CSSStyleValueVector*
        (cbState: UnsafeMutableRawPointer?, canvasRef: UnsafeMutableRawPointer?, paintSize: UnsafeMutableRawPointer?, styleProps: UnsafeMutableRawPointer?, cssStyleValuesRef: UnsafeRawPointer?) in
        let cb = unsafeBitCast(cbState, to: PaintCallbackState.self)
        var w: CInt = 0
        var h: CInt = 0
        PaintSizeGet(paintSize, &w, &h)
        let canvas = PaintCanvasRenderingContext2d(reference: canvasRef!, window: cb.parent!.window)
        let size = IntSize(width: Int(w), height: Int(h))
        cb.painter!.paint(canvas: canvas, size: size)
        //cb.dispose()
      })
    }
  }

  internal func addCallback(_ cb: PaintCallbackState) {
    callbacks.append(cb)
  }

  internal func removeCallback(_ cb: PaintCallbackState) {
    for (i, item) in callbacks.enumerated() {
      if item === cb {
        callbacks.remove(at: i)
        return
      }
    }
  }

}

internal class PaintCallbackState {
  
  internal var devicePixelRatio: Double
  internal var painter: CSSPainter?
  internal var paintCallback: PaintCallback?
  internal weak var parent: PaintWorkletGlobalScope?
  
  init(_ parent: PaintWorkletGlobalScope, _ devicePixelRatio: Double, _ cb: @escaping PaintCallback) {
    self.parent = parent
    self.paintCallback = cb
    self.devicePixelRatio = devicePixelRatio
    self.parent!.addCallback(self)
  }
  
  init(_ parent: PaintWorkletGlobalScope, _ devicePixelRatio: Double, _ painter: CSSPainter) {
    self.parent = parent
    self.painter = painter
    self.devicePixelRatio = devicePixelRatio
    self.parent!.addCallback(self)
  }

  func dispose() {
    parent!.removeCallback(self)
  }

}