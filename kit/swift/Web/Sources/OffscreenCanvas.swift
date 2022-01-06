// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Foundation

public class OffscreenCanvas {

  public var width: Int {
    return Int(OffscreenCanvasGetWidth(reference))
  }

  public var height: Int {
    return Int(OffscreenCanvasGetHeight(reference))
  }

  public var context2d: OffscreenCanvasRenderingContext2d {
    if _context2d == nil {
      _context2d = createContext2d()
    }
    return _context2d!
  }

  public var glContext: WebGLRenderingContext {
    if _glContext == nil {
      _glContext = createContext3d(type: "webgl")
    }
    return _glContext!
  }

  public var gl2Context: WebGL2RenderingContext {
    if _gl2Context == nil {
      _gl2Context = (createContext3d(type: "webgl2") as! WebGL2RenderingContext)
    }
    return _gl2Context!
  }

  var reference: OffscreenCanvasRef
  internal var window: WebWindow?
  internal var worker: WebWorker?
  internal var scope: ServiceWorkerGlobalScope?
  private var _context2d: OffscreenCanvasRenderingContext2d?
  private var _glContext: WebGLRenderingContext?
  private var _gl2Context: WebGL2RenderingContext?

  public init(width: Int, height: Int, window: WebWindow) {
    reference = OffscreenCanvasCreate(CInt(width), CInt(height))
    self.window = window
  }

  public init(width: Int, height: Int, worker: WebWorker) {
    reference = OffscreenCanvasCreate(CInt(width), CInt(height))
    self.worker = worker
  }

  public init(width: Int, height: Int, scope: ServiceWorkerGlobalScope) {
    reference = OffscreenCanvasCreate(CInt(width), CInt(height))
    self.scope = scope
  }

  init(reference: OffscreenCanvasRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: OffscreenCanvasRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: OffscreenCanvasRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func bindToWindow(_ window: WebWindow) {
    self.worker = nil
    self.window = window
    self.scope = nil
  }

  public func bindToWorker(_ worker: WebWorker) {
    self.worker = worker
    self.window = nil
    self.scope = nil
  }

  public func bindToServiceWorker(_ scope: ServiceWorkerGlobalScope) {
    self.worker = nil
    self.window = nil
    self.scope = scope
  }

  deinit {
    OffscreenCanvasDestroy(reference)
  }

  public func createContext2d() -> OffscreenCanvasRenderingContext2d {
    return OffscreenCanvasRenderingContext2d(canvas: self, reference: createContextInternal(type: "2d")!)
  }

  public func createContext3d(type: String) -> WebGLRenderingContext? {
    guard let ref = createContextInternal(type: type) else {
      return nil
    }
    if let w = window {
      return type == "webgl2" ? WebGL2RenderingContext(reference: ref, window: w) : WebGLRenderingContext(reference: ref, window: w)
    }
    if let wrk = worker {
      return type == "webgl2" ? WebGL2RenderingContext(reference: ref, worker: wrk) : WebGLRenderingContext(reference: ref, worker: wrk)
    }
    if let s = scope {
      return type == "webgl2" ? WebGL2RenderingContext(reference: ref, scope: s) : WebGLRenderingContext(reference: ref, scope: s)
    }
    return nil
  }

  private func createContextInternal(type: String) -> UnsafeMutableRawPointer? {
    return type.withCString { (cstr: UnsafePointer<Int8>?) -> UnsafeMutableRawPointer? in
      if let w = window {
        return OffscreenCanvasCreateContext(reference, w.reference, cstr)
      }
      if let wrk = worker {
        return OffscreenCanvasCreateContextFromWorker(reference, wrk.reference, cstr)
      }
      if let s = scope {
        return OffscreenCanvasCreateContextFromServiceWorker(reference, s.reference, cstr)
      }
      return nil
    }
  }

}