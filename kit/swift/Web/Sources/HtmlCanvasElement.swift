// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Compositor

public class HtmlCanvasElement : HtmlElement {

  public var size: IntSize {
    get {
      var w: CInt = 0
      var h: CInt = 0
      _HTMLCanvasElementGetSize(reference, &w, &h)
      return IntSize(width: Int(w), height: Int(h))
    }
    set {
      _HTMLCanvasElementSetSize(reference, CInt(newValue.width), CInt(newValue.height))
    }
  }

  public var width: Int {
    return size.width
  }

  public var height: Int {
    return size.height
  }

  public var layer: Compositor.Layer? {
    let ref = _HTMLCanvasElementGetLayer(reference)
    return ref != nil ? Compositor.Layer(reference: ref!) : nil
  }

  public var context2d: CanvasRenderingContext2d {
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

  private var _context2d: CanvasRenderingContext2d?
  private var _glContext: WebGLRenderingContext?
  private var _gl2Context: WebGL2RenderingContext?

  public init(document: WebDocument) {
    super.init(reference: _HTMLCanvasElementCreate(document.reference))
  }

  required init(reference: WebNodeRef) {
    super.init(reference: reference)
  }

  public func createContext2d() -> CanvasRenderingContext2d { 
    return CanvasRenderingContext2d(reference: createContextInternal(type: "2d")!, window: document!.domWindow)
  }

  public func createContext3d(type: String) -> WebGLRenderingContext? {
    guard let ref = createContextInternal(type: type) else {
      return nil
    }
    return type == "webgl2" ? WebGL2RenderingContext(reference: ref, window: document!.domWindow) : WebGLRenderingContext(reference: ref, window: document!.domWindow)
  }

  public func transferControlToOffscreen(window: WebWindow) -> OffscreenCanvas {
    return OffscreenCanvas(reference: _HTMLCanvasElementTransferControlToOffscreen(reference), window: window)
  }

  private func createContextInternal(type: String) -> UnsafeMutableRawPointer? {
    return type.withCString { (cstr: UnsafePointer<Int8>?) -> UnsafeMutableRawPointer? in
      return _HTMLCanvasElementCreateContext(reference, cstr)
    }
  }

}

extension WebElement {

  public func asHtmlCanvas() -> HtmlCanvasElement? {
    return asHtmlElement(to: HtmlCanvasElement.self)
  }

}