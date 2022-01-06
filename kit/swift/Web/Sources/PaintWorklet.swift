// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public typealias PaintCallback = (_: PaintCanvasRenderingContext2d, _: IntSize) -> Void

public class PaintWorklet {

  public var devicePixelRatio: Double {
    return scopes[0].devicePixelRatio
  }
  
  var reference: WorkletRef
  let window: WebWindow
  var scopes: [PaintWorkletGlobalScope] = []

  internal init(reference: WorkletRef, window: WebWindow) {
    self.reference = reference
    self.window = window
    let scopeCount = Int(PaintWorkletGetPaintWorkletGlobalScopeCount(self.reference))
    for i in 0..<scopeCount {
      scopes.append(PaintWorkletGlobalScope(reference: PaintWorkletGetPaintWorkletGlobalScopeAt(self.reference, CInt(i)), window: window))
    }
  }

  public func addModule(url: String) -> Promise<None> {
    let ref: ScriptPromiseRef = url.withCString { 
      return PaintWorkletAddModule(reference, $0)!
    }
    return Promise<None>(reference: ref, window: window)
  }

  public func registerPaint(name: String, _ paintCallback: @escaping PaintCallback) {
    for scope in scopes {
      scope.registerPaint(name: name, paintCallback)
    }
  }

  public func registerPaint(_ painter: CSSPainter) {
    for scope in scopes {
      scope.registerPaint(painter)
    }
  }

}