// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

// TODO:  Uma ideia seria ter handlers para operacoes predifinidas de biblioteca
// 'std' onde ja seria permitido acesso a files, net, etc..
// so que teriamos que definir um delegate, de forma a controlarmos essas operações
// "de fora".. ou seja cancelar ou so usar pra imprimir, debugar, etc..

public class JsEngine {
  
  //public let instance = JsRuntime()
  
  var reference: JsEngineRef

  public static func current() -> JsEngine? {
    if let ref = _JavascriptEngineGetCurrent() {
      return JsEngine(reference: ref)
    }
    return nil
  }

  public init() {
    reference = _JavascriptEngineCreate()
  }

  internal init(reference: JsEngineRef) {
    self.reference = reference
  }

  deinit {
    _JavascriptEngineShutdown(reference)
  }

  public func initialize() -> Bool {
    return _JavascriptEngineInit(reference) == 1
  }
  
  // TODO: internally we could bind a context to a thread local storage
  // so each thread have a 'natural' context
  public func makeContext() -> JsContext? {
    let ref = _JavascriptEngineCreateContext(reference)
    if ref == nil {
      return nil
    }
    return JsContext(reference: ref!)
  }

}
