// Copyright (c) 2016-2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class JsContext {

  var reference: JavascriptContextRef

  // get the "current" context for current thread
  // public static func current() -> JsContext? {
  //   let ref = _JavascriptContextGetCurrent()
  //   if ref == nil {
  //     return nil
  //   }
  //   return JsContext(reference: ref!)
  // }

  public static func create() -> JsContext? {
    if let engine = JsEngine.current() {
      return engine.makeContext()
    }
    return nil
  }

  public init(reference: JavascriptContextRef) {
    self.reference = reference
  }

  deinit {
    _JavascriptContextDestroy(reference)
  }

   /*
   *  let n: Double = context.within {
   *    let x = eval("2 + 2")
   *    return x.value
   *  }
   * 
   * instead of:
   *
   *  let x = context.eval("2 + 2")
   *  guard let n = x.To<JsNumber>(context: context)?.getNumber(context: context) else {
   *    ... error
   *  }
   */

  //public var within: () -> JavascriptValue = {
  //}

  public func parse(source: JsSourceScript) -> JsScript? {
    //let ref = _JavascriptContextParseScript(reference, source.reference)
    //return JsScript(reference: ref!)
    return nil
  }

  public func parse(string: String) -> JsScript? {
    var ref: JsScriptRef? = nil

    string.withCString { cstr in 
      ref = _JavascriptContextParseScriptUTF8(reference, cstr)
    }

    if ref == nil {
      return nil
    }

    return JsScript(reference: ref!)
  }

  public func execute(script: JsScript) -> JavascriptValue? {
    let ref = _JavascriptContextExecuteScript(reference, script.reference)
    if ref != nil {
      return JavascriptValue(reference: ref!)
    }
    return nil
  }

  // try to parse and run in one shot
  public func execute(string: String) -> JavascriptValue? {
    var ref: JavascriptValueRef? = nil

    string.withCString { cstr in 
      ref = _JavascriptContextEvalUTF8(reference, cstr)
    }
    if ref != nil {
      return JavascriptValue(reference: ref!)
    }
    return nil
  }

  /*
   * if let math = context.import("Math") {
   *   let pi = math.pi
   * }
   */
  public func `import`(_ module: String) throws -> JavascriptValue {
    //guard let reference = _JavascriptModuleImport(module) else {
      throw JsException.moduleNotFound(module)
    //}

    //return JavascriptValue(reference: reference!)
  }

}
