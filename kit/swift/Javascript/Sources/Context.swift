// Copyright (c) 2016-2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation

@dynamicMemberLookup
public struct JavascriptContext {

  public var global: JavascriptObject {
    return _global!
  }

  public var reference: JavascriptContextRef
  private var _global: JavascriptObject?
  public static var instance: JavascriptContext?


  // get the "current" context for current thread
  public static var current: JavascriptContext {
    if JavascriptContext.instance == nil {
      let _ = JavascriptContext()
    }
    return instance!
  }

  public init() {
    self.reference = _JavascriptContextGetCurrent()
    _global = JavascriptObject(context: self, reference: _JavascriptContextGetGlobal(reference)!)
    JavascriptContext.instance = self
  }

  public init(reference: JavascriptContextRef) {
    self.reference = reference
    _global = JavascriptObject(context: self, reference: _JavascriptContextGetGlobal(reference)!)
  }

  //deinit {
  //  _JavascriptContextDestroy(reference)
  //}

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

  // parse and run
  public func executeScript(_ source: String) -> JavascriptValue? {
    let ref = source.utf8CString.withUnsafeBufferPointer {
      return _JavascriptContextParseAndRunUTF8(reference, $0.baseAddress, CInt($0.count-1))
    }
    return ref == nil ? nil : JavascriptValue(context: self, reference: ref!)
  }

  public func executeWasm(data: Data, function: String) -> Int {
    guard let module = WasmCompiledModule.compile(context: self, data: data) else {
      return -1
    }
    return executeWasm(module: module, function: function)
  }

  public func executeWasm(data: Data) -> Int {
    guard let module = WasmCompiledModule.compile(context: self, data: data) else {
      return -1
    }
    return executeWasm(module: module)
  }

  public func executeWasm(module: WasmCompiledModule) -> Int {
    return Int(_JavascriptContextExecuteWasmMain(reference, module.reference))
  }
  
  // TODO: args
  public func executeWasm(module: WasmCompiledModule, function: String) -> Int {
    return function.withCString {
      return Int(_JavascriptContextExecuteWasm(reference, module.reference, $0, 0, nil))
    }
  }

  /*
   * if let math = context.import("Math") {
   *   let pi = math.pi
   * }
   */
  public func `import`(_ module: String) throws -> JavascriptValue {
    //guard let reference = _JavascriptModuleImport(module) else {
      throw JavascriptException.moduleNotFound(module)
    //}

    //return JavascriptValue(reference: reference!)
  }

  public func bindFunction(named: String, _ fn: @escaping JavascriptFunctionCallback) -> JavascriptFunction {
    let function = JavascriptFunction(context: self, name: named, callback: fn)
    let _ = global.set(key: JavascriptString(context: self, string: named), value: function)
    return function
  }

  /// This is a trick to be able to reference or call anything directly on
  /// context. We just proxy it through the 'global' object associated with the context
  public subscript(dynamicMember name: String) -> JavascriptValue {
    get {
      guard let result = global.get(key: name) else {
        return JavascriptValue.Undefined(context: self)
      }
      result.parent = global
      return result
    }
  }
    
  public subscript(key: [JavascriptConvertible]) -> JavascriptValue {
    get {
        let keyValue = flattenedSubscriptIndices(self, key)
        guard let result = global.get(key: keyValue) else {
          return JavascriptValue.Undefined(context: self)
        }
        result.parent = global
        return result
    }
    set {
        let keyObject = flattenedSubscriptIndices(self, key)
        //if let newValue = newValue {
          let _ = global.set(key: keyObject, value: newValue)
        //} else {
        //  let _ = global.delete(key: keyObject)
        //}
    }
  }
    
  public subscript(key: JavascriptConvertible...) -> JavascriptValue {
    get {
      return global[key]
    }
    set {
      global[key] = newValue
    }
  }

}
