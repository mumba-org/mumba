// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public protocol ScriptValue {
  init?(_ : JavascriptContext, _: JavascriptValue)
}

// public struct WrappedScriptValue<T: AnyObject> {

//   let value: ScriptValue<T>

//   WrappedScriptValue(_ value: ScriptValue<T>) {
//     self.value = value
//   }
  
//   public func unwrap() -> T? {
//     return value.unwrap()
//   }

// }

public typealias None = Int

extension None : ScriptValue {

  public init?(_ : JavascriptContext, _: JavascriptValue) {
    return nil
  }

}

// FIXME
extension Bool : ScriptValue {

  public init?(_ ctx : JavascriptContext, _ v: JavascriptValue) {
    self = PromiseBooleanFromJavascriptValue(ctx.reference, v.reference) != 0
  }

}

extension String : ScriptValue {

  public init?(_ ctx : JavascriptContext, _ v: JavascriptValue) {
    var len: CInt = 0
    let cstr = PromiseStringFromJavascriptValue(ctx.reference, v.reference, &len)
    self = cstr == nil ? String() : String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

}

extension ArrayBuffer : ScriptValue {

  public init?(_ ctx : JavascriptContext, _ v: JavascriptValue) {
    let ref = PromiseArrayBufferFromJavascriptValue(ctx.reference, v.reference)
    self = ArrayBuffer(reference: ref!)
  }

}

extension FormData : ScriptValue {

  public init?(_ ctx : JavascriptContext, _ v: JavascriptValue) {
    let ref = PromiseFormDataFromJavascriptValue(ctx.reference, v.reference)
    self = FormData(reference: ref!)
  }

}

extension Blob : ScriptValue {

  public init?(_ ctx : JavascriptContext, _ v: JavascriptValue) {
    let ref = PromiseBlobFromJavascriptValue(ctx.reference, v.reference)
    self = Blob(reference: ref!)
  }

}
