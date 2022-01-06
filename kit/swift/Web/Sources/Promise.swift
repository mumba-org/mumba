// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public typealias PromiseResolveFunctionCallback<T : ScriptValue> = (_: T) -> Void
public typealias PromiseResolveJavascriptFunctionCallback = (_: JavascriptValue) -> Void
public typealias PromiseRejectFunctionCallback = () -> Void

public protocol PromiseCallbackOwner : class {
  func thenFunc(_ : JavascriptContext, _ : JavascriptValue)
  func onFunctionCallbackCreate(_ : FunctionCallbackState)
  func onFunctionCallbackDispose(_ : FunctionCallbackState)
}

public class Promise<T: ScriptValue> : PromiseCallbackOwner {
  
  var reference: ScriptPromiseRef
  var window: WebWindow?
  var worker: WebWorker?
  var scope: ServiceWorkerGlobalScope?
  var thenCallback: PromiseResolveFunctionCallback<T>?

  private var callbackStates: ContiguousArray<FunctionCallbackState> = ContiguousArray<FunctionCallbackState>()

  init(reference: ScriptPromiseRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: ScriptPromiseRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: ScriptPromiseRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  // FIXME: support for service worker global scope
  init(reference: ScriptPromiseRef) {
    self.reference = reference
  }

  deinit {
    WebScriptPromiseDestroy(reference)
  }

  // FIXME: non-js(aka non v8::Value) promises
  public func then(_ callback: @escaping PromiseResolveFunctionCallback<T>, _ rejected: @escaping PromiseRejectFunctionCallback) -> Promise<T> {
    if window != nil {
      return thenforWindow(callback, rejected)
    }
    return thenforWorker(callback, rejected)
  }

  // public func catch(_ callback: @escaping JavascriptFunctionCallback) {
  //   let state = FunctionCallbackState(self, callback)
  //   let stateRef = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  //   WebScriptPromiseCatch(reference, window, stateRef, { (handle: UnsafeMutableRawPointer?) in 
  //     print("ScriptPromise.catch() callback called()")
  //     let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
  //     funcState.callback()
  //     funcState.dispose()
  //   })
  // }

  public func onFunctionCallbackCreate(_ state: FunctionCallbackState) {
    callbackStates.append(state)
  }

  public func onFunctionCallbackDispose(_ state: FunctionCallbackState) {
    for (i, cur) in callbackStates.enumerated() {
      if cur === state { 
        callbackStates.remove(at: i)
        return
      }
    }
  }

  public func thenFunc(_ ctx: JavascriptContext,  _ value: JavascriptValue) {
    thenCallback!(T(ctx, value)!)
  }


  private func thenforWindow(_ callback: @escaping PromiseResolveFunctionCallback<T>, _ rejected: @escaping PromiseRejectFunctionCallback) -> Promise<T> {
    thenCallback = callback
    let state = FunctionCallbackState(self, rejected)
    let stateRef = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let ref = WebScriptPromiseThen(reference, self.window!.reference, stateRef, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, p0: UnsafeMutableRawPointer?) in 
      let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
      // this is temporary and will get out of scope, so just use it to get 'T' out of it
      let jsContext = JavascriptContext(reference: context!)
      let arg = JavascriptValue(context: jsContext, reference: p0!)
      funcState.then(jsContext, arg)
      funcState.dispose()
    },{ (handle: UnsafeMutableRawPointer?) in 
      let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
      funcState.rejected()
      funcState.dispose()
    })
    return Promise(reference: ref!, window: window!)
  }

  private func thenforWorker(_ callback: @escaping PromiseResolveFunctionCallback<T>, _ rejected: @escaping PromiseRejectFunctionCallback) -> Promise<T> {
    thenCallback = callback
    let state = FunctionCallbackState(self, rejected)
    let stateRef = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let ref = WebScriptPromiseThenForWorker(reference, self.worker!.reference, stateRef, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, p0: UnsafeMutableRawPointer?) in 
      let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
      // this is temporary and will get out of scope, so just use it to get 'T' out of it
      let jsContext = JavascriptContext(reference: context!)
      let arg = JavascriptValue(context: jsContext, reference: p0!)
      funcState.then(jsContext, arg)
      funcState.dispose()
    },{ (handle: UnsafeMutableRawPointer?) in 
      let funcState = unsafeBitCast(handle, to: FunctionCallbackState.self)
      funcState.rejected()
      funcState.dispose()
    })
    return Promise(reference: ref!, worker: worker!)
  }

}

public class FunctionCallbackState {
  
  let rejected: PromiseRejectFunctionCallback
  var owner: PromiseCallbackOwner?
  
  init(_ owner: PromiseCallbackOwner, _ rejected: @escaping PromiseRejectFunctionCallback) {
    self.owner = owner
    self.rejected = rejected
    self.owner!.onFunctionCallbackCreate(self)
  }

  func then(_ ctx: JavascriptContext, _ arg: JavascriptValue) {
    self.owner!.thenFunc(ctx, arg)
  }

  func dispose() {
    owner!.onFunctionCallbackDispose(self)
  } 
}