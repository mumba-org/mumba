// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Javascript
import Foundation
import MumbaShims

public typealias WebWorkerListenerCallback = (_: MessageEvent) -> Void
public typealias WebWorkerTaskCallback = (_: WebWorkerContext) -> Void
public typealias RequestAnimationCallback = (_: Double) -> Void

public protocol WebWorkerNative : class {
  
  var worker: WebWorker? { get }
  var threadId: Int { get }

  func onInit(context: WebWorkerContext)
  func onMessage(event: MessageEvent)

  func evaluateScript(_ : String) -> Bool
}

extension WebWorkerNative {

  public var threadId: Int {
    guard let w = worker else {
      return -1
    }
    return w.threadId
  }

  public func evaluateScript( _ string: String) -> Bool {
    return worker?.evaluateScript(string) ?? false
  }

}

public enum WebWorkerType : Int {
  case classic = 0
  case module = 1
  case native = 2
}

@dynamicMemberLookup
@dynamicCallable
public struct WebWorkerContext {
  
  public let worker: WebWorker
  public var global: JavascriptObject {
    return worker.jsGlobal!
  }
  public var jsContext: JavascriptContext {
    return worker.jsContext!
  }

  public init(worker: WebWorker) {
    self.worker = worker
  }

  public subscript(dynamicMember name: String) -> JavascriptValue {
    get {
      guard let result = global.get(key: name) else {
        return JavascriptValue.Undefined(context: worker.jsContext!)
      }
      result.parent = global
      return result
    }
  }
    
  public subscript(key: [JavascriptConvertible]) -> JavascriptValue {
    get {
      let keyValue = flattenedSubscriptIndices(worker.jsContext!, key)
      guard let result = global.get(key: keyValue) else {
        return JavascriptValue.Undefined(context: worker.jsContext!)
      }
      result.parent = global
      return result
    }
    set {
      let keyObject = flattenedSubscriptIndices(worker.jsContext!, key)
      let _ = global.set(key: keyObject, value: newValue)
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

  @discardableResult
  public func dynamicallyCall(
    withArguments args: JavascriptConvertible...) -> JavascriptValue {
    if let fn = global.cast(to: JavascriptFunction.self) {
      let argArray = args.map { $0.javascriptValue }
      return fn.call(recv: global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
    }
    return JavascriptValue.Undefined(context: worker.jsContext!)
  }

  @discardableResult
  public func dynamicallyCall(
    withArguments args: [JavascriptConvertible] = []) -> JavascriptValue {
    if let fn = global.cast(to: JavascriptFunction.self) {
      let argsArray = args.map { $0.javascriptValue }
      return fn.call(recv: global, argc: args.count, argv: argsArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
    }
    return JavascriptValue.Undefined(context: worker.jsContext!)
  }

  @discardableResult
  public func dynamicallyCall(
      withKeywordArguments args:
      KeyValuePairs<String, JavascriptConvertible> = [:]) -> JavascriptValue {
    if let fn = global.cast(to: JavascriptFunction.self) {
      let argArray = args.map { $0.1.javascriptValue }
      return fn.call(recv: global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
    }
    return JavascriptValue.Undefined(context: worker.jsContext!)
  }
}

public class WebWorker {

  public var type: WebWorkerType {
    return WebWorkerType(rawValue: Int(WebWorkerGetType(reference)))!
  }

  internal var threadId: Int {
    return Int(WebWorkerGetThreadId(reference))
  }
  
  public var reference: WebWorkerRef!

  let window: WebWindow
  var native: WebWorkerNative?
  private var listeners: [ListenerCallbackState] = []
  private var tasks: [TaskCallbackState] = []
  internal var callbacks: [FetchCallbackState] = []
  private var tasksLock: Lock = Lock()

  internal var jsGlobal: JavascriptObject?
  internal var jsContext: JavascriptContext?

  public init(window: WebWindow, url: String) {
    self.window = window
    reference = url.withCString {
      return WebWorkerCreate(window.reference, $0)
    }
  }

  public init(window: WebWindow, native: WebWorkerNative) {
    self.window = window
    self.native = native
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    var callbacks = WorkerNativeClientCallbacks()
    memset(&callbacks, 0, MemoryLayout<WorkerNativeClientCallbacks>.stride)

    callbacks.OnInit = { (handle: UnsafeMutableRawPointer?, workerGlobalScope: UnsafeMutableRawPointer?) in 
      let this = unsafeBitCast(handle, to: WebWorker.self)
      this.jsContext = JavascriptContext(reference: WebWorkerGetV8Context(this.reference))
      this.jsGlobal = JavascriptObject(context: this.jsContext!, reference: WebWorkerGetV8GlobalWithContext(this.reference, this.jsContext!.reference))
      this.native!.onInit(context: WebWorkerContext(worker: this))
    }
    callbacks.OnMessage = { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?, port: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, portCount: CInt, bitmapsRef: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, bitmapsCount: CInt) in 
      let this = unsafeBitCast(handle, to: WebWorker.self)
      var ports: [MessagePort] = []
      var bitmaps: [ImageBitmap] = []
      for i in 0..<Int(portCount) {
        ports.append(MessagePort(reference: port![i]!, worker: this))
      }
      for i in 0..<Int(bitmapsCount) {
        bitmaps.append(ImageBitmap(reference: bitmapsRef![i]!))
      }
      this.native!.onMessage(event: MessageEvent(reference: evhandle!, worker: this, ports: ports, bitmaps: bitmaps))
    }
    reference = WebWorkerCreateNative(window.reference, state, callbacks)
  }

  deinit {
    WebWorkerDestroy(reference)
  }

  public func terminate() {
    WebWorkerTerminate(reference)
  }

  public func onMessage(_ callback: @escaping WebServiceListenerCallback) -> Bool {
    let state = ListenerCallbackState(self, window, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    return WebWorkerSetOnMessageEventListener(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
      let holder = unsafeBitCast(handle, to: ListenerCallbackState.self)
      if let cb = holder.callback {
        cb(MessageEvent(reference: evhandle!, window: holder.window))
      }
    }) != 0
  }

  public func requestAnimationFrame(_ callback: @escaping RequestAnimationCallback) {
    let state = ListenerCallbackState(self, window, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    WebWorkerRequestAnimationFrame(reference, listenerState, { (handle: UnsafeMutableRawPointer?, highres: Double) in
      let holder = unsafeBitCast(handle, to: ListenerCallbackState.self)
      if let cb = holder.requestAnimationCallback {
        cb(highres)
      }
      holder.dispose()
    })
  }

  public func postMessage<T>(_ data: T, ports: [MessagePort] = []) {
    switch T.self {
      case is String.Type:
        postString(data as! String, ports: ports)
      case is UInt8.Type:
        postUInt8(data as! UInt8, ports: ports)
      case is UInt16.Type:
        postUInt16(data as! UInt16, ports: ports)  
      case is UInt.Type:
        postUInt(data as! UInt, ports: ports)
      case is UInt32.Type:
        postUInt32(data as! UInt32, ports: ports)     
      case is UInt64.Type:
        postUInt64(data as! UInt64, ports: ports)
      case is Int8.Type:
        postInt8(data as! Int8, ports: ports)
      case is Int16.Type:
        postInt16(data as! Int16, ports: ports)
      case is Int32.Type:
        postInt32(data as! Int32, ports: ports)
      case is Int.Type:
        postInt(data as! Int, ports: ports)
      case is Int64.Type:
        postInt64(data as! Int64, ports: ports)
      case is Float.Type:
        postFloat(data as! Float, ports: ports)  
      case is Double.Type:
        postDouble(data as! Double, ports: ports)
      case is Data.Type:
        postData(data as! Data, ports: ports)
      case is UnsafeMutableRawPointer.Type:
        postBytes(data as! UnsafeMutableRawPointer, ports: ports)
      case is Blob.Type:
        postBlob(data as! Blob, ports: ports)
      case is ArrayBuffer.Type:
        postArrayBuffer(data as! ArrayBuffer, ports: ports)  
      //case is Array.Type:
      //  postArray(data as! Array)
      //case is Any.Type: // ?? does it work giving anything is Any?
      //  postStruct(data as Any)
      default:
        postStruct(data)
    }
  }

  public func postString(_ string: String, ports: [MessagePort] = []) {
    let serialized = SerializedScriptValue(window: window, string: string, ports: ports)
    postSerializedScriptValue(serialized)
  }
  
  public func postUInt(_ uint: UInt, ports: [MessagePort] = []) {

  }

  public func postUInt8(_ uint: UInt8, ports: [MessagePort] = []) {

  }

  public func postUInt16(_ uint: UInt16, ports: [MessagePort] = []) {

  }

  public func postUInt32(_ uint: UInt32, ports: [MessagePort] = []) {

  }

  public func postUInt64(_ int: UInt64, ports: [MessagePort] = []) {
    
  }
  
  public func postInt8(_ int: Int8, ports: [MessagePort] = []) {

  }

  public func postInt16(_ int: Int16, ports: [MessagePort] = []) {

  }

  public func postInt32(_ int: Int32, ports: [MessagePort] = []) {

  }

  public func postInt(_ int: Int, ports: [MessagePort] = []) {

  }

  public func postInt64(_ int: Int64, ports: [MessagePort] = []) {

  }
      
  public func postFloat(_ float: Float, ports: [MessagePort] = []) {

  }
      
  public func postDouble(_ double: Double, ports: [MessagePort] = []) {

  }
      
  public func postData(_ data: Data, ports: [MessagePort] = []) {

  }
      
  public func postBytes(_ bytes: UnsafeMutableRawPointer, ports: [MessagePort] = []) {

  }

  public func postBlob(_ blob: Blob, ports: [MessagePort] = []) {
    let serialized = SerializedScriptValue(window: window, blob: blob, ports: ports)
    postSerializedScriptValue(serialized)
  }

  public func postArrayBuffer(_ array: ArrayBuffer, ports: [MessagePort] = []) {
    let serialized = SerializedScriptValue(window: window, array: array, ports: ports)
    postSerializedScriptValue(serialized)
  }

  public func postSerializedScriptValue(_ serialized: SerializedScriptValue) {
    WebWorkerPostMessageSerializedScriptValue(reference, window.reference, serialized.ownedReference)
  }

  public func postStruct(_ object: Any) {

  }

  public func postArray<T>(_ array: Array<T>) {
     switch T.self {
      case is String.Type:
        postStringArray(array as! Array<String>)
      case is UInt8.Type:
        postUInt8Array(array as! Array<UInt8>)
      case is UInt16.Type:
        postUInt16Array(array as! Array<UInt16>)  
      case is UInt.Type:
        postUIntArray(array as! Array<UInt>)
      case is UInt32.Type:
        postUInt32Array(array as! Array<UInt32>)     
      case is UInt64.Type:
        postUInt64Array(array as! Array<UInt64>)
      case is Int8.Type:
        postInt8Array(array as! Array<Int8>)
      case is Int16.Type:
        postInt16Array(array as! Array<Int16>)
      case is Int32.Type:
        postInt32Array(array as! Array<Int32>)
      case is Int.Type:
        postIntArray(array as! Array<Int>)
      case is Int64.Type:
        postInt64Array(array as! Array<Int64>)
      case is Float.Type:
        postFloatArray(array as! Array<Float>)  
      case is Double.Type:
        postDoubleArray(array as! Array<Double>)
      default:
        break
      //case is Any.Type:
      //  postStructArray(array as! Array<Any>)
     }
  }

  public func postStringArray(_ array: Array<String>) {
    
  }

  public func postUInt8Array(_ array: Array<UInt8>) {
   
  }

  public func postUInt16Array(_ array: Array<UInt16>) { 
   
  }

  public func postUIntArray(_ array: Array<UInt>) {
    
  }

  public func postUInt32Array(_ array: Array<UInt32>) {
    
  }

  public func postUInt64Array(_ array: Array<UInt64>) {
    
  }

  public func postInt8Array(_ array: Array<Int8>) {
    
  }

  public func postInt16Array(_ array: Array<Int16>) {
    
  }

  public func postInt32Array(_ array: Array<Int32>) {
    
  }

  public func postIntArray(_ array: Array<Int>) {
    
  }

  public func postInt64Array(_ array: Array<Int64>) {
    
  }

  public func postFloatArray(_ array: Array<Float>)  {
    
  }

  public func postDoubleArray(_ array: Array<Double>) {
    
  }

  public func postStructArray(_ array: Array<Any>) {
    
  }

  public func postTask(_ task: @escaping WebWorkerTaskCallback) {
    postDelayedTask(task, delay: TimeDelta())
  }

  public func postDelayedTask(_ task: @escaping WebWorkerTaskCallback, delay: TimeDelta) {
    let state = TaskCallbackState(self, task)
    addTaskCallback(state)
    let taskState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    WebWorkerPostTask(reference, delay.microseconds, taskState, { (handle: UnsafeMutableRawPointer?) in 
      let holder = unsafeBitCast(handle, to: TaskCallbackState.self)
      holder.callback(WebWorkerContext(worker: holder.worker!))
      // note: dispose will use a reference to <this> web worker object here
      // to remove itself.. while the array have a proper lock, the handle itself doesnt
      // so we might get into trouble here if this web worker is also acessed by the 'main' thread
      // at the same time.
      // (find a way to fix this issue, as the program may break and it will be hard to know whatever hit them)
      holder.dispose()
    })
  }

  // only to be used when is a 'native' worker
  internal func evaluateScript(_ string: String) -> Bool {
    return string.withCString {
      return WebWorkerEvaluateScriptSource(reference, $0)
    } != 0
  }

  internal func addListenerCallback(_ cb: ListenerCallbackState) {
    listeners.append(cb)
  }

  internal func removeListenerCallback(_ cb: ListenerCallbackState) {
    for (i, item) in listeners.enumerated() {
      if item === cb {
        listeners.remove(at: i)
        return
      }
    }
  }

  fileprivate func addTaskCallback(_ cb: TaskCallbackState) {
    tasks.append(cb)
  }

  fileprivate func removeTaskCallback(_ cb: TaskCallbackState) {
    tasksLock.withLock {
      for (i, item) in self.tasks.enumerated() {
        if item === cb {
          self.tasks.remove(at: i)
          return
        }
      }
    }
  }


}

internal class ListenerCallbackState {

  weak var worker: WebWorker?
  var callback: WebWorkerListenerCallback?
  var requestAnimationCallback: RequestAnimationCallback?
  let window: WebWindow

  init(_ worker: WebWorker, _ window: WebWindow, _ cb: @escaping WebWorkerListenerCallback) {
    self.worker = worker
    self.callback = cb
    self.window = window
  }

  init(_ worker: WebWorker, _ window: WebWindow, _ cb: @escaping RequestAnimationCallback) {
    self.worker = worker
    self.requestAnimationCallback = cb
    self.window = window
  }

  func dispose() {
    if self.requestAnimationCallback != nil {
      self.worker!.removeListenerCallback(self)
    }
  }

}

fileprivate class TaskCallbackState {

  weak var worker: WebWorker?
  let callback: WebWorkerTaskCallback

  init(_ worker: WebWorker, _ cb: @escaping WebWorkerTaskCallback) {
    self.worker = worker
    self.callback = cb
  }

  func dispose() {
    // FIXME: worker also NEEDS A LOCK here
    // as dispose is called from the worker thread
    worker!.removeTaskCallback(self)
  }

}