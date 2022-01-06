// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public typealias MessagePortListenerCallback = (_: MessageEvent) -> Void

public class MessagePort {

  var reference: MessagePortRef
  var owned: OwnedMessagePortRef?
  private var listeners: [MessagePortListenerHolder] = []
  private var window: WebWindow?
  private var worker: WebWorker?
  private var globalScope: ServiceWorkerGlobalScope?

  public init(window: WebWindow) {
    owned = MessagePortCreate()
    self.window = window
    self.reference = MessagePortGetReference(owned!)
  }

  public init(owning: MessagePort, worker: WebWorker) {
    owned = MessagePortCreateOwning(owning.reference)
    self.reference = owning.reference
    self.worker = worker
  }

  public init(owning: MessagePort, globalScope: ServiceWorkerGlobalScope) {
    owned = MessagePortCreateOwning(owning.reference)
    self.reference = owning.reference
    self.globalScope = globalScope
  }

  init(reference: MessagePortRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: MessagePortRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }
  // FIXME: temp to support ServiceWorker
  init(reference: MessagePortRef) {
    self.reference = reference
  }

  deinit {
    if let ref = owned {
      MessagePortDestroy(ref)
    }
  }

  public func onMessage(_ listenerCallback: @escaping MessagePortListenerCallback) -> Bool {
    // FIXME: the consumer might be a worker on the worker thread size, so window wont cut it 
    let state = MessagePortListenerHolder(callback: listenerCallback, window: window!)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    return MessagePortSetOnMessageEventListener(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
      let holder = unsafeBitCast(handle, to: MessagePortListenerHolder.self)
      if let cb = holder.callback {
        cb(MessageEvent(reference: evhandle!, window: holder.window))
      }
      //holder.dispose()
    }) != 0
  }

  // public func removeEventListener(
  //   _ event: String,
  //   listener: EventListener) -> Bool {
  //   var index: Int = 0
  //   var maybeHolder: MessagePortListenerHolder?
  //   for (i, listener) in listeners.enumerated() {
  //     if listener.event == event {
  //       index = i
  //       maybeHolder = listener
  //       break
  //     }
  //   }
  //   guard let state = maybeHolder else {
  //     return false
  //   }
  //   let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  //   let result = event.withCString {
  //     return MessagePortRemoveEventListener(reference, $0, listenerState) != 0
  //   }
  //   listeners.remove(at: index)
  //   return result
  // }

  public func postMessage(string: String, ports: [MessagePort] = []) {
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    string.withCString {
      if let wrk = worker {
        MessagePortPostMessageStringFromWorker(reference, wrk.reference, portRefs, CInt(ports.count), $0, CInt(string.count))
      }
      if let wnd = window {
        MessagePortPostMessageString(reference, wnd.reference, portRefs, CInt(ports.count), $0, CInt(string.count))
      }
      if let global = globalScope {
        MessagePortPostMessageStringFromServiceWorker(reference, global.reference, portRefs, CInt(ports.count), $0, CInt(string.count))
      }
    }
    free(portRefs)
  }

  public func postMessage(blob: Blob, ports: [MessagePort] = []) {
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    if let wrk = worker {
      MessagePortPostMessageBlobFromWorker(reference, wrk.reference, portRefs, CInt(ports.count), blob.reference)
    }
    if let wnd = window {
      MessagePortPostMessageBlob(reference, wnd.reference, portRefs, CInt(ports.count), blob.reference)
    }
    free(portRefs)
  }

  public func postMessage(arrayBuffer: ArrayBuffer, ports: [MessagePort] = []) {
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    if let wrk = worker {
      MessagePortPostMessageArrayBufferFromWorker(reference, wrk.reference, portRefs, CInt(ports.count), arrayBuffer.reference)
    }
    if let wnd = window {
      MessagePortPostMessageArrayBuffer(reference, wnd.reference, portRefs, CInt(ports.count), arrayBuffer.reference)
    }
    free(portRefs)
  }

  public func postMessage(serializedScriptValue: SerializedScriptValue) {
    if let wrk = worker {
      MessagePortPostMessageSerializedScriptValueFromWorker(reference, wrk.reference, serializedScriptValue.ownedReference)
    }
    if let wnd = window {
      MessagePortPostMessageSerializedScriptValue(reference, wnd.reference, serializedScriptValue.ownedReference)
    }
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
    var serialized: SerializedScriptValue?
    if let wrk = worker {
      serialized = SerializedScriptValue(worker: wrk, string: string, ports: ports)
    } 
    if let wnd = window {
      serialized = SerializedScriptValue(window: wnd, string: string, ports: ports)
    }
    postMessage(serializedScriptValue: serialized!)
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
    var serialized: SerializedScriptValue?
    if let wrk = worker {
      serialized = SerializedScriptValue(worker: wrk, blob: blob, ports: ports)
    } 
    if let wnd = window {
      serialized = SerializedScriptValue(window: wnd, blob: blob, ports: ports)
    }
    postMessage(serializedScriptValue: serialized!)
  }

  public func postArrayBuffer(_ array: ArrayBuffer, ports: [MessagePort] = []) {
    var serialized: SerializedScriptValue?
    if let wrk = worker {
      serialized = SerializedScriptValue(worker: wrk, array: array, ports: ports)
    } 
    if let wnd = window {
      serialized = SerializedScriptValue(window: wnd, array: array, ports: ports)
    }
    postMessage(serializedScriptValue: serialized!)
  }

  public func postSerializedScriptValue(_ serialized: SerializedScriptValue) {
    WebWorkerPostMessageSerializedScriptValue(reference, window!.reference, serialized.ownedReference)
  }

  public func postStruct(_ object: Any) {

  }

  internal func destroy(_ holder: MessagePortListenerHolder) {
    for (i, item) in listeners.enumerated() {
      if item === holder {
        listeners.remove(at: i)
      }
    }
  }

}

internal class MessagePortListenerHolder {

  var callback: MessagePortListenerCallback?
  var window: WebWindow

  init(callback: @escaping MessagePortListenerCallback, window: WebWindow) {
    self.callback = callback
    self.window = window
  }

}