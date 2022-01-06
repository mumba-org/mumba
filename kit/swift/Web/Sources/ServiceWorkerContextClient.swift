// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript
import Base

public typealias ServiceWorkerMessageListenerCallback = (_: ExtendableMessageEvent) -> Void
public typealias ServiceWorkerFetchListenerCallback = (_: FetchEvent) -> Void
public typealias ServiceWorkerInstallListenerCallback = (_: InstallEvent) -> Void
public typealias ServiceWorkerActivateListenerCallback = (_: ExtendableEvent) -> Void
public typealias ServiceWorkerClientsGetCallback = (_: ServiceWorkerClient?) -> Void
public typealias ServiceWorkerClientsClaimCallback = () -> Void
public typealias ServiceWorkerTaskCallback = (_: ServiceWorkerGlobalScope) -> Void

public protocol ServiceWorkerContextClient : class {
  var unsafeState: UnsafeMutableRawPointer? { get }
  var callbacks: WorkerNativeClientCallbacks { get }
}

public protocol ServiceWorkerContextClientDelegate {
  // FIXME: find a way to not leak ServiceWorkerGlobalScope which is more of a internal
  //        object.. the problem is 'init' is called on the global scope object
  //        where we dont have access to the proper ServiceWorker object
  func onInit(global: ServiceWorkerGlobalScope)
  func onMessage(event: ExtendableMessageEvent)
  func onTerminate()
}

public class ServiceWorkerContextClientImpl : ServiceWorkerContextClient {
  
  public var unsafeState: UnsafeMutableRawPointer? {
    return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  }
  
  public var callbacks: WorkerNativeClientCallbacks

  let delegate: ServiceWorkerContextClientDelegate
  var scope: ServiceWorkerGlobalScope?
  
  public init(delegate: ServiceWorkerContextClientDelegate) {
    self.delegate = delegate
    callbacks = WorkerNativeClientCallbacks()
    memset(&callbacks, 0, MemoryLayout<WorkerNativeClientCallbacks>.stride)
    callbacks.OnInit = { (handle: UnsafeMutableRawPointer?, workerGlobalScope: UnsafeMutableRawPointer?) in
      let state = unsafeBitCast(handle, to: ServiceWorkerContextClientImpl.self)
      state.scope = ServiceWorkerGlobalScope(reference: workerGlobalScope!)
      state.delegate.onInit(global: state.scope!)
    }
    callbacks.OnTerminate = { (handle: UnsafeMutableRawPointer?) in
      let state = unsafeBitCast(handle, to: ServiceWorkerContextClientImpl.self)
      state.delegate.onTerminate()
    }
    callbacks.OnMessage = { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?, port: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, portCount: CInt, bitmaps: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, bitmapCount: CInt) in
      var ports: [MessagePort] = []
      let state = unsafeBitCast(handle, to: ServiceWorkerContextClientImpl.self)
      for i in 0..<Int(portCount) {
        ports.append(MessagePort(reference: port![i]!))
      }
      state.delegate.onMessage(event: ExtendableMessageEvent(reference: evhandle!, scope: state.scope!, ports: ports))
    }
  }
}

// FIXME: find a way to not leak ServiceWorkerGlobalScope which is more of a internal
//        object.. the problem is 'init' is called on the global scope object
//        where we dont have access to the proper ServiceWorker object
public class ServiceWorkerGlobalScope : FetchCallbackHolder {

  public var isInstalling: Bool {
    return ServiceWorkerGlobalScopeIsInstalling(reference) != 0
  }

  public var serviceWorker: WebServiceWorker {
    if _serviceWorker == nil {
      _serviceWorker = WebServiceWorker(reference: ServiceWorkerGlobalScopeGetServiceWorker(reference), globalScope: self)
    }
    return _serviceWorker!
  }

  public var javascriptContext: JavascriptContext {
    if _javascriptContext == nil {
      _javascriptContext = JavascriptContext(reference: ServiceWorkerGlobalScopeGetJavascriptContext(reference))
    }
    return _javascriptContext!
  }

  public var clients: ServiceWorkerClients {
    if _clients == nil {
      _clients = ServiceWorkerClients(reference: ServiceWorkerGlobalScopeGetClients(reference), scope: self)
    }
    return _clients!
  }
  
  public let reference: ServiceWorkerGlobalScopeRef
  internal var callbacks: [FetchCallbackState] = []
  internal var listeners: [ServiceWorkerListenerCallbackState] = []
  private var _javascriptContext: JavascriptContext?
  private var _serviceWorker: WebServiceWorker?
  private var _clients: ServiceWorkerClients?
  private var tasks: [TaskCallbackState] = []
  private var tasksLock: Lock = Lock()

  public init(reference: ServiceWorkerGlobalScopeRef) {
    self.reference = reference
  }

  public func skipWaiting() -> Promise<None> {
    return Promise(reference: ServiceWorkerGlobalScopeSkipWaiting(reference))
  }

  public func fetch(url: String, _ callback: @escaping FetchCallback) {
    let state = FetchCallbackState(scope: self, self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    url.withCString {
      ServiceWorkerGlobalScopeFetch(reference, $0, statePtr, { (handle: UnsafeMutableRawPointer?, response: UnsafeMutableRawPointer?) in
        let cbState = unsafeBitCast(handle, to: FetchCallbackState.self)
        cbState.run(Response(reference: response!, workerGlobalScope: cbState.scope!))
        cbState.dispose()
      })
    }
  }

  public func evaluateScript(_ str: String) {
    str.withCString {
      ServiceWorkerGlobalScopeEvaluateScriptSource(reference, $0)
    }
  }

  // public func postMessage(string: String) {
  //   //ServiceWorkerGlobalScopePostMessageString(ServiceWorkerGlobalScopeRef handle, MessagePortRef* ports, int port_count, const char* message, int message_len)
  // }

  // public func postMessage(blob: Blob) {
  //   //ServiceWorkerGlobalScopePostMessageBlob(ServiceWorkerGlobalScopeRef handle, MessagePortRef* ports, int port_count, BlobRef blob)
  // }

  // public func postMessage(buffer: ArrayBuffer) {
  //   //ServiceWorkerGlobalScopePostMessageArrayBuffer(ServiceWorkerGlobalScopeRef handle, MessagePortRef* ports, int port_count, DOMArrayBufferRef buffer)
  // }

  // public func postMessage(serializedScriptValue: SerializedScriptValue) {
  //   //ServiceWorkerGlobalScopePostMessageSerializedScriptValue(ServiceWorkerGlobalScopeRef handle, OwnedSerializedScriptValueRef serialized_script)
  // }

  public func postTask(_ task: @escaping ServiceWorkerTaskCallback) {
    postDelayedTask(task, delay: TimeDelta())
  }

  public func postDelayedTask(_ task: @escaping ServiceWorkerTaskCallback, delay: TimeDelta) {
    let state = TaskCallbackState(self, task)
    addTaskCallback(state)
    let taskState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    ServiceWorkerGlobalScopePostTask(reference, delay.microseconds, taskState, { (handle: UnsafeMutableRawPointer?) in 
      let holder = unsafeBitCast(handle, to: TaskCallbackState.self)
      holder.callback(holder.worker!)
      // note: dispose will use a reference to <this> web worker object here
      // to remove itself.. while the array have a proper lock, the handle itself doesnt
      // so we might get into trouble here if this web worker is also acessed by the 'main' thread
      // at the same time.
      // (find a way to fix this issue, as the program may break and it will be hard to know whatever hit them)
      holder.dispose()
    })
  }

  public func onMessage(_ callback: @escaping ServiceWorkerMessageListenerCallback) {
    let state = ServiceWorkerListenerCallbackState(self, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    ServiceWorkerGlobalScopeSetOnMessageEventListener(reference, listenerState, 
     { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
       let holder = unsafeBitCast(handle, to: ServiceWorkerListenerCallbackState.self)
       if let cb = holder.messageCallback {
         cb(ExtendableMessageEvent(reference: evhandle!, scope: holder.globalScope!))
       }
     })
  }

  public func onInstall(_ callback: @escaping ServiceWorkerInstallListenerCallback) {
    let state = ServiceWorkerListenerCallbackState(self, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    ServiceWorkerGlobalScopeSetOnInstallEventListener(reference, listenerState, 
     { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
       let holder = unsafeBitCast(handle, to: ServiceWorkerListenerCallbackState.self)
       if let cb = holder.installCallback {
         cb(InstallEvent(reference: evhandle!))
       }
     }
    )
  }

  public func onActivate(_ callback: @escaping ServiceWorkerActivateListenerCallback) {
    let state = ServiceWorkerListenerCallbackState(self, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    ServiceWorkerGlobalScopeSetOnActivateEventListener(reference, listenerState, 
     { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
       let holder = unsafeBitCast(handle, to: ServiceWorkerListenerCallbackState.self)
       if let cb = holder.activateCallback {
         cb(ExtendableEvent(reference: evhandle!, scope: holder.globalScope!))
       }
     }
    )
  }

  public func onFetch(_ callback: @escaping ServiceWorkerFetchListenerCallback) {
    let state = ServiceWorkerListenerCallbackState(self, callback)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    ServiceWorkerGlobalScopeSetOnFetchEventListener(reference, listenerState, 
     { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
       let holder = unsafeBitCast(handle, to: ServiceWorkerListenerCallbackState.self)
       if let cb = holder.fetchCallback {
         cb(FetchEvent(reference: evhandle!, scope: holder.globalScope!))
       }
     }
    )
  }

  public func addCallback(_ state: FetchCallbackState) {
    callbacks.append(state)
  }

  public func removeCallback(_ state: FetchCallbackState) {
    for (index, callback) in callbacks.enumerated() {
      if state === callback {
        callbacks.remove(at: index)
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

public class ServiceWorkerClients {
  let reference: WebServiceWorkerClientsRef
  let scope: ServiceWorkerGlobalScope
  var callbacks: [ServiceWorkerClientsCallbackState] = []

  init(reference: WebServiceWorkerClientsRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func get(uuid: String, _ cb: @escaping ServiceWorkerClientsGetCallback) {
    let state = ServiceWorkerClientsCallbackState(self, scope, cb)
    callbacks.append(state)
    let cbState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    uuid.withCString {
      WebServiceWorkerClientsGet(reference, scope.reference, $0, cbState, 
      { (handle: UnsafeMutableRawPointer?, client: UnsafeMutableRawPointer?) in 
        let holder = unsafeBitCast(handle, to: ServiceWorkerClientsCallbackState.self)
        holder.getCallback!(client == nil ? nil : ServiceWorkerClient(reference: client!, scope: holder.scope))
        holder.dispose()
      })
    }
  }

  public func claim(_ cb: @escaping ServiceWorkerClientsClaimCallback) {
    let state = ServiceWorkerClientsCallbackState(self, scope, cb)
    callbacks.append(state)
    let cbState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    WebServiceWorkerClientsClaim(reference, scope.reference, cbState, 
     { (handle: UnsafeMutableRawPointer?, value: UnsafeMutableRawPointer?) in 
       let holder = unsafeBitCast(handle, to: ServiceWorkerClientsCallbackState.self)
       holder.claimCallback!()
       holder.dispose()
     }
    )
  }

  public func claim() -> Promise<None> {
    return Promise(reference: WebServiceWorkerClientsClaimPromise(reference, scope.reference), scope: scope)
  }

  internal func addCallback(_ state: ServiceWorkerClientsCallbackState) {
    callbacks.append(state)
  }

  internal func removeCallback(_ state: ServiceWorkerClientsCallbackState) {
    for (index, callback) in callbacks.enumerated() {
      if state === callback {
        callbacks.remove(at: index)
        return
      }
    }
  }
}

public class ServiceWorkerClient {
  let reference: WebServiceWorkerClientRef
  let scope: ServiceWorkerGlobalScope
  init(reference: WebServiceWorkerClientsRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func postMessage(string: String, ports: [MessagePort]) {
    let serialized = SerializedScriptValue(scope: scope, string: string, ports: ports)    
    postMessage(serializedScriptValue: serialized)
  }

  public func postMessage(serializedScriptValue: SerializedScriptValue) {
    WebServiceWorkerClientPostMessage(reference, scope.reference, serializedScriptValue.ownedReference) 
  }
}

// FIXME: a simple CallbackState<T> where T = Callback type
//        could be reused for everyone
//        with a CallbackStateContainer owning the array of states
//        No reason to duplicate this code
internal class ServiceWorkerListenerCallbackState {

  var messageCallback: ServiceWorkerMessageListenerCallback?
  var fetchCallback: ServiceWorkerFetchListenerCallback?
  var installCallback: ServiceWorkerInstallListenerCallback?
  var activateCallback: ServiceWorkerActivateListenerCallback?
  weak var globalScope: ServiceWorkerGlobalScope?

  init(_ globalScope: ServiceWorkerGlobalScope, _ cb: @escaping ServiceWorkerMessageListenerCallback) {
    self.globalScope = globalScope
    self.messageCallback = cb
  }

  init(_ globalScope: ServiceWorkerGlobalScope, _ cb: @escaping ServiceWorkerFetchListenerCallback) {
    self.globalScope = globalScope
    self.fetchCallback = cb
  }

  init(_ globalScope: ServiceWorkerGlobalScope, _ cb: @escaping ServiceWorkerInstallListenerCallback) {
    self.globalScope = globalScope
    self.installCallback = cb
  }

  init(_ globalScope: ServiceWorkerGlobalScope, _ cb: @escaping ServiceWorkerActivateListenerCallback) {
    self.globalScope = globalScope
    self.activateCallback = cb
  }

}

// FIXME: a simple CallbackState<T> where T = Callback type
//        could be reused for everyone
//        with a CallbackStateContainer owning the array of states
//        No reason to duplicate this code everywhere
internal class ServiceWorkerClientsCallbackState {
  let clients: ServiceWorkerClients
  let scope: ServiceWorkerGlobalScope
  var getCallback: ServiceWorkerClientsGetCallback?
  var claimCallback: ServiceWorkerClientsClaimCallback?
  init(_ clients: ServiceWorkerClients, _ scope: ServiceWorkerGlobalScope, _ callback: @escaping ServiceWorkerClientsGetCallback) {
    self.clients = clients
    self.getCallback = callback
    self.scope = scope
  }

  init(_ clients: ServiceWorkerClients, _ scope: ServiceWorkerGlobalScope, _ callback: @escaping ServiceWorkerClientsClaimCallback) {
    self.clients = clients
    self.claimCallback = callback
    self.scope = scope
  }
  public func dispose() {
    clients.removeCallback(self)
  }
}

fileprivate class TaskCallbackState {

  weak var worker: ServiceWorkerGlobalScope?
  let callback: ServiceWorkerTaskCallback

  init(_ worker: ServiceWorkerGlobalScope, _ cb: @escaping ServiceWorkerTaskCallback) {
    self.worker = worker
    self.callback = cb
  }

  func dispose() {
    // FIXME: worker also NEEDS A LOCK here
    // as dispose is called from the worker thread
    worker!.removeTaskCallback(self)
  }

}