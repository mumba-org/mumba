// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public enum WebServiceWorkerResponseType : Int {
	case Basic = 0
    case CORS
    case Default
    case Error
    case Opaque
    case OpaqueRedirect
}

// public protocol WebServiceWorkerNetworkProvider {
//   // Returns an identifier of this provider.
//   var providerId: Int { get }

//   // Whether the document associated with WebDocumentLoader is controlled by a
//   // service worker.
//   var hasControllerServiceWorker: Bool { get }

//   // Returns an identifier of the service worker controlling the document
//   // associated with the WebDocumentLoader.
//   var controllerServiceWorkerId: Int64 { get }

//   // A request is about to be sent out, and the client may modify it. Request
//   // is writable, and changes to the URL, for example, will change the request
//   // made.
//   func willSendRequest(request: WebURLRequest)

//   // S13nServiceWorker:
//   // Returns a URLLoader for the associated context. May return nullptr
//   // if this doesn't provide a ServiceWorker specific URLLoader.
//   func createURLLoader(request: WebURLRequest) -> WebURLLoader?
// }

// extension WebServiceWorkerNetworkProvider {
//   public var providerId: Int { return -1 }	
//   public var hasControllerServiceWorker: Bool { return false }
//   public var controllerServiceWorkerId: Int64 { return -1 }
//   public func willSendRequest(request: WebURLRequest) {}
//   public func createURLLoader(request: WebURLRequest) -> WebURLLoader? {
//     return nil
//   }
// }

public typealias WebServiceListenerCallback = (_: MessageEvent) -> Void

public protocol WebResponseHandler : class {
  var unmanagedSelf: UnsafeMutableRawPointer? { get }
  var name: String { get }
  func createCallbacks() -> CResponseHandler
  func willHandleResponse(response: WebURLResponse) -> Bool
  func onDataAvailable(input: UnsafePointer<Int8>?, inputSize: Int) -> Int
  func onFinishLoading(errorCode: Int, totalTransferSize: Int) -> Int
  func writeResult(output: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?, 
                   outputSize: UnsafeMutablePointer<CInt>?)
}

public class WebServiceWorkerNetworkProvider {//: WebServiceWorkerNetworkProvider {
	
	public var serviceWorkerProviderId: Int {
    didSet {
      _WebServiceWorkerNetworkProviderSetServiceWorkerProviderId(reference, CInt(self.serviceWorkerProviderId))
    }
  }
	public var hasControllerServiceWorker: Bool { return false }
	public var controllerServiceWorkerId: Int64 { return -1 }
  public var handlers: ContiguousArray<WebResponseHandler>

	internal var reference: WebServiceWorkerNetworkProviderRef?
	private var loader: WebURLLoaderImpl?

	public init(providerId: Int, routeId: Int) {
    self.serviceWorkerProviderId = providerId
    handlers = ContiguousArray<WebResponseHandler>() 
	  
	  var callbacks = WebServiceWorkerNetworkProviderCbs()
	  memset(&callbacks, 0, MemoryLayout<WebServiceWorkerNetworkProviderCbs>.stride)
	  
	  callbacks.GetProviderId = { (handle: UnsafeMutableRawPointer?) -> CInt in 
	  	let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
	  	return CInt(state.serviceWorkerProviderId)
	  }

	  callbacks.HasControllerServiceWorker = { (handle: UnsafeMutableRawPointer?) -> CInt in 
	  	guard handle != nil else {
	  		//print("WebServiceWorkerNetworkProvider: BAD null passed to callback")
	  		return 0
	  	}
	  	let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
	  	return state.hasControllerServiceWorker ? 1 : 0
	  }

	  callbacks.GetControllerServiceWorkerId = { (handle: UnsafeMutableRawPointer?) -> Int64 in 
	  	let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
	  	return state.controllerServiceWorkerId
	  }

	  callbacks.WillSendRequest = { (handle: UnsafeMutableRawPointer?, req: UnsafeMutableRawPointer?) in 
	  	let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
	  	state.willSendRequest(request: WebURLRequest(reference: req!))
	  }

	  callbacks.CreateURLLoader = { (handle: UnsafeMutableRawPointer?, req: UnsafeMutableRawPointer?, callbacks: UnsafeMutablePointer<CBlinkPlatformCallbacks>?) -> UnsafeMutableRawPointer? in 
	  	let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
      let loader = state.createURLLoader(request: WebURLRequest(reference: req!)) as? WebURLLoaderImpl
      callbacks!.pointee = loader!.createCallbacks()
      return loader!.unmanagedSelf
	  }

    callbacks.CountResponseHandler = { (handle: UnsafeMutableRawPointer?) -> CInt in 
      let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
      return CInt(state.handlers.count)
    }

    callbacks.GetResponseHandlerAt = { (handle: UnsafeMutableRawPointer?, index: CInt, callbacks: UnsafeMutablePointer<CResponseHandler>?) -> UnsafeMutableRawPointer? in 
      let state = unsafeBitCast(handle, to: WebServiceWorkerNetworkProvider.self)
      let offset = Int(index)
      guard offset < state.handlers.endIndex else {
        print("GetResponseHandlerAt: returning null")
        return nil
      }
      let responseHandler = state.handlers[offset]
      callbacks!.pointee = responseHandler.createCallbacks()
      return responseHandler.unmanagedSelf
    }

	  let selfHandle = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
	  
    self.reference = _WebServiceWorkerNetworkProviderCreate(CInt(providerId), CInt(routeId), selfHandle, callbacks)
	}

	deinit {
	  _WebServiceWorkerNetworkProviderDestroy(reference)	
	}

  public func addHandler(_ handler: WebResponseHandler) {
    handlers.append(handler)
  }

  public func removeHandler(_ handler: WebResponseHandler) {
    for (index, item) in handlers.enumerated() {
      if item === handler {
        handlers.remove(at: index)
        return
      }
    } 
  }

  public func removeHandler(name: String) {
    for (index, item) in handlers.enumerated() {
      if item.name == name {
        handlers.remove(at: index)
        return
      }
    }
  }

	public func willSendRequest(request: WebURLRequest) {
    //print("WebServiceWorkerNetworkProvider.willSendRequest: (empty)")	
  }

  public func createURLLoader(request: WebURLRequest) -> WebURLLoader? {
    // NOTE: we are keeping a reference, so the object dont go away 
    //       see how we can manage this in a more
    //       clever way
    loader = WebURLLoaderImpl(request: request)
    return loader
  }
}

public class WebServiceWorkerRegistration : ScriptValue {

  public var installing: WebServiceWorker? {
    guard let ref = WebServiceWorkerRegistrationGetInstalling(reference) else {
      return nil
    }
    return WebServiceWorker(reference: ref, context: context!)
  }
  
  public var waiting: WebServiceWorker? {
    guard let ref = WebServiceWorkerRegistrationGetWaiting(reference) else {
      return nil
    }
    return WebServiceWorker(reference: ref, context: context!)
  }
  
  public var active: WebServiceWorker? {
    guard let ref = WebServiceWorkerRegistrationGetActive(reference) else {
      return nil
    }
    return WebServiceWorker(reference: ref, context: context!)
  }
  
  public var scope: String {
    var len: CInt = 0
    let cstr = WebServiceWorkerRegistrationGetScope(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  public var updateViaCache: String {
    var len: CInt = 0
    let cstr = WebServiceWorkerRegistrationGetUpdateViaCache(reference, &len)
    return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
  }

  public var navigationPreload: WebNavigationPreloadManager? {
    guard let ref = WebServiceWorkerRegistrationGetNavigationPreload(reference) else {
      return nil
    }
    return WebNavigationPreloadManager(reference: ref)
  }

  public var onUpdateFoundListener: ListenerCallback? {
    get {
      return _onUpdateFoundListener
    }
    set {
      guard let listener = newValue else {
        return
      }
      //WebServiceWorkerRegistrationAddOnUpdateFoundEventListener(reference, void* state, void(*on_updatefound)(void*,void*));
      _onUpdateFoundListener = listener
    }
  }

  let reference: WebServiceWorkerRegistrationRef
  var window: WebWindow?
  var context: JavascriptContext?
  var _onUpdateFoundListener: ListenerCallback?

  public required init?(_ context: JavascriptContext, _ value: JavascriptValue) {
    guard let ref = WebServiceWorkerRegistrationFromJavascriptValue(context.reference, value.reference) else {
      return nil
    }
    self.context = context
    self.reference = ref
  }

  init(reference: WebServiceWorkerRegistrationRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  public func update() -> Promise<Bool> {
    let ref = WebServiceWorkerRegistrationUpdate(reference)
    return Promise<Bool>(reference: ref!, window: window!)
  }

  public func unregister() -> Promise<None> {
    let ref = WebServiceWorkerRegistrationUnregister(reference)
    return Promise<None>(reference: ref!, window: window!)
  }

}

public class WebServiceWorkerProvider {

	var reference: UnsafeMutableRawPointer

	init(reference: UnsafeMutableRawPointer) {
		self.reference = reference
	}
}

public enum WebServiceScriptType : Int {
  case classic = 0
  case module = 1
  case native = 2
}

public class WebServiceWorkerContainer {

  public var controller: WebServiceWorker? {
    guard let ref = WebServiceWorkerContainerGetController(reference) else {
      return nil
    }
    return WebServiceWorker(reference: ref, window: window)
  }

  var reference: WebServiceWorkerContainerRef
  let window: WebWindow
  private var listeners: [WebServiceListenerHolder] = []

  init(reference: WebServiceWorkerContainerRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  public func register(_ url: String, type: WebServiceScriptType) -> Promise<WebServiceWorkerRegistration> {
    let ref: ScriptPromiseRef = url.withCString { 
      return WebServiceWorkerContainerRegister(reference, window.reference, CInt(type.rawValue), $0)!
    }
    return Promise<WebServiceWorkerRegistration>(reference: ref, window: window)
  }


  public func register(_ url: String, scope: String, type: WebServiceScriptType) -> Promise<WebServiceWorkerRegistration> {
    let ref = url.withCString { urlCStr in 
      return scope.withCString { scopedCStr in
        return WebServiceWorkerContainerRegisterWithScope(reference, window.reference, CInt(type.rawValue), urlCStr, scopedCStr)!
      }
    }
    return Promise<WebServiceWorkerRegistration>(reference: ref, window: window)
  }

  public func onMessage(
    _ listenerCallback: @escaping WebServiceListenerCallback) -> Bool {
    let state = WebServiceListenerHolder(callback: listenerCallback, window: self.window)
    listeners.append(state)
    let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    return WebServiceWorkerContainerSetOnMessageEventListener(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
      let holder = unsafeBitCast(handle, to: WebServiceListenerHolder.self)
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
  //   var maybeHolder: WebServiceListenerHolder?
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
  //     return WebServiceWorkerContainerRemoveEventListener(reference, $0, listenerState) != 0
  //   }
  //   listeners.remove(at: index)
  //   return result
  // }

  internal func destroy(_ holder: WebServiceListenerHolder) {
    for (i, item) in listeners.enumerated() {
      if item === holder {
        listeners.remove(at: i)
      }
    }
  }

}

public enum WebServiceWorkerType : Int {
  case classic = 0
  case native = 1
}

public class WebServiceWorker {

  public var scriptUrl: String {
    var len: CInt = 0      
    guard let ref = WebServiceWorkerGetScriptUrl(reference, &len) else {
      return String()
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public var window: WebWindow?
  public var globalScope: ServiceWorkerGlobalScope?

  var reference: WebServiceWorkerRef
  internal var jsGlobal: JavascriptObject?
  internal var jsContext: JavascriptContext?

  // NOTE: passing LocalDomWindow is only reasonable if accessing ServiceWorker from the UI/main thread
  //       is there a case where we could access this object from the service worker thread?
  //       if so passing this is not very good. Again we can push for a ExecutionContext
  //       which than can be a DOMWindow or a Document if on UI thread and something else
  //       if we are on the ServiceWorker thread
  init(reference: WebServiceWorkerRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: WebServiceWorkerRef, globalScope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.globalScope = globalScope
  }

  init(reference: WebServiceWorkerRef, context: JavascriptContext?) {
   self.reference = reference
   self.jsContext = context
  }

  public func postMessage(string: String, ports: [MessagePort]) {
    // FIXME: we can use stack allocation here, no need to go for the heap
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    if self.window != nil {
      string.withCString {
        WebServiceWorkerPostMessageString(reference, window!.reference, portRefs, CInt(ports.count), $0, CInt(string.count))
      }
    }
    if self.globalScope != nil {
      string.withCString {
        WebServiceWorkerPostMessageStringFromWorker(reference, globalScope!.reference, portRefs, CInt(ports.count), $0, CInt(string.count))
      }
    }
    if (self.window == nil && self.globalScope == nil) {
      print("ServiceWorker.postMessage: ERROR - both window and global scope are nil")
    }
    free(portRefs)
  }

  public func postMessage(blob: Blob, ports: [MessagePort]) {
    // FIXME: we can use stack allocation here, no need to go for the heap
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    if window != nil {
      WebServiceWorkerPostMessageBlob(reference, window!.reference, portRefs, CInt(ports.count), blob.reference)
    }
    if globalScope != nil {
      WebServiceWorkerPostMessageBlobFromWorker(reference, globalScope!.reference, portRefs, CInt(ports.count), blob.reference)
    }
    free(portRefs)
  }

  public func postMessage(arrayBuffer: ArrayBuffer, ports: [MessagePort]) {
    // FIXME: we can use stack allocation here, no need to go for the heap
    let allocatedSize = ports.count * MemoryLayout<MessagePortRef>.size
    let portRefs: UnsafeMutablePointer<MessagePortRef?> = malloc(allocatedSize).bindMemory(to: MessagePortRef?.self, capacity: allocatedSize)
    for i in 0..<ports.count {
      portRefs[i] = ports[i].reference
    }
    if window != nil {
      WebServiceWorkerPostMessageArrayBuffer(reference, window!.reference, portRefs, CInt(ports.count), arrayBuffer.reference)
    }
    if globalScope != nil {
      WebServiceWorkerPostMessageArrayBufferFromWorker(reference, globalScope!.reference, portRefs, CInt(ports.count), arrayBuffer.reference)
    }
    free(portRefs)
  }

  public func postMessage(serializedScriptValue: SerializedScriptValue) {
    if window != nil {
      WebServiceWorkerPostMessageSerializedScriptValue(reference, window!.reference, serializedScriptValue.ownedReference)
    }
    if globalScope != nil {
      WebServiceWorkerPostMessageSerializedScriptValue(reference, globalScope!.reference, serializedScriptValue.ownedReference)
    }
  }

}

// ??
public protocol WebServiceWorkerHost {
  func onWorkerStarted()
  func onWorkerStopped()
}

// public protocol WebServiceWorkerNative : class {
  
//   var worker: WebWorker? { get }
//   var threadId: Int { get }

//   func onInit(context: WebWorkerContext)
//   func onMessage(event: MessageEvent)

//   func evaluateScript(_ : String) -> Bool
// }

// extension WebServiceWorkerNative {

//   public var threadId: Int {
//     guard let w = worker else {
//       return -1
//     }
//     return w.threadId
//   }

//   public func evaluateScript( _ string: String) -> Bool {
//     return worker?.evaluateScript(string) ?? false
//   }

// }

// @dynamicMemberLookup
// @dynamicCallable
// public struct WebServiceWorkerContext {
  
//   public let worker: WebServiceWorker
//   public var global: JavascriptObject {
//     return worker.jsGlobal!
//   }
//   public var jsContext: JavascriptContext {
//     return worker.jsContext!
//   }

//   public init(worker: WebServiceWorker) {
//     self.worker = worker
//   }

//   public subscript(dynamicMember name: String) -> JavascriptValue {
//     get {
//       guard let result = global.get(key: name) else {
//         return JavascriptValue.Undefined(context: worker.jsContext!)
//       }
//       result.parent = global
//       return result
//     }
//   }
    
//   public subscript(key: [JavascriptConvertible]) -> JavascriptValue {
//     get {
//       let keyValue = flattenedSubscriptIndices(worker.jsContext!, key)
//       guard let result = global.get(key: keyValue) else {
//         return JavascriptValue.Undefined(context: worker.jsContext!)
//       }
//       result.parent = global
//       return result
//     }
//     set {
//       let keyObject = flattenedSubscriptIndices(worker.jsContext!, key)
//       let _ = global.set(key: keyObject, value: newValue)
//     }
//   }
    
//   public subscript(key: JavascriptConvertible...) -> JavascriptValue {
//     get {
//       return global[key]
//     }
//     set {
//       global[key] = newValue
//     }
//   }

//   @discardableResult
//   public func dynamicallyCall(
//     withArguments args: JavascriptConvertible...) -> JavascriptValue {
//     if let fn = global.cast(to: JavascriptFunction.self) {
//       let argArray = args.map { $0.javascriptValue }
//       return fn.call(recv: global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
//     }
//     return JavascriptValue.Undefined(context: worker.jsContext!)
//   }

//   @discardableResult
//   public func dynamicallyCall(
//     withArguments args: [JavascriptConvertible] = []) -> JavascriptValue {
//     if let fn = global.cast(to: JavascriptFunction.self) {
//       let argsArray = args.map { $0.javascriptValue }
//       return fn.call(recv: global, argc: args.count, argv: argsArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
//     }
//     return JavascriptValue.Undefined(context: worker.jsContext!)
//   }

//   @discardableResult
//   public func dynamicallyCall(
//       withKeywordArguments args:
//       KeyValuePairs<String, JavascriptConvertible> = [:]) -> JavascriptValue {
//     if let fn = global.cast(to: JavascriptFunction.self) {
//       let argArray = args.map { $0.1.javascriptValue }
//       return fn.call(recv: global, argc: args.count, argv: argArray) ?? JavascriptValue.Undefined(context: worker.jsContext!)
//     }
//     return JavascriptValue.Undefined(context: worker.jsContext!)
//   }
// }

internal class WebServiceListenerHolder {

  var callback: WebServiceListenerCallback?
  var window: WebWindow

  init(callback: @escaping WebServiceListenerCallback, window: WebWindow) {
    self.callback = callback
    self.window = window
  }

}