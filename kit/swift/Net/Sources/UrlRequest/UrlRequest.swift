// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

// CronetEngine.Builder engineBuilder = new CronetEngine.Builder(getContext());
// CronetEngine engine = engineBuilder.build();
// Executor executor = Executors.newSingleThreadExecutor();
// MyCallback callback = new MyCallback();
// UrlRequest.Builder requestBuilder = engine.newUrlRequestBuilder(
//    "https://www.example.com", callback, executor);
// UrlRequest request = requestBuilder.build();
// request.start();

public enum UrlRequestPriority : Int {
  case Idle = 0
  case Lowest = 1
  case Low = 2
  case Medium = 3
  case Highest = 4
}


public class UrlRequestHeaders {
  
  public subscript(index: String) -> String? {
    get {
      guard let ptr = headers[index] else {
        return nil
      }
      return String(cString: Cronet_HttpHeader_value_get(ptr)!)
    }
    set {
      guard let ptr = headers[index] else {
        let newPtr = Cronet_HttpHeader_Create()
        index.withCString {
          Cronet_HttpHeader_name_set(newPtr, $0)
        }
        if let v = newValue {
          v.withCString {
            Cronet_HttpHeader_value_set(newPtr, $0)
          }
        }
        headers[index] = newPtr
        return
      }
      if let v = newValue {
        v.withCString {
          Cronet_HttpHeader_value_set(ptr, $0)
        }
      }
    }
  }
  
  internal var headers: [String: Cronet_HttpHeaderPtr]

  public init () {
    headers = [:]
  }

  deinit {
    for item in headers {
      Cronet_HttpHeader_Destroy(item.1)
    }
  }
}

public struct UrlRequestParams {
  public var httpMethod: String = String()
  public var requestHeaders: [String : String] = [:]
  public var disableCache: Bool = false
  public var priority: UrlRequestPriority = UrlRequestPriority.Medium
  public var uploadDataProvider: UploadDataProvider?
  public var uploadDataProviderExecutor: UrlExecutor?
  public var allowDirectExecutor: Bool = true

  public init() {}
}

public class UrlRequest {

  public var isDone: Bool {
    return Cronet_UrlRequest_IsDone(reference) != 0
  }

  public var httpMethod: String {
    get {
      return String(cString: Cronet_UrlRequestParams_http_method_get(params)!)
    }
    set {
      newValue.withCString {
        Cronet_UrlRequestParams_http_method_set(params, $0)
      }
    }
  }

  public subscript(index: String) -> String? {
    get {
      return _header[index]
    }
    set {
      if let s = newValue {
        _header[index] = s
        let ptr = _header.headers[s]
        Cronet_UrlRequestParams_request_headers_add(params, ptr)
      } else {
        _header[index] = String()
      }
    }
  }

  public var disableCache: Bool {
    get {
      return Cronet_UrlRequestParams_disable_cache_get(params) != 0
    }
    set {
      Cronet_UrlRequestParams_disable_cache_set(params, newValue ? 1 : 0)
    }
  }

  public var priority: UrlRequestPriority {
    get {
      return fromPriority(Cronet_UrlRequestParams_priority_get(params))
    }
    set {
      Cronet_UrlRequestParams_priority_set(params, Cronet_UrlRequestParams_REQUEST_PRIORITY(rawValue: UInt32(newValue.rawValue)))
    }
  }

  public var uploadDataProvider: UploadDataProvider? {
    get {
      return _uploadDataProvider?.impl
    }
    set {
      if let p = newValue {
        _uploadDataProvider = UploadDataProviderWrapper(provider: p)
        Cronet_UrlRequestParams_upload_data_provider_set(params, _uploadDataProvider!.reference)
      } else {
        _uploadDataProvider = nil
      }
    }
  }

  public var uploadDataProviderExecutor: UrlExecutor? {
    get {
      return _uploadDataProviderExecutor
    }
    set {
      _uploadDataProviderExecutor = newValue
      if let e = newValue {
        Cronet_UrlRequestParams_upload_data_provider_executor_set(params, e.reference)
      }
    }
  }

  public var allowDirectExecutor: Bool {
    get {
      return Cronet_UrlRequestParams_allow_direct_executor_get(params) != 0
    }
    set {
      Cronet_UrlRequestParams_allow_direct_executor_set(params, newValue ? 1 : 0)
    }
  }

  public var handler: UrlRequestHandler {
    return delegateCallbacks.handler
  }

  private var _header: UrlRequestHeaders!
  private var _uploadDataProvider: UploadDataProviderWrapper?
  private var _uploadDataProviderExecutor: UrlExecutor?
  var reference: Cronet_UrlRequestPtr
  var params: Cronet_UrlRequestParamsPtr!
  var delegateCallbacks: UrlRequestHandlerCallbacks!
  var owned: Bool
  
  public init(engine: UrlEngine, executor: UrlExecutor, handler: UrlRequestHandler, url: String, params: UrlRequestParams) {
    owned = true
    _header = createHeaders(params)
    delegateCallbacks = UrlRequestHandlerCallbacks(handler: handler)
    reference = Cronet_UrlRequest_Create()
    self.params = createParameters(params)
    _uploadDataProvider = createUploadDataProvider(self.params, params)
    url.withCString { curl in
      Cronet_UrlRequest_InitWithParams(
        reference,
        engine.reference,
        curl,
        self.params,
        delegateCallbacks.reference,
        executor.reference)
    }
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_UrlRequest_SetClientContext(reference, statePtr)
  }

  init(reference: Cronet_UrlRequestPtr) {
    owned = false
    self.reference = reference
  }

  deinit {
    if owned {
      Cronet_UrlRequest_Destroy(reference)
      Cronet_UrlRequestParams_Destroy(params)
    }
  }
  
  public func start() {
    Cronet_UrlRequest_Start(reference)
  }

  public func followRedirect() -> UrlResult {
    return fromResult(Cronet_UrlRequest_FollowRedirect(reference))
  }

  public func read(buffer: UrlBuffer) -> UrlResult {
    return fromResult(Cronet_UrlRequest_Read(reference, buffer.reference))
  }

  public func cancel() {
    Cronet_UrlRequest_Cancel(reference)
  }
  
  public func getStatus(listener: UrlRequestStatusListener) {
    //Cronet_UrlRequest_GetStatus(reference, )
  }

}

internal func createUploadDataProvider(_ paramsPtr: Cronet_UrlRequestParamsPtr, _ p: UrlRequestParams) -> UploadDataProviderWrapper? {
  if let pr = p.uploadDataProvider {
    let provider = UploadDataProviderWrapper(provider: pr)
    Cronet_UrlRequestParams_upload_data_provider_set(paramsPtr, provider.reference)
    return provider
  }
  return nil
}

internal func createParameters(_ p: UrlRequestParams) -> Cronet_UrlRequestParamsPtr {
  let params = Cronet_UrlRequestParams_Create()
  Cronet_UrlRequestParams_disable_cache_set(params, p.disableCache ? 1 : 0)
  Cronet_UrlRequestParams_allow_direct_executor_set(params, p.allowDirectExecutor ? 1 : 0)
  if !p.httpMethod.isEmpty {
    p.httpMethod.withCString {
      Cronet_UrlRequestParams_http_method_set(params, $0)
    }
  }
  Cronet_UrlRequestParams_priority_set(params, Cronet_UrlRequestParams_REQUEST_PRIORITY(rawValue:UInt32(p.priority.rawValue)))
  if let e = p.uploadDataProviderExecutor {
    Cronet_UrlRequestParams_upload_data_provider_executor_set(params, e.reference)
  }
  return params!
}

internal func createHeaders(_ p: UrlRequestParams) -> UrlRequestHeaders {
  let headers = UrlRequestHeaders()
  for item in p.requestHeaders {
    headers[item.0] = item.1
  }
  return headers
}

internal func fromPriority(_ p: Cronet_UrlRequestParams_REQUEST_PRIORITY) -> UrlRequestPriority  {
  switch p {
    case Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_IDLE:
      return UrlRequestPriority.Idle
    case Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_LOWEST:
      return UrlRequestPriority.Lowest
    case Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_LOW:
      return UrlRequestPriority.Low
    case Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_MEDIUM:
      return UrlRequestPriority.Medium
    case Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_HIGHEST:
      return UrlRequestPriority.Highest
    default:
      return UrlRequestPriority.Medium
  }
}

internal class UrlRequestHandlerCallbacks {

  var reference: Cronet_UrlRequestCallbackPtr
  var handler: UrlRequestHandler

  init(handler: UrlRequestHandler) {
    self.handler = handler
    reference = Cronet_UrlRequestCallback_CreateWith(
      // OnRedirectReceivedFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?, 
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?,
         newLocationUrl: Cronet_String?) in 
        print("UrlRequestHandler -> OnRedirectReceived callback")
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        this.handler.onRedirectReceived(request: req, info: UrlResponseInfo(reference: infoPtr!), locationUrl: newLocationUrl != nil ? String(cString: newLocationUrl!) : String())
      },
      // OnResponseStartedFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?,  
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?) in 
         print("UrlRequestHandler -> OnResponseStarted callback")
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        this.handler.onResponseStarted(request: req, info: UrlResponseInfo(reference: infoPtr!))
      },
      // OnReadCompletedFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?,
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?,
         bufferPtr: Cronet_BufferPtr?,
         bytesRead: UInt64) in 
        print("UrlRequestHandler -> OnReadCompleted callback") 
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        let bufContext = Cronet_BufferCallback_GetClientContext(bufferPtr)
        let buf = unsafeBitCast(bufContext, to: UrlBuffer.self)
        this.handler.onReadCompleted(request: req, info: UrlResponseInfo(reference: infoPtr!), buffer: buf, bytesRead: bytesRead)
      },
      // OnSucceededFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?,
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?) in 
         print("UrlRequestHandler -> OnSucceeded callback")
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        this.handler.onSucceeded(request: req, info: UrlResponseInfo(reference: infoPtr!))
      },
      // OnFailedFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?,
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?,
         errorPtr: Cronet_ErrorPtr?) in 
        print("UrlRequestHandler -> OnFailed callback") 
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        this.handler.onFailed(request: req, info: UrlResponseInfo(reference: infoPtr!), error: UrlRequestError(reference: errorPtr!))
      },
      // OnCanceledFunc
      { (ptr: Cronet_UrlRequestCallbackPtr?,
         requestPtr: Cronet_UrlRequestPtr?,
         infoPtr: Cronet_UrlResponseInfoPtr?) in 
         print("UrlRequestHandler -> OnCanceled callback")
        let context = Cronet_UrlRequestCallback_GetClientContext(ptr)
        let this = unsafeBitCast(context, to: UrlRequestHandlerCallbacks.self)
        let reqContext = Cronet_UrlRequest_GetClientContext(requestPtr)
        let req = unsafeBitCast(reqContext, to: UrlRequest.self)
        this.handler.onCanceled(request: req, info: UrlResponseInfo(reference: infoPtr!))
      }
    )
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_UrlRequestCallback_SetClientContext(reference, statePtr)
  }

  deinit {
    Cronet_UrlRequestCallback_Destroy(reference)
  }

}