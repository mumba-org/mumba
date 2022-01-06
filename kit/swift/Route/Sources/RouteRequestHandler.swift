// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol RouteRequestHandler {
  var id: Int { get }
  var status: Int { get }
  var url: String { get }
  // fixme: not a string
  var responseInfo: String { get }
  var method: String { get }
  var mimeType: String  { get }
  var creationTime: Int64 { get }
  var totalReceivedBytes: Int64  { get }
  var rawBodyBytes: Int64 { get }
  var expectedContentSize: Int64 { get }
  var responseHeaders: String { get }

  func start() -> Int
  func followDeferredRedirect()
  func read(buffer: UnsafeMutableRawPointer?, maxBytes: Int, bytesRead: inout Int) -> Int
  func cancelWithError(error: Int) -> Int
}

public protocol RouteRequestHandlerDelegate {
  var routeCount: Int { get }
  func createRequestHandler(id: Int, url: String) -> RouteRequestHandler
  func getRequestHandler(id: Int) -> RouteRequestHandler?
  func getRouteHeader(url: String) -> String
  func getRouteHandler(url: String) -> RouteHandler?
  func lookupRoute(path: String) -> RouteEntry?
  func lookupRoute(url: String) -> RouteEntry?
  func lookupRoute(uuid: String) -> RouteEntry?
  func onComplete(id: Int, status: Int)
}

public class RouteRequestHandlerInterface {

  public var state: UnsafeMutableRawPointer {
    return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  }

  public private(set) var callbacks: RouteRequestHandlerCallbacks
  public private(set) var delegate: RouteRequestHandlerDelegate?
  
  public init(delegate: RouteRequestHandlerDelegate) {
    callbacks = RouteRequestHandlerCallbacks()
    self.delegate = delegate
    
    callbacks.OnRequestCreated = { (state: UnsafeMutableRawPointer?, curl: UnsafePointer<CChar>?, cid: CInt) in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      let _ = this.delegate?.createRequestHandler(id: Int(cid), url: String(cString: curl!))
    }

    callbacks.OnComplete = { (state: UnsafeMutableRawPointer?, cid: CInt, status: CInt) in 
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      let _ = this.delegate?.onComplete(id: Int(cid), status: Int(status))
    }
    
    callbacks.GetMethod = { (state: UnsafeMutableRawPointer?, cid: CInt) -> UnsafePointer<CChar>? in
      var r: UnsafePointer<CChar>?
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) {
        req.method.withCString {
          r = $0
        }
      }
      return r
    }
    
    callbacks.GetMimeType = { (state: UnsafeMutableRawPointer?, cid: CInt) -> UnsafePointer<CChar>? in
      var r: UnsafePointer<CChar>?
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) {
        req.mimeType.withCString {
          r = $0
        }
      }
      return r
    }
    
    callbacks.GetCreationTime = { (state: UnsafeMutableRawPointer?, cid: CInt) -> Int64 in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) {
        return req.creationTime
      }
      return 0
    }
    
    callbacks.GetTotalReceivedBytes = { (state: UnsafeMutableRawPointer?, cid: CInt) -> Int64 in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) {
         return req.totalReceivedBytes 
      }
      return 0
    }
    
    callbacks.GetRawBodyBytes = { (state: UnsafeMutableRawPointer?, cid: CInt) -> Int64 in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        return req.rawBodyBytes
      }
      return 0
    }
    
    callbacks.GetLoadTimingInfo = { (state: UnsafeMutableRawPointer?, cid: CInt, info: UnsafeMutableRawPointer?) in
      //let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
    }
    
    callbacks.GetExpectedContentSize = { (state: UnsafeMutableRawPointer?, cid: CInt) -> Int64 in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        return req.expectedContentSize
      }
      return 0
    }
    
    callbacks.GetResponseHeaders = { (state: UnsafeMutableRawPointer?, cid: CInt, size: UnsafeMutablePointer<CInt>?) -> UnsafePointer<CChar>? in
      var r: UnsafePointer<CChar>?
      size!.pointee = 0
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        let header = req.responseHeaders
        size!.pointee = CInt(header.count)
        header.withCString {
          r = $0
        }  
      }
      return r
    }

    callbacks.GetStatus = { (state: UnsafeMutableRawPointer?, requestId: CInt) -> CInt in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(requestId)) { 
        return CInt(req.status)
      }
      return -2
    }
    
    callbacks.GetResponseInfo = { (state: UnsafeMutableRawPointer?, cid: CInt, info: UnsafeMutableRawPointer?) in
      //let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
    }
    
    callbacks.Start = { (state: UnsafeMutableRawPointer?, cid: CInt) -> CInt in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        return CInt(req.start())
      }
      return -2
    }
    
    callbacks.FollowDeferredRedirect = { (state: UnsafeMutableRawPointer?, cid: CInt) in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        req.followDeferredRedirect()
      }
    }
    
    callbacks.Read = { (state: UnsafeMutableRawPointer?, cid: CInt, buf: UnsafeMutableRawPointer?, maxBytes: CInt, bytesRead: UnsafeMutablePointer<CInt>?) -> CInt in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        var bytesReaded: Int = 0
        let result = CInt(req.read(buffer: buf, maxBytes: Int(maxBytes), bytesRead: &bytesReaded))
        bytesRead!.pointee = CInt(bytesReaded)
        return result
      }
      return -2
    }
    
    callbacks.CancelWithError = { (state: UnsafeMutableRawPointer?, cid: CInt, error: CInt) -> CInt in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let req = this.delegate!.getRequestHandler(id: Int(cid)) { 
        return CInt(req.cancelWithError(error: Int(error))) 
      }
      return 0
    }
    
    callbacks.GetRouteHeader = { (state: UnsafeMutableRawPointer?, curl: UnsafePointer<CChar>?, size: UnsafeMutablePointer<CInt>?) -> UnsafePointer<CChar>? in
      var r: UnsafePointer<CChar>?
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      let header = this.delegate!.getRouteHeader(url: String(cString: curl!))
      size!.pointee = CInt(header.count)
      header.withCString {
        r = $0
      }  
      return r
    }

    callbacks.LookupRouteByPath = {
      (state: UnsafeMutableRawPointer?,
       path: UnsafePointer<CChar>?,
       type: UnsafeMutablePointer<CInt>?,
       transportType: UnsafeMutablePointer<CInt>?,
       transportMode: UnsafeMutablePointer<CInt>?,
       scheme: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, 
       schemeSize: UnsafeMutablePointer<CInt>?,
       name: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       nameSize: UnsafeMutablePointer<CInt>?,
       pathOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       pathSize: UnsafeMutablePointer<CInt>?,
       url: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       urlSize: UnsafeMutablePointer<CInt>?,
       title: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       titleSize: UnsafeMutablePointer<CInt>?,
       contentType: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       contentSize: UnsafeMutablePointer<CInt>?) -> CInt in
       
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)

      if let route = this.delegate!.lookupRoute(path: String(cString: path!)) {
        type!.pointee = CInt(route.type.rawValue)
        transportType!.pointee = CInt(route.transportType.rawValue)
        transportMode!.pointee = CInt(route.rpcTransportMode.rawValue)
        schemeSize!.pointee = CInt(route.scheme.count)
        nameSize!.pointee = CInt(route.name.count)
        pathSize!.pointee = CInt(route.path.count)
        urlSize!.pointee = CInt(route.url.count)
        titleSize!.pointee = CInt(route.title.count)
        contentSize!.pointee = CInt(route.contentType.count)

        route.scheme.utf8CString.withUnsafeBytes {
          scheme!.pointee = malloc(route.scheme.count).bindMemory(to: Int8.self, capacity: route.scheme.count)
          memcpy(scheme!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.scheme.count), route.scheme.count)
        }

        route.name.utf8CString.withUnsafeBytes {
          name!.pointee = malloc(route.name.count).bindMemory(to: Int8.self, capacity: route.name.count)
          memcpy(name!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.name.count), route.name.count)
        }

        route.path.utf8CString.withUnsafeBytes {
          pathOut!.pointee = malloc(route.path.count).bindMemory(to: Int8.self, capacity: route.path.count)
          memcpy(pathOut!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.path.count), route.path.count)
        }

        route.url.utf8CString.withUnsafeBytes {
          url!.pointee = malloc(route.url.count).bindMemory(to: Int8.self, capacity: route.url.count)
          memcpy(url!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.url.count), route.url.count)
        }

        route.title.utf8CString.withUnsafeBytes {
          title!.pointee = malloc(route.title.count).bindMemory(to: Int8.self, capacity: route.title.count)
          memcpy(title!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.title.count), route.title.count)
        }

        route.contentType.utf8CString.withUnsafeBytes {
          contentType!.pointee = malloc(route.contentType.count).bindMemory(to: Int8.self, capacity: route.contentType.count)
          memcpy(contentType!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.contentType.count), route.contentType.count)
        }
        
        return 0
      }
      return 2
    }

    callbacks.LookupRouteByUrl = {
      (state: UnsafeMutableRawPointer?, 
       url: UnsafePointer<CChar>?,
       type: UnsafeMutablePointer<CInt>?,
       transportType: UnsafeMutablePointer<CInt>?,
       transportMode: UnsafeMutablePointer<CInt>?,
       scheme: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, 
       schemeSize: UnsafeMutablePointer<CInt>?,
       name: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       nameSize: UnsafeMutablePointer<CInt>?,
       path: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       pathSize: UnsafeMutablePointer<CInt>?,
       urlOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       urlSize: UnsafeMutablePointer<CInt>?,
       title: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       titleSize: UnsafeMutablePointer<CInt>?,
       contentType: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       contentSize: UnsafeMutablePointer<CInt>?) -> CInt in

      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)

      if let route = this.delegate!.lookupRoute(url: String(cString: url!)) {
        type!.pointee = CInt(route.type.rawValue)
        transportType!.pointee = CInt(route.transportType.rawValue)
        transportMode!.pointee = CInt(route.rpcTransportMode.rawValue)

        schemeSize!.pointee = CInt(route.scheme.count)
        nameSize!.pointee = CInt(route.name.count)
        pathSize!.pointee = CInt(route.path.count)
        urlSize!.pointee = CInt(route.url.count)
        titleSize!.pointee = CInt(route.title.count)
        contentSize!.pointee = CInt(route.contentType.count)

        route.scheme.utf8CString.withUnsafeBytes {
          scheme!.pointee = malloc(route.scheme.count).bindMemory(to: Int8.self, capacity: route.scheme.count)
          memcpy(scheme!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.scheme.count), route.scheme.count)
        }

        route.name.utf8CString.withUnsafeBytes {
          name!.pointee = malloc(route.name.count).bindMemory(to: Int8.self, capacity: route.name.count)
          memcpy(name!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.name.count), route.name.count)
        }

        route.path.utf8CString.withUnsafeBytes {
          path!.pointee = malloc(route.path.count).bindMemory(to: Int8.self, capacity: route.path.count)
          memcpy(path!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.path.count), route.path.count)
        }

        route.url.utf8CString.withUnsafeBytes {
          urlOut!.pointee = malloc(route.url.count).bindMemory(to: Int8.self, capacity: route.url.count)
          memcpy(urlOut!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.url.count), route.url.count)
        }

        route.title.utf8CString.withUnsafeBytes {
          title!.pointee = malloc(route.title.count).bindMemory(to: Int8.self, capacity: route.title.count)
          memcpy(title!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.title.count), route.title.count)
        }

        route.contentType.utf8CString.withUnsafeBytes {
          contentType!.pointee = malloc(route.contentType.count).bindMemory(to: Int8.self, capacity: route.contentType.count)
          memcpy(contentType!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.contentType.count), route.contentType.count)
        }
        
        return 0
      }
      return 2
    }
  
    callbacks.LookupRouteByUUID = {
      (state: UnsafeMutableRawPointer?, 
       uuid: UnsafePointer<CChar>?,
       type: UnsafeMutablePointer<CInt>?,
       transportType: UnsafeMutablePointer<CInt>?,
       transportMode: UnsafeMutablePointer<CInt>?,
       scheme: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, 
       schemeSize: UnsafeMutablePointer<CInt>?,
       name: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       nameSize: UnsafeMutablePointer<CInt>?,
       path: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       pathSize: UnsafeMutablePointer<CInt>?,
       url: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       urlSize: UnsafeMutablePointer<CInt>?,
       title: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       titleSize: UnsafeMutablePointer<CInt>?,
       contentType: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
       contentSize: UnsafeMutablePointer<CInt>?) -> CInt in
      
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      if let route = this.delegate!.lookupRoute(uuid: String(cString: uuid!)) {
        type!.pointee = CInt(route.type.rawValue)
        transportType!.pointee = CInt(route.transportType.rawValue)
        transportMode!.pointee = CInt(route.rpcTransportMode.rawValue)

        schemeSize!.pointee = CInt(route.scheme.count)
        nameSize!.pointee = CInt(route.name.count)
        pathSize!.pointee = CInt(route.path.count)
        urlSize!.pointee = CInt(route.url.count)
        titleSize!.pointee = CInt(route.title.count)
        contentSize!.pointee = CInt(route.contentType.count)

        route.scheme.utf8CString.withUnsafeBytes {
          scheme!.pointee = malloc(route.scheme.count).bindMemory(to: Int8.self, capacity: route.scheme.count)
          memcpy(scheme!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.scheme.count), route.scheme.count)
        }

        route.name.utf8CString.withUnsafeBytes {
          name!.pointee = malloc(route.name.count).bindMemory(to: Int8.self, capacity: route.name.count)
          memcpy(name!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.name.count), route.name.count)
        }

        route.path.utf8CString.withUnsafeBytes {
          path!.pointee = malloc(route.path.count).bindMemory(to: Int8.self, capacity: route.path.count)
          memcpy(path!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.path.count), route.path.count)
        }

        route.url.utf8CString.withUnsafeBytes {
          url!.pointee = malloc(route.url.count).bindMemory(to: Int8.self, capacity: route.url.count)
          memcpy(url!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.url.count), route.url.count)
        }

        route.title.utf8CString.withUnsafeBytes {
          title!.pointee = malloc(route.title.count).bindMemory(to: Int8.self, capacity: route.title.count)
          memcpy(title!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.title.count), route.title.count)
        }

        route.contentType.utf8CString.withUnsafeBytes {
          contentType!.pointee = malloc(route.contentType.count).bindMemory(to: Int8.self, capacity: route.contentType.count)
          memcpy(contentType!.pointee!, $0.baseAddress!.bindMemory(to: Int8.self, capacity: route.contentType.count), route.contentType.count)
        }
        
        return 0
      }
      return 2
    }
  
    callbacks.GetRouteCount = { (state: UnsafeMutableRawPointer?) -> CInt in
      let this = unsafeBitCast(state, to: RouteRequestHandlerInterface.self)
      let count = this.delegate!.routeCount
      return CInt(count)
    }

  }

}
