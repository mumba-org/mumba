// Copyright (c) 2018 World. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Engine
import WorldApi
import Net
import Data
import Route

public class WorldContext : EngineContext,
                            StorageDelegate,
                            RouteRequestHandlerDelegate {

  public var storage: Storage {
    if _storage == nil {
      _storage = createStorage(delegate: self)
    }
    return _storage!
  }

  public var routeCount: Int { 
    return provider?.routes.count ?? 0
  }

  private var server: ServiceServer?
  private var provider: WorldProviderImpl?
  private var _storage: Storage?
  internal var lastLaunchedApplicationId: Int = 0
  private var requests: [Int: WorldRouteRequestHandler] = [:]
  
  public override init() {
    super.init()
  }

  open override func onInit(containerContext: ContainerContext) {
    super.initialize(containerContext: containerContext, routeRequestHandler: self)
    provider = WorldProviderImpl(context: self)
    server = try! ServiceServer(port: 8082, serviceProviders: [provider!])
    server!.start()
  }

  open override func onShutdown() {
    super.onShutdown()
  }

  open override func onApplicationInstanceLaunched(instance: ApplicationInstance) {
    print("WorldContext: application was launched sucessfully. id: \(instance.id) name: \(instance.name) url: \(instance.url)")
    lastLaunchedApplicationId = instance.id
  }
  
  open override func onApplicationInstanceLaunchFailed(status: Engine.Status, instance: ApplicationInstance) {
    print("WorldContext: application \(instance.id): \(instance.name) launch failed")
  }
  
  open override func onApplicationInstanceKilled(status: Engine.Status, instance: ApplicationInstance) {
    print("WorldContext: application \(instance.id): \(instance.name) was killed")
  }

  open override func onApplicationInstanceClosed(status: Engine.Status, instance: ApplicationInstance) {
    print("WorldContext: application \(instance.id): \(instance.name) was closed")
  }

  open override func onApplicationInstanceActivated(instance: ApplicationInstance) {
    print("WorldContext: application \(instance.id): \(instance.name) was activated")
  }

  public func getRouteHeader(url: String) -> String {
    print("WorldContext: getRouteHeader")
    guard var handler = getRouteHandler(url: url) else {
      return String()
    }
    return handler.getResponseHeaders(url: url)
  }
  
  public func createRequestHandler(id: Int, url: String) -> RouteRequestHandler {
    print("WorldContext: createRequestHandler: \(id) \(url)")
    let request = WorldRouteRequestHandler(context: self, id: id, url: url)
    requests[id] = request
    return request
  }

  public func getRouteHandler(url: String) -> RouteHandler? {
    print("WorldContext: getRouteHandler: \(url)")
    var route = String(url[url.index(url.firstIndex(of: "/")!, offsetBy: 2)..<url.endIndex])
    route = "/" + String(route[route.startIndex..<route.firstIndex(of: "/")!])
    return provider?.routes.handler(at: route)
  }

  public func getRequestHandler(id: Int) -> RouteRequestHandler? {
    print("WorldContext: getRequestHandler: \(id)")
    return requests[id]
  }

  public func lookupRoute(path: String) -> RouteEntry? {
    print("WorldContext: lookupRoute => \(path)")
    guard let handler = provider?.routes.handler(at: path) else {
      return nil
    }
    return handler.entry
  }
  
  public func lookupRoute(url: String) -> RouteEntry? {
    print("WorldContext: lookupRoute => \(url)")
    guard let handler = provider?.routes.handler(at: url) else {
      return nil
    }
    return handler.entry
  }
  
  public func lookupRoute(uuid: String) -> RouteEntry? {
    print("WorldContext: lookupRoute => \(uuid)")
    return nil
  }

  public func onComplete(id: Int, status: Int) {
    print("WorldContext: onComplete => \(id) \(status)")
  }

  open func onShareDHTAnnounceReply(uuid: String, peers: Int) {
    //print("WorldContext.onShareDHTAnnounceReply: \(uuid) peers: \(peers)")
  }
  open func onShareMetadataReceived(uuid: String) {
    //print("WorldContext.onShareMetadataReceived: \(uuid)")
  }
  open func onShareMetadataError(uuid: String, error: Int) {
    //print("WorldContext.onShareMetadataError: \(uuid) error: \(error)")
  }
  open func onSharePieceReadError(uuid: String, piece: Int, error: Int) {
    //print("WorldContext.onSharePieceReadError: \(uuid) error: \(error)")
  }
  open func onSharePiecePass(uuid: String, piece: Int) {
    //print("WorldContext.onSharePiecePass: \(uuid) piece: \(piece)")
  }
  open func onSharePieceFailed(uuid: String, piece: Int) {
    //print("WorldContext.onSharePieceFailed: \(uuid) piece: \(piece)")
  }
  open func onSharePieceRead(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
    //print("WorldContext.onSharePieceRead: \(uuid) piece: \(piece) size: \(size)")
  }
  open func onSharePieceWrite(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
    //print("WorldContext.onSharePieceWrite: \(uuid) piece: \(piece) size: \(size)")
  }
  open func onSharePieceHashFailed(uuid: String, piece: Int) {
    //print("WorldContext.onSharePieceHashFailed: \(uuid) piece: \(piece)")
  }
  open func onShareCheckingFiles(uuid: String) {
    //print("WorldContext.onShareCheckingFiles: \(uuid)")
  }
  open func onShareDownloadingMetadata(uuid: String) {
    //print("WorldContext.onShareDownloadingMetadata: \(uuid)")
  }
  open func onShareFileRenamed(uuid: String, fileOffset: Int, name: String, error: Int) {
    //print("WorldContext.onShareFileRenamed: \(uuid)")
  }
  open func onShareResumed(uuid: String) {
    //print("WorldContext.onShareResumed: \(uuid)")
  }
  open func onShareChecked(uuid: String, result: Int) {
    //print("WorldContext.onShareChecked: \(uuid) result: \(result)")
  }
  open func onSharePieceComplete(uuid: String, piece: Int) {
    //print("WorldContext.onSharePieceComplete: \(uuid) piece: \(piece)")
  }
  open func onShareFileComplete(uuid: String, fileOffset: Int) {
    //print("WorldContext.onShareFileComplete: \(uuid) file: \(fileOffset)")
  }
  open func onShareDownloading(uuid: String) {
    //print("WorldContext.onShareDownloading: \(uuid)")
  }
  open func onShareComplete(uuid: String) {
    //print("WorldContext.onTorretComplete: \(uuid)")
  } 
  open func onShareSeeding(uuid: String) {
    //print("WorldContext.onShareSeeding: \(uuid)")
  } 
  open func onSharePaused(uuid: String) {
    //print("WorldContext.onSharePaused: \(uuid)")
  }

}

class WorldRouteRequestHandler : RouteRequestHandler {

  public private(set) var id: Int
  public private(set) var url: String
  public private(set) var status: Int = 0
  
  public var responseInfo: String {
    return String()
  }
  
  public var method: String {
    return String("GET")
  }
  
  public var mimeType: String {
    return handler.contentType
  }
  
  public var creationTime: Int64 {
    return created.microseconds
  }
  
  public var totalReceivedBytes: Int64 = 0

  public var rawBodyBytes: Int64 {
    return handler.getRawBodyBytes(url: url)
  }

  public var expectedContentSize: Int64 {
    return handler.getExpectedContentSize(url: url)
  }

  public var responseHeaders: String {
    return handler.getResponseHeaders(url: url) 
  }

  private var handler: RouteHandler!
  private weak var context: WorldContext?
  private var routeRequest: RouteRequest?
  private let created: TimeTicks
  private let doneReadingEvent: WaitableEvent = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)

  public init(context: WorldContext, id: Int, url: String) {
    self.context = context
    self.id = id
    self.url = url
    self.created = TimeTicks.now
    self.handler = context.getRouteHandler(url: url)                            
    if self.handler == nil {
      print("no handler for \(url) found")
      return
    }
  }

  public func start() -> Int {
    print("WorldRouteRequestHandler.start")
    routeRequest = RouteRequest()
    routeRequest!.url = url
    routeRequest!.callId = id
    var result = -99
    let startCompletion = RouteCompletion({
      result = $0
    })
    postTask { [self] in
      self.handler.onResponseStarted(request: routeRequest!, info: RouteResponseInfo(), completion: startCompletion)
    }
    startCompletion.wait()
    return result
  }
  
  public func followDeferredRedirect() {
    print("WorldRouteRequestHandler.followDeferredRedirect")
  }
  
  public func cancelWithError(error: Int) -> Int { 
    print("WorldRouteRequestHandler.cancelWithError: \(error)")
    return 0 
  }
  
  public func read(buffer: UnsafeMutableRawPointer?, maxBytes: Int, bytesRead: inout Int) -> Int { 
    print("WorldRouteRequestHandler.read")
    var result = -99
    let readCompletion = RouteCompletion({
      result = $0
    })
    postTask { [self] in
      self.handler.read(request: self.routeRequest!, buffer: buffer, maxBytes: maxBytes, completion: readCompletion)
    }
    readCompletion.wait()
    bytesRead = result
    totalReceivedBytes += Int64(bytesRead)
    return bytesRead
  }
}


@_silgen_name("ApplicationInit")
public func ApplicationInit() {
  let main = WorldContext()
  Engine.initialize(delegate: main)
}

@_silgen_name("ApplicationDestroy")
public func ApplicationDestroy() {
  Engine.destroy()
}

@_silgen_name("ApplicationGetClient")
public func ApplicationGetClient() -> UnsafeMutableRawPointer {
  return Engine.getClient()
}