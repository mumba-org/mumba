// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Engine
import TweedyApi
import Net
import Data
import Graphics
import Route

public class TweedyContext : EngineContext,
                             StorageDelegate,
                             ApplicationInstanceObserver,
                             RouteRequestHandlerDelegate {

  public var storage: Storage {
    return _storage!
  }

  public var routeCount: Int { 
    return tweedy?.routes.count ?? 0
  }

  private var server: ServiceServer?
  private var tweedy: TweedyProviderImpl?
  private var _storage: Storage?
  internal var lastLaunchedApplicationId: Int = 0
  private var requests: [Int: TweedyRouteRequestHandler] = [:]
  
  public override init() {
    super.init()
  }

  open override func onInit(containerContext: ContainerContext) {

    _storage = createStorage(delegate: self)
    
    super.initialize(containerContext: containerContext, routeRequestHandler: self)
    
    tweedy = TweedyProviderImpl(context: self)
    server = try! ServiceServer(port: 8081, serviceProviders: [tweedy!])
    server!.start()
  }

  open override func onShutdown() {
    super.shutdown()
    //if let service = blogService {
    //  do {
   //     try service.shutdown()
   //   } catch {
   //     print("unknown error on RPCService.shutdown()")
   //   }
   // }
  }

  open override func onApplicationInstanceLaunched(instance: ApplicationInstance) {
    //print("TweedyContext: application was launched sucessfully. id: \(instance.id) name: \(instance.name) url: \(instance.url)\n")
    lastLaunchedApplicationId = instance.id
    instance.addObserver(self)
  }
  
  open override func onApplicationInstanceLaunchFailed(status: Engine.Status, instance: ApplicationInstance) {
    print("TweedyContext: application \(instance.id): \(instance.name) launch failed")
  }
  
  open override func onApplicationInstanceKilled(status: Engine.Status, instance: ApplicationInstance) {
    print("TweedyContext: application \(instance.id): \(instance.name) was killed")
  }

  open override func onApplicationInstanceClosed(status: Engine.Status, instance: ApplicationInstance) {
    //print("TweedyContext: application \(instance.id): \(instance.name) was closed")
  }

  open override func onApplicationInstanceActivated(instance: ApplicationInstance) {
    print("TweedyContext: application \(instance.id): \(instance.name) was activated")
  }

  public func getRouteHeader(url: String) -> String {
    guard var handler = getRouteHandler(url: url) else {
      return String()
    }
    return handler.getResponseHeaders(url: url)
  }
  
  public func createRequestHandler(id: Int, url: String) -> RouteRequestHandler {
    let request = TweedyRouteRequestHandler(context: self, id: id, url: url)
    requests[id] = request
    return request
  }

  public func getRouteHandler(url: String) -> RouteHandler? {
    var route = String(url[url.index(url.firstIndex(of: "/")!, offsetBy: 2)..<url.endIndex])
    route = "/" + String(route[route.startIndex..<route.firstIndex(of: "/")!])
    let handler = tweedy?.routes.handler(at: route)
    return handler
  }

  public func lookupRoute(path: String) -> RouteEntry? {
    print("TweedyContext.lookupRoute => path:\(path)")
    guard let handler = tweedy?.routes.handler(at: path) else {
      if path == "/hello" {  
        var greet = HelloHandler(context: self)//GreetingsHandler()
        greet.path = path
        greet.url = "tweedy:/" + path
        tweedy?.routes.bind(path, greet)
        return greet.entry
      }
      return nil
    }
    return handler.entry
  }
  
  public func lookupRoute(url: String) -> RouteEntry? {
    print("TweedyContext.lookupRoute => url: \(url)")
    guard let handler = tweedy?.routes.handler(at: url) else {
      if url == "tweedy://hello" {  
        var greet = HelloHandler(context: self) // GreetingsHandler()
        greet.path = url
        greet.url = url
        tweedy?.routes.bind(url, greet)
        return greet.entry
      }
      return nil
    }
    return handler.entry
  }
  
  public func lookupRoute(uuid: String) -> RouteEntry? {
    print("TweedyContext.lookupRoute => uuid:\(uuid)")
    return nil
  }
  
  public func onComplete(id: Int, status: Int) {
    //print("TweedyContext.onComplete: id: \(id)")
  }

  public func getRequestHandler(id: Int) -> RouteRequestHandler? {
    return requests[id]
  }

  open func onShareDHTAnnounceReply(uuid: String, peers: Int) {
    print("TweedyContext.onShareDHTAnnounceReply: \(uuid) peers: \(peers)")
  }
  open func onShareMetadataReceived(uuid: String) {
    print("TweedyContext.onShareMetadataReceived: \(uuid)")
  }
  open func onShareMetadataError(uuid: String, error: Int) {
    print("TweedyContext.onShareMetadataError: \(uuid) error: \(error)")
  }
  open func onSharePieceReadError(uuid: String, piece: Int, error: Int) {
    print("TweedyContext.onSharePieceReadError: \(uuid) error: \(error)")
  }
  open func onSharePiecePass(uuid: String, piece: Int) {
    print("TweedyContext.onSharePiecePass: \(uuid) piece: \(piece)")
  }
  open func onSharePieceFailed(uuid: String, piece: Int) {
    print("TweedyContext.onSharePieceFailed: \(uuid) piece: \(piece)")
  }
  open func onSharePieceRead(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
    print("TweedyContext.onSharePieceRead: \(uuid) piece: \(piece) size: \(size)")
  }
  open func onSharePieceWrite(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int) {
    print("TweedyContext.onSharePieceWrite: \(uuid) piece: \(piece) size: \(size)")
  }
  open func onSharePieceHashFailed(uuid: String, piece: Int) {
    print("TweedyContext.onSharePieceHashFailed: \(uuid) piece: \(piece)")
  }
  open func onShareCheckingFiles(uuid: String) {
    print("TweedyContext.onShareCheckingFiles: \(uuid)")
  }
  open func onShareDownloadingMetadata(uuid: String) {
    print("TweedyContext.onShareDownloadingMetadata: \(uuid)")
  }
  open func onShareFileRenamed(uuid: String, fileOffset: Int, name: String, error: Int) {
    print("TweedyContext.onShareFileRenamed: \(uuid)")
  }
  open func onShareResumed(uuid: String) {
    print("TweedyContext.onShareResumed: \(uuid)")
  }
  open func onShareChecked(uuid: String, result: Int) {
    print("TweedyContext.onShareChecked: \(uuid) result: \(result)")
  }
  open func onSharePieceComplete(uuid: String, piece: Int) {
    print("TweedyContext.onSharePieceComplete: \(uuid) piece: \(piece)")
  }
  open func onShareFileComplete(uuid: String, fileOffset: Int) {
    print("TweedyContext.onShareFileComplete: \(uuid) file: \(fileOffset)")
  }
  open func onShareDownloading(uuid: String) {
    print("TweedyContext.onShareDownloading: \(uuid)")
  }
  open func onShareComplete(uuid: String) {
    print("TweedyContext.onTorretComplete: \(uuid)")
  } 
  open func onShareSeeding(uuid: String) {
    print("TweedyContext.onShareSeeding: \(uuid)")
  } 
  open func onSharePaused(uuid: String) {
    print("TweedyContext.onSharePaused: \(uuid)")
  }

  // ApplicationInstanceObserver

  public func onApplicationStateChanged(oldState: ApplicationState, newState: ApplicationState) {
    //print("TweedyContext.onApplicationStateChanged")
  }
  public func onBoundsChanged(bounds: IntRect) {
    print("TweedyContext.onBoundsChanged")
  }
  public func onVisible() {
    print("TweedyContext.onVisible")
  }
  public func onHidden() {
    print("TweedyContext.onHidden")
  }
  
  // Page
  public func onFrameAttached(frameId: String, parentFrameId: String) {
    print("TweedyContext.onFrameAttached")
  }
  public func onDomContentEventFired(timestamp: Int64) {
    //print("TweedyContext.onDomContentEventFired")
  }
  public func onFrameClearedScheduledNavigation(frameId: String) {
    print("TweedyContext.onFrameClearedScheduledNavigation")
  }
  public func onFrameDetached(frameId: String) {
    print("TweedyContext.onFrameDetached")
  }
  public func onFrameNavigated(frame: Frame) {
    //print("TweedyContext.onFrameNavigated: frame: \(frame.id)")
  }
  public func onFrameResized() {
    print("TweedyContext.onFrameResized")
  }
  public func onFrameScheduledNavigation(frameId: String, delay: Int, reason: NavigationReason, url: String) {
    print("TweedyContext.onFrameScheduledNavigation")
  }
  public func onFrameStartedLoading(frameId: String) {
    //print("TweedyContext.onFrameStartedLoading: \(frameId)")
  }
  public func onFrameStoppedLoading(frameId: String) {
    //print("TweedyContext.onFrameStoppedLoading")
  }
  public func onInterstitialHidden() {
    print("TweedyContext.onInterstitialHidden")
  }
  public func onInterstitialShown() {
    print("TweedyContext.onInterstitialShown")
  }
  public func onJavascriptDialogClosed(result: Bool, userInput: String) {
    print("TweedyContext.onJavascriptDialogClosed")
  }
  public func onJavascriptDialogOpening(url: String, message: String, type: DialogType, hasBrowserHandler: Bool, defaultPrompt: String?) {
    print("TweedyContext.onJavascriptDialogOpening")
  }
  public func onLifecycleEvent(frameId: String, loaderId: Int, name: String, timestamp: TimeTicks) {
    //print("TweedyContext.onLifecycleEvent: frame: \(frameId) name: \(name) timestamp: \(timestamp.microseconds)")
  }
  public func onLoadEventFired(timestamp: TimeTicks) {
    //print("TweedyContext.onLoadEventFired: timestamp: \(timestamp.microseconds)")
  }
  public func onNavigatedWithinDocument(frameId: String, url: String) {
    print("TweedyContext.onNavigatedWithinDocument: frame: \(frameId) url: \(url)")
  }
  public func onScreencastFrame(base64Data: String, metadata: ScreencastFrameMetadata, sessionId: Int) {
    print("TweedyContext.onScreencastFrame")
  }
  public func onScreencastVisibilityChanged(visible: Bool) {
    print("TweedyContext.onScreencastVisibilityChanged")
  }
  public func onWindowOpen(url: String, windowName: String, windowFeatures: [String], userGesture: Bool) {
    print("TweedyContext.onWindowOpen")
  }
  public func onPageLayoutInvalidated(resized: Bool) {
    //print("TweedyContext.onPageLayoutInvalidated: resized? \(resized)")
  }
  // Overlay
  public func inspectNodeRequested(backendNode: Int) {
    print("TweedyContext.inspectNodeRequested")
  }
  public func nodeHighlightRequested(nodeId: Int) {
    print("TweedyContext.nodeHighlightRequested")
  }
  public func screenshotRequested(viewport: Viewport) {
    print("TweedyContext.screenshotRequested")
  }
  // worker
  public func workerErrorReported(errorMessage: ServiceWorkerErrorMessage) {
    print("TweedyContext.workerErrorReported")
  }
  public func workerRegistrationUpdated(registrations: [ServiceWorkerRegistration]) {
    print("TweedyContext.workerRegistrationUpdated")
  }
  public func workerVersionUpdated(versions: [ServiceWorkerVersion]) {
    print("TweedyContext.workerVersionUpdated")
  }
  public func onAttachedToTarget(sessionId: String, targetInfo: TargetInfo) {
    print("TweedyContext.onAttachedToTarget")
  }
  public func onDetachedFromTarget(sessionId: String, targetId: String?) {
    print("TweedyContext.onDetachedFromTarget")
  }
  public func onReceivedMessageFromTarget(sessionId: String, message: String, targetId: String?) {
    print("TweedyContext.onReceivedMessageFromTarget")
  }
  // Storage
  public func onCacheStorageContentUpdated(origin: String, cacheName: String) {
    print("TweedyContext.onCacheStorageContentUpdated")
  }
  public func onCacheStorageListUpdated(origin: String) {
    print("TweedyContext.onCacheStorageListUpdated")
  }
  public func onIndexedDBContentUpdated(origin: String, databaseName: String, objectStoreName: String) {
    print("TweedyContext.onIndexedDBContentUpdated")
  }
  public func onIndexedDBListUpdated(origin: String) {
    print("TweedyContext.onIndexedDBListUpdated")
  }
  // Tethering
  public func onAccepted(port: Int, connectionId: String) {
    print("TweedyContext.onAccepted")
  }
  // Network
  public func onDataReceived(requestId: String, timestamp: TimeTicks, dataLength: Int64, encodedDataLength: Int64) {
    print("TweedyContext.onDataReceived")
  }
  public func onEventSourceMessageReceived(requestId: String, timestamp: Int64, eventName: String, eventId: String, data: String) {
    print("TweedyContext.onEventSourceMessageReceived")
  }
  public func onLoadingFailed(requestId: String, timestamp: Int64, type: ResourceType, errorText: String, canceled: Bool, blockedReason: BlockedReason) {
    print("TweedyContext.onLoadingFailed")
  }
  public func onLoadingFinished(requestId: String, timestamp: Int64, encodedDataLength: Int64, blockedCrossSiteDocument: Bool) {
    print("TweedyContext.onLoadingFinished: request: \(requestId) timestamp: \(timestamp) encodedDataLength: \(encodedDataLength)")
  }
  public func onRequestIntercepted(
    interceptionId: String, 
    request: Request, 
    frameId: String, 
    resourceType: ResourceType, 
    isNavigationRequest: Bool, 
    isDownload: Bool, 
    redirectUrl: String, 
    authChallenge: AuthChallenge, 
    responseErrorReason: ErrorReason, 
    responseStatusCode: Int, 
    responseHeaders: [String: String]) {

    print("TweedyContext.onRequestIntercepted")
  }
  
  public func onRequestServedFromCache(requestId: String) {
    print("TweedyContext.onRequestServedFromCache")
  }

  public func onRequestWillBeSent(
    requestId: String, 
    loaderId: String,
    documentUrl: String, 
    request: Request, 
    timestamp: Int64, 
    walltime: Int64, 
    initiator: Initiator, 
    redirectResponse: Response, 
    type: ResourceType, 
    frameId: String?, 
    hasUserGesture: Bool) {

    print("TweedyContext.onRequestWillBeSent")
  }
  
  public func onResourceChangedPriority(requestId: String, newPriority: ResourcePriority, timestamp: Int64) {
    print("TweedyContext.onResourceChangedPriority")
  }

  public func onResponseReceived(requestId: String, loaderId: String, timestamp: Int64, type: ResourceType, response: Response, frameId: String?) {
    print("TweedyContext.onResponseReceived")
  }
  public func onWebSocketClosed(requestId: String, timestamp: Int64) {
    print("TweedyContext.onWebSocketClosed")
  }
  public func onWebSocketCreated(requestId: String, url: String, initiator: Initiator) {
    print("TweedyContext.onWebSocketCreated")
  }
  public func onWebSocketFrameError(requestId: String, timestamp: Int64, errorMessage: String) {
    print("TweedyContext.onWebSocketFrameError")
  }
  public func onWebSocketFrameReceived(requestId: String, timestamp: Int64, response: WebSocketFrame) {
    print("TweedyContext.onWebSocketFrameReceived")
  }
  public func onWebSocketFrameSent(requestId: String, timestamp: Int64, response: WebSocketFrame) {
    print("TweedyContext.onWebSocketFrameSent")
  }
  public func onWebSocketHandshakeResponseReceived(requestId: String, timestamp: Int64, response: WebSocketResponse) {
    print("TweedyContext.onWebSocketHandshakeResponseReceived")
  }
  public func onWebSocketWillSendHandshakeRequest(requestId: String, timestamp: Int64, walltime: Int64, request: WebSocketRequest) {
    print("TweedyContext.onWebSocketWillSendHandshakeRequest")
  }
  public func flush() {
    print("TweedyContext.flush")
  }
  // LayerTree
  public func onLayerPainted(layerId: String, clipX: Int, clipY: Int, clipW: Int, clipH: Int) {
    print("TweedyContext.onLayerPainted")
  }
  public func onLayerTreeDidChange(layers: [Layer]) {
    print("TweedyContext.onLayerTreeDidChange")
  }
  // Headless
  public func onNeedsBeginFramesChanged(needsBeginFrames: Bool) {
    print("TweedyContext.onNeedsBeginFramesChanged")
  }
  // DOMStorage
  public func onDomStorageItemAdded(storageId: StorageId, key: String, newValue: String) {
    print("TweedyContext.onDomStorageItemAdded")
  }

  public func onDomStorageItemRemoved(storageId: StorageId, key: String) {
    print("TweedyContext.onDomStorageItemRemoved")
  }

  public func onDomStorageItemUpdated(storageId: StorageId, key: String, oldValue: String, newValue: String) {
    print("TweedyContext.onDomStorageItemUpdated")
  }

  public func onDomStorageItemsCleared(storageId: StorageId) {
    print("TweedyContext.onDomStorageItemsCleared")
  }

  // Database
  public func onAddDatabase(database: Engine.Database) {
    print("TweedyContext.onAddDatabase")
  }
  // Emulation
  public func onVirtualTimeAdvanced(virtualTimeElapsed: Int) {
    print("TweedyContext.onVirtualTimeAdvanced")
  }
  public func onVirtualTimeBudgetExpired() {
    print("TweedyContext.onVirtualTimeBudgetExpired")
  }
  public func onVirtualTimePaused(virtualTimeElapsed: Int) {
    print("TweedyContext.onVirtualTimePaused")
  }
  // DOM
  public func setChildNodes(parentId: Int, nodes: [DOMNode]) {
    print("TweedyContext.setChildNodes")
  }
  public func onAttributeModified(nodeId: Int, name: String, value: String) {
    print("TweedyContext.onAttributeModified")
  }
  public func onAttributeRemoved(nodeId: Int, name: String) {
    print("TweedyContext.onAttributeRemoved")
  }
  public func onCharacterDataModified(nodeId: Int, characterData: String) {
    print("TweedyContext.onCharacterDataModified")
  }
  public func onChildNodeCountUpdated(nodeId: Int, childNodeCount: Int) {
    print("TweedyContext.onChildNodeCountUpdated")
  }
  public func onChildNodeInserted(parentNodeId: Int, previousNodeId: Int, node: DOMNode) {
    print("TweedyContext.onChildNodeInserted")
  }
  public func onChildNodeRemoved(parentNodeId: Int, nodeId: Int) {
    print("TweedyContext.onChildNodeRemoved")
  }
  public func onDistributedNodesUpdated(insertionPointId: Int, distributedNodes: [BackendNode]) {
    print("TweedyContext.onDistributedNodesUpdated")
  }
  public func onDocumentUpdated() {
    //print("TweedyContext.onDocumentUpdated")
  }
  public func onInlineStyleInvalidated(nodeIds: [Int]) {
    print("TweedyContext.onInlineStyleInvalidated")
  }
  public func onPseudoElementAdded(parentId: Int, pseudoElement: DOMNode) {
    print("TweedyContext.onPseudoElementAdded")
  }
  public func onPseudoElementRemoved(parentId: Int, pseudoElementId: Int) {
    print("TweedyContext.onPseudoElementRemoved")
  }
  public func onShadowRootPopped(hostId: Int, rootId: Int) {
    print("TweedyContext.onShadowRootPopped")
  }
  public func onShadowRootPushed(hostId: Int, root: DOMNode) {
    print("TweedyContext.onShadowRootPushed")
  }
  // CSS
  public func onFontsUpdated(font: FontFace) {
    print("TweedyContext.onFontsUpdated")
  }
  public func onMediaQueryResultChanged() {
    print("TweedyContext.onMediaQueryResultChanged")
  }
  public func onStyleSheetAdded(header: CSSStyleSheetHeader) {
    print("TweedyContext.onStyleSheetAdded")
  }
  public func onStyleSheetChanged(styleSheetId: String) {
    print("TweedyContext.onStyleSheetChanged")
  }
  public func onStyleSheetRemoved(styleSheetId: String) {
    print("TweedyContext.onStyleSheetRemoved")
  }
  // ApplicationCache
  public func onApplicationCacheStatusUpdated(frameId: String, manifestUrl: String, status: Int) {
    print("TweedyContext.onApplicationCacheStatusUpdated")
  }
  public func onNetworkStateUpdated(isNowOnline: Bool) {
    print("TweedyContext.onNetworkStateUpdated")
  }
  // Animation
  public func onAnimationCanceled(id: String) {
    print("TweedyContext.onAnimationCanceled")
  }
  public func onAnimationCreated(id: String) {
    print("TweedyContext.onAnimationCreated")
  }
  public func onAnimationStarted(animation: Animation) {
    print("TweedyContext.onAnimationStarted")
  }

}

class TweedyRouteRequestHandler : RouteRequestHandler {

  public private(set) var id: Int
  public private(set) var url: String
  public var status: Int {
    return 0
  }

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
    //return String("HTTP 1.1 200 OK\n\nContent-Length: \(hello.count)\n Content-Type: text/html; charset=UTF-8")
  }
  
  private var firstTime: Bool = true
  private let hello = "<html><body><h1 align=\"center\">hello world from swift!</h1></body></html>"
  private var handler: RouteHandler!
  private weak var context: TweedyContext?
  private var routeRequest: RouteRequest?
  private let created: TimeTicks

  private let doneReadingEvent: WaitableEvent = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)

  public init(context: TweedyContext, id: Int, url: String) {
    self.context = context
    self.id = id
    self.url = url
    self.created = TimeTicks.now
 
    self.handler = context.getRouteHandler(url: url)                            
    if self.handler == nil {
      print("no handler for \(url) found")
      return
    }
    let bufferSize = handler.bufferSize
    handler.lastCallId = id
    //handler.closeCompletion = { doNothing() }
  }

  public func start() -> Int {
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

  }
  
  public func read(buffer: UnsafeMutableRawPointer?, maxBytes: Int, bytesRead: inout Int) -> Int { 
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

  public func cancelWithError(error: Int) -> Int { return 0 }
}

@_silgen_name("ApplicationInit")
public func ApplicationInit() {
  let main = TweedyContext()
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
