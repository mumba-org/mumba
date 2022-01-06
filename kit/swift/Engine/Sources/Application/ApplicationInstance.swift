// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims
import Foundation

public enum ApplicationState : Int {
  case None = 0
  case Running = 1
  case Killed = 2
  case LaunchError = 3
}

public typealias GetInfoCallback = (GPUInfo, String, String, String) -> Void
public typealias GetVersionCallback = (String, String, String, String, String) -> Void
public typealias GetHostCommandLineCallback = ([String]) -> Void
public typealias GetHistogramsCallback = ([Histogram]) -> Void
public typealias GetHistogramCallback = (Histogram) -> Void
public typealias GetWindowBoundsCallback = (Bounds) -> Void
public typealias GetWindowForTargetCallback = (Int, Bounds) -> Void
public typealias AddScriptToEvaluateOnNewDocumentCallback = (String) -> Void
public typealias NavigateCallback = (String, Int, String) -> Void
public typealias GetNavigationHistoryCallback = (Int, [NavigationEntry]) -> Void
public typealias GetCookiesCallback = ([Cookie]) -> Void
public typealias GetResourceTreeCallback = (FrameResourceTree) -> Void
public typealias GetFrameTreeCallback = (FrameTree) -> Void
public typealias GetResourceContentCallback = (String, Bool) -> Void
public typealias SearchInResourceCallback = ([SearchMatch]) -> Void
public typealias CaptureScreenshotCallback = (String) -> Void
public typealias PrintToPDFCallback = (String) -> Void
public typealias GetAppManifestCallback = (String, [String], String?) -> Void
public typealias GetLayoutMetricsCallback = (LayoutViewport, VisualViewport, Int, Int, Int, Int) -> Void
public typealias CreateIsolatedWorldCallback = (Int) -> Void
public typealias CanClearBrowserCacheCallback = (Bool) -> Void
public typealias CanClearBrowserCookiesCallback = (Bool) -> Void
public typealias CanEmulateNetworkConditionsCallback = (Bool) -> Void
public typealias GetAllCookiesCallback = ([Cookie]) -> Void
public typealias GetCertificateCallback = ([String]) -> Void
//public typealias GetCookiesCallback = ([Cookie]) -> Void
public typealias GetResponseBodyCallback = (String, Bool) -> Void
public typealias GetRequestPostDataCallback = (String) -> Void
public typealias GetResponseBodyForInterceptionCallback = (String, Bool) -> Void
public typealias TakeResponseBodyForInterceptionAsStreamCallback = (String) -> Void
public typealias SearchInResponseBodyCallback = ([SearchMatch]) -> Void
public typealias SetCookieCallback = (Bool) -> Void
public typealias CompositingReasonsCallback = ([String]) -> Void
public typealias LoadSnapshotCallback = (String) -> Void
public typealias MakeSnapshotCallback = (String) -> Void
public typealias ProfileSnapshotCallback = ([[Double]]) -> Void
public typealias ReplaySnapshotCallback = (String) -> Void
public typealias SnapshotCommandLogCallback = (String) -> Void
public typealias DispatchKeyEventCallback = (Bool) -> Void
public typealias DispatchMouseEventCallback = (Bool) -> Void
public typealias DispatchTouchEventCallback = (Bool) -> Void
public typealias EmulateTouchFromMouseEventCallback = (Bool) -> Void
public typealias SynthesizePinchGestureCallback = (Bool) -> Void
public typealias SynthesizeScrollGestureCallback = (Bool) -> Void
public typealias SynthesizeTapGestureCallback = (Bool) -> Void
public typealias ClearObjectStoreCallback = (Bool) -> Void
public typealias DeleteDatabaseCallback = (Bool) -> Void
public typealias DeleteObjectStoreEntriesCallback = (Bool) -> Void
public typealias RequestDataCallback = ([IndexedDBDataEntry], Bool) -> Void
public typealias RequestDatabaseCallback = (DatabaseWithObjectStores) -> Void
public typealias RequestDatabaseNamesCallback = ([String]) -> Void
public typealias ReadCallback = (Bool, String, Bool) -> Void
public typealias ResolveBlobCallback = (String) -> Void
public typealias BeginFrameCallback = (Bool, String?) -> Void
public typealias GetDOMStorageItemsCallback = ([[String]]) -> Void
public typealias ExecuteSQLCallback = ([String], [Value], SQLError?) -> Void
public typealias GetDatabaseTableNamesCallback = ([String]) -> Void
public typealias CanEmulateCallback = (Bool) -> Void
public typealias SetVirtualTimePolicyCallback = (Int64, Int64) -> Void
public typealias GetSnapshotCallback = ([DOMSnapshotNode], [LayoutTreeNode], [ComputedStyle]) -> Void
public typealias CollectClassNamesFromSubtreeCallback = ([String]) -> Void
public typealias CopyToCallback = (Int) -> Void
public typealias DescribeNodeCallback = (DOMNode) -> Void
public typealias GetAttributesCallback = ([String]) -> Void
public typealias GetBoxModelCallback = (BoxModel) -> Void
public typealias GetDocumentCallback = (DOMNode) -> Void
public typealias GetFlattenedDocumentCallback = ([DOMNode]) -> Void
public typealias GetNodeForLocationCallback = (Int) -> Void
public typealias GetOuterHTMLCallback = (String) -> Void
public typealias GetRelayoutBoundaryCallback = (Int) -> Void
public typealias GetSearchResultsCallback = ([Int]) -> Void
public typealias MoveToCallback = (Int) -> Void
public typealias PerformSearchCallback = (String, Int) -> Void
public typealias PushNodeByPathToFrontendCallback = (Int) -> Void
public typealias PushNodesByBackendIdsToFrontendCallback = ([Int]) -> Void
public typealias QuerySelectorCallback = (Int) -> Void
public typealias QuerySelectorAllCallback = ([Int]) -> Void
public typealias RequestNodeCallback = (Int) -> Void
public typealias ResolveNodeCallback = (RemoteObject) -> Void
public typealias SetNodeNameCallback = (Int) -> Void
public typealias GetFrameOwnerCallback = (Int) -> Void
public typealias AddRuleCallback = (CSSRule) -> Void
public typealias CollectClassNamesCallback = ([String]) -> Void
public typealias CreateStyleSheetCallback = (String) -> Void
public typealias GetBackgroundColorsCallback = ([String], String?, String?, String?) -> Void
public typealias GetComputedStyleForNodeCallback = ([CSSComputedStyleProperty]) -> Void
public typealias GetInlineStylesForNodeCallback = (CSSStyle, CSSStyle) -> Void
public typealias GetMatchedStylesForNodeCallback = (CSSStyle, CSSStyle, [RuleMatch], [PseudoElementMatches], [InheritedStyleEntry], [CSSKeyframesRule]) -> Void
public typealias GetMediaQueriesCallback = ([CSSMedia]) -> Void
public typealias GetPlatformFontsForNodeCallback = ([PlatformFontUsage]) -> Void
public typealias GetStyleSheetTextCallback = (String) -> Void
public typealias SetKeyframeKeyCallback = (CSSValue) -> Void
public typealias SetMediaTextCallback = (CSSMedia) -> Void
public typealias SetRuleSelectorCallback = (SelectorList) -> Void
public typealias SetStyleSheetTextCallback = (String?) -> Void
public typealias SetStyleTextsCallback = ([CSSStyle]) -> Void
public typealias StopRuleUsageTrackingCallback = ([CSSRuleUsage]) -> Void
public typealias TakeCoverageDeltaCallback = ([CSSRuleUsage]) -> Void
public typealias OpenCacheCallback = (Int) -> Void
public typealias HasCacheCallback = (Bool) -> Void
public typealias DeleteCacheCallback = (Bool) -> Void
public typealias DeleteEntryCallback = (Bool) -> Void
public typealias PutEntryCallback = (Bool) -> Void
public typealias RequestCacheNamesCallback = ([Cache]) -> Void
public typealias RequestCachedResponseCallback = (CachedResponse) -> Void
public typealias RequestEntriesCallback = ([DataEntry], Bool) -> Void
public typealias GetApplicationCacheForFrameCallback = (ApplicationCache) -> Void
public typealias GetFramesWithManifestsCallback = ([FrameWithManifest]) -> Void
public typealias GetManifestForFrameCallback = (String) -> Void
public typealias GetCurrentTimeCallback = (Int) -> Void
public typealias GetPlaybackRateCallback = (Int) -> Void
public typealias ResolveAnimationCallback = (Animation) -> Void
public typealias GetPartialAXTreeCallback = ([AXNode]) -> Void

public protocol ApplicationInstanceObserver : class {
  func onApplicationStateChanged(oldState: ApplicationState, newState: ApplicationState)
  func onBoundsChanged(bounds: IntRect)
  func onVisible()
  func onHidden()
  // Page
  func onFrameAttached(frameId: String, parentFrameId: String)
  func onDomContentEventFired(timestamp: Int64)
  func onFrameClearedScheduledNavigation(frameId: String)
  func onFrameDetached(frameId: String)
  func onFrameNavigated(frame: Frame)
  func onFrameResized()
  func onFrameScheduledNavigation(frameId: String, delay: Int, reason: NavigationReason, url: String)
  func onFrameStartedLoading(frameId: String)
  func onFrameStoppedLoading(frameId: String)
  func onInterstitialHidden()
  func onInterstitialShown()
  func onJavascriptDialogClosed(result: Bool, userInput: String)
  func onJavascriptDialogOpening(url: String, message: String, type: DialogType, hasBrowserHandler: Bool, defaultPrompt: String?)
  func onLifecycleEvent(frameId: String, loaderId: Int, name: String, timestamp: TimeTicks)
  func onLoadEventFired(timestamp: TimeTicks)
  func onNavigatedWithinDocument(frameId: String, url: String)
  func onScreencastFrame(base64Data: String, metadata: ScreencastFrameMetadata, sessionId: Int)
  func onScreencastVisibilityChanged(visible: Bool)
  func onWindowOpen(url: String, windowName: String, windowFeatures: [String], userGesture: Bool)
  func onPageLayoutInvalidated(resized: Bool)
  // Overlay
  func inspectNodeRequested(backendNode: Int)
  func nodeHighlightRequested(nodeId: Int)
  func screenshotRequested(viewport: Viewport)
  // worker
  func workerErrorReported(errorMessage: ServiceWorkerErrorMessage)
  func workerRegistrationUpdated(registrations: [ServiceWorkerRegistration])
  func workerVersionUpdated(versions: [ServiceWorkerVersion])
  func onAttachedToTarget(sessionId: String, targetInfo: TargetInfo)
  func onDetachedFromTarget(sessionId: String, targetId: String?)
  func onReceivedMessageFromTarget(sessionId: String, message: String, targetId: String?)
  // Storage
  func onCacheStorageContentUpdated(origin: String, cacheName: String)
  func onCacheStorageListUpdated(origin: String)
  func onIndexedDBContentUpdated(origin: String, databaseName: String, objectStoreName: String)
  func onIndexedDBListUpdated(origin: String)
  // Tethering
  func onAccepted(port: Int, connectionId: String)
  // Network
  func onDataReceived(requestId: String, timestamp: TimeTicks, dataLength: Int64, encodedDataLength: Int64)
  func onEventSourceMessageReceived(requestId: String, timestamp: Int64, eventName: String, eventId: String, data: String)
  func onLoadingFailed(requestId: String, timestamp: Int64, type: ResourceType, errorText: String, canceled: Bool, blockedReason: BlockedReason)
  func onLoadingFinished(requestId: String, timestamp: Int64, encodedDataLength: Int64, blockedCrossSiteDocument: Bool)
  func onRequestIntercepted(
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
    responseHeaders: [String: String])
  func onRequestServedFromCache(requestId: String)
  func onRequestWillBeSent(
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
    hasUserGesture: Bool)
  func onResourceChangedPriority(requestId: String, newPriority: ResourcePriority, timestamp: Int64)
  func onResponseReceived(requestId: String, loaderId: String, timestamp: Int64, type: ResourceType, response: Response, frameId: String?)
  func onWebSocketClosed(requestId: String, timestamp: Int64)
  func onWebSocketCreated(requestId: String, url: String, initiator: Initiator)
  func onWebSocketFrameError(requestId: String, timestamp: Int64, errorMessage: String)
  func onWebSocketFrameReceived(requestId: String, timestamp: Int64, response: WebSocketFrame)
  func onWebSocketFrameSent(requestId: String, timestamp: Int64, response: WebSocketFrame)
  func onWebSocketHandshakeResponseReceived(requestId: String, timestamp: Int64, response: WebSocketResponse)
  func onWebSocketWillSendHandshakeRequest(requestId: String, timestamp: Int64, walltime: Int64, request: WebSocketRequest)
  func flush()
  // LayerTree
  func onLayerPainted(layerId: String, clipX: Int, clipY: Int, clipW: Int, clipH: Int)
  func onLayerTreeDidChange(layers: [Layer])
  // Headless
  func onNeedsBeginFramesChanged(needsBeginFrames: Bool)
  // DOMStorage
  func onDomStorageItemAdded(storageId: StorageId, key: String, newValue: String)
  func onDomStorageItemRemoved(storageId: StorageId, key: String)
  func onDomStorageItemUpdated(storageId: StorageId, key: String, oldValue: String, newValue: String)
  func onDomStorageItemsCleared(storageId: StorageId)
  // Database
  func onAddDatabase(database: Database)
  // Emulation
  func onVirtualTimeAdvanced(virtualTimeElapsed: Int)
  func onVirtualTimeBudgetExpired()
  func onVirtualTimePaused(virtualTimeElapsed: Int)
  // DOM
  func setChildNodes(parentId: Int, nodes: [DOMNode])
  func onAttributeModified(nodeId: Int, name: String, value: String)
  func onAttributeRemoved(nodeId: Int, name: String)
  func onCharacterDataModified(nodeId: Int, characterData: String)
  func onChildNodeCountUpdated(nodeId: Int, childNodeCount: Int)
  func onChildNodeInserted(parentNodeId: Int, previousNodeId: Int, node: DOMNode)
  func onChildNodeRemoved(parentNodeId: Int, nodeId: Int)
  func onDistributedNodesUpdated(insertionPointId: Int, distributedNodes: [BackendNode])
  func onDocumentUpdated()
  func onInlineStyleInvalidated(nodeIds: [Int])
  func onPseudoElementAdded(parentId: Int, pseudoElement: DOMNode)  
  func onPseudoElementRemoved(parentId: Int, pseudoElementId: Int)
  func onShadowRootPopped(hostId: Int, rootId: Int)
  func onShadowRootPushed(hostId: Int, root: DOMNode)
  // CSS
  func onFontsUpdated(font: FontFace)
  func onMediaQueryResultChanged()
  func onStyleSheetAdded(header: CSSStyleSheetHeader)
  func onStyleSheetChanged(styleSheetId: String)
  func onStyleSheetRemoved(styleSheetId: String)
  // ApplicationCache
  func onApplicationCacheStatusUpdated(frameId: String, manifestUrl: String, status: Int)
  func onNetworkStateUpdated(isNowOnline: Bool)
  // Animation
  func onAnimationCanceled(id: String)
  func onAnimationCreated(id: String)
  func onAnimationStarted(animation: Animation)
}

public class ApplicationInstance {

  public let id: Int
  public let name: String
  public let url: String
  public let uuid: String
  public var state: ApplicationState = ApplicationState.None {
    didSet {
      for observer in observers {
        observer.onApplicationStateChanged(oldState: oldValue, newState: self.state)
      }
    }
  }
  public private(set) var entries: [String: ApplicationEntry]
  private var observers: ContiguousArray<ApplicationInstanceObserver>
  private weak var host: ApplicationHost!
  private var callbacks: [CallbackHolder] = []
  
  public init(
    host: ApplicationHost,
    id: Int,
    name: String,
    url: String,
    uuid: String) {
    
    self.host = host
    self.id = id
    self.name = name
    self.url = url
    self.uuid = uuid

    entries = [:]
    observers = ContiguousArray<ApplicationInstanceObserver>()

    var pageCallbacks = CPageCallbacks()

    pageCallbacks.OnFrameAttached = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?, parent_frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameAttached(frameId: String(cString: frame_id!), parentFrameId: String(cString: parent_frame_id!))
    }
    pageCallbacks.OnDomContentEventFired = { (handle: UnsafeMutableRawPointer?, timestamp: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onDomContentEventFired(timestamp: timestamp)
    }
    pageCallbacks.OnFrameClearedScheduledNavigation = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameClearedScheduledNavigation(frameId: String(cString: frame_id!))
    }
    pageCallbacks.OnFrameDetached = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameDetached(frameId: String(cString: frame_id!))
    }
    pageCallbacks.OnFrameNavigated = { (handle: UnsafeMutableRawPointer?, framePtr: FramePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var frame = Frame()
      if framePtr != nil {
        frame.decode(framePtr!)
      }
      this.onFrameNavigated(frame: frame)
    }
    pageCallbacks.OnFrameResized = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameResized()
    }
    pageCallbacks.OnFrameScheduledNavigation = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?, delay: Int32, reason: NavigationReasonEnum, url: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameScheduledNavigation(frameId: String(cString: frame_id!), delay: Int(delay), reason: NavigationReason(rawValue: Int(reason))!, url: String(cString: url!))
    }
    pageCallbacks.OnFrameStartedLoading = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameStartedLoading(frameId: String(cString: frame_id!))
    }
    pageCallbacks.OnFrameStoppedLoading = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onFrameStoppedLoading(frameId: String(cString: frame_id!))
    }
    pageCallbacks.OnInterstitialHidden = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onInterstitialHidden()
    }
    pageCallbacks.OnInterstitialShown = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onInterstitialShown()
    }
    pageCallbacks.OnJavascriptDialogClosed = { (handle: UnsafeMutableRawPointer?, result: CInt, user_input: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onJavascriptDialogClosed(result: result != 0, userInput: String(cString: user_input!))
    }
    pageCallbacks.OnJavascriptDialogOpening = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?, message: UnsafePointer<CChar>?, type: DialogTypeEnum, /* bool */ has_browser_handler: CInt, /* optional */ default_prompt: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onJavascriptDialogOpening(url: String(cString: url!), message: String(cString: message!), type: DialogType(rawValue: Int(type))!, hasBrowserHandler: has_browser_handler == 0, defaultPrompt: default_prompt == nil ? String() : String(cString: default_prompt!))
    }
    pageCallbacks.OnLifecycleEvent = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?, loader_id: Int32, name: UnsafePointer<CChar>?, timestamp: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onLifecycleEvent(frameId: String(cString: frame_id!), loaderId: Int(loader_id), name: String(cString: name!), timestamp: TimeTicks(microseconds: timestamp))
    }
    pageCallbacks.OnLoadEventFired = { (handle: UnsafeMutableRawPointer?, timestamp: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onLoadEventFired(timestamp: TimeTicks(microseconds: timestamp))
    }
    pageCallbacks.OnNavigatedWithinDocument = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onNavigatedWithinDocument(frameId: String(cString: frame_id!), url: String(cString: url!))
    }
    pageCallbacks.OnScreencastFrame = { (handle: UnsafeMutableRawPointer?, base64_data: UnsafePointer<CChar>?, metadataPtr: ScreencastFrameMetadataPtrRef?, session_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var metadata = ScreencastFrameMetadata()
      if metadataPtr != nil {
        metadata.decode(metadataPtr!)
      }
      this.onScreencastFrame(base64Data: String(cString: base64_data!), metadata: metadata, sessionId: Int(session_id))
    }
    pageCallbacks.OnScreencastVisibilityChanged = { (handle: UnsafeMutableRawPointer?, visible: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onScreencastVisibilityChanged(visible: visible != 0)
    }
    pageCallbacks.OnWindowOpen = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?, window_name: UnsafePointer<CChar>?, window_features: UnsafeMutablePointer<UnsafePointer<CChar>?>?, window_features_count: CInt, user_gesture: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var features: [String] = []
      for i in 0..<window_features_count {
        features.append(String(cString: window_features![Int(i)]!))
      }
      this.onWindowOpen(url: String(cString: url!), windowName: String(cString: window_name!), windowFeatures: features, userGesture: user_gesture != 0)
    }
    pageCallbacks.OnPageLayoutInvalidated = { (handle: UnsafeMutableRawPointer?, resized: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onPageLayoutInvalidated(resized: resized != 0)
    }

    _ApplicationHostSetPageCallbacks(host.reference, pageCallbacks)

    var overlayCallbacks = COverlayCallbacks()
    overlayCallbacks.InspectNodeRequested = { (handle: UnsafeMutableRawPointer?, backend_node_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.inspectNodeRequested(backendNode: Int(backend_node_id))
    }
    overlayCallbacks.NodeHighlightRequested = { (handle: UnsafeMutableRawPointer?, node_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.nodeHighlightRequested(nodeId: Int(node_id))
    }
    overlayCallbacks.ScreenshotRequested = { (handle: UnsafeMutableRawPointer?, viewportPtr: ViewportPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var viewport = Viewport()
      if viewportPtr != nil {
        viewport.decode(viewportPtr!)
      }
      this.screenshotRequested(viewport: viewport)
    }

    _ApplicationHostSetOverlayCallbacks(host.reference, overlayCallbacks)

    var workerCallbacks = CWorkerCallbacks()
    workerCallbacks.WorkerErrorReported = { (handle: UnsafeMutableRawPointer?, errorMessagePtr: ServiceWorkerErrorMessagePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var message = ServiceWorkerErrorMessage()
      if errorMessagePtr != nil {
        message.decode(errorMessagePtr!)
      }
      this.workerErrorReported(errorMessage: message)
    }

    workerCallbacks.WorkerRegistrationUpdated = { (handle: UnsafeMutableRawPointer?, registrations: UnsafeMutablePointer<ServiceWorkerRegistrationPtrRef?>?, registrationsCount: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var arr: [ServiceWorkerRegistration] = []
      for i in 0..<Int(registrationsCount) {
        var registration = ServiceWorkerRegistration()
        registration.decode(registrations![i]!)
        arr.append(registration)
      }
      this.workerRegistrationUpdated(registrations: arr)
    }

    workerCallbacks.WorkerVersionUpdated = { (handle: UnsafeMutableRawPointer?, versions: UnsafeMutablePointer<ServiceWorkerVersionPtrRef?>?, versionsCount: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var arr: [ServiceWorkerVersion] = []
      for i in 0..<Int(versionsCount) {
        var version = ServiceWorkerVersion()
        version.decode(versions![i]!)
        arr.append(version)
      }
      this.workerVersionUpdated(versions: arr)
    }

    workerCallbacks.OnAttachedToTarget = { (handle: UnsafeMutableRawPointer?, session_id: UnsafePointer<CChar>?, target_info: TargetInfoPtrRef?, waiting_for_debugger: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var info = TargetInfo()
      info.decode(target_info!)
      this.onAttachedToTarget(sessionId: String(cString: session_id!), targetInfo: info)
    }

    workerCallbacks.OnDetachedFromTarget = { (handle: UnsafeMutableRawPointer?, session_id: UnsafePointer<CChar>?, /* optional */ target_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onDetachedFromTarget(sessionId: String(cString: session_id!), targetId: target_id == nil ? nil : String(cString: target_id!))
    }

    workerCallbacks.OnReceivedMessageFromTarget = { (handle: UnsafeMutableRawPointer?, session_id: UnsafePointer<CChar>?, message: UnsafePointer<CChar>?, /* optional */ target_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onReceivedMessageFromTarget(sessionId: String(cString: session_id!), message: String(cString: message!), targetId: target_id == nil ? nil : String(cString: target_id!))
    }

    _ApplicationHostSetWorkerCallbacks(host.reference, workerCallbacks)

    var storageCallbacks = CStorageCallbacks()
    storageCallbacks.OnCacheStorageContentUpdated = { (handle: UnsafeMutableRawPointer?, origin: UnsafePointer<CChar>?, cache_name: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onCacheStorageContentUpdated(origin: String(cString: origin!), cacheName: String(cString: cache_name!))
    }
    storageCallbacks.OnCacheStorageListUpdated = { (handle: UnsafeMutableRawPointer?, origin: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onCacheStorageListUpdated(origin: String(cString: origin!))
    }
    storageCallbacks.OnIndexedDBContentUpdated = { (handle: UnsafeMutableRawPointer?, origin: UnsafePointer<CChar>?, database_name: UnsafePointer<CChar>?, object_store_name: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onIndexedDBContentUpdated(origin: String(cString: origin!), databaseName: String(cString: database_name!), objectStoreName: String(cString: object_store_name!))
    }
    storageCallbacks.OnIndexedDBListUpdated = { (handle: UnsafeMutableRawPointer?, origin: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onIndexedDBListUpdated(origin: String(cString: origin!))
    }

    _ApplicationHostSetStorageCallbacks(host.reference, storageCallbacks)
    
    var tetheringCallbacks = CTetheringCallbacks()
    tetheringCallbacks.OnAccepted = { (handle: UnsafeMutableRawPointer?, port: Int32, connection_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onAccepted(port: Int(port), connectionId: String(cString: connection_id!))
    }

    _ApplicationHostSetTetheringCallbacks(host.reference, tetheringCallbacks)

    var networkCallbacks = CNetworkCallbacks()
    networkCallbacks.OnDataReceived = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, data_length: Int64, encoded_data_length: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onDataReceived(requestId: String(cString: request_id!), timestamp: TimeTicks(microseconds: timestamp), dataLength: data_length, encodedDataLength: encoded_data_length)
    }
    networkCallbacks.OnEventSourceMessageReceived = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, event_name: UnsafePointer<CChar>?, event_id: UnsafePointer<CChar>?, data: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onEventSourceMessageReceived(requestId: String(cString: request_id!), timestamp: timestamp, eventName: String(cString: event_name!), eventId: String(cString: event_id!), data: String(cString: data!))
    }
    networkCallbacks.OnLoadingFailed = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, type: ResourceTypeEnum, error_text: UnsafePointer<CChar>?, canceled: CInt, blocked_reason: BlockedReasonEnum) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onLoadingFailed(requestId: String(cString: request_id!), timestamp: timestamp, type: ResourceType(rawValue: Int(type))!, errorText: error_text == nil ? String() : String(cString: error_text!), canceled: canceled == 0, blockedReason: BlockedReason(rawValue: Int(blocked_reason))!)
    }
    networkCallbacks.OnLoadingFinished = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, encoded_data_length: Int64, blocked_cross_site_document: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onLoadingFinished(requestId: String(cString: request_id!), timestamp: timestamp, encodedDataLength: encoded_data_length, blockedCrossSiteDocument: blocked_cross_site_document == 0)
    }
    networkCallbacks.OnRequestIntercepted = { (handle: UnsafeMutableRawPointer?,
      interception_id: UnsafePointer<CChar>?, 
      request: RequestPtrRef?, 
      frame_id: UnsafePointer<CChar>?, 
      resource_type: ResourceTypeEnum, 
      is_navigation_request: CInt, 
      is_download: CInt, 
      /* optional */ redirect_url: UnsafePointer<CChar>?, 
      auth_challenge: AuthChallengePtrRef?, 
      response_error_reason: ErrorReasonEnum, 
      response_status_code: Int32, 
      response_headers_keys: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      response_headers_keys_count: CInt, 
      response_headers_values: UnsafeMutablePointer<UnsafePointer<CChar>?>?, 
      response_headers_values_count: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var responseHeaders: [String: String] = [:]
      for i in 0..<response_headers_keys_count {
        responseHeaders[String(cString: response_headers_keys![Int(i)]!)] = String(cString: response_headers_values![Int(i)]!)
      }

      var challenge = AuthChallenge()
      challenge.decode(auth_challenge!)

      this.onRequestIntercepted(
        interceptionId: String(cString: interception_id!), 
        request: Request(), 
        frameId: String(cString: frame_id!), 
        resourceType: ResourceType(rawValue: Int(resource_type))!, 
        isNavigationRequest: is_navigation_request == 0, 
        isDownload: is_download == 0, 
        redirectUrl: String(cString: redirect_url!), 
        authChallenge: challenge, 
        responseErrorReason: ErrorReason(rawValue: Int(response_error_reason))!, 
        responseStatusCode: Int(response_status_code), 
        responseHeaders: responseHeaders)
 
    }
    networkCallbacks.OnRequestServedFromCache = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onRequestServedFromCache(requestId: String(cString: request_id!))
    }
    networkCallbacks.OnRequestWillBeSent = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, loader_id: UnsafePointer<CChar>?, 
      document_url: UnsafePointer<CChar>?, 
      request: RequestPtrRef?, 
      timestamp: Int64, 
      walltime: Int64, 
      initiator: InitiatorPtrRef?, 
      redirect_response: ResponsePtrRef?, 
      type: ResourceTypeEnum, 
      /* optional */ frame_id: UnsafePointer<CChar>?, 
      has_user_gesture: CInt /* bool */) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onRequestWillBeSent(
        requestId: String(cString: request_id!), 
        loaderId: String(cString: loader_id!),
        documentUrl: String(cString: document_url!), 
        request: Request(), 
        timestamp: timestamp, 
        walltime: walltime, 
        initiator: Initiator(), 
        redirectResponse: Response(), 
        type: ResourceType(rawValue: Int(type))!, 
        frameId: frame_id == nil ? nil : String(cString: frame_id!), 
        hasUserGesture: has_user_gesture == 0)
    }
    networkCallbacks.OnResourceChangedPriority = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, new_priority: ResourcePriorityEnum, timestamp: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onResourceChangedPriority(requestId: String(cString: request_id!), newPriority: ResourcePriority(rawValue: Int(new_priority))!, timestamp: timestamp)
    }
    networkCallbacks.OnResponseReceived = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, loader_id: UnsafePointer<CChar>?, timestamp: Int64, type: ResourceTypeEnum, response: ResponsePtrRef?, /* optional */ frame_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onResponseReceived(requestId: String(cString: request_id!), loaderId: String(cString: loader_id!), timestamp: timestamp, type: ResourceType(rawValue: Int(type))!, response: Response(), frameId: frame_id == nil ? nil : String(cString: frame_id!))
    }
    networkCallbacks.OnWebSocketClosed = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onWebSocketClosed(requestId: String(cString: request_id!), timestamp: timestamp)
    }
    networkCallbacks.OnWebSocketCreated = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?, initiatorPtr: InitiatorPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var initiator = Initiator()
      initiator.decode(initiatorPtr!)
      this.onWebSocketCreated(requestId: String(cString: request_id!), url: String(cString: url!), initiator: initiator)
    }
    networkCallbacks.OnWebSocketFrameError = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, error_message: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onWebSocketFrameError(requestId: String(cString: request_id!), timestamp: timestamp, errorMessage: error_message == nil ? String() : String(cString: request_id!))
    }
    networkCallbacks.OnWebSocketFrameReceived = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, responsePtr: WebSocketFramePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var response = WebSocketFrame()
      response.decode(responsePtr!)
      this.onWebSocketFrameReceived(requestId: String(cString: request_id!), timestamp: timestamp, response: response)
    }
    networkCallbacks.OnWebSocketFrameSent = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, responsePtr: WebSocketFramePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var response = WebSocketFrame()
      response.decode(responsePtr!)
      this.onWebSocketFrameSent(requestId: String(cString: request_id!), timestamp: timestamp, response: response)
    }
    networkCallbacks.OnWebSocketHandshakeResponseReceived = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, responsePtr: WebSocketResponsePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var response = WebSocketResponse()
      response.decode(responsePtr!)
      this.onWebSocketHandshakeResponseReceived(requestId: String(cString: request_id!), timestamp: timestamp, response: response)
    }
    networkCallbacks.OnWebSocketWillSendHandshakeRequest = { (handle: UnsafeMutableRawPointer?, request_id: UnsafePointer<CChar>?, timestamp: Int64, wall_time: Int64, requestPtr: WebSocketRequestPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var request = WebSocketRequest()
      request.decode(requestPtr!)
      this.onWebSocketWillSendHandshakeRequest(requestId: String(cString: request_id!), timestamp: timestamp, walltime: wall_time, request: request)
    }
    networkCallbacks.Flush = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.flush()
    }
    _ApplicationHostSetNetworkCallbacks(host.reference, networkCallbacks)

    var layerTreeCallbacks = CLayerTreeCallbacks()
    layerTreeCallbacks.OnLayerPainted = { (handle: UnsafeMutableRawPointer?, layer_id: UnsafePointer<CChar>?, clip_x: CInt, clip_y: CInt, clip_w: CInt, clip_h: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onLayerPainted(layerId: String(cString: layer_id!), clipX: Int(clip_x), clipY: Int(clip_y), clipW: Int(clip_w), clipH: Int(clip_h))
    }
    
    layerTreeCallbacks.OnLayerTreeDidChange = { (handle: UnsafeMutableRawPointer?,  /* optional */ layersPtr: UnsafeMutablePointer<LayerPtrRef?>?, layers_count: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var layers: [Layer] = []
      for i in 0..<Int(layers_count) {
        var layer = Layer()
        layer.decode(layersPtr![i]!)
        layers.append(layer)
      }
      this.onLayerTreeDidChange(layers: layers)
    }
    _ApplicationHostSetLayerTreeCallbacks(host.reference, layerTreeCallbacks)

    var headlessCallbacks = CHeadlessCallbacks()
    headlessCallbacks.OnNeedsBeginFramesChanged = { (handle: UnsafeMutableRawPointer?, needs_begin_frames: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onNeedsBeginFramesChanged(needsBeginFrames: needs_begin_frames == 0)
    }
    _ApplicationHostSetHeadlessCallbacks(host.reference, headlessCallbacks)

    var domStorageCallbacks = CDOMStorageCallbacks()
    domStorageCallbacks.OnDomStorageItemAdded = { (handle: UnsafeMutableRawPointer?, storage_id: StorageIdPtrRef?, key: UnsafePointer<CChar>?, new_value: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var storage = StorageId()
      storage.decode(storage_id!)
      this.onDomStorageItemAdded(storageId: storage, key: String(cString: key!), newValue: String(cString: new_value!))
    }
    
    domStorageCallbacks.OnDomStorageItemRemoved = { (handle: UnsafeMutableRawPointer?, storage_id: StorageIdPtrRef?, key: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var storage = StorageId()
      storage.decode(storage_id!)
      this.onDomStorageItemRemoved(storageId: storage, key: String(cString: key!))
    }
    
    domStorageCallbacks.OnDomStorageItemUpdated = { (handle: UnsafeMutableRawPointer?, storage_id: StorageIdPtrRef?, key: UnsafePointer<CChar>?, old_value: UnsafePointer<CChar>?, new_value: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var storage = StorageId()
      storage.decode(storage_id!)
      this.onDomStorageItemUpdated(storageId: storage, key: String(cString: key!), oldValue: String(cString: old_value!), newValue: String(cString: new_value!))
    }
    
    domStorageCallbacks.OnDomStorageItemsCleared = { (handle: UnsafeMutableRawPointer?, storage_id: StorageIdPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var storage = StorageId()
      storage.decode(storage_id!)
      this.onDomStorageItemsCleared(storageId: storage)
    }
    _ApplicationHostSetDOMStorageCallbacks(host.reference, domStorageCallbacks)

    var databaseCallbacks = CDatabaseCallbacks()
    databaseCallbacks.OnAddDatabase = { (handle: UnsafeMutableRawPointer?, databasePtr: DatabasePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var database = Database()
      database.decode(databasePtr!)
      this.onAddDatabase(database: database)
    }
    _ApplicationHostSetDatabaseCallback(host.reference, databaseCallbacks)

    var emulationCallbacks = CEmulationCallbacks()
    emulationCallbacks.OnVirtualTimeAdvanced = { (handle: UnsafeMutableRawPointer?, virtual_time_elapsed: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onVirtualTimeAdvanced(virtualTimeElapsed: Int(virtual_time_elapsed))
    }
    
    emulationCallbacks.OnVirtualTimeBudgetExpired = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onVirtualTimeBudgetExpired()
    }
    
    emulationCallbacks.OnVirtualTimePaused = { (handle: UnsafeMutableRawPointer?, virtual_time_elapsed: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onVirtualTimePaused(virtualTimeElapsed: Int(virtual_time_elapsed))
    }
    _ApplicationHostSetEmulationCallbacks(host.reference, emulationCallbacks)

    var domCallbacks = CDOMCallbacks()
    domCallbacks.SetChildNodes = { (handle: UnsafeMutableRawPointer?, parent_id: Int32, nodesPtr: UnsafeMutablePointer<DOMNodePtrRef?>?, nodes_count: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var nodes: [DOMNode] = []
      for i in 0..<Int(nodes_count) {
        var node = DOMNode()
        node.decode(nodesPtr![i]!)
        nodes.append(node)
      }
      this.setChildNodes(parentId: Int(parent_id), nodes: nodes)
    }
    domCallbacks.OnAttributeModified = { (handle: UnsafeMutableRawPointer?, node_id: Int32, name: UnsafePointer<CChar>?, value: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onAttributeModified(nodeId: Int(node_id), name: String(cString: name!), value: String(cString: value!))
    }
    domCallbacks.OnAttributeRemoved = { (handle: UnsafeMutableRawPointer?, node_id: Int32, name: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onAttributeRemoved(nodeId: Int(node_id), name: String(cString: name!))
    }
    domCallbacks.OnCharacterDataModified = { (handle: UnsafeMutableRawPointer?, node_id: Int32, character_data: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onCharacterDataModified(nodeId: Int(node_id), characterData: String(cString: character_data!))
    }
    domCallbacks.OnChildNodeCountUpdated = { (handle: UnsafeMutableRawPointer?, node_id: Int32, child_node_count: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onChildNodeCountUpdated(nodeId: Int(node_id), childNodeCount: Int(child_node_count))
    }
    domCallbacks.OnChildNodeInserted = { (handle: UnsafeMutableRawPointer?, parent_node_id: Int32, previous_node_id: Int32, nodePtr: DOMNodePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var node = DOMNode()
      node.decode(nodePtr!)
      this.onChildNodeInserted(parentNodeId: Int(parent_node_id), previousNodeId: Int(previous_node_id), node: node)
    }
    domCallbacks.OnChildNodeRemoved = { (handle: UnsafeMutableRawPointer?, parent_node_id: Int32, node_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onChildNodeRemoved(parentNodeId: Int(parent_node_id), nodeId: Int(node_id))
    }
    domCallbacks.OnDistributedNodesUpdated = { (handle: UnsafeMutableRawPointer?, insertion_point_id: Int32, distributed_nodes: UnsafeMutablePointer<BackendNodePtrRef?>?, distributed_nodes_count: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var nodes: [BackendNode] = []
      for i in 0..<Int(distributed_nodes_count) {
        var node = BackendNode()
        node.decode(distributed_nodes![i]!)
        nodes.append(node)
      }
      this.onDistributedNodesUpdated(insertionPointId: Int(insertion_point_id), distributedNodes: nodes)
    }
    domCallbacks.OnDocumentUpdated = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onDocumentUpdated()
    }
    domCallbacks.OnInlineStyleInvalidated = { (handle: UnsafeMutableRawPointer?, node_ids: UnsafeMutablePointer<Int32>?, node_ids_count: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var nodes: [Int] = []
      for i in 0..<node_ids_count {
        nodes.append(Int(node_ids![Int(i)]))
      }
      this.onInlineStyleInvalidated(nodeIds: nodes)
    }
    domCallbacks.OnPseudoElementAdded = { (handle: UnsafeMutableRawPointer?, parent_id: Int32, pseudo_element: DOMNodePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var node = DOMNode()
      node.decode(pseudo_element!)
      this.onPseudoElementAdded(parentId: Int(parent_id), pseudoElement: node)
    }
    domCallbacks.OnPseudoElementRemoved = { (handle: UnsafeMutableRawPointer?, parent_id: Int32, pseudo_element_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onPseudoElementRemoved(parentId: Int(parent_id), pseudoElementId: Int(pseudo_element_id))
    }
    domCallbacks.OnShadowRootPopped = { (handle: UnsafeMutableRawPointer?, host_id: Int32, root_id: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onShadowRootPopped(hostId: Int(host_id), rootId: Int(root_id))
    }
    domCallbacks.OnShadowRootPushed = { (handle: UnsafeMutableRawPointer?, host_id: Int32, root: DOMNodePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var node = DOMNode()
      node.decode(root!)
      this.onShadowRootPushed(hostId: Int(host_id), root: node)
    }
    _ApplicationHostSetDOMCallbacks(host.reference, domCallbacks)

    var cssCallbacks = CCSSCallbacks()
    cssCallbacks.OnFontsUpdated = { (handle: UnsafeMutableRawPointer?, fontPtr: FontFacePtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var font = FontFace()
      font.decode(fontPtr!)
      this.onFontsUpdated(font: font)
    }
    cssCallbacks.OnMediaQueryResultChanged = { (handle: UnsafeMutableRawPointer?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onMediaQueryResultChanged()
    }
    cssCallbacks.OnStyleSheetAdded = { (handle: UnsafeMutableRawPointer?, headerPtr: CSSStyleSheetHeaderPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var header = CSSStyleSheetHeader()
      header.decode(headerPtr!)
      this.onStyleSheetAdded(header: header)
    }
    cssCallbacks.OnStyleSheetChanged = { (handle: UnsafeMutableRawPointer?, style_sheet_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onStyleSheetChanged(styleSheetId: String(cString: style_sheet_id!))
    }
    cssCallbacks.OnStyleSheetRemoved = { (handle: UnsafeMutableRawPointer?, style_sheet_id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onStyleSheetRemoved(styleSheetId: String(cString: style_sheet_id!))
    }
    _ApplicationHostSetCSSCallbacks(host.reference, cssCallbacks)

    var applicationCacheCallbacks = CApplicationCacheCallbacks()
    applicationCacheCallbacks.OnApplicationCacheStatusUpdated = { (handle: UnsafeMutableRawPointer?, frame_id: UnsafePointer<CChar>?, manifest_url: UnsafePointer<CChar>?, status: Int32) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onApplicationCacheStatusUpdated(frameId: String(cString: frame_id!), manifestUrl: String(cString: manifest_url!), status: Int(status))
    }
    
    applicationCacheCallbacks.OnNetworkStateUpdated = { (handle: UnsafeMutableRawPointer?, is_now_online: CInt) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onNetworkStateUpdated(isNowOnline: is_now_online != 0)
    }
    _ApplicationHostSetApplicationCacheCallbacks(host.reference, applicationCacheCallbacks)

    var animationCallbacks = CAnimationCallbacks()
    animationCallbacks.OnAnimationCanceled = { (handle: UnsafeMutableRawPointer?, id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onAnimationCanceled(id: String(cString: id!))
    }
    
    animationCallbacks.OnAnimationCreated = { (handle: UnsafeMutableRawPointer?, id: UnsafePointer<CChar>?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      this.onAnimationCreated(id: String(cString: id!))
    }
    
    animationCallbacks.OnAnimationStarted = { (handle: UnsafeMutableRawPointer?, animationPtr: AnimationPtrRef?) in
      let this = unsafeBitCast(handle, to: ApplicationInstance.self)
      var anim = Animation()
      anim.decode(animationPtr!)
      this.onAnimationStarted(animation: anim)
    }

    _ApplicationHostSetAnimationCallbacks(host.reference, animationCallbacks)
    
    let selfState = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostSetDriverStateForInstance(host.reference, CInt(id), selfState)

    // enable all functionality on application process
    // _ApplicationHostOverlayEnable(host.reference, CInt(id))
    // _ApplicationHostPageEnable(host.reference, CInt(id))
    // _ApplicationHostWorkerEnable(host.reference, CInt(id))
    // _ApplicationHostNetworkEnable(host.reference, CInt(id), /* max_total_buffer_size */ CInt.max, /*max_resource_buffer_size*/ CInt.max, /*max_post_data_size*/ CInt.max)
    // _ApplicationHostLayerTreeEnable(host.reference, CInt(id))
    // _ApplicationHostIndexedDBEnable(host.reference, CInt(id))
    // _ApplicationHostDOMStorageEnable(host.reference, CInt(id))
    // _ApplicationHostDatabaseEnable(host.reference, CInt(id))
    // _ApplicationHostDOMEnable(host.reference, CInt(id))
    // _ApplicationHostCSSEnable(host.reference, CInt(id))
    // _ApplicationHostApplicationCacheEnable(host.reference, CInt(id))
    // _ApplicationHostAnimationEnable(host.reference, CInt(id))
  
  
    // FIXME: should be enabled only if app is trully headless  
    //_ApplicationHostHeadlessEnable(ApplicationHostRef handle, int instance_id)
  
  }


  public func addObserver(_ observer: ApplicationInstanceObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: ApplicationInstanceObserver) {
    for (index, current) in observers.enumerated() {
      if current === observer {
        observers.remove(at: index)
        return
      }
    }
  }

  public func addCallbackHolder(_ callback: CallbackHolder) {
    callbacks.append(callback)
  }

  public func removeCallbackHolder(_ callback: CallbackHolder) {
    for (i, cb) in callbacks.enumerated() {
      if cb === callback {
        callbacks.remove(at: i)
        return
      }
    }
  }

  public func getInfo(_ callback: @escaping GetInfoCallback) {
    let holder = CallbackHolder(self, getInfo: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostSystemInfoGetInfo(host.reference, CInt(id), 
    // (*CGetInfoCallback)(void*, GPUInfoPtrRef, const char*, const char*, const char*)
    { (handle: UnsafeMutableRawPointer?, info: GPUInfoPtrRef?, modelName: UnsafePointer<CChar>?, modelVersion: UnsafePointer<CChar>?, commandLine: UnsafePointer<CChar>?) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      let gpuInfo = GPUInfo()
      gpuInfo.decode(info!)
      state.getInfo!(gpuInfo, String(cString: modelName!), String(cString: modelVersion!), String(cString: commandLine!))
      state.dispose()
      // callback()
    }, holderInstance)
  }

  // Host
  public func closeHost() {
    _ApplicationHostHostClose(host.reference, CInt(id))
  }

  public func getHostVersion(_ callback: @escaping GetVersionCallback) {
    let holder = CallbackHolder(self, getVersion: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostHostGetVersion(host.reference, CInt(id), { 
      // (void*, const char*, const char*, const char*, const char*, const char*)
      (handle: UnsafeMutableRawPointer?, protocolVersion: UnsafePointer<CChar>?, product: UnsafePointer<CChar>?, revision: UnsafePointer<CChar>?, userAgent: UnsafePointer<CChar>?, jsVersion: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getVersion!(String(cString: protocolVersion!), String(cString: product!), String(cString: revision!), String(cString: userAgent!), String(cString: jsVersion!))
        state.dispose()
     }, holderInstance)
  }

  public func getHostCommandLine(_ callback: @escaping GetHostCommandLineCallback) {
    let holder = CallbackHolder(self, getHostCommandLine: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostHostGetHostCommandLine(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, cmdLine: UnsafeMutablePointer<UnsafePointer<CChar>?>?, count: CInt) in 
        var arr = [String]()
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        for i in 0..<count {
          arr.append(String(cString: cmdLine![Int(i)]!))
        }
        state.getHostCommandLine!(arr)
        state.dispose()
    }, holderInstance)
  }

  public func getHistograms(query: String?, _ callback: @escaping GetHistogramsCallback) {
    let holder = CallbackHolder(self, getHistograms: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    guard let q = query else {
      _ApplicationHostHostGetHistograms(host.reference, CInt(id), nil, {
        (handle: UnsafeMutableRawPointer?, histos: UnsafeMutablePointer<HistogramPtrRef?>?, count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var histograms: [Histogram] = []
        for i in 0..<Int(count) {
          var histogram = Histogram()
          histogram.decode(histos![i]!)
        }
        state.getHistograms!(histograms)
        state.dispose()
      }, holderInstance)
      return
    }
    q.withCString {
    _ApplicationHostHostGetHistograms(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, histos: UnsafeMutablePointer<HistogramPtrRef?>?, count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var histograms: [Histogram] = []
        for i in 0..<Int(count) {
          var histogram = Histogram()
          histogram.decode(histos![i]!)
        }
        state.getHistograms!(histograms)
        state.dispose()
      }, holderInstance)
    }
  }

  public func getHistogram(name: String, _ callback: @escaping GetHistogramCallback) {
    let holder = CallbackHolder(self, getHistogram: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    name.withCString {
      _ApplicationHostHostGetHistogram(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, histo: HistogramPtrRef?) in
         let state = unsafeBitCast(handle, to: CallbackHolder.self)
         var histogram = Histogram()
         histogram.decode(histo!)
         state.getHistogram!(histogram)
         state.dispose()
      }, holderInstance)
    }
  }

  public func getWindowBounds(windowId: Int, _ callback: @escaping GetWindowBoundsCallback) {
    let holder = CallbackHolder(self, getWindowBounds: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostHostGetWindowBounds(host.reference, CInt(id), CInt(windowId), {
      (handle: UnsafeMutableRawPointer?, boundsPtr: BoundsPtrRef?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var bounds = Bounds()
        bounds.decode(boundsPtr!)
        state.getWindowBounds!(bounds)
        state.dispose()
    }, holderInstance)
  }

  public func setWindowBounds(windowId: Int, bounds: Bounds) {
    _ApplicationHostHostSetWindowBounds(host.reference, CInt(id), CInt(windowId), nil)
  }

  public func getWindowForTarget(targetId: String, _ callback: @escaping GetWindowForTargetCallback) {
    let holder = CallbackHolder(self, getWindowForTarget: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    targetId.withCString {
      _ApplicationHostHostGetWindowForTarget(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, window_id: CInt, boundsPtr: BoundsPtrRef?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var bounds = Bounds()
        bounds.decode(boundsPtr!)
        state.getWindowForTarget!(Int(window_id), Bounds())
      }, holderInstance)
    }
  }

  // Overlay
  public func hideHighlight() {
    _ApplicationHostOverlayHideHighlight(host.reference, CInt(id))
  }

  public func highlightFrame(frameId: String, contentColor: RGBA, contentOutlineColor: RGBA) {
    frameId.withCString {
      // FIXME
      _ApplicationHostOverlayHighlightFrame(host.reference, CInt(id), $0, nil, nil)
    }
  }

  public func highlightNode(config: HighlightConfig, node: Int, backendNode: Int?, objectId: String?) {
    // FIXME
    guard let oid = objectId else {
      _ApplicationHostOverlayHighlightNode(host.reference, CInt(id), nil, CInt(node), CInt(backendNode ?? -1), nil)
      return
    }
    oid.withCString {
      _ApplicationHostOverlayHighlightNode(host.reference, CInt(id), nil, CInt(node), CInt(backendNode ?? -1), $0)
    }
  }

  public func highlightQuad(quad: [Double], color: RGBA, outlineColor: RGBA) {
    var doubles: UnsafeMutablePointer<Double>?
    doubles = malloc(quad.count * MemoryLayout<Double>.size).load(as: UnsafeMutablePointer<Double>.self)
    for i in 0..<quad.count {
      doubles![i] = quad[i]
    }
    _ApplicationHostOverlayHighlightQuad(host.reference, CInt(id), doubles, CInt(quad.count), nil, nil)
    free(doubles)
  }

  public func highlightRect(_ r: IntRect, color: RGBA, outlineColor: RGBA) {
    highlightRect(x: r.x, y: r.y, width: r.width, height: r.height, color: color, outlineColor: outlineColor)
  }

  public func highlightRect(x: Int, y: Int, width: Int, height: Int, color: RGBA, outlineColor: RGBA) {
    _ApplicationHostOverlayHighlightRect(host.reference, CInt(id), CInt(x), CInt(y), CInt(width), CInt(height), 
      CInt(color.r),
      CInt(color.g),
      CInt(color.b),
      color.a, 
      CInt(outlineColor.r),
      CInt(outlineColor.g),
      CInt(outlineColor.b),
      outlineColor.a)
  }

  //public func setInspectMode() {
  //  _ApplicationHostOverlaySetInspectMode(host.reference, CInt(id), InspectModeEnum mode, HighlightConfigPtrRef highlight_config);
  //}

  //public func setPausedInDebuggerMessage() {
  //  _ApplicationHostOverlaySetPausedInDebuggerMessage(host.reference, CInt(id), const char* /* optional */ message);
  //}

  public func setShowDebugBorders(_ show: Bool) {
    _ApplicationHostOverlaySetShowDebugBorders(host.reference, CInt(id), show ? 1 : 0)
  }

  public func setShowFPSCounter(_ show: Bool) {
    _ApplicationHostOverlaySetShowFPSCounter(host.reference, CInt(id), show ? 1 : 0)
  }

  public func setShowPaintRects(_ show: Bool) {
    _ApplicationHostOverlaySetShowPaintRects(host.reference, CInt(id), show ? 1 : 0)
  }

  public func setShowScrollBottleneckRects(_ show: Bool) {
    _ApplicationHostOverlaySetShowScrollBottleneckRects(host.reference, CInt(id), show ? 1 : 0)
  }

  public func setShowViewportSizeOnResize(_ show: Bool) {
    _ApplicationHostOverlaySetShowViewportSizeOnResize(host.reference, CInt(id), show ? 1 : 0)
  }

  //public func setSuspended() {
  //  _ApplicationHostOverlaySetSuspended(host.reference, CInt(id), int /* bool */ suspended);
  //}

  // Page
  public func addScriptToEvaluateOnNewDocument(source: String, _ callback: @escaping AddScriptToEvaluateOnNewDocumentCallback) {
    let holder = CallbackHolder(self, addScriptToEvaluateOnNewDocument: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    source.withCString {
      _ApplicationHostPageAddScriptToEvaluateOnNewDocument(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, identifier: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.addScriptToEvaluateOnNewDocument!(String(cString: identifier!))
        state.dispose()
      }, holderInstance)
    }
  }

  public func removeScriptToEvaluateOnNewDocument(identifier: String) {
    identifier.withCString {
      _ApplicationHostPageRemoveScriptToEvaluateOnNewDocument(host.reference, CInt(id), $0)
    }
  }

  public func setAutoAttachToCreatedPages(_ autoAttach: Bool) {
    _ApplicationHostPageSetAutoAttachToCreatedPages(host.reference, CInt(id), autoAttach ? 1 : 0)
  }

  public func setLifecycleEventsEnabled(_ enabled: Bool) {
    _ApplicationHostPageSetLifecycleEventsEnabled(host.reference, CInt(id), enabled ? 1 : 0)
  }

  public func reload(ignoreCache: Bool, scriptToEvaluateOnLoad: String?) {
    guard let script = scriptToEvaluateOnLoad else {
      _ApplicationHostPageReload(host.reference, CInt(id), ignoreCache ? 1 : 0, nil)  
      return
    }
    script.withCString {
      _ApplicationHostPageReload(host.reference, CInt(id), ignoreCache ? 1 : 0, $0)
    }
  }

  public func setAdBlockingEnabled(_ enabled: Bool) {
    _ApplicationHostPageSetAdBlockingEnabled(host.reference, CInt(id), enabled ? 1 : 0)
  }

  public func navigate(url: String, referrer: String, transitionType: TransitionType, _ callback: @escaping NavigateCallback) {
    let holder = CallbackHolder(self, navigate: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    url.withCString { curl in
      referrer.withCString { creferrer in
        _ApplicationHostPageNavigate(host.reference, CInt(id), curl, creferrer, CInt(transitionType.rawValue), {
          (handle: UnsafeMutableRawPointer?, frameId: UnsafePointer<CChar>?, loaderId: CInt, errorText: UnsafePointer<CChar>?) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.navigate!(String(cString: frameId!), Int(loaderId), errorText == nil ? String() : String(cString: errorText!))
          state.dispose()
        }, holderInstance)
      }
    }
  }

  public func stopLoading() {
    _ApplicationHostPageStopLoading(host.reference, CInt(id));
  }
  
  public func getNavigationHistory(_ callback: @escaping GetNavigationHistoryCallback) {
    let holder = CallbackHolder(self, getNavigationHistory: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetNavigationHistory(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, currentIndex: CInt, entries: UnsafeMutablePointer<NavigationEntryPtrRef?>?, count: CInt) in  
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [NavigationEntry] = []
      for i in 0..<Int(count) {
        var entry = NavigationEntry()
        entry.decode(entries![i]!)
        arr.append(entry)
      }
      state.getNavigationHistory!(Int(currentIndex), arr)
    }, holderInstance)
  }

  public func navigateToHistoryEntry(_ entry: Int) {
    _ApplicationHostPageNavigateToHistoryEntry(host.reference, CInt(id), CInt(entry))
  }

  public func getCookies(_ callback: @escaping GetCookiesCallback) {
    let holder = CallbackHolder(self, getCookies: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetCookies(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, cookies: UnsafeMutablePointer<CookiePtrRef?>?, count: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [Cookie] = []
      for i in 0..<Int(count) {
        var cookie = Cookie()
        cookie.decode(cookies![i]!)
        arr.append(cookie)
      }
      state.getCookies!(arr)
    }, holderInstance)
  }

  public func deleteCookie(name: String, url: String) {
    name.withCString { cname in
      url.withCString { curl in
        _ApplicationHostPageDeleteCookie(host.reference, CInt(id), cname, curl)
      }
    }
  }

  public func getResourceTree(_ callback: @escaping GetResourceTreeCallback) {
    let holder = CallbackHolder(self, getResourceTree: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetResourceTree(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, treePtr: FrameResourceTreePtrRef?) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var tree = FrameResourceTree()
      tree.decode(treePtr!)
      state.getResourceTree!(tree)
    }, holderInstance)
  }

  public func getFrameTree(_ callback: @escaping GetFrameTreeCallback) { 
    let holder = CallbackHolder(self, getFrameTree: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetFrameTree(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, treePtr: FrameTreePtrRef?) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var tree = FrameTree()
      tree.decode(treePtr!)
      state.getFrameTree!(tree)
    }, holderInstance)
  }

  public func getResourceContent(frameId: String, url: String, _ callback: @escaping GetResourceContentCallback) {
    let holder = CallbackHolder(self, getResourceContent: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frameId.withCString { cframe in
      url.withCString { curl in
        _ApplicationHostPageGetResourceContent(host.reference, CInt(id), cframe, curl, {
          (handle: UnsafeMutableRawPointer?, content: UnsafePointer<CChar>?, base64Encoded: CInt) in 
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.getResourceContent!(String(cString: content!), base64Encoded != 0)
        }, holderInstance)
      }
    }
  }

  public func searchInResource(frameId: String, url: String, query: String, caseSensitive: Bool, isRegex: Bool, _ callback: @escaping SearchInResourceCallback) {
    let holder = CallbackHolder(self, searchInResource: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frameId.withCString { cframe in
      url.withCString { curl in
        query.withCString { cquery in
          _ApplicationHostPageSearchInResource(host.reference, CInt(id), cframe, curl, cquery, caseSensitive ? 1 : 0, isRegex ? 1 : 0, {
            (handle: UnsafeMutableRawPointer?, result: UnsafeMutablePointer<SearchMatchPtrRef?>?, count: CInt) in 
            let state = unsafeBitCast(handle, to: CallbackHolder.self)
            var matches: [SearchMatch] = []
            for i in 0..<Int(count) {
              var match = SearchMatch()
              match.decode(result![i]!)
              matches.append(match)
            }
            state.searchInResource!(matches)
          }, holderInstance)
        }
      }
    }
  }

  public func setDocumentContent(frameId: String, html: String) {
    frameId.withCString { cframe in
      html.withCString { chtml in
        _ApplicationHostPageSetDocumentContent(host.reference, CInt(id), cframe, chtml)
      }
    }
  }

  // public func setDeviceMetricsOverride() {
  //   _ApplicationHostPageSetDeviceMetricsOverride(host.reference, CInt(id), int32_t width, int32_t height, int32_t device_scale_factor, int /* bool */ mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, int /* bool */ dont_set_visible_size, ScreenOrientationPtrRef screen_orientation, ViewportPtrRef viewport);
  // }
  
  // public func clearDeviceMetricsOverride() {
  //   _ApplicationHostPageClearDeviceMetricsOverride(host.reference, CInt(id));
  // }
  
  // public func setGeolocationOverride() {
  //   _ApplicationHostPageSetGeolocationOverride(host.reference, CInt(id), int32_t latitude, int32_t longitude, int32_t accuracy);
  // }
  
  // public func clearGeolocationOverride() {
  //   _ApplicationHostPageClearGeolocationOverride(host.reference, CInt(id));
  // }
  
  // public func setDeviceOrientationOverride() {
  //   _ApplicationHostPageSetDeviceOrientationOverride(host.reference, CInt(id), int32_t alpha, int32_t beta, int32_t gamma);
  // }
  
  // public func clearDeviceOrientationOverride() {
  //   _ApplicationHostPageClearDeviceOrientationOverride(host.reference, CInt(id));
  // }
  
  public func setTouchEmulationEnabled(_ enabled: Bool, configuration: String?) {
    guard let cfg = configuration else {
      _ApplicationHostPageSetTouchEmulationEnabled(host.reference, CInt(id), enabled ? 1 : 0, nil)  
      return
    }
    cfg.withCString {
      _ApplicationHostPageSetTouchEmulationEnabled(host.reference, CInt(id), enabled ? 1 : 0, $0)
    }
  }
  
  public func captureScreenshot(format: FrameFormat, quality: Int, clip: Viewport, fromSurface: Bool, _ callback: @escaping CaptureScreenshotCallback) {
    let holder = CallbackHolder(self, captureScreenshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageCaptureScreenshot(host.reference, CInt(id), CInt(format.rawValue), CInt(quality), nil, fromSurface ? 1 : 0, {
      (handle: UnsafeMutableRawPointer?, base64Data: UnsafePointer<CChar>?) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.captureScreenshot!(String(cString: base64Data!))
    }, holderInstance)
  }
  
  public func printToPDF(landscape: Bool,
                         displayHeaderFooter: Bool, 
                         printBackground: Bool, 
                         scale: Float, 
                         paperWidth: Float, 
                         paperHeight: Float, 
                         marginTop: Float, 
                         marginBottom: Float, 
                         marginLeft: Float, 
                         marginRight: Float, 
                         pageRanges: String?, 
                         ignoreInvalidPageRanges: Bool, 
                         _ callback: @escaping PrintToPDFCallback) {
    let holder = CallbackHolder(self, printToPDF: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var ranges: UnsafePointer<CChar>?
    pageRanges?.withCString {
      ranges = $0
    }
    _ApplicationHostPagePrintToPDF(
      host.reference, 
      CInt(id), 
      landscape ? 1 : 0, 
      displayHeaderFooter ? 1 : 0, 
      printBackground ? 1 : 0, 
      scale, 
      paperWidth, 
      paperHeight, 
      marginTop, 
      marginBottom, 
      marginLeft, 
      marginRight, 
      ranges, 
      ignoreInvalidPageRanges ? 1 : 0, 
      {
        (handle: UnsafeMutableRawPointer?, base64Data: UnsafePointer<CChar>?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.printToPDF!(String(cString: base64Data!))
      }, holderInstance)
  }
  
  public func startScreencast(format: FrameFormat, quality: Int, maxWidth: Int, maxHeight: Int, everyNthFrame: Int) {
    _ApplicationHostPageStartScreencast(host.reference, CInt(id), CInt(format.rawValue), CInt(quality), CInt(maxWidth), CInt(maxHeight), CInt(everyNthFrame))
  }
  
  public func stopScreencast() {
    _ApplicationHostPageStopScreencast(host.reference, CInt(id))
  }
  
  public func setBypassCSP(_ enable: Bool) {
    _ApplicationHostPageSetBypassCSP(host.reference, CInt(id), enable ? 1 : 0)
  }
  
  public func screencastFrameAck(sessionId: Int) {
    _ApplicationHostPageScreencastFrameAck(host.reference, CInt(id), CInt(sessionId))
  }
  
  public func handleJavaScriptDialog(accept: Bool, promptText: String) {
    promptText.withCString {
      _ApplicationHostPageHandleJavaScriptDialog(host.reference, CInt(id), accept ? 1 : 0, $0)
    }
  }
  
  public func getAppManifest(_ callback: @escaping GetAppManifestCallback) {
    let holder = CallbackHolder(self, getAppManifest: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetAppManifest(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?, errors: UnsafeMutablePointer<UnsafePointer<CChar>?>?, err_count: CInt, data: UnsafePointer<CChar>?) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [String] = []
      for i in 0..<Int(err_count) {
        arr.append(String(cString: errors![i]!))
      } 
      state.getAppManifest!(String(cString: url!), arr, String(cString: data!))
    }, holderInstance)
  }

  public func requestAppBanner() {
    _ApplicationHostPageRequestAppBanner(host.reference, CInt(id))
  }
  
  public func getLayoutMetrics(_ callback: @escaping GetLayoutMetricsCallback) {
    let holder = CallbackHolder(self, getLayoutMetrics: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostPageGetLayoutMetrics(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, layoutViewport: LayoutViewportPtrRef?, visualViewport: VisualViewportPtrRef?, sx: CInt, sy: CInt, sw: CInt, sh: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var layout = LayoutViewport()
      var visual = VisualViewport()
      layout.decode(layoutViewport!)
      visual.decode(visualViewport!)
      state.getLayoutMetrics!(layout, visual, Int(sx), Int(sy), Int(sw), Int(sh))
    }, holderInstance)
  }
  
  public func createIsolatedWorld(frameId: String, worldName: String?, grantUniversalAccess: Bool, _ callback: @escaping CreateIsolatedWorldCallback) {
    var cname: UnsafePointer<CChar>?
    let holder = CallbackHolder(self, createIsolatedWorld: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    worldName?.withCString {
      cname = $0
    }
    frameId.withCString { cframe in
      _ApplicationHostPageCreateIsolatedWorld(host.reference, CInt(id), cframe, cname, grantUniversalAccess ? 1 : 0, {
        (handle: UnsafeMutableRawPointer?, executionContextId: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.createIsolatedWorld!(Int(executionContextId))
      }, holderInstance)
    }
  }
  
  public func bringToFront() {
    _ApplicationHostPageBringToFront(host.reference, CInt(id));
  }
  
  public func setDownloadBehavior(behavior: String, downloadPath: String?) {
    behavior.withCString { cbehavior in
      downloadPath?.withCString { cpath in
        _ApplicationHostPageSetDownloadBehavior(host.reference, CInt(id), cbehavior, cpath)
      }
    }
  }
  
  public func closePage() {
    _ApplicationHostPageClose(host.reference, CInt(id));
  }
  
  // Worker
  public func deliverPushMessage(origin: String, registration: String, data: String) {
    origin.withCString { corigin in
      registration.withCString { creg in
        data.withCString { cdata in 
          _ApplicationHostWorkerDeliverPushMessage(host.reference, CInt(id), corigin, creg, cdata)
        }
      }
    }
  }
  
  public func dispatchSyncEvent(origin: String, registration: String, tag: String, lastChance: Bool) {
    origin.withCString { corigin in
      registration.withCString { creg in
        tag.withCString { ctag in
          _ApplicationHostWorkerDispatchSyncEvent(host.reference, CInt(id), corigin, creg, ctag, lastChance ? 1 : 0)
        }
      }
    }
  }

  //public func inspectWorker() {
  //  _ApplicationHostWorkerInspectWorker(host.reference, CInt(id), const char* version_id);
  //}

  public func setForceUpdateOnPageLoad(_ force: Bool) {
    _ApplicationHostWorkerSetForceUpdateOnPageLoad(host.reference, CInt(id), force ? 1 : 0)
  }

  public func skipWaiting(scope: String) {
    scope.withCString {
      _ApplicationHostWorkerSkipWaiting(host.reference, CInt(id), $0)
    }
  }
  
  public func startWorker(scope: String) {
    scope.withCString {
      _ApplicationHostWorkerStartWorker(host.reference, CInt(id), $0)
    }
  }

  public func stopAllWorkers() {
    _ApplicationHostWorkerStopAllWorkers(host.reference, CInt(id))
  }
  
  public func stopWorker(version: String) {
    version.withCString {
      _ApplicationHostWorkerStopWorker(host.reference, CInt(id), $0)
    }
  }
  
  public func unregister(scope: String) {
    scope.withCString {
      _ApplicationHostWorkerUnregister(host.reference, CInt(id), $0)
    }
  }
  
  public func updateRegistration(scope: String) {
    scope.withCString {
      _ApplicationHostWorkerUpdateRegistration(host.reference, CInt(id), $0)
    }
  }
  
  public func sendMessageToTarget(message: String, session: String?, target: String?) {
    message.withCString { cmsg in 
      session?.withCString{ csession in
        target?.withCString{ ctarget in 
          _ApplicationHostWorkerSendMessageToTarget(host.reference, CInt(id), cmsg, csession, ctarget)
        }
      }
    }
  }
  
  // Storage
  public func clearDataForOrigin(origin: String, storageTypes: [StorageType]) {
    var ctypes: UnsafeMutablePointer<StorageTypeEnum>?
    ctypes = malloc(storageTypes.count * MemoryLayout<StorageTypeEnum>.size).load(as: UnsafeMutablePointer<StorageTypeEnum>.self)
    for i in 0..<storageTypes.count {
      ctypes![i] = StorageTypeEnum(storageTypes[i].rawValue)
    }
    origin.withCString {
      _ApplicationHostStorageClearDataForOrigin(host.reference, CInt(id), $0, ctypes, CInt(storageTypes.count))
    }
  }

  public func getUsageAndQuota(origin: String, usage: Int64, quota: Int64, usageBreakdown: [UsageForType]) {
    var usages: UnsafeMutablePointer<UsageForTypePtrRef?>?
    usages = malloc(usageBreakdown.count * MemoryLayout<UsageForTypePtrRef>.size).load(as: UnsafeMutablePointer<UsageForTypePtrRef?>.self)
    // FIXME
    for i in 0..<usageBreakdown.count {
      usages![i] = nil//usageBreakdown[i]
    }
    origin.withCString {
      _ApplicationHostStorageGetUsageAndQuota(host.reference, CInt(id), $0, usage, quota, usages!, CInt(usageBreakdown.count))
    }
  }

  public func trackCacheStorageForOrigin(origin: String) {
    origin.withCString {
      _ApplicationHostStorageTrackCacheStorageForOrigin(host.reference, CInt(id), $0)
    }
  }

  public func trackIndexedDBForOrigin(origin: String) {
    origin.withCString {
      _ApplicationHostStorageTrackIndexedDBForOrigin(host.reference, CInt(id), $0)
    }
  }

  public func untrackCacheStorageForOrigin(origin: String) {
    origin.withCString {
      _ApplicationHostStorageUntrackCacheStorageForOrigin(host.reference, CInt(id), $0)
    }
  }

  public func untrackIndexedDBForOrigin(origin: String) {
    origin.withCString {
      _ApplicationHostStorageUntrackIndexedDBForOrigin(host.reference, CInt(id), $0)
    }
  }
  
  // Tethering
  public func bind(port: Int) {
    _ApplicationHostTetheringBind(host.reference, CInt(id), CInt(port))
  }

  public func unbind(port: Int) {
    _ApplicationHostTetheringUnbind(host.reference, CInt(id), CInt(port))
  }

  // Network
  public func canClearBrowserCache(_ callback: @escaping CanClearBrowserCacheCallback) {
    let holder = CallbackHolder(self, canClearBrowserCache: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostNetworkCanClearBrowserCache(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, result: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.canClearBrowserCache!(result != 0)
    }, holderInstance)
  }

  public func canClearBrowserCookies(_ callback: @escaping CanClearBrowserCookiesCallback) {
    let holder = CallbackHolder(self, canClearBrowserCookies: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostNetworkCanClearBrowserCookies(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, result: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.canClearBrowserCookies!(result != 0)
    }, holderInstance)
  }

  public func canEmulateNetworkConditions(_ callback: @escaping CanEmulateNetworkConditionsCallback) {
    let holder = CallbackHolder(self, canEmulateNetworkConditions: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostNetworkCanEmulateNetworkConditions(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, result: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.canEmulateNetworkConditions!(result != 0)
    }, holderInstance)
  }

  public func clearBrowserCache() {
    _ApplicationHostNetworkClearBrowserCache(host.reference, CInt(id))
  }

  public func clearBrowserCookies() {
    _ApplicationHostNetworkClearBrowserCookies(host.reference, CInt(id))
  }

  public func continueInterceptedRequest(
    interception: String, 
    reason: ErrorReason,
    rawResponse: String?, 
    url: String?,
    method: String?,
    postData: String?,
    header: [String: String]?,
    authChallenge: AuthChallengeResponse) {

    var keys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var values: UnsafeMutablePointer<UnsafePointer<CChar>?>?

    if header != nil {
      var i = 0
      keys = malloc(header!.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
      values = malloc(header!.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
      for item in header! {
        keys![i] = malloc(item.0.count * MemoryLayout<CChar>.size).load(as: UnsafePointer<CChar>.self)
        values![i] = malloc(item.1.count * MemoryLayout<CChar>.size).load(as: UnsafePointer<CChar>.self)
        item.0.withCString {
          memcpy(UnsafeMutablePointer(mutating: keys![i]!), $0, item.0.count)
        }
        item.1.withCString {
          memcpy(UnsafeMutablePointer(mutating: values![i]!), $0, item.1.count)
        }
        i += 1
      }
    }

    interception.withCString { cintercept in
      rawResponse?.withCString { cresp in
        url?.withCString { curl in
          method?.withCString { cmethod in
            postData?.withCString { cpost in
              _ApplicationHostNetworkContinueInterceptedRequest(
                host.reference, 
                CInt(id), 
                cintercept, 
                CInt(reason.rawValue), 
                cresp, 
                curl, 
                cmethod, 
                cpost, 
                keys, 
                CInt(header!.count), 
                values, 
                CInt(header!.count), 
              nil)
            }
          }
        }
      }
    }

    if header != nil {
      var i = 0
      for item in header! {
        free(UnsafeMutablePointer(mutating: keys![i]))
        free(UnsafeMutablePointer(mutating: values![i]))
        i += 1
      }
      free(keys)
      free(values)
    }
  }

  public func deleteCookies(name: String, url: String?, domain: String?, path: String?) {
    name.withCString { cname in
      url?.withCString { curl in
        domain?.withCString { cdom in
          path?.withCString { cpath in
            _ApplicationHostNetworkDeleteCookies(
              host.reference, 
              CInt(id), 
              cname, 
              curl, 
              cdom, 
              cpath)
          }
        }
      }
    }
  }

  public func emulateNetworkConditions(
    offline: Bool, 
    latency: Int64, 
    downloadThroughput: Int64, 
    uploadThroughput: Int64, 
    connectionType: ConnectionType) {
    _ApplicationHostNetworkEmulateNetworkConditions(
      host.reference, 
      CInt(id), 
      offline ? 1 : 0, 
      latency, 
      downloadThroughput, 
      uploadThroughput, 
      CInt(connectionType.rawValue))
  }

  public func getAllCookies(_ callback: @escaping GetAllCookiesCallback) {
    let holder = CallbackHolder(self, getAllCookies: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostNetworkGetAllCookies(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, cookies: UnsafeMutablePointer<CookiePtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [Cookie] = []
      for i in 0..<Int(count) {
        let cookie = Cookie()
        cookie.decode(cookies![i]!)
        arr.append(cookie)
      }
      state.getAllCookies!(arr)
    }, holderInstance)
  }

  public func getCertificate(origin: String, _ callback: @escaping GetCertificateCallback) {
    let holder = CallbackHolder(self, getCertificate: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    origin.withCString {
      _ApplicationHostNetworkGetCertificate(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, table_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var tables: [String] = []
      for i in 0..<Int(count) {
        tables.append(String(cString: table_names![i]!))
      }
      state.getCertificate!(tables)
      }, holderInstance)
    }
  }

  public func getCookies(urls maybeUrls: [String]?, _ callback: @escaping GetCookiesCallback) {
    let holder = CallbackHolder(self, getCookies: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    guard let urls = maybeUrls else {
      _ApplicationHostNetworkGetCookies(host.reference, CInt(id), nil, 0, {
        (handle: UnsafeMutableRawPointer?, cookies: UnsafeMutablePointer<CookiePtrRef?>?, count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [Cookie] = []
        for i in 0..<Int(count) {
          let cookie = Cookie()
          cookie.decode(cookies![i]!)
          arr.append(cookie)
        }
        state.getCookies!(arr)
      }, holderInstance)
      return
    }
    var curls: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    curls = malloc(urls.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    var i = 0
    for url in urls {
      url.withCString {
        curls![i] = $0
      }
      i += 1
    }
    _ApplicationHostNetworkGetCookies(host.reference, CInt(id), curls, CInt(urls.count), {
      (handle: UnsafeMutableRawPointer?, cookies: UnsafeMutablePointer<CookiePtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [Cookie] = []
      for i in 0..<Int(count) {
        let cookie = Cookie()
        cookie.decode(cookies![i]!)
        arr.append(cookie)
      }
      state.getCookies!(arr)
    }, holderInstance)
    
    free(curls)
  }

  public func getResponseBody(requestId: String, _ callback: @escaping GetResponseBodyCallback) {
    let holder = CallbackHolder(self, getResponseBody: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    requestId.withCString {
      _ApplicationHostNetworkGetResponseBody(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, body: UnsafePointer<CChar>?, base64_encoded: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getResponseBody!(String(cString: body!), base64_encoded != 0)
      }, holderInstance)
    }
  }

  public func getRequestPostData(requestId: String, _ callback: @escaping GetRequestPostDataCallback) {
    let holder = CallbackHolder(self, getRequestPostData: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    requestId.withCString {
      _ApplicationHostNetworkGetRequestPostData(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, post_data: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getRequestPostData!(String(cString: post_data!))
      }, holderInstance)
    }
  }

  public func getResponseBodyForInterception(_ interceptionId: String, _ callback: @escaping GetResponseBodyForInterceptionCallback) {
    let holder = CallbackHolder(self, getResponseBodyForInterception: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    interceptionId.withCString {
      _ApplicationHostNetworkGetResponseBodyForInterception(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, body: UnsafePointer<CChar>?, base64_encoded: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getResponseBodyForInterception!(String(cString: body!), base64_encoded != 0)
      }, holderInstance)
    }
  }

  public func takeResponseBodyForInterceptionAsStream(_ interceptionId: String, _ callback: @escaping TakeResponseBodyForInterceptionAsStreamCallback) {
    let holder = CallbackHolder(self, takeResponseBodyForInterceptionAsStream: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    interceptionId.withCString {
      _ApplicationHostNetworkTakeResponseBodyForInterceptionAsStream(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, stream: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.takeResponseBodyForInterceptionAsStream!(String(cString: stream!))
      }, holderInstance)
    }
  }

  public func replayXHR(requestId: String) {
    requestId.withCString {
      _ApplicationHostNetworkReplayXHR(host.reference, CInt(id), $0)
    }
  }

  public func searchInResponseBody(requestId: String, query: String, caseSensitive: Bool, isRegex: Bool, _ callback: @escaping SearchInResponseBodyCallback) {
    let holder = CallbackHolder(self, searchInResponseBody: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    requestId.withCString { creq in
      query.withCString { cquery in
        _ApplicationHostNetworkSearchInResponseBody(host.reference, CInt(id), creq, cquery, caseSensitive ? 1 : 0, isRegex ? 1 : 0, {
          (handle: UnsafeMutableRawPointer?, matches: UnsafeMutablePointer<SearchMatchPtrRef?>?, count: CInt) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          var arr: [SearchMatch] = []
          for i in 0..<Int(count) {
            var match = SearchMatch()
            match.decode(matches![i]!)
            arr.append(match)
          }
          state.searchInResponseBody!(arr)
        }, holderInstance)
      }
    }
  }

  public func setBlockedURLs(urls: [String]) {
    var curls: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var i = 0
    curls = malloc(urls.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for url in urls {
      url.withCString {
        curls![i] = $0
        i += 1
      }
    }
    _ApplicationHostNetworkSetBlockedURLs(host.reference, CInt(id), curls, CInt(urls.count))
  }

  public func setBypassServiceWorker(_ bypass: Bool) {
    _ApplicationHostNetworkSetBypassServiceWorker(host.reference, CInt(id), bypass ? 1 : 0)
  }

  public func setCacheDisabled(_ disabled: Bool) {
    _ApplicationHostNetworkSetCacheDisabled(host.reference, CInt(id), disabled ? 1 : 0)
  }

  public func setCookie(
    name: String, 
    value: String, 
    url: String?, 
    domain: String?, 
    path: String?, 
    secure: Bool, 
    httpOnly: Bool, 
    sameSite: CookieSameSite, 
    expires: Int64, 
    _ callback: @escaping SetCookieCallback) {
    let holder = CallbackHolder(self, setCookie: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    url?.withCString { curl in
      domain?.withCString { cdom in
        path?.withCString { cpath in
          name.withCString { cname in
            value.withCString { cvalue in
              _ApplicationHostNetworkSetCookie(host.reference, CInt(id), cname, cvalue, curl, cdom, cpath, secure ? 1 : 0, httpOnly ? 1 : 0, CInt(sameSite.rawValue), expires, {
                (handle: UnsafeMutableRawPointer?, result: CInt) in
                let state = unsafeBitCast(handle, to: CallbackHolder.self)
                state.setCookie!(result != 0)
              }, holderInstance)
            }
          }
        }
      }
    }
  }

  public func setCookies(cookies: [CookieParam]) {
    var ccookies: UnsafeMutablePointer<CookieParamPtrRef?>?
    ccookies = malloc(cookies.count).load(as: UnsafeMutablePointer<CookieParamPtrRef?>.self)
    _ApplicationHostNetworkSetCookies(host.reference, CInt(id), ccookies, CInt(cookies.count))
    free(ccookies)
  }

  public func setDataSizeLimits(maxTotalSize: Int, maxResourceSize: Int) {
    _ApplicationHostNetworkSetDataSizeLimits(host.reference, CInt(id), CInt(maxTotalSize), CInt(maxResourceSize))
  }

  public func setExtraHTTPHeaders(_ headers: [String: String]) {
    var keys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var values: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var i = 0
    keys = malloc(headers.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    values = malloc(headers.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in headers {
      keys![i] = malloc(item.0.count * MemoryLayout<CChar>.size).load(as: UnsafePointer<CChar>.self)
      values![i] = malloc(item.1.count * MemoryLayout<CChar>.size).load(as: UnsafePointer<CChar>.self)
      item.0.withCString { ckey in
        memcpy(UnsafeMutablePointer(mutating: keys![i]!), ckey, item.0.count)
      }
      item.1.withCString { cval in
        memcpy(UnsafeMutablePointer(mutating: values![i]!), cval, item.1.count)
      }
      i += 1
    }

    _ApplicationHostNetworkSetExtraHTTPHeaders(host.reference, CInt(id), keys, CInt(headers.count), values, CInt(headers.count))

    for item in headers {
      free(UnsafeMutablePointer(mutating: keys![i]))
      free(UnsafeMutablePointer(mutating: values![i]))
    }
    free(keys)
    free(values)
  }

  public func setRequestInterception(patterns: [RequestPattern]) {
    var cpatterns: UnsafeMutablePointer<RequestPatternPtrRef?>?
    var i = 0
    cpatterns = malloc(patterns.count * MemoryLayout<RequestPatternPtrRef>.size).load(as: UnsafeMutablePointer<RequestPatternPtrRef?>.self)
    for pattern in patterns {
      // FIXME
      cpatterns![i] = nil
      i += 1
    }
    _ApplicationHostNetworkSetRequestInterception(host.reference, CInt(id), cpatterns, CInt(patterns.count))
    free(cpatterns)
  }

  public func setUserAgentOverride(userAgent: String) {
    userAgent.withCString {
      _ApplicationHostNetworkSetUserAgentOverride(host.reference, CInt(id), $0)
    }
  }
  
  // LayerTree
  public func compositingReasons(layerId: String, _ callback: @escaping CompositingReasonsCallback) {
    let holder = CallbackHolder(self, compositingReasons: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    layerId.withCString {
      _ApplicationHostLayerTreeCompositingReasons(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, compositing_reasons: UnsafeMutablePointer<UnsafePointer<CChar>?>?, count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var reasons: [String] = []
        for i in 0..<Int(count) {
          reasons.append(String(cString: compositing_reasons![i]!))
        }
        state.compositingReasons!(reasons)
      }, holderInstance)
    }
  }

  public func loadSnapshot(tiles: [PictureTile], _ callback: @escaping LoadSnapshotCallback) {
    let holder = CallbackHolder(self, loadSnapshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var ctiles: UnsafeMutablePointer<PictureTilePtrRef?>?
    var i = 0
    ctiles = malloc(tiles.count * MemoryLayout<PictureTilePtrRef>.size).load(as: UnsafeMutablePointer<PictureTilePtrRef?>.self)
    for tile in tiles {
      // FIXME
      ctiles![i] = nil
      i += 1
    }
    _ApplicationHostLayerTreeLoadSnapshot(host.reference, CInt(id), ctiles, CInt(tiles.count), {
      (handle: UnsafeMutableRawPointer?, id: UnsafePointer<CChar>?) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.loadSnapshot!(String(cString: id!))
    }, holderInstance)
    free(ctiles)
  }

  public func makeSnapshot(layerId: String, _ callback: @escaping MakeSnapshotCallback) {
    let holder = CallbackHolder(self, makeSnapshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    layerId.withCString {
      _ApplicationHostLayerTreeMakeSnapshot(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, snapshotId: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.makeSnapshot!(String(cString: snapshotId!))
      }, holderInstance)
    }
  }

  public func profileSnapshot(snapshotId: String, minRepeatCount: Int, minDuration: Int, clip: IntRect, _ callback: @escaping ProfileSnapshotCallback) {
    let holder = CallbackHolder(self, profileSnapshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    snapshotId.withCString {
      _ApplicationHostLayerTreeProfileSnapshot(host.reference, CInt(id), $0, CInt(minRepeatCount), CInt(minDuration), CInt(clip.x), CInt(clip.y), CInt(clip.width), CInt(clip.height), {
        (handle: UnsafeMutableRawPointer?, values: UnsafeMutablePointer<UnsafeMutablePointer<Double>?>?, x_axis_count: CInt, y_axis_count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var vals: [[Double]] = [[]]
        for x in 0..<Int(x_axis_count) {
          var arr: [Double] = []
          for y in 0..<Int(y_axis_count) {
            arr.append(values![x]![y])
          }
          vals.append(arr)
        }
        state.profileSnapshot!(vals)
      }, holderInstance)
    }
  }

  public func releaseSnapshot(snapshotId: String) {
    snapshotId.withCString {
      _ApplicationHostLayerTreeReleaseSnapshot(host.reference, CInt(id), $0)
    }
  }

  public func replaySnapshot(snapshotId: String, fromStep: Int, toStep: Int, scale: Int, _ callback: @escaping ReplaySnapshotCallback) {
    let holder = CallbackHolder(self, replaySnapshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    snapshotId.withCString {
      _ApplicationHostLayerTreeReplaySnapshot(host.reference, CInt(id), $0, CInt(fromStep), CInt(toStep), CInt(scale), {
        (handle: UnsafeMutableRawPointer?, data_url: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.replaySnapshot!(String(cString: data_url!))
      }, holderInstance)
    }
  }

  public func snapshotCommandLog(snapshotId: String, _ callback: @escaping SnapshotCommandLogCallback) {
    let holder = CallbackHolder(self, snapshotCommandLog: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    snapshotId.withCString {
      _ApplicationHostLayerTreeSnapshotCommandLog(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, command_log: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.snapshotCommandLog!(String(cString: command_log!))
      }, holderInstance)
    }
  }
  
  // Input
  public func dispatchKeyEvent(
    type: KeyEventType, 
    modifiers: Int, 
    timestamp: Int64, 
    text: String?, 
    unmodifiedText: String?, 
    keyIdentifier: String?, 
    code: String?, 
    key: String?, 
    windowsVirtualKeyCode: Int, 
    nativeVirtualKeyCode: Int32, 
    autoRepeat: Bool, 
    isKeypad: Bool, 
    isSystemKey: Bool, 
    location: Int, 
    _ callback: @escaping DispatchKeyEventCallback) {
    let holder = CallbackHolder(self, dispatchKeyEvent: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    text?.withCString { ctext in
      unmodifiedText?.withCString { cunmodtext in
        keyIdentifier?.withCString { ckeyid in
          code?.withCString { ccode in
            key?.withCString { ckey in
            _ApplicationHostInputDispatchKeyEvent(host.reference, 
              CInt(id), 
              CInt(type.rawValue), 
              CInt(modifiers), 
              timestamp, 
              ctext, 
              cunmodtext, 
              ckeyid, 
              ccode, 
              ckey, 
              CInt(windowsVirtualKeyCode), 
              CInt(nativeVirtualKeyCode), 
              autoRepeat ? 1 : 0, 
              isKeypad ? 1 : 0, 
              isSystemKey ? 1 : 0, 
              CInt(location), 
              {
                (handle: UnsafeMutableRawPointer?, result: CInt) in
                let state = unsafeBitCast(handle, to: CallbackHolder.self)
                state.dispatchKeyEvent!(result != 0)
              }, holderInstance)
            }
          }
        }
      }
    }

  }

  public func dispatchMouseEvent(
    type: MouseEventType, 
    x: Int, 
    y: Int, 
    modifiers: Int, 
    timestamp: TimeTicks, 
    button: MouseButton, 
    clickCount: Int, 
    deltaX: Int, 
    deltaY: Int, 
    callback: @escaping DispatchMouseEventCallback) {
    
    let holder = CallbackHolder(self, dispatchMouseEvent: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    _ApplicationHostInputDispatchMouseEvent(
      host.reference, 
      CInt(id), 
      CInt(type.rawValue), 
      CInt(x), 
      CInt(y), 
      CInt(modifiers), 
      timestamp.microseconds, 
      CInt(button.rawValue), 
      CInt(clickCount), 
      CInt(deltaX), 
      CInt(deltaY), 
      {
        (handle: UnsafeMutableRawPointer?, result: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.dispatchMouseEvent!(result != 0)
      }, holderInstance)
  }

  public func dispatchTouchEvent(
    type: TouchEventType, 
    touchPoints: [TouchPoint], 
    modifiers: Int32, 
    timestamp: Int64, 
    _ callback: @escaping DispatchTouchEventCallback) {
    let holder = CallbackHolder(self, dispatchTouchEvent: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var cpoints: UnsafeMutablePointer<TouchPointPtrRef?>?
    var i = 0
    cpoints = malloc(touchPoints.count * MemoryLayout<TouchPointPtrRef>.size).load(as: UnsafeMutablePointer<TouchPointPtrRef?>.self)
    for touch in touchPoints {
      // FIXME
      cpoints![i] = nil
      i += 1
    }
    _ApplicationHostInputDispatchTouchEvent(
      host.reference, 
      CInt(id), 
      CInt(type.rawValue), 
      cpoints, 
      CInt(touchPoints.count), 
      CInt(modifiers), 
      timestamp, 
      {
        (handle: UnsafeMutableRawPointer?, result: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.dispatchTouchEvent!(result != 0)
      }, holderInstance)

      free(cpoints)
  }

  public func emulateTouchFromMouseEvent(
    type: MouseEventType, 
    x: Int, 
    y: Int,
    button: MouseButton, 
    timestamp: Int64, 
    deltaX: Int, 
    deltaY: Int, 
    modifiers: Int, 
    clickCount: Int, 
    _ callback: @escaping EmulateTouchFromMouseEventCallback) {
    
    let holder = CallbackHolder(self, emulateTouchFromMouseEvent: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    _ApplicationHostInputEmulateTouchFromMouseEvent(
      host.reference, 
      CInt(id), 
      CInt(type.rawValue), 
      CInt(x), 
      CInt(y), 
      CInt(button.rawValue), 
      timestamp, 
      CInt(deltaX), 
      CInt(deltaY), 
      CInt(modifiers), 
      CInt(clickCount), {
        (handle: UnsafeMutableRawPointer?, result: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.emulateTouchFromMouseEvent!(result != 0)
      }, holderInstance)
  }

  public func setIgnoreInputEvents(_ ignore: Bool) {
    _ApplicationHostInputSetIgnoreInputEvents(host.reference, CInt(id), ignore ? 1 : 0)
  }

  public func synthesizePinchGesture(
    x: Int, 
    y: Int,
    scaleFactor: Int, 
    relativeSpeed: Int, 
    type: GestureSourceType, 
    _ callback: @escaping SynthesizePinchGestureCallback) {
    
    let holder = CallbackHolder(self, synthesizePinchGesture: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    _ApplicationHostInputSynthesizePinchGesture(
      host.reference, 
      CInt(id), 
      CInt(x), 
      CInt(y), 
      CInt(scaleFactor), 
      CInt(relativeSpeed), 
      CInt(type.rawValue),
      {
        (handle: UnsafeMutableRawPointer?, result: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.synthesizePinchGesture!(result != 0)
      }, holderInstance)
  }

  public func scrollGesture(
    x: Int, 
    y: Int,
    xDistance: Int, 
    yDistance: Int, 
    xOverscroll: Int, 
    yOverscroll: Int, 
    preventFling: Bool, 
    speed: Int, 
    type: GestureSourceType, 
    repeatCount: Int, 
    repeatDelayMs: Int, 
    interactionMarkerName: String?, 
    _ callback: @escaping SynthesizeScrollGestureCallback) {
    let holder = CallbackHolder(self, synthesizeScrollGesture: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    interactionMarkerName?.withCString {
      _ApplicationHostInputSynthesizeScrollGesture(
        host.reference, 
        CInt(id), 
        CInt(x), 
        CInt(y), 
        CInt(xDistance), 
        CInt(yDistance), 
        CInt(xOverscroll), 
        CInt(yOverscroll),
        preventFling ? 1 : 0, 
        CInt(speed), 
        CInt(type.rawValue), 
        CInt(repeatCount), 
        CInt(repeatDelayMs), 
        $0, 
        {
          (handle: UnsafeMutableRawPointer?, result: CInt) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.synthesizeScrollGesture!(result != 0)
        }, holderInstance)
    }
  }

  public func tapGesture(
    x: Int, 
    y: Int, 
    duration: Int, 
    tapCount: Int, 
    type: GestureSourceType,
    _ callback: @escaping SynthesizeTapGestureCallback
  ) {
    let holder = CallbackHolder(self, synthesizeTapGesture: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostInputSynthesizeTapGesture(
      host.reference, 
      CInt(id), 
      CInt(x), 
      CInt(y), 
      CInt(duration), 
      CInt(tapCount), 
      CInt(type.rawValue), 
      {
        (handle: UnsafeMutableRawPointer?, result: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.synthesizeTapGesture!(result != 0)
      }, holderInstance)
  }
  
  // IndexedDB
  public func clearIndexedDBObjectStore(
    origin: String, 
    database: String, 
    objectStore: String, 
    _ callback: @escaping ClearObjectStoreCallback) {
    let holder = CallbackHolder(self, clearObjectStore: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    origin.withCString { corigin in
      database.withCString { cdb in
        objectStore.withCString { cobject in
          _ApplicationHostIndexedDBClearObjectStore(host.reference, CInt(id), corigin, cdb, cobject, {
            (handle: UnsafeMutableRawPointer?, result: CInt) in
            let state = unsafeBitCast(handle, to: CallbackHolder.self)
            state.clearObjectStore!(result != 0)
          }, holderInstance)
        }
      }
    }
  }

  public func deleteIndexedDBDatabase(origin: String, database: String, _ callback: @escaping DeleteDatabaseCallback) {
    let holder = CallbackHolder(self, deleteDatabase: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    origin.withCString { corigin in
      database.withCString { cdb in
        _ApplicationHostIndexedDBDeleteDatabase(host.reference, CInt(id), corigin, cdb, {
          (handle: UnsafeMutableRawPointer?, result: CInt) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.deleteDatabase!(result != 0)
        }, holderInstance)
      }
    }
  }

  public func deleteIndexedDBObjectStoreEntries(
    origin: String, 
    database: String,
    objectStore: String, 
    range: KeyRange, 
    _ callback: @escaping DeleteObjectStoreEntriesCallback) {
    
    let holder = CallbackHolder(self, deleteObjectStoreEntries: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    origin.withCString { corigin in
      database.withCString { cdb in
        objectStore.withCString { cobject in
         // FIXME
          _ApplicationHostIndexedDBDeleteObjectStoreEntries(host.reference, CInt(id), corigin, cdb, cobject, nil, {
            (handle: UnsafeMutableRawPointer?, result: CInt) in
            let state = unsafeBitCast(handle, to: CallbackHolder.self)
            state.deleteObjectStoreEntries!(result != 0)
          }, holderInstance)
        }
      }
    }
  }

  public func requestIndexedDBData(
    origin: String, 
    database: String,
    objectStore: String, 
    index: String, 
    skipCount: Int, 
    pageSize: Int, 
    key: KeyRange, 
    _ callback: @escaping RequestDataCallback) {

    let holder = CallbackHolder(self, requestData: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    // FIXME
    origin.withCString { corigin in
        database.withCString { cdb in  
          objectStore.withCString { cobj in  
            index.withCString { cindex in
              _ApplicationHostIndexedDBRequestData(host.reference, CInt(id), corigin, cdb, cobj, cindex, CInt(skipCount), CInt(pageSize), nil, {
                (handle: UnsafeMutableRawPointer?, entries: UnsafeMutablePointer<IndexedDBDataEntryPtrRef?>?, entry_count: CInt, has_more: CInt) in     
                let state = unsafeBitCast(handle, to: CallbackHolder.self)
                var entries_arr: [IndexedDBDataEntry] = []
                for i in 0..<Int(entry_count) {
                  let entry = IndexedDBDataEntry()
                  entry.decode(entries![i]!)
                  entries_arr.append(entry)
                }
                state.requestData!(entries_arr, has_more != 0)
              }, holderInstance)
            }
          }
        }
    }
  }

  public func requestIndexedDBDatabase(
    origin: String, 
    database: String,
    _ callback: @escaping RequestDatabaseCallback) {
    let holder = CallbackHolder(self, requestDatabase: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    origin.withCString { corigin in
      database.withCString { cdb in
        _ApplicationHostIndexedDBRequestDatabase(host.reference, CInt(id), corigin, cdb, {
          (handle: UnsafeMutableRawPointer?, dbPtr: DatabaseWithObjectStoresPtrRef?) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          let db = DatabaseWithObjectStores()
          db.decode(dbPtr!)
          state.requestDatabase!(db)
        }, holderInstance)
      }
    }
  }

  public func requestIndexedDBDatabaseNames(
    origin: String,
    _ callback: @escaping RequestDatabaseNamesCallback) {
    let holder = CallbackHolder(self, requestDatabaseNames: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    origin.withCString {
      _ApplicationHostIndexedDBRequestDatabaseNames(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, names_count: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var names_arr: [String] = []
        for i in 0..<Int(names_count) {
          names_arr.append(String(cString: names![i]!))
        }
        state.requestDatabaseNames!(names_arr)
      }, holderInstance)
    }
  }
  
  // IO
  public func closeHandle(handle: String) {
    handle.withCString {
      _ApplicationHostIOClose(host.reference, CInt(id), $0)
    }
  }

  public func readHandle(handle: String, offset: Int, size: Int, _ callback: @escaping ReadCallback) {
    let holder = CallbackHolder(self, read: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    handle.withCString {
      _ApplicationHostIORead(host.reference, CInt(id), $0, CInt(offset), CInt(size), {
        (handle: UnsafeMutableRawPointer?, base64_encoded: CInt, data: UnsafePointer<CChar>?, eof: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.read!(base64_encoded != 0, String(cString: data!), eof != 0)
      }, holderInstance)
    }
  }

  public func resolveBlob(objectId: String, _ callback: @escaping ResolveBlobCallback)  {
    let holder = CallbackHolder(self, resolveBlob: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    objectId.withCString {
      _ApplicationHostIOResolveBlob(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, uuid: UnsafePointer<CChar>?) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.resolveBlob!(String(cString: uuid!))
      }, holderInstance)
    }
  }
  
  // Headless
  public func beginFrame(
    frameTime: Int64, 
    frameTimeTicks: Int, 
    deadline: Int64, 
    deadlineTicks: Int, 
    interval: Int, 
    noDisplayUpdates: Bool, 
    screenshot: ScreenshotParams, 
    _ callback: @escaping BeginFrameCallback) {
    let holder = CallbackHolder(self, beginFrame: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    // FIXME
    _ApplicationHostHeadlessBeginFrame(host.reference, CInt(id), frameTime, CInt(frameTimeTicks), deadline, CInt(deadlineTicks), CInt(interval), noDisplayUpdates ? 1 : 0, nil, {
      (handle: UnsafeMutableRawPointer?, has_damage: CInt, screenshot_data: UnsafePointer<CChar>?) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.beginFrame!(has_damage != 0, screenshot_data == nil ? String() : String(cString: screenshot_data!))
    }, holderInstance)
  }

  public func enterDeterministicMode(initialDate: Int) {
    _ApplicationHostHeadlessEnterDeterministicMode(host.reference, CInt(id), CInt(initialDate))
  }
  
  // DOMStorage
  public func clearDOMStorage(id sid: StorageId) {
    // FIXME
    _ApplicationHostDOMStorageClear(host.reference, CInt(id), nil)
  }

  public func getDOMStorageItems(id sid: StorageId, _ callback: @escaping GetDOMStorageItemsCallback) {
    let holder = CallbackHolder(self, getDOMStorageItems: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    // FIXME
    _ApplicationHostDOMStorageGetDOMStorageItems(host.reference, CInt(id), nil, {
      (handle: UnsafeMutableRawPointer?, items: UnsafeMutablePointer<UnsafeMutablePointer<UnsafePointer<CChar>?>?>?, arr_x_count: CInt, arr_y_count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var it_arr: [[String]] = [[]]
      for x in 0..<Int(arr_x_count) {
        var inner: [String] = []
        for y in 0..<Int(arr_y_count) {
          inner.append(String(cString: items![x]![y]!))
        }
        it_arr.append(inner)
      }
      state.getDOMStorageItems!(it_arr)
    }, holderInstance)
  }

  public func removeDOMStorageItem(id sid: StorageId, key: String) {
    key.withCString { ckey in
     // FIXME
      _ApplicationHostDOMStorageRemoveDOMStorageItem(host.reference, CInt(id), nil, ckey)
    }
  }

  public func setDOMStorageItem(id sid: StorageId, key: String, value: String) {
    key.withCString { ckey in
      value.withCString { cval in
        // FIXME
        _ApplicationHostDOMStorageSetDOMStorageItem(host.reference, CInt(id), nil, ckey, cval)
      }
    }
  }
  
  // Database
  public func executeSQL(id dbid: String, query: String, _ callback: @escaping ExecuteSQLCallback) {
    let holder = CallbackHolder(self, executeSQL: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    dbid.withCString { cid in
      query.withCString { cquery in
        _ApplicationHostDatabaseExecuteSQL(host.reference, CInt(id), cid, cquery, {
          (handle: UnsafeMutableRawPointer?, column_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, column_names_count: CInt, values: UnsafeMutablePointer<OwnedValueRef?>?, values_count: CInt, error: ErrorPtrRef?) in
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          var column_arr: [String] = []
          var values_arr: [Value] = []

          for i in 0..<Int(column_names_count) {
            column_arr.append(String(cString: column_names![i]!))
          }
          for i in 0..<Int(values_count) {
            values_arr.append(Value.null)
          }
          var err = SQLError()
          if error != nil {
            err.decode(error!)
          }
          state.executeSQL!(column_arr, values_arr, error == nil ? nil : err)
        }, holderInstance)
      }
    }
  }

  public func getDatabaseTableNames(id dbid: String, _ callback: @escaping GetDatabaseTableNamesCallback) {
    let holder = CallbackHolder(self, getDatabaseTableNames: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    dbid.withCString {
      _ApplicationHostDatabaseGetDatabaseTableNames(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, tbl_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, tbl_count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [String] = []
      for i in 0..<Int(tbl_count) {
        arr.append(String(cString: tbl_names![i]!))
      }
      state.getDatabaseTableNames!(arr)
      }, holderInstance)
    }
  }
  
  // DeviceOrientation
  public func clearDeviceOrientationOverride() {
    _ApplicationHostDeviceOrientationClearDeviceOrientationOverride(host.reference, CInt(id));
  }

  public func setDeviceOrientationOverride(alpha: Int, beta: Int, gamma: Int) {
    _ApplicationHostDeviceOrientationSetDeviceOrientationOverride(host.reference, CInt(id), CInt(alpha), CInt(beta), CInt(gamma))
  }

  // Emulation
  public func canEmulate(_ callback: @escaping CanEmulateCallback) {
    let holder = CallbackHolder(self, canEmulate: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostEmulationCanEmulate(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, result: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.canEmulate!(result != 0) 
    }, holderInstance)
  }

  public func clearDeviceMetricsOverride() {
    _ApplicationHostEmulationClearDeviceMetricsOverride(host.reference, CInt(id))
  }

  public func clearGeolocationOverride() {
    _ApplicationHostEmulationClearGeolocationOverride(host.reference, CInt(id))
  }

  public func resetPageScaleFactor() {
    _ApplicationHostEmulationResetPageScaleFactor(host.reference, CInt(id))
  }

  public func setCPUThrottlingRate(rate: Int) {
    _ApplicationHostEmulationSetCPUThrottlingRate(host.reference, CInt(id), CInt(rate))
  }

  public func setDefaultBackgroundColorOverride(color: RGBA) {
    // FIXME
    _ApplicationHostEmulationSetDefaultBackgroundColorOverride(host.reference, CInt(id), nil)
  }

  public func setDeviceMetricsOverride(
    width: Int, 
    height: Int, 
    deviceScaleFactor: Float, 
    mobile: Bool, 
    scale: Float, 
    screenWidth: Int, 
    screenHeight: Int, 
    positionX: Int, 
    positionY: Int,
    dontSetVisibleSize: Bool, 
    orientation: ScreenOrientation, 
    viewport: Viewport) {
    // FIXME
    _ApplicationHostEmulationSetDeviceMetricsOverride(host.reference, CInt(id), CInt(width), CInt(height), deviceScaleFactor, mobile ? 1 : 0, scale, CInt(screenWidth), CInt(screenHeight), CInt(positionX), CInt(positionY), dontSetVisibleSize ? 1 : 0, nil, nil)
  }

  public func setEmitTouchEventsForMouse(enabled: Bool, configuration: TouchEventForMouseConfiguration) {
    _ApplicationHostEmulationSetEmitTouchEventsForMouse(host.reference, CInt(id), enabled ? 1 : 0, CInt(configuration.rawValue))
  }

  public func setEmulatedMedia(_ media: String) {
    media.withCString {
      _ApplicationHostEmulationSetEmulatedMedia(host.reference, CInt(id), $0)
    }
  }

  public func setGeolocationOverride(latitude: Int64, longitude: Int64, accuracy: Int64) {
    _ApplicationHostEmulationSetGeolocationOverride(host.reference, CInt(id), latitude, longitude, accuracy)
  }

  public func setNavigatorOverrides(platform: String) {
    platform.withCString {
      _ApplicationHostEmulationSetNavigatorOverrides(host.reference, CInt(id), $0)
    }
  }

  public func setPageScaleFactor(_ factor: Float) {
    _ApplicationHostEmulationSetPageScaleFactor(host.reference, CInt(id), factor)
  }

  public func setScriptExecutionDisabled(_ disabled: Bool) {
    _ApplicationHostEmulationSetScriptExecutionDisabled(host.reference, CInt(id), disabled ? 1 : 0)
  }

  public func setTouchEmulationEnabled(_ enabled: Bool, maxTouchPoints: Int) {
    _ApplicationHostEmulationSetTouchEmulationEnabled(host.reference, CInt(id), enabled ? 1 : 0, CInt(maxTouchPoints))
  }

  public func setVirtualTimePolicy(
    policy: VirtualTimePolicy, 
    budget: Int, 
    maxVirtualTimeTaskStarvationCount: Int, 
    waitForNavigation: Bool, 
    _ callback: @escaping SetVirtualTimePolicyCallback) {
    let holder = CallbackHolder(self, setVirtualTimePolicy: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostEmulationSetVirtualTimePolicy(host.reference, CInt(id), CInt(policy.rawValue), CInt(budget), CInt(maxVirtualTimeTaskStarvationCount), waitForNavigation ? 1 : 0, {
      (handle: UnsafeMutableRawPointer?, virtualTimeBase: Int64, virtualTimeTicksBase: Int64) in  
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.setVirtualTimePolicy!(virtualTimeBase, virtualTimeTicksBase)
    }, holderInstance)
  }

  public func setVisibleSize(_ size: IntSize) {
    setVisibleSize(width: size.width, height: size.height)
  }

  public func setVisibleSize(width: Int, height: Int) {
    _ApplicationHostEmulationSetVisibleSize(host.reference, CInt(id), CInt(width), CInt(height))
  }
  
  // DOMSnapshot
  public func getSnapshot(
    computedStyleWhitelist: [String],
    includeEventListeners: Bool, 
    includePaintOrder: Bool, 
    includeUserAgentShadowTree: Bool, 
    _ callback: @escaping GetSnapshotCallback) {

    var i = 0
    var cstyles: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    cstyles = malloc(computedStyleWhitelist.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in computedStyleWhitelist {
      item.withCString {
        cstyles![i] = $0
      }
      i += 1
    }
    let holder = CallbackHolder(self, getSnapshot: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    _ApplicationHostDOMSnapshotGetSnapshot(
      host.reference, 
      CInt(id),
      cstyles,
      CInt(computedStyleWhitelist.count), 
      includeEventListeners ? 1 : 0, 
      includePaintOrder ? 1 : 0, 
      includeUserAgentShadowTree ? 1 : 0, 
      {
        (handle: UnsafeMutableRawPointer?, snapshots: UnsafeMutablePointer<DOMSnapshotNodePtrRef?>?, snapshots_count: CInt, layouts: UnsafeMutablePointer<LayoutTreeNodePtrRef?>?, layouts_count: CInt, styles: UnsafeMutablePointer<ComputedStylePtrRef?>?, styles_count: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var snapshot_arr: [DOMSnapshotNode] = []
        var layout_arr: [LayoutTreeNode] = []
        var style_arr: [ComputedStyle] = []

        for i in 0..<Int(snapshots_count) {
          let node = DOMSnapshotNode()
          node.decode(snapshots![i]!)
          snapshot_arr.append(node)
        }

        for i in 0..<Int(layouts_count) {
          let node = LayoutTreeNode()
          node.decode(layouts![i]!)
          layout_arr.append(node)
        }

        for i in 0..<Int(styles_count) {
          let node = ComputedStyle()
          node.decode(styles![i]!)
          style_arr.append(node)
        }
    
        state.getSnapshot!(snapshot_arr, layout_arr, style_arr)
      }, holderInstance)

      free(cstyles)
  }
  
  // DOM
  public func collectClassNamesFromSubtree(node: Int, _ callback: @escaping CollectClassNamesFromSubtreeCallback) {
    let holder = CallbackHolder(self, collectClassNamesFromSubtree: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMCollectClassNamesFromSubtree(host.reference, CInt(id), CInt(node), 
    {
      (handle: UnsafeMutableRawPointer?, cls_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, cls_count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [String] = []
      for i in 0..<Int(cls_count) {
        arr.append(String(cString: cls_names![i]!))
      }
      state.collectClassNamesFromSubtree!(arr)
    }, holderInstance)
  }

  public func copyTo(node: Int, targetNode: Int, anchorNode: Int, _ callback: @escaping CopyToCallback) {
    let holder = CallbackHolder(self, copyTo: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMCopyTo(host.reference, CInt(id), CInt(node), CInt(targetNode), CInt(anchorNode), {
      (handle: UnsafeMutableRawPointer?, nodeId: Int32) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.copyTo!(Int(nodeId))
    }, holderInstance)
  }

  public func describeNode(
    node: Int, 
    backendNode: Int?, 
    object: String?, 
    depth: Int, 
    pierce: Bool, 
    _ callback: @escaping DescribeNodeCallback) {
    
    let holder = CallbackHolder(self, describeNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    object?.withCString {
      _ApplicationHostDOMDescribeNode(host.reference, CInt(id), CInt(node), CInt(backendNode ?? -1), $0, CInt(depth), pierce ? 1 : 0, {
        (handle: UnsafeMutableRawPointer?, nodePtr: DOMNodePtrRef?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        let node = DOMNode()
        if (nodePtr != nil) {
          node.decode(nodePtr!)
        }
        state.describeNode!(node)
      }, holderInstance)
    }
  }

  public func discardSearchResults(id searchId: String) {
    searchId.withCString {
      _ApplicationHostDOMDiscardSearchResults(host.reference, CInt(id), $0)
    }
  }

  public func focus(node: Int, backendNode: Int?, object: String?) {
    object?.withCString {
      _ApplicationHostDOMFocus(host.reference, CInt(id), CInt(node), CInt(backendNode ?? -1), $0)
    }
  }

  public func getAttributes(node: Int, _ callback: @escaping GetAttributesCallback) {
    let holder = CallbackHolder(self, getAttributes: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMGetAttributes(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, attrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?, attr_count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [String] = []
      for i in 0..<Int(attr_count) {
        arr.append(String(cString: attrs![i]!))
      }
      state.getAttributes!(arr)
    }, holderInstance)
  }

  public func getBoxModel(node: Int, backendNode: Int?, object: String?, _ callback: @escaping GetBoxModelCallback) {
    let holder = CallbackHolder(self, getBoxModel: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    object?.withCString {
      _ApplicationHostDOMGetBoxModel(host.reference, CInt(id), CInt(node), CInt(backendNode ?? -1), $0, {
        (handle: UnsafeMutableRawPointer?, box: BoxModelPtrRef?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        let model = BoxModel()
        model.decode(box!)
        state.getBoxModel!(model)
      }, holderInstance)
    }
  }

  public func getDocument(depth: Int, pierce: Bool, _ callback: @escaping GetDocumentCallback) {
    let holder = CallbackHolder(self, getDocument: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMGetDocument(host.reference, CInt(id), CInt(depth), pierce ? 1 : 0, {
      (handle: UnsafeMutableRawPointer?, nodePtr: DOMNodePtrRef?) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      let node = DOMNode()
      node.decode(nodePtr!)
      state.getDocument!(node)
    }, holderInstance)
  }

  public func getFlattenedDocument(depth: Int, pierce: Bool, _ callback: @escaping GetFlattenedDocumentCallback) {
    let holder = CallbackHolder(self, getFlattenedDocument: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMGetFlattenedDocument(host.reference, CInt(id), CInt(depth), pierce ? 1 : 0, {
      (handle: UnsafeMutableRawPointer?, nodes: UnsafeMutablePointer<DOMNodePtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [DOMNode] = []
      for i in 0..<Int(count) {
        let node = DOMNode()
        node.decode(nodes![i]!)
        arr.append(node)
      }
      state.getFlattenedDocument!(arr)
    }, holderInstance)
  }

  public func getNodeForLocation(x: Int, y: Int, includeUserAgentShadowDom: Bool, _ callback: @escaping GetNodeForLocationCallback) {
    let holder = CallbackHolder(self, getNodeForLocation: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMGetNodeForLocation(host.reference, CInt(id), CInt(x), CInt(y), includeUserAgentShadowDom ? 1 : 0, {
      (handle: UnsafeMutableRawPointer?, node_id: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getNodeForLocation!(Int(node_id))
    }, holderInstance)
  }

  public func getOuterHTML(node: Int, backendNode: Int?, object: String?, _ callback: @escaping GetOuterHTMLCallback) {
    let holder = CallbackHolder(self, getOuterHTML: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    object?.withCString {
    _ApplicationHostDOMGetOuterHTML(host.reference, CInt(id), CInt(node), CInt(backendNode ?? -1), $0, 
      { 
        (handle: UnsafeMutableRawPointer?, html: UnsafePointer<CChar>?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getOuterHTML!(String(cString: html!))
      }, holderInstance)
    }
  }

  public func getRelayoutBoundary(node: Int, _ callback: @escaping GetRelayoutBoundaryCallback) {
    let holder = CallbackHolder(self, getRelayoutBoundary: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMGetRelayoutBoundary(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.getRelayoutBoundary!(Int(node_id))
    }, holderInstance)
  }

  public func getSearchResults(searchId: String, fromIndex: Int, toIndex: Int, _ callback: @escaping GetSearchResultsCallback) {
    let holder = CallbackHolder(self, getSearchResults: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    searchId.withCString {
      _ApplicationHostDOMGetSearchResults(host.reference, CInt(id), $0, CInt(fromIndex), CInt(toIndex), {
        (handle: UnsafeMutableRawPointer?, node_ids: UnsafePointer<Int32>?, count: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [Int] = []
        for i in 0..<Int(count) {
          arr.append(Int(node_ids![i]))
        }
        state.getSearchResults!(arr)
      }, holderInstance)
    }
  }

  public func domHideHighlight() {
    _ApplicationHostDOMHideHighlight(host.reference, CInt(id))
  }

  public func highlightNode(config: HighlightConfig, node: Int, backendNode: Int?, object: Int?) {
    // FIXME
    _ApplicationHostDOMHighlightNode(host.reference, CInt(id), nil, CInt(node), CInt(backendNode ?? 0), CInt(object ?? 0))
  }

  public func highlightRect(x: Int, y: Int, width: Int, height: Int, color: RGBA, outline_color: RGBA) {
    // FIXME
    _ApplicationHostDOMHighlightRect(host.reference, CInt(id), CInt(x), CInt(y), CInt(width), CInt(height), nil, nil)
  }

  public func markUndoableState() {
    _ApplicationHostDOMMarkUndoableState(host.reference, CInt(id));
  }

  public func moveTo(node: Int, targetNodeId: Int, insertBeforeNodeId: Int, _ callback: @escaping MoveToCallback) {
    let holder = CallbackHolder(self, moveTo: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostDOMMoveTo(host.reference, CInt(id), CInt(node), CInt(targetNodeId), CInt(insertBeforeNodeId), {
      (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.moveTo!(Int(node_id))
    }, holderInstance)
  }

  public func performSearch(query: String, includeUserAgentShadowDom: Bool, _ callback: @escaping PerformSearchCallback) {
    let holder = CallbackHolder(self, performSearch: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    query.withCString {
      _ApplicationHostDOMPerformSearch(host.reference, CInt(id), $0, includeUserAgentShadowDom ? 1 : 0, {
        (handle: UnsafeMutableRawPointer?, search_id: UnsafePointer<CChar>?, result_count: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.performSearch!(String(cString: search_id!), Int(result_count))
      }, holderInstance)
    }
  }

  public func pushNodeByPathToFrontend(path: String, _ callback: @escaping PushNodeByPathToFrontendCallback) {
    let holder = CallbackHolder(self, pushNodeByPathToFrontend: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    path.withCString {
      _ApplicationHostDOMPushNodeByPathToFrontend(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.pushNodeByPathToFrontend!(Int(node_id))
      }, holderInstance)
    }
  }

  public func pushNodesByBackendIdsToFrontend(backendNodeIds: [Int], _ callback: @escaping PushNodesByBackendIdsToFrontendCallback) {
    let holder = CallbackHolder(self, pushNodesByBackendIdsToFrontend: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var i = 0
    var cnodes: UnsafeMutablePointer<CInt>?
    cnodes = malloc(backendNodeIds.count * MemoryLayout<CInt>.size).load(as: UnsafeMutablePointer<CInt>.self)
    for item in backendNodeIds {
      cnodes![i] = CInt(item)
      i += 1
    }
    _ApplicationHostDOMPushNodesByBackendIdsToFrontend(host.reference, CInt(id), cnodes, CInt(backendNodeIds.count), {
      (handle: UnsafeMutableRawPointer?, node_ids: UnsafePointer<Int32>?, count: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [Int] = []
      for i in 0..<Int(count) {
        arr.append(Int(node_ids![i]))
      }
      state.pushNodesByBackendIdsToFrontend!(arr)
    }, holderInstance)
    free(cnodes)
  }

  public func querySelector(_ node: Int, selector sel: String, _ callback: @escaping QuerySelectorCallback) {
    let holder = CallbackHolder(self, querySelector: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    sel.withCString { csel in
      _ApplicationHostDOMQuerySelector(host.reference, CInt(id), CInt(node), csel, {
        (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.querySelector!(Int(node_id))
      }, holderInstance)
    }

  }

  public func querySelectorAll(_ node: Int, selector sel: String, _ callback: @escaping QuerySelectorAllCallback) {
    let holder = CallbackHolder(self, querySelectorAll: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    sel.withCString {
      _ApplicationHostDOMQuerySelectorAll(host.reference, CInt(id), CInt(node), $0, {
        (handle: UnsafeMutableRawPointer?, node_ids: UnsafePointer<Int32>?, count: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [Int] = []
        for i in 0..<Int(count) {
          arr.append(Int(node_ids![i]))
        }
        state.querySelectorAll!(arr)
      }, holderInstance)
    }
  }

  public func redo() {
    _ApplicationHostDOMRedo(host.reference, CInt(id));
  }

  public func removeAttribute(_ node: Int, name: String) {
    name.withCString {
      _ApplicationHostDOMRemoveAttribute(host.reference, CInt(id), CInt(node), $0)
    }
  }

  public func removeNode(_ node: Int) {
    _ApplicationHostDOMRemoveNode(host.reference, CInt(id), CInt(node))
  }

  public func requestChildNodes(_  node: Int, depth: Int, pierce: Bool) {
    _ApplicationHostDOMRequestChildNodes(host.reference, CInt(id), CInt(node), CInt(depth), pierce ? 1 : 0)
  }

  public func requestNode(object: String, _ callback: @escaping RequestNodeCallback) {
    let holder = CallbackHolder(self, requestNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    object.withCString {
      _ApplicationHostDOMRequestNode(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, node_id: Int32) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.requestNode!(Int(node_id))
      }, holderInstance)
    }
  }

  public func resolveNode(_ node: Int, objectGroup: String?, _ callback: @escaping ResolveNodeCallback) {
    let holder = CallbackHolder(self, resolveNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    objectGroup?.withCString {
      _ApplicationHostDOMResolveNode(host.reference, CInt(id), CInt(node), $0, {
        (handle: UnsafeMutableRawPointer?, remote: RemoteObjectPtrRef?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.resolveNode!(RemoteObject())
      }, holderInstance)
    }
  }

  public func setAttributeValue(_ node: Int, name: String, value: String) {
    name.withCString { cname in
      value.withCString { cvalue in
        _ApplicationHostDOMSetAttributeValue(host.reference, CInt(id), CInt(node), cname, cvalue)
      }
    }
  }

  public func setAttributesAsText(_ node: Int, text: String, name: String?) {
    text.withCString { ctext in
      name?.withCString { cname in
        _ApplicationHostDOMSetAttributesAsText(host.reference, CInt(id), CInt(node), ctext, cname)
      }
    }
  }

  public func setFileInputFiles(files: [String], node: Int, backendNode: Int?, object: String?) {
    var i = 0
    var cfiles: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    cfiles = malloc(files.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in files {
      item.withCString {
        cfiles![i] = $0
      }
      i += 1
    }
    object?.withCString {
      _ApplicationHostDOMSetFileInputFiles(
        host.reference, 
        CInt(id), 
        cfiles, 
        CInt(files.count), 
        CInt(node), 
        CInt(backendNode ?? -1), 
        $0)
    }
    free(cfiles)
  }

  // public func setInspectedNode() {
  //   _ApplicationHostDOMSetInspectedNode(host.reference, CInt(id), int32_t node_id);
  // }

  public func setNodeName(_ node: Int, name: String, _ callback: @escaping SetNodeNameCallback) {
    let holder = CallbackHolder(self, setNodeName: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    name.withCString {
      _ApplicationHostDOMSetNodeName(host.reference, CInt(id), CInt(node), $0, {
        (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.setNodeName!(Int(node_id))
      }, holderInstance)
    }
  }

  public func setNodeValue(_ node: Int, value: String) {
    value.withCString {
      _ApplicationHostDOMSetNodeValue(host.reference, CInt(id), CInt(node), $0)
    }
  }

  public func setOuterHTML(_ node: Int, html: String) {
    html.withCString {
      _ApplicationHostDOMSetOuterHTML(host.reference, CInt(id), CInt(node), $0)
    }
  }

  public func undo() {
    _ApplicationHostDOMUndo(host.reference, CInt(id))
  }

  public func getFrameOwner(frame: String, _ callback: @escaping GetFrameOwnerCallback) {
    let holder = CallbackHolder(self, getFrameOwner: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frame.withCString { 
      _ApplicationHostDOMGetFrameOwner(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, node_id: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getFrameOwner!(Int(node_id))
      }, holderInstance)
    }
  }
  
  // CSS
  public func addRule(styleSheet: String, ruleText: String, location: SourceRange, _ callback: @escaping AddRuleCallback) {
    let holder = CallbackHolder(self, addRule: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    // FIXME
    styleSheet.withCString { cstyle in
      ruleText.withCString { crule in
        _ApplicationHostCSSAddRule(host.reference, CInt(id), cstyle, crule, nil, {
          (handle: UnsafeMutableRawPointer?, rulePtr: CSSRulePtrRef?) in 
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          let rule = CSSRule()
          rule.decode(rulePtr!)
          state.addRule!(rule)
        }, holderInstance)
      }
    }
  }

  public func collectClassNames(styleSheet: String, _ callback: @escaping CollectClassNamesCallback) {
    let holder = CallbackHolder(self, collectClassNames: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString {
      _ApplicationHostCSSCollectClassNames(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, class_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?, class_names_count: CInt) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [String] = []
        for i in 0..<Int(class_names_count) {
          arr.append(String(cString: class_names![i]!))
        }
        state.collectClassNames!(arr)
      }, holderInstance)
    }
  }

  public func createStyleSheet(frame: String, _ callback: @escaping CreateStyleSheetCallback) {
    let holder = CallbackHolder(self, createStyleSheet: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frame.withCString {
      _ApplicationHostCSSCreateStyleSheet(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, style_sheet_id: UnsafePointer<CChar>?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.createStyleSheet!(String(cString: style_sheet_id!))
      }, holderInstance)
    }
  }

  public func forcePseudoState(_ node: Int, forcedPseudo: [String]) {
    var i = 0
    var cpseudo: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    cpseudo = malloc(forcedPseudo.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in forcedPseudo {
      item.withCString {
        cpseudo![i] = $0
      }
      i += 1
    }
    _ApplicationHostCSSForcePseudoState(host.reference, CInt(id), CInt(node), cpseudo, CInt(forcedPseudo.count))
    free(cpseudo)
  }

  public func getBackgroundColors(_ node: Int, _ callback: @escaping GetBackgroundColorsCallback) {
    let holder = CallbackHolder(self, getBackgroundColors: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetBackgroundColors(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?,
       background_colors: UnsafeMutablePointer<UnsafePointer<CChar>?>? /* optional */, 
       background_colors_count: CInt, 
       computed_font_size: UnsafePointer<CChar>? /* optional */, 
       computed_font_weight: UnsafePointer<CChar>? /* optional */, 
       computed_body_font_size: UnsafePointer<CChar>? /* optional */) in 
      
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var bg: [String] = []
      for i in 0..<Int(background_colors_count) {
        bg.append(String(cString: background_colors![i]!))
      }
      state.getBackgroundColors!(
        bg, 
        computed_font_size == nil ? nil : String(cString: computed_font_size!),
        computed_font_weight == nil ? nil : String(cString: computed_font_weight!),
        computed_body_font_size == nil ? nil : String(cString: computed_body_font_size!))
    }, holderInstance)
  }

  public func getComputedStyleForNode(_ node: Int, _ callback: @escaping GetComputedStyleForNodeCallback) {
    let holder = CallbackHolder(self, getComputedStyleForNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetComputedStyleForNode(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, styles: UnsafeMutablePointer<CSSComputedStylePropertyPtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [CSSComputedStyleProperty] = []
      for i in 0..<Int(count) {
        var property = CSSComputedStyleProperty()
        property.decode(styles![i]!)
        arr.append(property)
      }
      state.getComputedStyleForNode!(arr)
    }, holderInstance)
  }

  public func getInlineStylesForNode(_ node: Int, _ callback: @escaping GetInlineStylesForNodeCallback) {
    let holder = CallbackHolder(self, getInlineStylesForNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetInlineStylesForNode(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, inlineStylePtr: CSSStylePtrRef?, attributesStylePtr: CSSStylePtrRef?) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      
      var inlineStyle = CSSStyle() 
      inlineStyle.decode(inlineStylePtr!)
      
      var attrStyle = CSSStyle()
      attrStyle.decode(attributesStylePtr!)

      state.getInlineStylesForNode!(inlineStyle, attrStyle)
    }, holderInstance)
  }

  public func getMatchedStylesForNode(_ node: Int, _ callback: @escaping GetMatchedStylesForNodeCallback) {
    let holder = CallbackHolder(self, getMatchedStylesForNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetMatchedStylesForNode(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, 
       inlineStylePtr: CSSStylePtrRef?, 
       attributesStylePtr: CSSStylePtrRef?, 
       matched_css_rules: UnsafeMutablePointer<RuleMatchPtrRef?>?, 
       matched_css_rules_count: CInt, 
       pseudo_elements: UnsafeMutablePointer<PseudoElementMatchesPtrRef?>?, 
       pseudo_elements_count: CInt, 
       inheritedPtr: UnsafeMutablePointer<InheritedStyleEntryPtrRef?>?, 
       inherited_count: CInt, 
       css_keyframes_rules: UnsafeMutablePointer<CSSKeyframesRulePtrRef?>?, 
       css_keyframes_rules_count: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      
      var inlineStyle = CSSStyle() 
      inlineStyle.decode(inlineStylePtr!)
      
      var attrStyle = CSSStyle()
      attrStyle.decode(attributesStylePtr!)

      var matched: [RuleMatch] = []
      var elems: [PseudoElementMatches] = []
      var inheriteds: [InheritedStyleEntry] = []
      var keyframes: [CSSKeyframesRule] = []

      for i in 0..<Int(matched_css_rules_count) {
        var match = RuleMatch()
        match.decode(matched_css_rules![i]!)
        matched.append(match)
      }

      for i in 0..<Int(pseudo_elements_count) {
        var elem = PseudoElementMatches()
        elem.decode(pseudo_elements![i]!)
        elems.append(elem)
      }

      for i in 0..<Int(inherited_count) {
        var inherited = InheritedStyleEntry()
        inherited.decode(inheritedPtr![i]!)
        inheriteds.append(inherited)
      }

      for i in 0..<Int(css_keyframes_rules_count) {
        var rule = CSSKeyframesRule()
        rule.decode(css_keyframes_rules![i]!)
        keyframes.append(rule)
      }

      state.getMatchedStylesForNode!(inlineStyle, attrStyle, matched, elems, inheriteds, keyframes) 
    }, holderInstance)
  }

  public func getMediaQueries(_ callback: @escaping GetMediaQueriesCallback) {
    let holder = CallbackHolder(self, getMediaQueries: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetMediaQueries(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, medias: UnsafeMutablePointer<CSSMediaPtrRef?>?, count: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [CSSMedia] = []
      for i in 0..<Int(count) {
        var media = CSSMedia()
        media.decode(medias![i]!)
        arr.append(media)
      }
      state.getMediaQueries!(arr)
    }, holderInstance)
  }

  public func getPlatformFontsForNode(_ node: Int, _ callback: @escaping GetPlatformFontsForNodeCallback) {
    let holder = CallbackHolder(self, getPlatformFontsForNode: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSGetPlatformFontsForNode(host.reference, CInt(id), CInt(node), {
      (handle: UnsafeMutableRawPointer?, usage: UnsafeMutablePointer<PlatformFontUsagePtrRef?>?, count: CInt) in 
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [PlatformFontUsage] = []
      for i in 0..<Int(count) {
        var font = PlatformFontUsage()
        font.decode(usage![i]!)
        arr.append(font)
      }
      state.getPlatformFontsForNode!(arr)
    }, holderInstance)
  }

  public func getStyleSheetText(styleSheet: String, _ callback: @escaping GetStyleSheetTextCallback) {
    let holder = CallbackHolder(self, getStyleSheetText: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString {
      _ApplicationHostCSSGetStyleSheetText(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, text: UnsafePointer<CChar>?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getStyleSheetText!(String(cString: text!))
      }, holderInstance)
    }
  }

  public func setEffectivePropertyValueForNode(_ node: Int, property: String, value: String) {
    property.withCString { cprop in
      value.withCString { cval in
        _ApplicationHostCSSSetEffectivePropertyValueForNode(host.reference, CInt(id), CInt(node), cprop, cval)
      }
    }
  }

  public func setKeyframeKey(styleSheet: String, range: SourceRange, key: String, _ callback: @escaping SetKeyframeKeyCallback) {
    let holder = CallbackHolder(self, setKeyframeKey: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString { cstyle in
      key.withCString { ckey in
        // FIXME
        _ApplicationHostCSSSetKeyframeKey(host.reference, CInt(id), cstyle, nil, ckey, {
          (handle: UnsafeMutableRawPointer?, valuePtr: CSSValuePtrRef?) in 
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          var value = CSSValue()
          value.decode(valuePtr!)
          state.setKeyframeKey!(value)
        }, holderInstance)
      }
    }
  }

  public func setMediaText(styleSheet: String, range: SourceRange, text: String, _ callback: @escaping SetMediaTextCallback) {
    let holder = CallbackHolder(self, setMediaText: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString { cstyle in
      text.withCString { ctext in
        // FIXME
        _ApplicationHostCSSSetMediaText(host.reference, CInt(id), cstyle, nil, ctext, {
          (handle: UnsafeMutableRawPointer?, mediaPtr: CSSMediaPtrRef?) in 
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          var media = CSSMedia()
          media.decode(mediaPtr!)
          state.setMediaText!(media)
        }, holderInstance)
      }
    }
  }

  public func setRuleSelector(styleSheet: String, range: SourceRange, selector: String, _ callback: @escaping SetRuleSelectorCallback) {
    let holder = CallbackHolder(self, setRuleSelector: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString { cstyle in
      selector.withCString { csel in
        // FIXME
        _ApplicationHostCSSSetRuleSelector(host.reference, CInt(id), cstyle, nil, csel, {
          (handle: UnsafeMutableRawPointer?, selectorList: SelectorListPtrRef?) in 
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var list = SelectorList()
        list.decode(selectorList!)
        state.setRuleSelector!(list)
        }, holderInstance)
      }
    }
  }

  public func setStyleSheetText(styleSheet: String, text: String, _ callback: @escaping SetStyleSheetTextCallback) {
    let holder = CallbackHolder(self, setStyleSheetText: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    styleSheet.withCString { cstyle in
      text.withCString { ctext in
        _ApplicationHostCSSSetStyleSheetText(host.reference, CInt(id), cstyle, ctext, {
          (handle: UnsafeMutableRawPointer?, sourceMapUrl: UnsafePointer<CChar>?) in    
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.setStyleSheetText!(String(cString: sourceMapUrl!))
        }, holderInstance)
      }
    }
  }

  public func setStyleTexts(edits: [StyleDeclarationEdit], _ callback: @escaping SetStyleTextsCallback) {
    let holder = CallbackHolder(self, setStyleTexts: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var cedits: UnsafeMutablePointer<StyleDeclarationEditPtrRef?>?
    var i = 0
    cedits = malloc(edits.count * MemoryLayout<StyleDeclarationEditPtrRef>.size).load(as: UnsafeMutablePointer<StyleDeclarationEditPtrRef?>.self)
    for edit in edits {
      // FIXME
      cedits![i] = nil
      i += 1
    }
    _ApplicationHostCSSSetStyleTexts(host.reference, CInt(id), cedits, CInt(edits.count), {
      (handle: UnsafeMutableRawPointer?, styles: UnsafeMutablePointer<CSSStylePtrRef?>?, count: CInt) in

    }, holderInstance)
    free(cedits)
  }

  public func startRuleUsageTracking() {
    _ApplicationHostCSSStartRuleUsageTracking(host.reference, CInt(id))
  }

  public func stopRuleUsageTracking(_ callback: @escaping StopRuleUsageTrackingCallback) {
    let holder = CallbackHolder(self, stopRuleUsageTracking: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSStopRuleUsageTracking(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, rules: UnsafeMutablePointer<CSSRuleUsagePtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [CSSRuleUsage] = []
      for i in 0..<Int(count) {
        var usage = CSSRuleUsage()
        usage.decode(rules![i]!)
        arr.append(usage)
      }
      state.stopRuleUsageTracking!(arr)
    }, holderInstance)
  }

  public func takeCoverageDelta(_ callback: @escaping TakeCoverageDeltaCallback) {
    let holder = CallbackHolder(self, takeCoverageDelta: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostCSSTakeCoverageDelta(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, rules: UnsafeMutablePointer<CSSRuleUsagePtrRef?>?, count: CInt) in  
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [CSSRuleUsage] = []
      for i in 0..<Int(count) {
        var usage = CSSRuleUsage()
        usage.decode(rules![i]!)
        arr.append(usage)
      }
      state.takeCoverageDelta!(arr)
    }, holderInstance)
  }
  
  // CacheStorage
  public func hasCache(_ cacheId: String, _ callback: @escaping HasCacheCallback) {
    let holder = CallbackHolder(self, hasCache: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString {
      _ApplicationHostCacheStorageHasCache(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, result: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.hasCache!(result != 0)
      }, holderInstance)
    }
  }
  
  public func openCache(_ cacheId: String, _ callback: @escaping OpenCacheCallback) {
    let holder = CallbackHolder(self, openCache: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString {
      _ApplicationHostCacheStorageOpenCache(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, result: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.openCache!(Int(result))
      }, holderInstance)
    }
  }
  
  public func deleteCache(_ cacheId: String, _ callback: @escaping DeleteCacheCallback) {
    let holder = CallbackHolder(self, deleteCache: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString {
      _ApplicationHostCacheStorageDeleteCache(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, result: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.deleteCache!(result != 0)
      }, holderInstance)
    }
  }

  public func deleteCacheEntry(_ cacheId: String, request: String, _ callback: @escaping DeleteEntryCallback) {
    let holder = CallbackHolder(self, deleteEntry: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString { ccache in
      request.withCString { creq in
        _ApplicationHostCacheStorageDeleteEntry(host.reference, CInt(id), ccache, creq, {
          (handle: UnsafeMutableRawPointer?, result: CInt) in  
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.deleteEntry!(result != 0)
        }, holderInstance)
      }
    }
  }

  public func putCacheEntry(_ cacheId: String, request: String, content: String, _ callback: @escaping PutEntryCallback) {
    putCacheEntry(cacheId, request: request, content: Data(content.utf8), callback)
  }

  public func putCacheEntry(_ cacheId: String, request: String, content: Data, _ callback: @escaping PutEntryCallback) {
    let holder = CallbackHolder(self, putEntry: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString { ccache in
      request.withCString { creq in
        content.withUnsafeBytes { cbytes in
          _ApplicationHostCacheStoragePutEntryData(host.reference, CInt(id), ccache, creq, cbytes, CInt(content.count), {
            (handle: UnsafeMutableRawPointer?, result: CInt) in  
            let state = unsafeBitCast(handle, to: CallbackHolder.self)
            state.putEntry!(result != 0)
          }, holderInstance)
        }
      }
    }
  }

  public func putCacheEntry(_ cacheId: String, request: String, blob: BlobData, _ callback: @escaping PutEntryCallback) {
    let holder = CallbackHolder(self, putEntry: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString { ccache in
      request.withCString { creq in
        _ApplicationHostCacheStoragePutEntryBlob(host.reference, CInt(id), ccache, creq, blob.reference, {
          (handle: UnsafeMutableRawPointer?, result: CInt) in  
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.putEntry!(result != 0)
        }, holderInstance)
      }
    }
  }

  public func requestCacheNames(origin: String, _ callback: @escaping RequestCacheNamesCallback) {
    let holder = CallbackHolder(self, requestCacheNames: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    origin.withCString { 
      _ApplicationHostCacheStorageRequestCacheNames(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, caches: UnsafeMutablePointer<CachePtrRef?>?, count: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [Cache] = []
        for i in 0..<Int(count) {
          var cache = Cache()
          cache.decode(caches![i]!)
          arr.append(cache)
        }
        state.requestCacheNames!(arr)
      }, holderInstance)
    }
  }

  public func requestCachedResponse(_ cacheId: String, url: String, base64Encoded: Bool, _ callback: @escaping RequestCachedResponseCallback) {
    let holder = CallbackHolder(self, requestCachedResponse: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString { ccache in
      url.withCString { curl in
        _ApplicationHostCacheStorageRequestCachedResponse(host.reference, CInt(id), ccache, curl, base64Encoded ? 1 : 0, {
          (handle: UnsafeMutableRawPointer?, responseBody: UnsafePointer<CChar>?, csize: CInt) in 
          let state = unsafeBitCast(handle, to: CallbackHolder.self)
          state.requestCachedResponse!(CachedResponse(body: Data(bytes: responseBody!, count: Int(csize))))  
        }, holderInstance)
      }
    }
  }

  public func requestCacheEntries(_ cacheId: String, skipCount: Int, pageSize: Int, _ callback: @escaping RequestEntriesCallback) {
    let holder = CallbackHolder(self, requestEntries: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    cacheId.withCString {
      _ApplicationHostCacheStorageRequestEntries(host.reference, CInt(id), $0, CInt(skipCount), CInt(pageSize), {
        (handle: UnsafeMutableRawPointer?, entryPtr: UnsafeMutablePointer<DataEntryPtrRef?>?, count: CInt, hasMore: CInt) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var arr: [DataEntry] = []
        for i in 0..<Int(count) {
          var entry = DataEntry()
          entry.decode(entryPtr![i]!)
          arr.append(entry)
        }
        state.requestEntries!(arr, hasMore != 0)
      }, holderInstance)
    }
  }
  
  // ApplicationCache
  public func getApplicationCacheForFrame(_ frameId: String, _ callback: @escaping GetApplicationCacheForFrameCallback) {
    let holder = CallbackHolder(self, getApplicationCacheForFrame: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frameId.withCString {
      _ApplicationHostApplicationCacheGetApplicationCacheForFrame(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, appCache: ApplicationCachePtrRef?) in  
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var cache = ApplicationCache()
        cache.decode(appCache!)
        state.getApplicationCacheForFrame!(cache)
      }, holderInstance)
    }
  }

  public func getFramesWithManifests(_ callback: @escaping GetFramesWithManifestsCallback) {
    let holder = CallbackHolder(self, getFramesWithManifests: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostApplicationCacheGetFramesWithManifests(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, frames: UnsafeMutablePointer<FrameWithManifestPtrRef?>?, count: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      var arr: [FrameWithManifest] = []
      for i in 0..<Int(count) {
        var frame = FrameWithManifest()
        frame.decode(frames![i]!)
        arr.append(frame)
      }
      state.getFramesWithManifests!(arr)
    }, holderInstance)
  }

  public func getManifestForFrame(_ frame: String, _ callback: @escaping GetManifestForFrameCallback) {
    let holder = CallbackHolder(self, getManifestForFrame: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    frame.withCString { 
      _ApplicationHostApplicationCacheGetManifestForFrame(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, manifest: UnsafePointer<CChar>?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getManifestForFrame!(String(cString: manifest!))
      }, holderInstance)
    }
  }

  // Animation
  public func getAnimationCurrentTime(_ animation: String, _ callback: @escaping GetCurrentTimeCallback) {
    let holder = CallbackHolder(self, getCurrentTime: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    animation.withCString {
      _ApplicationHostAnimationGetCurrentTime(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, time: CInt) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        state.getCurrentTime!(Int(time))    
      }, holderInstance)
    }
  }

  public func getAnimationPlaybackRate(_ callback: @escaping GetPlaybackRateCallback) {
    let holder = CallbackHolder(self, getPlaybackRate: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostAnimationGetPlaybackRate(host.reference, CInt(id), {
      (handle: UnsafeMutableRawPointer?, rate: CInt) in
      let state = unsafeBitCast(handle, to: CallbackHolder.self)
      state.getPlaybackRate!(Int(rate))  
    }, holderInstance)
  }

  public func releaseAnimations(_ animations: [String]) {
    var i = 0
    var canims: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    canims = malloc(animations.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in animations {
      item.withCString {
        canims![i] = $0
      }
      i += 1
    }
    _ApplicationHostAnimationReleaseAnimations(host.reference, CInt(id), canims, CInt(animations.count))
    free(canims)
  }

  public func resolveAnimation(_ animation: String, _ callback: @escaping ResolveAnimationCallback) {
    let holder = CallbackHolder(self, resolveAnimation: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    animation.withCString {
      _ApplicationHostAnimationResolveAnimation(host.reference, CInt(id), $0, {
        (handle: UnsafeMutableRawPointer?, animation: AnimationPtrRef?) in
        let state = unsafeBitCast(handle, to: CallbackHolder.self)
        var anim = Animation()
        anim.decode(animation!)
        state.resolveAnimation!(anim)
      }, holderInstance)
    }
  }

  public func seekAnimations(_ animations: [String], currentTime: Int) {
    var i = 0
    var canims: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    canims = malloc(animations.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in animations {
      item.withCString {
        canims![i] = $0
      }
      i += 1
    }
    _ApplicationHostAnimationSeekAnimations(
      host.reference, 
      CInt(id), 
      canims, 
      CInt(animations.count), 
      CInt(currentTime))
    
    free(canims)
  }

  public func setPaused(_ animations: [String], paused: Bool) {
    var i = 0
    var canims: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    canims = malloc(animations.count * MemoryLayout<UnsafePointer<CChar>>.size).load(as: UnsafeMutablePointer<UnsafePointer<CChar>?>.self)
    for item in animations {
      item.withCString {
        canims![i] = $0
      }
      i += 1
    }
    _ApplicationHostAnimationSetPaused(
      host.reference, 
      CInt(id), 
      canims, 
      CInt(animations.count), 
      paused ? 1 : 0)

    free(canims)
  }

  public func setAnimationPlaybackRate(playbackRate: Int) {
    _ApplicationHostAnimationSetPlaybackRate(host.reference, CInt(id), CInt(playbackRate))
  }

  public func setAnimationTiming(_ animation: String, duration: Int, delay: Int) {
    animation.withCString {
      _ApplicationHostAnimationSetTiming(host.reference, CInt(id), $0, CInt(duration), CInt(delay))
    }
  }
  
  // Accessibility
  public func getPartialAXTree(node: String, backendNode: Int, object: String, fetchRelatives: Bool, _ callback: @escaping GetPartialAXTreeCallback) {
    let holder = CallbackHolder(self, getPartialAXTree: callback)
    let holderInstance = unsafeBitCast(Unmanaged.passUnretained(holder).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    node.withCString { cnode in
      object.withCString { cobj in
        _ApplicationHostAccessibilityGetPartialAXTree(
          host.reference, 
          CInt(id),
          cnode, 
          CInt(backendNode), 
          cobj, 
          fetchRelatives ? 1 : 0, 
          {
            (handle: UnsafeMutableRawPointer?, nodes: UnsafeMutablePointer<AXNodePtrRef?>?, nodeCount: CInt) in
            let state = unsafeBitCast(handle, to: CallbackHolder.self)
            var arr: [AXNode] = []
            for i in 0..<Int(nodeCount) {
              var axnode = AXNode()
              axnode.decode(nodes![i]!)
              arr.append(axnode)
            }
            state.getPartialAXTree!(arr)
          }, holderInstance)
      }
    }
  }


  public func onBoundsChanged(bounds: IntRect) {
    for observer in observers {
      observer.onBoundsChanged(bounds: bounds)
    }   
  }

  public func onVisible() {
    for observer in observers {
      observer.onVisible()
    } 
  }
  
  public func onHidden() {
    for observer in observers {
      observer.onHidden()
    }
  }

  // Page callbacks
  func onFrameAttached(frameId: String, parentFrameId: String) {
    for observer in observers {
      observer.onFrameAttached(frameId: frameId, parentFrameId: parentFrameId)
    } 
  }

  func onDomContentEventFired(timestamp: Int64) {
    for observer in observers {
      observer.onDomContentEventFired(timestamp: timestamp)
    }
  }

  func onFrameClearedScheduledNavigation(frameId: String) {
    for observer in observers {
      observer.onFrameClearedScheduledNavigation(frameId: frameId)
    }
  }

  func onFrameDetached(frameId: String) {
    for observer in observers {
      observer.onFrameDetached(frameId: frameId)
    }
  }

  func onFrameNavigated(frame: Frame) {
    for observer in observers {
      observer.onFrameNavigated(frame: frame)
    }
  }

  func onFrameResized() {
    for observer in observers {
      observer.onFrameResized()
    }
  }

  func onFrameScheduledNavigation(frameId: String, delay: Int, reason: NavigationReason, url: String) {
    for observer in observers {
      observer.onFrameScheduledNavigation(frameId: frameId, delay: delay, reason: reason, url: url)
    }
  }
  
  func onFrameStartedLoading(frameId: String) {
    for observer in observers {
      observer.onFrameStartedLoading(frameId: frameId)
    }
  }
  
  func onFrameStoppedLoading(frameId: String) {
    for observer in observers {
      observer.onFrameStoppedLoading(frameId: frameId)
    }
  }
  
  func onInterstitialHidden() {
    for observer in observers {
      observer.onInterstitialHidden()
    }
  }
  
  func onInterstitialShown() {
    for observer in observers {
      observer.onInterstitialShown()
    }
  }
  
  func onJavascriptDialogClosed(result: Bool, userInput: String) {
    for observer in observers {
      observer.onJavascriptDialogClosed(result: result, userInput: userInput)
    }
  }
  
  func onJavascriptDialogOpening(url: String, message: String, type: DialogType, hasBrowserHandler: Bool, defaultPrompt: String?) {
    for observer in observers {
      observer.onJavascriptDialogOpening(url: url, message: message, type: type, hasBrowserHandler: hasBrowserHandler, defaultPrompt: defaultPrompt)
    }
  }
  
  func onLifecycleEvent(frameId: String, loaderId: Int, name: String, timestamp: TimeTicks) {
    for observer in observers {
      observer.onLifecycleEvent(frameId: frameId, loaderId: loaderId, name: name, timestamp: timestamp)
    }
  }
  
  func onLoadEventFired(timestamp: TimeTicks) {
    for observer in observers {
      observer.onLoadEventFired(timestamp: timestamp)
    }
  }
  
  func onNavigatedWithinDocument(frameId: String, url: String) {
    for observer in observers {
      observer.onNavigatedWithinDocument(frameId: frameId, url: url)
    }
  }
  
  func onScreencastFrame(base64Data: String, metadata: ScreencastFrameMetadata, sessionId: Int) {
    for observer in observers {
      observer.onScreencastFrame(base64Data: base64Data, metadata: metadata, sessionId: sessionId)
    }
  }
  
  func onScreencastVisibilityChanged(visible: Bool) {
    for observer in observers {
      observer.onScreencastVisibilityChanged(visible: visible)
    }
  }
  
  func onWindowOpen(url: String, windowName: String, windowFeatures: [String], userGesture: Bool) {
    for observer in observers {
      observer.onWindowOpen(url: url, windowName: windowName, windowFeatures: windowFeatures, userGesture: userGesture)
    }
  }
  
  func onPageLayoutInvalidated(resized: Bool) {
    for observer in observers {
      observer.onPageLayoutInvalidated(resized: resized)
    }
  }

  // Overlay

  func inspectNodeRequested(backendNode: Int) {
    for observer in observers {
      observer.inspectNodeRequested(backendNode: backendNode)
    }
  }

  func nodeHighlightRequested(nodeId: Int) {
    for observer in observers {
      observer.nodeHighlightRequested(nodeId: nodeId)
    }
  }

  func screenshotRequested(viewport: Viewport) {
    for observer in observers {
      observer.screenshotRequested(viewport: viewport)
    }
  }

  // Worker
  func workerErrorReported(errorMessage: ServiceWorkerErrorMessage) {
    for observer in observers {
      observer.workerErrorReported(errorMessage: errorMessage)
    }
  }
  
  func workerRegistrationUpdated(registrations: [ServiceWorkerRegistration]) {
    for observer in observers {
      observer.workerRegistrationUpdated(registrations: registrations)
    }
  }
  
  func workerVersionUpdated(versions: [ServiceWorkerVersion]) {
    for observer in observers {
      observer.workerVersionUpdated(versions: versions)
    }
  }
  
  func onAttachedToTarget(sessionId: String, targetInfo: TargetInfo) {
    for observer in observers {
      observer.onAttachedToTarget(sessionId: sessionId, targetInfo: targetInfo)
    }
  }
  
  func onDetachedFromTarget(sessionId: String, targetId: String?) {
    for observer in observers {
      observer.onDetachedFromTarget(sessionId: sessionId, targetId: targetId) 
    }
  }
  
  func onReceivedMessageFromTarget(sessionId: String, message: String, targetId: String?) {
    for observer in observers {
      observer.onReceivedMessageFromTarget(sessionId: sessionId, message: message, targetId: targetId)
    }
  }

  // Storage
  func onCacheStorageContentUpdated(origin: String, cacheName: String) {
    for observer in observers {
      observer.onCacheStorageContentUpdated(origin: origin, cacheName: cacheName)
    }
  }
  
  func onCacheStorageListUpdated(origin: String) {
    for observer in observers {
      observer.onCacheStorageListUpdated(origin: origin)
    }
  }
  
  func onIndexedDBContentUpdated(origin: String, databaseName: String, objectStoreName: String) {
    for observer in observers {
      observer.onIndexedDBContentUpdated(origin: origin, databaseName: databaseName, objectStoreName: objectStoreName)
    }
  }
  
  func onIndexedDBListUpdated(origin: String) {
    for observer in observers {
      observer.onIndexedDBListUpdated(origin: origin)
    }
  }

  // tethering
  func onAccepted(port: Int, connectionId: String) {
    for observer in observers {
      observer.onAccepted(port: port, connectionId: connectionId)
    }
  }

  // network
  func onDataReceived(requestId: String, timestamp: TimeTicks, dataLength: Int64, encodedDataLength: Int64) {
    for observer in observers {
      observer.onDataReceived(requestId: requestId, timestamp: timestamp, dataLength: dataLength, encodedDataLength: encodedDataLength)
    }
  }

  func onEventSourceMessageReceived(requestId: String, timestamp: Int64, eventName: String, eventId: String, data: String) {
    for observer in observers {
      observer.onEventSourceMessageReceived(requestId: requestId, timestamp: timestamp, eventName: eventName, eventId: eventId, data: data)
    }
  }

  func onLoadingFailed(requestId: String, timestamp: Int64, type: ResourceType, errorText: String, canceled: Bool, blockedReason: BlockedReason) {
    for observer in observers {
      observer.onLoadingFailed(requestId: requestId, timestamp: timestamp, type: type, errorText: errorText, canceled: canceled, blockedReason: blockedReason)
    }
  }

  func onLoadingFinished(requestId: String, timestamp: Int64, encodedDataLength: Int64, blockedCrossSiteDocument: Bool) {
    for observer in observers {
      observer.onLoadingFinished(requestId: requestId, timestamp: timestamp, encodedDataLength: encodedDataLength, blockedCrossSiteDocument: blockedCrossSiteDocument)
    }
  }

  func onRequestIntercepted(
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
    for observer in observers {
      observer.onRequestIntercepted(
        interceptionId: interceptionId, 
        request: request, 
        frameId: frameId, 
        resourceType: resourceType, 
        isNavigationRequest: isNavigationRequest, 
        isDownload: isDownload, 
        redirectUrl: redirectUrl, 
        authChallenge: authChallenge, 
        responseErrorReason: responseErrorReason, 
        responseStatusCode: responseStatusCode, 
        responseHeaders: responseHeaders)
    }
  }

  func onRequestServedFromCache(requestId: String) {
    for observer in observers {
      observer.onRequestServedFromCache(requestId: requestId)
    }
  }

  func onRequestWillBeSent(
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
    
    for observer in observers {
      observer.onRequestWillBeSent(
        requestId: requestId, 
        loaderId: loaderId,
        documentUrl: documentUrl, 
        request: request, 
        timestamp: timestamp, 
        walltime: walltime, 
        initiator: initiator, 
        redirectResponse: redirectResponse, 
        type: type, 
        frameId: frameId, 
        hasUserGesture: hasUserGesture)
    }
  }
  
  func onResourceChangedPriority(requestId: String, newPriority: ResourcePriority, timestamp: Int64) {
    for observer in observers {
      observer.onResourceChangedPriority(requestId: requestId, newPriority: newPriority, timestamp: timestamp)
    }
  }

  func onResponseReceived(requestId: String, loaderId: String, timestamp: Int64, type: ResourceType, response: Response, frameId: String?) {
    for observer in observers {
      observer.onResponseReceived(requestId: requestId, loaderId: loaderId, timestamp: timestamp, type: type, response: response, frameId: frameId)
    }
  }

  func onWebSocketClosed(requestId: String, timestamp: Int64) {
    for observer in observers {
      observer.onWebSocketClosed(requestId: requestId, timestamp: timestamp)
    }
  }

  func onWebSocketCreated(requestId: String, url: String, initiator: Initiator) {
    for observer in observers {
      observer.onWebSocketCreated(requestId: requestId, url: url, initiator: initiator)
    }
  }

  func onWebSocketFrameError(requestId: String, timestamp: Int64, errorMessage: String) {
    for observer in observers {
      observer.onWebSocketFrameError(requestId: requestId, timestamp: timestamp, errorMessage: errorMessage)
    }
  }

  func onWebSocketFrameReceived(requestId: String, timestamp: Int64, response: WebSocketFrame) {
    for observer in observers {
      observer.onWebSocketFrameReceived(requestId: requestId, timestamp: timestamp, response: response)
    }
  }

  func onWebSocketFrameSent(requestId: String, timestamp: Int64, response: WebSocketFrame) {
    for observer in observers {
      observer.onWebSocketFrameSent(requestId: requestId, timestamp: timestamp, response: response)
    }
  }
  
  func onWebSocketHandshakeResponseReceived(requestId: String, timestamp: Int64, response: WebSocketResponse) {
    for observer in observers {
      observer.onWebSocketHandshakeResponseReceived(requestId: requestId, timestamp: timestamp, response: response)
    }
  }

  func onWebSocketWillSendHandshakeRequest(requestId: String, timestamp: Int64, walltime: Int64, request: WebSocketRequest) {
    for observer in observers {
      observer.onWebSocketWillSendHandshakeRequest(requestId: requestId, timestamp: timestamp, walltime: walltime, request: request)
    }
  }

  func flush() {
    for observer in observers {
      observer.flush()
    }
  }

  // LayerTree
  func onLayerPainted(layerId: String, clipX: Int, clipY: Int, clipW: Int, clipH: Int) {
    for observer in observers {
      observer.onLayerPainted(layerId: layerId, clipX: clipX, clipY: clipY, clipW: clipW, clipH: clipH)
    }
  }
  
  func onLayerTreeDidChange(layers: [Layer]) {
    for observer in observers {
      observer.onLayerTreeDidChange(layers: layers)
    }
  }

  // Headless
  func onNeedsBeginFramesChanged(needsBeginFrames: Bool) {
    for observer in observers {
      observer.onNeedsBeginFramesChanged(needsBeginFrames: needsBeginFrames)
    }
  }

  // DOMStorage
  func onDomStorageItemAdded(storageId: StorageId, key: String, newValue: String) {
    for observer in observers {
      observer.onDomStorageItemAdded(storageId: storageId, key: key, newValue: newValue)
    }
  }

  func onDomStorageItemRemoved(storageId: StorageId, key: String) {
    for observer in observers {
      observer.onDomStorageItemRemoved(storageId: storageId, key: key)
    }
  }

  func onDomStorageItemUpdated(storageId: StorageId, key: String, oldValue: String, newValue: String) {
    for observer in observers {
      observer.onDomStorageItemUpdated(storageId: storageId, key: key, oldValue: oldValue, newValue: newValue)
    }
  }
  
  func onDomStorageItemsCleared(storageId: StorageId) {
    for observer in observers {
      observer.onDomStorageItemsCleared(storageId: storageId)
    }
  }
  
  // Database
  func onAddDatabase(database: Database) {
    for observer in observers {
      observer.onAddDatabase(database: database)
    }
  }
  
  // Emulation
  func onVirtualTimeAdvanced(virtualTimeElapsed: Int) {
    for observer in observers {
      observer.onVirtualTimeAdvanced(virtualTimeElapsed: virtualTimeElapsed)
    }
  }
  
  func onVirtualTimeBudgetExpired() {
    for observer in observers {
      observer.onVirtualTimeBudgetExpired()
    }
  }
  
  func onVirtualTimePaused(virtualTimeElapsed: Int) {
    for observer in observers {
      observer.onVirtualTimePaused(virtualTimeElapsed: virtualTimeElapsed)
    }
  }
  
  // DOM
  func setChildNodes(parentId: Int, nodes: [DOMNode]) {
    for observer in observers {
      observer.setChildNodes(parentId: parentId, nodes: nodes)
    }
  }
  
  func onAttributeModified(nodeId: Int, name: String, value: String) {
    for observer in observers {
      observer.onAttributeModified(nodeId: nodeId, name: name, value: value)
    }
  }
  
  func onAttributeRemoved(nodeId: Int, name: String) {
    for observer in observers {
      observer.onAttributeRemoved(nodeId: nodeId, name: name)
    }
  }
  
  func onCharacterDataModified(nodeId: Int, characterData: String) {
    for observer in observers {
      observer.onCharacterDataModified(nodeId: nodeId, characterData: characterData)
    }
  }
  
  func onChildNodeCountUpdated(nodeId: Int, childNodeCount: Int) {
    for observer in observers {
      observer.onChildNodeCountUpdated(nodeId: nodeId, childNodeCount: childNodeCount)
    }
  }
  
  func onChildNodeInserted(parentNodeId: Int, previousNodeId: Int, node: DOMNode) {
    for observer in observers {
      observer.onChildNodeInserted(parentNodeId: parentNodeId, previousNodeId: previousNodeId, node: node)
    }
  }
  
  func onChildNodeRemoved(parentNodeId: Int, nodeId: Int) {
    for observer in observers {
      observer.onChildNodeRemoved(parentNodeId: parentNodeId, nodeId: nodeId)
    }
  }
  
  func onDistributedNodesUpdated(insertionPointId: Int, distributedNodes: [BackendNode]) {
    for observer in observers {
      observer.onDistributedNodesUpdated(insertionPointId: insertionPointId, distributedNodes: distributedNodes)
    }
  }
  
  func onDocumentUpdated() {
    for observer in observers {
      observer.onDocumentUpdated()
    }
  }
  
  func onInlineStyleInvalidated(nodeIds: [Int]) {
    for observer in observers {
      observer.onInlineStyleInvalidated(nodeIds: nodeIds)
    }
  }
  
  func onPseudoElementAdded(parentId: Int, pseudoElement: DOMNode) {
    for observer in observers {
      observer.onPseudoElementAdded(parentId: parentId, pseudoElement: pseudoElement)
    }
  }
  
  func onPseudoElementRemoved(parentId: Int, pseudoElementId: Int) {
    for observer in observers {
      observer.onPseudoElementRemoved(parentId: parentId, pseudoElementId: pseudoElementId)
    }
  }
  
  func onShadowRootPopped(hostId: Int, rootId: Int) {
    for observer in observers {
      observer.onShadowRootPopped(hostId: hostId, rootId: rootId)
    }
  }
  
  func onShadowRootPushed(hostId: Int, root: DOMNode) {
    for observer in observers {
      observer.onShadowRootPushed(hostId: hostId, root: root)
    }
  }
  
  // CSS
  func onFontsUpdated(font: FontFace) {
    for observer in observers {
      observer.onFontsUpdated(font: font)
    }
  }
  
  func onMediaQueryResultChanged() {
    for observer in observers {
      observer.onMediaQueryResultChanged()
    }
  }
  
  func onStyleSheetAdded(header: CSSStyleSheetHeader) {
    for observer in observers {
      observer.onStyleSheetAdded(header: header)
    }
  }
  
  func onStyleSheetChanged(styleSheetId: String) {
    for observer in observers {
      observer.onStyleSheetChanged(styleSheetId: styleSheetId)
    }
  }
   
  func onStyleSheetRemoved(styleSheetId: String) {
    for observer in observers {
      observer.onStyleSheetRemoved(styleSheetId: styleSheetId)
    }
  }
  
  // ApplicationCache
  func onApplicationCacheStatusUpdated(frameId: String, manifestUrl: String, status: Int) {
    for observer in observers {
      observer.onApplicationCacheStatusUpdated(frameId: frameId, manifestUrl: manifestUrl, status: status)
    }
  }
  
  func onNetworkStateUpdated(isNowOnline: Bool) {
    for observer in observers {
      observer.onNetworkStateUpdated(isNowOnline: isNowOnline)
    }
  }
  
  // Animation
  func onAnimationCanceled(id: String) {
    for observer in observers {
      observer.onAnimationCanceled(id: id)
    }
  }
  
  func onAnimationCreated(id: String) {
    for observer in observers {
      observer.onAnimationCreated(id: id)
    }
  }
  
  func onAnimationStarted(animation: Animation) {
    for observer in observers {
      observer.onAnimationStarted(animation: animation)
    }
  }

}

// public struct Caller<Fun> {
//   let callback: Fun
//   init(_ callback: Fun) {
//     self.callback = callback
//   }
//   func run(args: [Any] = []) {
//     callback(args)
//   }
// }

// @dynamicCallable
// public struct AnyCallback {
//   let fn: Caller<Fun>
//   init<Fun>(_ fn: Fun) {
//     self.fn = Caller<Fun>(fn)
//   }

//   func dynamicallyCall(withArguments args: [Any] = []) {
//     fn.run(args)
//   }
// }


public class CallbackHolder {
  weak var parent: ApplicationInstance?
  var getInfo: GetInfoCallback?
  var getVersion: GetVersionCallback?
  var getHostCommandLine: GetHostCommandLineCallback?
  var getHistograms: GetHistogramsCallback?
  var getHistogram: GetHistogramCallback?
  var getWindowBounds: GetWindowBoundsCallback?
  var getWindowForTarget: GetWindowForTargetCallback?
  var addScriptToEvaluateOnNewDocument: AddScriptToEvaluateOnNewDocumentCallback?
  var navigate: NavigateCallback?
  var getNavigationHistory: GetNavigationHistoryCallback?
  var getResourceTree: GetResourceTreeCallback?
  var getFrameTree: GetFrameTreeCallback?
  var getResourceContent: GetResourceContentCallback?
  var searchInResource: SearchInResourceCallback?
  var getAppManifest: GetAppManifestCallback?
  var getLayoutMetrics: GetLayoutMetricsCallback?
  var setCookie: SetCookieCallback?
  var profileSnapshot: ProfileSnapshotCallback?
  var emulateTouchFromMouseEvent: EmulateTouchFromMouseEventCallback?
  var requestData: RequestDataCallback?
  var requestDatabase: RequestDatabaseCallback?
  var read: ReadCallback?
  var beginFrame: BeginFrameCallback?
  var getDOMStorageItems: GetDOMStorageItemsCallback?
  var executeSQL: ExecuteSQLCallback?
  var setVirtualTimePolicy: SetVirtualTimePolicyCallback?
  var getSnapshot: GetSnapshotCallback?
  var copyTo: CopyToCallback?
  var describeNode: DescribeNodeCallback?
  var getDocument: GetDocumentCallback?
  var getBoxModel: GetBoxModelCallback?
  var getFlattenedDocument: GetFlattenedDocumentCallback?
  var getSearchResults: GetSearchResultsCallback?
  var performSearch: PerformSearchCallback?
  var resolveNode: ResolveNodeCallback?
  var addRule: AddRuleCallback?
  var getBackgroundColors: GetBackgroundColorsCallback?
  var getComputedStyleForNode: GetComputedStyleForNodeCallback?
  var getInlineStylesForNode: GetInlineStylesForNodeCallback?
  var getMatchedStylesForNode: GetMatchedStylesForNodeCallback?
  var getMediaQueries: GetMediaQueriesCallback?
  var getPlatformFontsForNode: GetPlatformFontsForNodeCallback?
  var setKeyframeKey: SetKeyframeKeyCallback?
  var setMediaText: SetMediaTextCallback?
  var setRuleSelector: SetRuleSelectorCallback?
  var setStyleSheetText: SetStyleSheetTextCallback?
  var setStyleTexts: SetStyleTextsCallback?
  var stopRuleUsageTracking: StopRuleUsageTrackingCallback?
  var takeCoverageDelta: TakeCoverageDeltaCallback?
  var requestCacheNames: RequestCacheNamesCallback?
  var requestCachedResponse: RequestCachedResponseCallback?
  var requestEntries: RequestEntriesCallback?
  var getApplicationCacheForFrame: GetApplicationCacheForFrameCallback?
  var getFramesWithManifests: GetFramesWithManifestsCallback?
  var resolveAnimation: ResolveAnimationCallback?
  var getPartialAXTree: GetPartialAXTreeCallback?
  var getCookies: GetCookiesCallback?
  var getAllCookies: GetAllCookiesCallback?

  var captureScreenshot: CaptureScreenshotCallback?
  var printToPDF: PrintToPDFCallback?
  var getRequestPostData: GetRequestPostDataCallback?
  var takeResponseBodyForInterceptionAsStream: TakeResponseBodyForInterceptionAsStreamCallback?
  var loadSnapshot: LoadSnapshotCallback?
  var makeSnapshot: MakeSnapshotCallback?
  var replaySnapshot: ReplaySnapshotCallback?
  var snapshotCommandLog: SnapshotCommandLogCallback?
  var resolveBlob: ResolveBlobCallback?
  var getOuterHTML: GetOuterHTMLCallback?
  var createStyleSheet: CreateStyleSheetCallback?
  var getStyleSheetText: GetStyleSheetTextCallback?
  var getManifestForFrame: GetManifestForFrameCallback?

  var createIsolatedWorld: CreateIsolatedWorldCallback?
  var getNodeForLocation: GetNodeForLocationCallback?
  var getRelayoutBoundary: GetRelayoutBoundaryCallback?
  var moveTo: MoveToCallback?
  var pushNodeByPathToFrontend: PushNodeByPathToFrontendCallback?
  var querySelector: QuerySelectorCallback?
  var requestNode: RequestNodeCallback?
  var setNodeName: SetNodeNameCallback?
  var getFrameOwner: GetFrameOwnerCallback?
  var getCurrentTime: GetCurrentTimeCallback?
  var getPlaybackRate: GetPlaybackRateCallback?

  var canClearBrowserCache: CanClearBrowserCacheCallback?
  var canClearBrowserCookies: CanClearBrowserCookiesCallback?
  var canEmulateNetworkConditions: CanEmulateNetworkConditionsCallback?
  var dispatchKeyEvent: DispatchKeyEventCallback?
  var dispatchMouseEvent: DispatchMouseEventCallback?
  var dispatchTouchEvent: DispatchTouchEventCallback?
  var synthesizePinchGesture: SynthesizePinchGestureCallback?
  var synthesizeScrollGesture: SynthesizeScrollGestureCallback?
  var synthesizeTapGesture: SynthesizeTapGestureCallback?
  var clearObjectStore: ClearObjectStoreCallback?
  var deleteDatabase: DeleteDatabaseCallback?
  var deleteObjectStoreEntries: DeleteObjectStoreEntriesCallback?
  var canEmulate: CanEmulateCallback?
  var openCache: OpenCacheCallback?
  var deleteCache: DeleteCacheCallback?
  var hasCache: HasCacheCallback?
  var deleteEntry: DeleteEntryCallback?
  var putEntry: PutEntryCallback?

  //
  var getCertificate: GetCertificateCallback?
  var compositingReasons: CompositingReasonsCallback?
  var requestDatabaseNames: RequestDatabaseNamesCallback?
  var getDatabaseTableNames: GetDatabaseTableNamesCallback?
  var collectClassNamesFromSubtree: CollectClassNamesFromSubtreeCallback?
  var getAttributes: GetAttributesCallback?
  var collectClassNames: CollectClassNamesCallback?

  var getResponseBody: GetResponseBodyCallback?
  var getResponseBodyForInterception: GetResponseBodyForInterceptionCallback?

  var searchInResponseBody: SearchInResponseBodyCallback?
  var pushNodesByBackendIdsToFrontend: PushNodesByBackendIdsToFrontendCallback?
  var querySelectorAll: QuerySelectorAllCallback?

  init(_ parent: ApplicationInstance, getInfo: @escaping GetInfoCallback) {
    self.parent = parent
    self.getInfo = getInfo
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getCookies: @escaping GetCookiesCallback) {
    self.parent = parent
    self.getCookies = getCookies
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getAllCookies: @escaping GetAllCookiesCallback) {
    self.parent = parent
    self.getAllCookies = getAllCookies
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getVersion: @escaping GetVersionCallback) {
    self.parent = parent
    self.getVersion = getVersion
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getHostCommandLine: @escaping GetHostCommandLineCallback) {
    self.parent = parent
    self.getHostCommandLine = getHostCommandLine
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getHistograms: @escaping GetHistogramsCallback) {
    self.parent = parent
    self.getHistograms = getHistograms
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getHistogram: @escaping GetHistogramCallback) {
    self.parent = parent
    self.getHistogram = getHistogram
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getWindowBounds: @escaping GetWindowBoundsCallback) {
    self.parent = parent
    self.getWindowBounds = getWindowBounds
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getWindowForTarget: @escaping GetWindowForTargetCallback) {
    self.parent = parent
    self.getWindowForTarget = getWindowForTarget
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, addScriptToEvaluateOnNewDocument: @escaping AddScriptToEvaluateOnNewDocumentCallback) {
    self.parent = parent
    self.addScriptToEvaluateOnNewDocument = addScriptToEvaluateOnNewDocument
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, navigate: @escaping NavigateCallback) {
    self.parent = parent
    self.navigate = navigate
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getNavigationHistory: @escaping GetNavigationHistoryCallback) {
    self.parent = parent
    self.getNavigationHistory = getNavigationHistory
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getResourceTree: @escaping GetResourceTreeCallback) {
    self.parent = parent
    self.getResourceTree = getResourceTree
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getFrameTree: @escaping GetFrameTreeCallback) {
    self.parent = parent
    self.getFrameTree = getFrameTree
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getResourceContent: @escaping GetResourceContentCallback) {
    self.parent = parent
    self.getResourceContent = getResourceContent
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, searchInResource: @escaping SearchInResourceCallback) {
    self.parent = parent
    self.searchInResource = searchInResource
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getAppManifest: @escaping GetAppManifestCallback) {
    self.parent = parent
    self.getAppManifest = getAppManifest
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getLayoutMetrics: @escaping GetLayoutMetricsCallback) {
    self.parent = parent
    self.getLayoutMetrics = getLayoutMetrics
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, profileSnapshot: @escaping ProfileSnapshotCallback) {
    self.parent = parent
    self.profileSnapshot = profileSnapshot
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestData: @escaping RequestDataCallback) {
    self.parent = parent
    self.requestData = requestData
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestDatabase: @escaping RequestDatabaseCallback) {
    self.parent = parent
    self.requestDatabase = requestDatabase
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, read: @escaping ReadCallback) {
    self.parent = parent
    self.read = read
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, beginFrame: @escaping BeginFrameCallback) {
    self.parent = parent
    self.beginFrame = beginFrame
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getDOMStorageItems: @escaping GetDOMStorageItemsCallback) {
    self.parent = parent
    self.getDOMStorageItems = getDOMStorageItems
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, executeSQL: @escaping ExecuteSQLCallback) {
    self.parent = parent
    self.executeSQL = executeSQL
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setVirtualTimePolicy: @escaping SetVirtualTimePolicyCallback) {
    self.parent = parent
    self.setVirtualTimePolicy = setVirtualTimePolicy
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getSnapshot: @escaping GetSnapshotCallback) {
    self.parent = parent
    self.getSnapshot = getSnapshot
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, copyTo: @escaping CopyToCallback) {
    self.parent = parent
    self.copyTo = copyTo
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, describeNode: @escaping DescribeNodeCallback) {
    self.parent = parent
    self.describeNode = describeNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getBoxModel: @escaping GetBoxModelCallback) {
    self.parent = parent
    self.getBoxModel = getBoxModel
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getFlattenedDocument: @escaping GetFlattenedDocumentCallback) {
    self.parent = parent
    self.getFlattenedDocument = getFlattenedDocument
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getSearchResults: @escaping GetSearchResultsCallback) {
    self.parent = parent
    self.getSearchResults = getSearchResults
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, performSearch: @escaping PerformSearchCallback) {
    self.parent = parent
    self.performSearch = performSearch
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, resolveNode: @escaping ResolveNodeCallback) {
    self.parent = parent
    self.resolveNode = resolveNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, addRule: @escaping AddRuleCallback) {
    self.parent = parent
    self.addRule = addRule
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getBackgroundColors: @escaping GetBackgroundColorsCallback) {
    self.parent = parent
    self.getBackgroundColors = getBackgroundColors
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getComputedStyleForNode: @escaping GetComputedStyleForNodeCallback) {
    self.parent = parent
    self.getComputedStyleForNode = getComputedStyleForNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getInlineStylesForNode: @escaping GetInlineStylesForNodeCallback) {
    self.parent = parent
    self.getInlineStylesForNode = getInlineStylesForNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getMatchedStylesForNode: @escaping GetMatchedStylesForNodeCallback) {
    self.parent = parent
    self.getMatchedStylesForNode = getMatchedStylesForNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getMediaQueries: @escaping GetMediaQueriesCallback) {
    self.parent = parent
    self.getMediaQueries = getMediaQueries
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getPlatformFontsForNode: @escaping GetPlatformFontsForNodeCallback) {
    self.parent = parent
    self.getPlatformFontsForNode = getPlatformFontsForNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setKeyframeKey: @escaping SetKeyframeKeyCallback) {
    self.parent = parent
    self.setKeyframeKey = setKeyframeKey
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setMediaText: @escaping SetMediaTextCallback) {
    self.parent = parent
    self.setMediaText = setMediaText
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setRuleSelector: @escaping SetRuleSelectorCallback) {
    self.parent = parent
    self.setRuleSelector = setRuleSelector
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setStyleSheetText: @escaping SetStyleSheetTextCallback) {
    self.parent = parent
    self.setStyleSheetText = setStyleSheetText
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setStyleTexts: @escaping SetStyleTextsCallback) {
    self.parent = parent
    self.setStyleTexts = setStyleTexts
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, stopRuleUsageTracking: @escaping StopRuleUsageTrackingCallback) {
    self.parent = parent
    self.stopRuleUsageTracking = stopRuleUsageTracking
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestCacheNames: @escaping RequestCacheNamesCallback) {
    self.parent = parent
    self.requestCacheNames = requestCacheNames
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestCachedResponse: @escaping RequestCachedResponseCallback) {
    self.parent = parent
    self.requestCachedResponse = requestCachedResponse
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestEntries: @escaping RequestEntriesCallback) {
    self.parent = parent
    self.requestEntries = requestEntries
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getApplicationCacheForFrame: @escaping GetApplicationCacheForFrameCallback) {
    self.parent = parent
    self.getApplicationCacheForFrame = getApplicationCacheForFrame
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getFramesWithManifests: @escaping GetFramesWithManifestsCallback) {
    self.parent = parent
    self.getFramesWithManifests = getFramesWithManifests
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, resolveAnimation: @escaping ResolveAnimationCallback) {
    self.parent = parent
    self.resolveAnimation = resolveAnimation
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getPartialAXTree: @escaping GetPartialAXTreeCallback) {
    self.parent = parent
    self.getPartialAXTree = getPartialAXTree
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, captureScreenshot: @escaping CaptureScreenshotCallback) {
    self.parent = parent
    self.captureScreenshot = captureScreenshot
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, printToPDF: @escaping PrintToPDFCallback) {
    self.parent = parent
    self.printToPDF = printToPDF
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getRequestPostData: @escaping GetRequestPostDataCallback) {
    self.parent = parent
    self.getRequestPostData = getRequestPostData
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, takeResponseBodyForInterceptionAsStream: @escaping TakeResponseBodyForInterceptionAsStreamCallback) {
    self.parent = parent
    self.takeResponseBodyForInterceptionAsStream = takeResponseBodyForInterceptionAsStream
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, loadSnapshot: @escaping LoadSnapshotCallback) {
    self.parent = parent
    self.loadSnapshot = loadSnapshot
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, makeSnapshot: @escaping MakeSnapshotCallback) {
    self.parent = parent
    self.makeSnapshot = makeSnapshot
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, replaySnapshot: @escaping ReplaySnapshotCallback) {
    self.parent = parent
    self.replaySnapshot = replaySnapshot
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, snapshotCommandLog: @escaping SnapshotCommandLogCallback) {
    self.parent = parent
    self.snapshotCommandLog = snapshotCommandLog
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, resolveBlob: @escaping ResolveBlobCallback) {
    self.parent = parent
    self.resolveBlob = resolveBlob
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getOuterHTML: @escaping GetOuterHTMLCallback) {
    self.parent = parent
    self.getOuterHTML = getOuterHTML
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, createStyleSheet: @escaping CreateStyleSheetCallback) {
    self.parent = parent
    self.createStyleSheet = createStyleSheet
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getStyleSheetText: @escaping GetStyleSheetTextCallback) {
    self.parent = parent
    self.getStyleSheetText = getStyleSheetText
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getManifestForFrame: @escaping GetManifestForFrameCallback) {
    self.parent = parent
    self.getManifestForFrame = getManifestForFrame
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getNodeForLocation: @escaping GetNodeForLocationCallback) {
    self.parent = parent
    self.getNodeForLocation = getNodeForLocation
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getRelayoutBoundary: @escaping GetRelayoutBoundaryCallback) {
    self.parent = parent
    self.getRelayoutBoundary = getRelayoutBoundary
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, moveTo: @escaping MoveToCallback) {
    self.parent = parent
    self.moveTo = moveTo
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, pushNodeByPathToFrontend: @escaping PushNodeByPathToFrontendCallback) {
    self.parent = parent
    self.pushNodeByPathToFrontend = pushNodeByPathToFrontend
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, querySelector: @escaping QuerySelectorCallback) {
    self.parent = parent
    self.querySelector = querySelector
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, requestNode: @escaping RequestNodeCallback) {
    self.parent = parent
    self.requestNode = requestNode
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setNodeName: @escaping SetNodeNameCallback) {
    self.parent = parent
    self.setNodeName = setNodeName
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getFrameOwner: @escaping GetFrameOwnerCallback) {
    self.parent = parent
    self.getFrameOwner = getFrameOwner
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getCurrentTime: @escaping GetCurrentTimeCallback) {
    self.parent = parent
    self.getCurrentTime = getCurrentTime
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getPlaybackRate: @escaping GetPlaybackRateCallback) {
    self.parent = parent
    self.getPlaybackRate = getPlaybackRate
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, createIsolatedWorld: @escaping CreateIsolatedWorldCallback) {
    self.parent = parent
    self.createIsolatedWorld = createIsolatedWorld
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, canClearBrowserCache: @escaping CanClearBrowserCacheCallback) {
    self.parent = parent
    self.canClearBrowserCache = canClearBrowserCache
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, canClearBrowserCookies: @escaping CanClearBrowserCookiesCallback) {
    self.parent = parent
    self.canClearBrowserCookies = canClearBrowserCookies
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, canEmulateNetworkConditions: @escaping CanEmulateNetworkConditionsCallback) {
    self.parent = parent
    self.canEmulateNetworkConditions = canEmulateNetworkConditions
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, setCookie: @escaping SetCookieCallback) {
    self.parent = parent
    self.setCookie = setCookie
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, dispatchKeyEvent: @escaping DispatchKeyEventCallback) {
    self.parent = parent
    self.dispatchKeyEvent = dispatchKeyEvent
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, dispatchMouseEvent: @escaping DispatchMouseEventCallback) {
    self.parent = parent
    self.dispatchMouseEvent = dispatchMouseEvent
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, dispatchTouchEvent: @escaping DispatchTouchEventCallback) {
    self.parent = parent
    self.dispatchTouchEvent = dispatchTouchEvent
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, emulateTouchFromMouseEvent: @escaping EmulateTouchFromMouseEventCallback) {
    self.parent = parent
    self.emulateTouchFromMouseEvent = emulateTouchFromMouseEvent
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, synthesizePinchGesture: @escaping SynthesizePinchGestureCallback) {
    self.parent = parent
    self.synthesizePinchGesture = synthesizePinchGesture
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, synthesizeScrollGesture: @escaping SynthesizeScrollGestureCallback) {
    self.parent = parent
    self.synthesizeScrollGesture = synthesizeScrollGesture
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, synthesizeTapGesture: @escaping SynthesizeTapGestureCallback) {
    self.parent = parent
    self.synthesizeTapGesture = synthesizeTapGesture
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, clearObjectStore: @escaping ClearObjectStoreCallback) {
    self.parent = parent
    self.clearObjectStore = clearObjectStore
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, deleteDatabase: @escaping DeleteDatabaseCallback) {
    self.parent = parent
    self.deleteDatabase = deleteDatabase
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, deleteObjectStoreEntries: @escaping DeleteObjectStoreEntriesCallback) {
    self.parent = parent
    self.deleteObjectStoreEntries = deleteObjectStoreEntries
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, canEmulate: @escaping CanEmulateCallback) {
    self.parent = parent
    self.canEmulate = canEmulate
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, deleteCache: @escaping DeleteCacheCallback) {
    self.parent = parent
    self.deleteCache = deleteCache
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, hasCache: @escaping HasCacheCallback) {
    self.parent = parent
    self.hasCache = hasCache
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, openCache: @escaping OpenCacheCallback) {
    self.parent = parent
    self.openCache = openCache
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, deleteEntry: @escaping DeleteEntryCallback) {
    self.parent = parent
    self.deleteEntry = deleteEntry
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, putEntry: @escaping PutEntryCallback) {
    self.parent = parent
    self.putEntry = putEntry
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getCertificate: @escaping GetCertificateCallback) {
    self.parent = parent
    self.getCertificate = getCertificate
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, compositingReasons: @escaping CompositingReasonsCallback) {
    self.parent = parent
    self.compositingReasons = compositingReasons
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, requestDatabaseNames: @escaping RequestDatabaseNamesCallback) {
    self.parent = parent
    self.requestDatabaseNames = requestDatabaseNames
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getDatabaseTableNames: @escaping GetDatabaseTableNamesCallback) {
    self.parent = parent
    self.getDatabaseTableNames = getDatabaseTableNames
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, collectClassNamesFromSubtree: @escaping CollectClassNamesFromSubtreeCallback) {
    self.parent = parent
    self.collectClassNamesFromSubtree = collectClassNamesFromSubtree
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getAttributes: @escaping GetAttributesCallback) {
    self.parent = parent
    self.getAttributes = getAttributes
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, collectClassNames: @escaping CollectClassNamesCallback) {
    self.parent = parent
    self.collectClassNames = collectClassNames
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getResponseBody: @escaping GetResponseBodyCallback) {
    self.parent = parent
    self.getResponseBody = getResponseBody
    self.parent!.addCallbackHolder(self)
  }
  
  init(_ parent: ApplicationInstance, getResponseBodyForInterception: @escaping GetResponseBodyForInterceptionCallback) {
    self.parent = parent
    self.getResponseBodyForInterception = getResponseBodyForInterception
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, searchInResponseBody: @escaping SearchInResponseBodyCallback) {
    self.parent = parent
    self.searchInResponseBody = searchInResponseBody
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, takeCoverageDelta: @escaping TakeCoverageDeltaCallback) {
    self.parent = parent
    self.takeCoverageDelta = takeCoverageDelta
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, getDocument: @escaping GetDocumentCallback) {
    self.parent = parent
    self.getDocument = getDocument
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, pushNodesByBackendIdsToFrontend: @escaping PushNodesByBackendIdsToFrontendCallback) {
    self.parent = parent
    self.pushNodesByBackendIdsToFrontend = pushNodesByBackendIdsToFrontend
    self.parent!.addCallbackHolder(self)
  }

  init(_ parent: ApplicationInstance, querySelectorAll: @escaping QuerySelectorAllCallback) {
    self.parent = parent
    self.querySelectorAll = querySelectorAll
    self.parent!.addCallbackHolder(self)
  }
  
  func dispose() {
    parent!.removeCallbackHolder(self)
  }

}

extension ApplicationInstanceObserver {
  public func onApplicationStateChanged(oldState: ApplicationState, newState: ApplicationState) {}
  public func onBoundsChanged(bounds: IntRect) {}
  public func onVisible() {}
  public func onHidden() {}
  public func onFrameAttached(frameId: String, parentFrameId: String) {}
  public func onDomContentEventFired(timestamp: Int64) {}
  public func onFrameClearedScheduledNavigation(frameId: String) {}
  public func onFrameDetached(frameId: String) {}
  public func onFrameNavigated(frame: Frame) {}
  public func onFrameResized() {}
  public func onFrameScheduledNavigation(frameId: String, delay: Int, reason: NavigationReason, url: String) {}
  public func onFrameStartedLoading(frameId: String) {}
  public func onFrameStoppedLoading(frameId: String) {}
  public func onInterstitialHidden() {}
  public func onInterstitialShown() {}
  public func onJavascriptDialogClosed(result: Bool, userInput: String) {}
  public func onJavascriptDialogOpening(url: String, message: String, type: DialogType, hasBrowserHandler: Bool, defaultPrompt: String?) {}
  public func onLifecycleEvent(frameId: String, loaderId: Int, name: String, timestamp: TimeTicks) {}
  public func onLoadEventFired(timestamp: TimeTicks) {}
  public func onNavigatedWithinDocument(frameId: String, url: String) {}
  public func onScreencastFrame(base64Data: String, metadata: ScreencastFrameMetadata, sessionId: Int) {}
  public func onScreencastVisibilityChanged(visible: Bool) {}
  public func onWindowOpen(url: String, windowName: String, windowFeatures: [String], userGesture: Bool) {}
  public func onPageLayoutInvalidated(resized: Bool) {}
  // Overlay
  public func inspectNodeRequested(backendNode: Int) {}
  public func nodeHighlightRequested(nodeId: Int) {}
  public func screenshotRequested(viewport: Viewport) {}
  // worker
  public func workerErrorReported(errorMessage: ServiceWorkerErrorMessage) {}
  public func workerRegistrationUpdated(registrations: [ServiceWorkerRegistration]) {}
  public func workerVersionUpdated(versions: [ServiceWorkerVersion]) {}
  public func onAttachedToTarget(sessionId: String, targetInfo: TargetInfo) {}
  public func onDetachedFromTarget(sessionId: String, targetId: String?) {}
  public func onReceivedMessageFromTarget(sessionId: String, message: String, targetId: String?) {}
  // Storage
  public func onCacheStorageContentUpdated(origin: String, cacheName: String) {}
  public func onCacheStorageListUpdated(origin: String) {}
  public func onIndexedDBContentUpdated(origin: String, databaseName: String, objectStoreName: String) {}
  public func onIndexedDBListUpdated(origin: String) {}
  // Tethering
  public func onAccepted(port: Int, connectionId: String) {}
  // Network
  public func onDataReceived(requestId: String, timestamp: TimeTicks, dataLength: Int64, encodedDataLength: Int64) {}
  public func onEventSourceMessageReceived(requestId: String, timestamp: Int64, eventName: String, eventId: String, data: String) {}
  public func onLoadingFailed(requestId: String, timestamp: Int64, type: ResourceType, errorText: String, canceled: Bool, blockedReason: BlockedReason) {}
  public func onLoadingFinished(requestId: String, timestamp: Int64, encodedDataLength: Int64, blockedCrossSiteDocument: Bool) {}
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
    responseHeaders: [String: String]) {}
  public func onRequestServedFromCache(requestId: String) {}
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
    hasUserGesture: Bool) {}
  public func onResourceChangedPriority(requestId: String, newPriority: ResourcePriority, timestamp: Int64) {}
  public func onResponseReceived(requestId: String, loaderId: String, timestamp: Int64, type: ResourceType, response: Response, frameId: String?) {}
  public func onWebSocketClosed(requestId: String, timestamp: Int64) {}
  public func onWebSocketCreated(requestId: String, url: String, initiator: Initiator) {}
  public func onWebSocketFrameError(requestId: String, timestamp: Int64, errorMessage: String) {}
  public func onWebSocketFrameReceived(requestId: String, timestamp: Int64, response: WebSocketFrame) {}
  public func onWebSocketFrameSent(requestId: String, timestamp: Int64, response: WebSocketFrame) {}
  public func onWebSocketHandshakeResponseReceived(requestId: String, timestamp: Int64, response: WebSocketResponse) {}
  public func onWebSocketWillSendHandshakeRequest(requestId: String, timestamp: Int64, walltime: Int64, request: WebSocketRequest) {}
  public func flush() {}
  // LayerTree
  public func onLayerPainted(layerId: String, clipX: Int, clipY: Int, clipW: Int, clipH: Int) {}
  public func onLayerTreeDidChange(layers: [Layer]) {}
  // Headless
  public func onNeedsBeginFramesChanged(needsBeginFrames: Bool) {}
  // DOMStorage
  public func onDomStorageItemAdded(storageId: StorageId, key: String, newValue: String) {}
  public func onDomStorageItemRemoved(storageId: StorageId, key: String) {}
  public func onDomStorageItemUpdated(storageId: StorageId, key: String, oldValue: String, newValue: String) {}
  public func onDomStorageItemsCleared(storageId: StorageId) {}
  // Database
  public func onAddDatabase(database: Database) {}
  // Emulation
  public func onVirtualTimeAdvanced(virtualTimeElapsed: Int) {}
  public func onVirtualTimeBudgetExpired() {}
  public func onVirtualTimePaused(virtualTimeElapsed: Int) {}
  // DOM
  public func setChildNodes(parentId: Int, nodes: [DOMNode]) {}
  public func onAttributeModified(nodeId: Int, name: String, value: String) {}
  public func onAttributeRemoved(nodeId: Int, name: String) {}
  public func onCharacterDataModified(nodeId: Int, characterData: String) {}
  public func onChildNodeCountUpdated(nodeId: Int, childNodeCount: Int) {}
  public func onChildNodeInserted(parentNodeId: Int, previousNodeId: Int, node: DOMNode) {}
  public func onChildNodeRemoved(parentNodeId: Int, nodeId: Int) {}
  public func onDistributedNodesUpdated(insertionPointId: Int, distributedNodes: [BackendNode]) {}
  public func onDocumentUpdated() {}
  public func onInlineStyleInvalidated(nodeIds: [Int]) {}
  public func onPseudoElementAdded(parentId: Int, pseudoElement: DOMNode) {}  
  public func onPseudoElementRemoved(parentId: Int, pseudoElementId: Int) {}
  public func onShadowRootPopped(hostId: Int, rootId: Int) {}
  public func onShadowRootPushed(hostId: Int, root: DOMNode) {}
  // CSS
  public func onFontsUpdated(font: FontFace) {}
  public func onMediaQueryResultChanged() {}
  public func onStyleSheetAdded(header: CSSStyleSheetHeader) {}
  public func onStyleSheetChanged(styleSheetId: String) {}
  public func onStyleSheetRemoved(styleSheetId: String) {}
  // ApplicationCache
  public func onApplicationCacheStatusUpdated(frameId: String, manifestUrl: String, status: Int) {}
  public func onNetworkStateUpdated(isNowOnline: Bool) {}
  // Animation
  public func onAnimationCanceled(id: String) {}
  public func onAnimationCreated(id: String) {}
  public func onAnimationStarted(animation: Animation) {}
}