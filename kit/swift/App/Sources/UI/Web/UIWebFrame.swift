// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Javascript
import Web

internal var bootstrapData: String? 

public struct NavigationInfo {
  public var timeCommitRequested: TimeTicks

  public init(time: TimeTicks) {
    self.timeCommitRequested = time
  }
}

public class UIWebFrame : WebLocalFrameClient,
                          UIWebFrameProxyDelegate  {
  
  // WebLocalFrameClient

  public var bluetooth: WebBluetooth? { return nil }
  public var usbClient: WebUSBClient? { return nil }
  public var permissionClient: WebPermissionClient? { return nil }
  public var webVRClient: WebVRClient? { return nil }
  public var userMediaClient: WebUserMediaClient? { return nil } 
  public var encryptedMediaClient: WebEncryptedMediaClient? { return nil }
  public var webMIDIClient: WebMIDIClient? { return nil }
  public var appBannerClient: WebAppBannerClient? { return nil }
  public var wakeLockClient: WebWakeLockClient? { return nil }
  public var geolocationClient: WebGeolocationClient? { return nil }
  public var pushClient: WebPushClient? { return nil } 
  public var shouldSearchSingleFrame: Bool { return false }
  public var handleCurrentKeyboardEvent: Bool { 
    //print("UIWebFrame.handleCurrentKeyboardEvent")
    var didExecuteCommand = false
    for (name, value) in window!.editCommands {
      //print("executing command '\(name)'")
      // In gtk and cocoa, it's possible to bind multiple edit commands to one
      // key (but it's the exception). Once one edit command is not executed, it
      // seems safest to not execute the rest.
      if !frame!.executeCommand(command: name,
                                value: value) {
        break
      }
      didExecuteCommand = true
    }

    return didExecuteCommand
  }
  public var shouldBlockWebGL: Bool { return false }
  public private(set) var visibilityState: WebPageVisibilityState

  //public var webUIWindow: WebUIWindow? {
  //  return webView
  //}

  public var isHidden: Bool {
    return window.isHidden
  }

  public private(set) var routingId: Int = 0
  public var frame: WebLocalFrame?
  //public var webView: WebView?
  public private(set) var isMainFrame: Bool = false
  private var frameProxy: UIWebFrameProxy?
  public private(set) var observers: ContiguousArray<UIWebFrameObserver>
  // the window that own us
  public private(set) weak var window: UIWebWindow!
  public private(set) var mediaPlayers: [WebMediaPlayer] 
  private var hostSideNavigationPending: Bool = false
  private var hostSideNavigationPendingUrl: String = String()
  private var hasAccessedInitialDocument: Bool = false
  private var committedFirstLoad: Bool = false
  private var pendingNavigation: NavigationInfo?
  private var frameSize: IntSize?
  private var selectionText: String
  private var nextProviderId: Int = 0
  private var providerId: Int = -99
  private var preferredSize: IntSize = IntSize()
  private var hasScrolledFocusedEditableNodeIntoRect: Bool = false
  private var rectForScrolledFocusedEditableNode: IntRect = IntRect()
  private var requestForCommitNavigation: WebURLRequest?
  private var mediaPlayerDelegate: UIWebMediaPlayerDelegate!

  // this should be temporary and gone.. 
  // when using a owned WebData, we may use the ExtraData property
  // to save heap allocated stuf that need to be cleaned up at some point
  private var htmlData: WebData?

  public var urlLoaderDispatcher: UrlLoaderDispatcher
  //public var urlLoaderClient: UrlLoaderClient?

  public init(window: UIWebWindow, params: VisualProperties, routingId: Int, isMainFrame: Bool) {
    observers = ContiguousArray<UIWebFrameObserver>()
    self.window = window
    self.routingId = routingId
    self.isMainFrame = isMainFrame
    visibilityState = WebPageVisibilityState.Visible
    selectionText = String()
    mediaPlayers = []
    urlLoaderDispatcher = UrlLoaderDispatcher()
    // FIX: for frames who are not main
    self.frame = WebFrame.createLocalMainFrame(view: window.webView!, client: self, interfaceRegistry: nil)
    mediaPlayerDelegate = UIWebMediaPlayerDelegate(parentFrame: self)
    
    window.registerFrame(self)
  }

  public func addObserver(_ observer: UIWebFrameObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: UIWebFrameObserver) {
    for (i, cur) in observers.enumerated() {
      if observer === cur {
        observers.remove(at: i)
      }
    }
  }

  public func frameRectsChanged(rect: IntRect) {
    let rectSize = IntSize(width: rect.width, height: rect.height)
    //if (frameSize == nil) || (frameSize! != rectSize) {
    self.frameSize = rectSize
    window.sendFrameSizeChanged(size: rectSize)
    //}
  }

  // WebFrameClient
  public func bindToFrame(frame: WebLocalFrame) {
    if self.frame == nil {
      //frame.client = self
      self.frame = frame
    }
    window.onFrameAttached(self)
  }

  //public func resize(viewport: IntSize) {
  //  if let view = webView {
  //    view.resize(size: viewport)
  //  }
  //}

  public func didCreateDocumentLoader(loader: WebDocumentLoader) {
    //let contentInitiated = pendingNavigationParams == nil

    //DocumentState* document_state =
    //DocumentState::FromDocumentLoader(document_loader);
    //if (!document_state) {
    //  document_state = new DocumentState;
    //  document_loader->SetExtraData(document_state);
    //  if (!content_initiated)
    //    PopulateDocumentStateFromPending(document_state);
    //}

    //blink::WebView* webview = render_view_->webview();
    // if (content_initiated && webview && webview->MainFrame() &&
    //     webview->MainFrame()->IsWebLocalFrame() &&
    //     webview->MainFrame()->ToWebLocalFrame()->GetDocumentLoader()) {
    //   DocumentState* old_document_state = DocumentState::FromDocumentLoader(
    //       webview->MainFrame()->ToWebLocalFrame()->GetDocumentLoader());
    //   if (old_document_state) {
    //     InternalDocumentStateData* internal_data =
    //         InternalDocumentStateData::FromDocumentState(document_state);
    //     InternalDocumentStateData* old_internal_data =
    //         InternalDocumentStateData::FromDocumentState(old_document_state);
    //     internal_data->set_is_overriding_user_agent(
    //         old_internal_data->is_overriding_user_agent());
    //   }
    // }

    

    // The rest of RenderView assumes that a WebDocumentLoader will always have a
    // non-null NavigationState.
    
    // TODO: implement this

    //updateNavigationState(document_state, false /* was_within_same_document */,
    //                      content_initiated);

    //NavigationStateImpl* navigation_state = static_cast<NavigationStateImpl*>(
    //    document_state->navigation_state());

    // Set the navigation start time in blink.
    //document_loader->SetNavigationStartTime(
    //    navigation_state->common_params().navigation_start);
    loader.setNavigationStartTime(TimeTicks.now)

    // If an actual navigation took place, inform the document loader of what
    // happened in the browser.
    //if (!navigation_state->request_params()
    //         .navigation_timing.fetch_start.is_null()) {
      // Set timing of several events that happened during navigation.
      // They will be used in blink for the Navigation Timing API.
    //  base::TimeTicks redirect_start =
    //      navigation_state->request_params().navigation_timing.redirect_start;
    //  base::TimeTicks redirect_end =
    //      navigation_state->request_params().navigation_timing.redirect_end;
    //  base::TimeTicks fetch_start =
    //      navigation_state->request_params().navigation_timing.fetch_start;

    //  document_loader->UpdateNavigation(
    //      redirect_start, redirect_end, fetch_start,
    //      !navigation_state->request_params().redirects.empty());
    //}

    // Update the source location before processing the navigation commit.
    //if (navigation_state->common_params().source_location.has_value()) {
    //  blink::WebSourceLocation source_location;
    //  source_location.url = WebString::FromLatin1(
    //      navigation_state->common_params().source_location->url);
    //  source_location.line_number =
    //      navigation_state->common_params().source_location->line_number;
    //  source_location.column_number =
    //      navigation_state->common_params().source_location->column_number;
    //  document_loader->SetSourceLocation(source_location);
    //}

    //if (navigation_state->request_params().was_activated)
    //  document_loader->SetUserActivated();
    loader.setUserActivated()

    // Create the serviceworker's per-document network observing object if it
    // does not exist (When navigation happens within a page, the provider already
    // exists).
    var serviceWorkerProviderId = self.providerId
    if loader.serviceWorkerNetworkProvider == nil && serviceWorkerProviderId == -99 {
      //loader.serviceWorkerNetworkProvider.serviceWorkerProviderId = self.providerId
      //print("didCreateDocumentLoader: avoiding creating serviceWorkerNetworkProvider with a invalid providerId = \(self.providerId)")  
      //return
      serviceWorkerProviderId = self.nextProviderId
      self.nextProviderId += 1
      return
    }
    
    
    //if serviceWorkerProviderId == -1 {
    //  serviceWorkerProviderId = self.nextProviderId
    //  self.nextProviderId += 1
    //}
    let provider = WebServiceWorkerNetworkProvider(providerId: serviceWorkerProviderId, routeId: routingId)//nextProviderId)
    //if let l = UrlLoaderClient {
    //  urlLoaderDispatcher.addHandler(l)
    provider.addHandler(urlLoaderDispatcher)
    window.dispatcher.serviceWorkerNetworkProvider = provider
    //}
    //self.serviceWorkerNetworkProvider = WebServiceWorkerNetworkProvider(providerId: nextProviderId)
    loader.serviceWorkerNetworkProvider = provider//serviceWorkerNetworkProvider!
    
    //scoped_refptr<network::SharedURLLoaderFactory> fallback_factory =
    //    network::SharedURLLoaderFactory::Create(
    //        GetLoaderFactoryBundle()->CloneWithoutDefaultFactory());
    //document_loader->SetServiceWorkerNetworkProvider(
    //    ServiceWorkerNetworkProvider::CreateForNavigation(
    //        routing_id_, navigation_state->request_params(), frame_,
    //        content_initiated, std::move(controller_service_worker_info_),
    //        std::move(fallback_factory)));
    //self.nextProviderId += 1
  }
    
  public func createPlugin(params: WebPluginParams) -> WebPlugin? {
    //print("\n\nUIWebFrame.createPlugin\n\n")
    //plugin = WebPlugin()
    //pluginView.layer = try! Layer(layer: plugin!.layer)
    //let settings = LayerSettings(type: .TextureLayer)
    //settings.client = pluginView
    //pluginView.layer = try! Layer(type: .Textured)//Layer(settings: settings)
    //return plugin
    return nil
  }

  public func createMediaPlayer(
      url: String, 
      client: WebMediaPlayerClient, 
      encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
      module: WebContentDecryptionModule?, 
      sinkId: String) -> WebMediaPlayer? {
    let mediaPlayer = WebMediaPlayer(
      delegate: mediaPlayerDelegate,
      frame: self.frame!,
      url: url,
      client: client,
      encryptedClient: encryptedClient, 
      module: module, 
      sinkId: sinkId,
      view: self.window.webView!)
    mediaPlayers.append(mediaPlayer)
    // NOTE: we are 'gaming' here.. the media::MediaPlayerImpl adds
    // itself as an observer of the delegate, but it does it before
    // we have our handle here, and theres nothing we can do with only
    // the native one.
    // So we are adding it 'manually' here as MediaPlayerImpl wishes
    mediaPlayerDelegate.addObserverInternal(mediaPlayer)
    return mediaPlayer
  }

  public func createMediaPlayer(
        descriptor: MediaStreamDescriptor,
        client: WebMediaPlayerClient, 
        encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
        module: WebContentDecryptionModule?, 
        sinkId: String) -> WebMediaPlayer? {
    let mediaPlayer = WebMediaPlayer(
      delegate: mediaPlayerDelegate,
      frame: self.frame!,
      descriptor: descriptor,
      client: client,
      encryptedClient: encryptedClient, 
      module: module, 
      sinkId: sinkId,
      view: self.window.webView!)
    mediaPlayers.append(mediaPlayer)
    mediaPlayerDelegate.addObserverInternal(mediaPlayer)
    return mediaPlayer
  }

  public func createMediaSession() -> WebMediaSession? {
    print("UIWebFrame.createMediaSession")
    return nil
  }

  public func createApplicationCacheHost(frame: WebFrame?, client: WebApplicationCacheHostClient?) -> WebApplicationCacheHost? {
    //print("UIWebFrame.createApplicationCacheHost")
    return nil
  }

  public func createServiceWorkerProvider(frame: WebFrame?) -> WebServiceWorkerProvider? {
    //print("UIWebFrame.createServiceWorkerProvider")
    return nil
  }

  public func createWorkerContentSettingsClientProxy(frame: WebFrame?) -> WorkerContentSettingsClientProxy? {
    //print("UIWebFrame.createWorkerContentSettingsClientProxy")
    return nil
  }

  public func createExternalPopupMenu(info: WebPopupMenuInfo, client: WebExternalPopupMenuClient?) -> WebExternalPopupMenu? {
    //print("UIWebFrame.createExternalPopupMenu")
    return nil
  }

  public func cookieJar(frame: WebFrame) -> WebCookieJar? {
    //print("UIWebFrame.cookieJar")
    return nil
  }

  public func canCreatePluginWithoutRenderer(mimeType: String) -> Bool {
    //print("UIWebFrame.canCreatePluginWithoutRenderer")
    return false
  }

  public func didAccessInitialDocument(frame: WebFrame) {
    //print("UIWebFrame.didAccessInitialDocument(\(routingId))")
    hasAccessedInitialDocument = true
  }

  public func createChildFrame(parent: WebFrame, 
      type: WebTreeScopeType, 
      name: String, 
      flags: WebSandboxFlags, 
      properties: WebFrameOwnerProperties) -> WebFrame? {
    print("UIWebFrame.createChildFrame")
    return nil
  }

  public func didChangeOpener(opener: WebFrame?) {
    if let openerFrame = opener {
      if let openerId = window.fromWebFrame(openerFrame)?.routingId {
        window.sendDidChangeOpener(opener: openerId)
      }
    }
  }

  public func frameDetached(type: WebFrameDetachType) {
    guard let localFrame = frame else {
      return
    }

    for observer in observers {
      observer.frameDetached(frame: self)
    }

    if type == .Remove {
      window.sendDetachFrame(id: routingId)
    }

    window.unregisterFrame(self)

    localFrame.close()
    self.frame = nil
  }

  public func frameFocused() {
    //print("UIWebFrame.frameFocused(\(routingId))")
    for observer in observers {
      observer.frameFocused(frame: self)
    }
    window.sendFrameFocused()
  }

  public func didChangeName(name: String) {
    //print("UIWebFrame.didChangeName(\(routingId)): \(name)")
    window.sendDidChangeName(name: name)
    for observer in observers {
      observer.didChangeName(frame: self, name: name)
    }
  }

  public func didChangeSandboxFlags(child: WebFrame, flags: WebSandboxFlags) {

  }

  public func didChangeFrameOwnerProperties(child: WebFrame, properties: WebFrameOwnerProperties) {

  }

  public func didMatchCSS(frame: WebFrame, newlyMatchingSelectors: [String], stoppedMatchingSelectors: [String])  {
    print("UIWebFrame.didMatchCSS \(newlyMatchingSelectors)")
  }
  
  public func shouldReportDetailedMessageForSource(source: String) -> Bool {
    //print("UIWebFrame.shouldReportDetailedMessageForSource: \(source)")
    return true
  }
  
  public func didAddMessageToConsole(message: WebConsoleMessage, sourceName: String, sourceLine: Int, stackTrace: String) {
    //print("UIWebFrame.didAddMessageToConsole: source: \(sourceName) line: \(sourceLine) message (level = \(message.level.rawValue)):\n \"\(message.text)\"")
  }

  public func loadURLExternally(request: WebURLRequest, policy: WebNavigationPolicy, downloadName: String, shouldReplaceCurrentEntry: Bool) {
    print("UIWebFrame.loadURLExternally")
  }

  public func decidePolicyForNavigation(info: WebFrameNavigationPolicyInfo) -> WebNavigationPolicy {
    return WebNavigationPolicy.CurrentTab
    //return WebNavigationPolicy.Ignore
  }

  public func hasPendingNavigation() -> Bool {
    //print("UIWebFrame.hasPendingNavigation")
    return pendingNavigation != nil
  }
  
  public func didStartLoading(toDifferentDocument: Bool) {
    //print("UIWebFrame.didStartLoading(\(routingId))")
    for observer in observers {
      observer.didStartLoading(frame: self, toDifferentDocument: toDifferentDocument)
    }
    if !toDifferentDocument {
      window.sendDidStartLoading(toDifferentDocument: toDifferentDocument)
    }
  }

  public func didStopLoading() {
    //print("UIWebFrame.didStopLoading(\(routingId))")
    sendUpdateFaviconUrls()
    for observer in observers {
      observer.didStopLoading(frame: self)
    }
    window.sendDidStopLoading()
  }

  public func didChangeLoadProgress(loadProgress: Double) {
    //print("UIWebFrame.didChangeLoadProgress(\(routingId)): \(loadProgress) %")
    window.sendDidChangeLoadProgress(loadProgress: loadProgress)
    for observer in observers {
      observer.didChangeLoadProgress(frame: self, loadProgress: loadProgress)
    }
  }

  public func didEnforceInsecureRequestPolicy() {

  }

  public func didEnforceInsecureNavigationsSet() {

  }

  public func findFrame(name: String) -> WebFrame? {
    print("UIWebFrame.findFrame")
    return nil
  }

  public func didChangeFramePolicy(childFrame: WebFrame?, flags: Int) {

  }

  public func setFocus(enable: Bool) {
    print("UIWebFrame.setFocus(\(routingId)). enable = \(enable)")
  }  

  public func didSetFramePolicyHeaders() {

  }

  public func setHasReceivedUserGesture() {

  }

  public func setHasReceivedUserGestureBeforeNavigation(_ value: Bool) {

  }

  public func downloadURL(urlRequest: WebURLRequest) {
    print("UIWebFrame.downloadURL")
  }

  public func loadErrorPage(reason: Int) {
    print("UIWebFrame.loadErrorPage(\(routingId)) reason: \(reason)")
  }

  public func allowContentInitiatedDataUrlNavigations(url: String) -> Bool {
    //print("UIWebFrame.allowContentInitiatedDataUrlNavigations(\(routingId)): \(url)")
    return true
  }

  public func didAddContentSecurityPolicies() {
    //print("UIWebFrame.didAddContentSecurityPolicies")
  }

  public func didBlockFramebust(url: String) {
    //print("UIWebFrame.didBlockFramebust")
  }

  public func abortClientNavigation() {
    print("UIWebFrame.abortClientNavigation")
  }

  public func didChangeContents() {
    //print("UIWebFrame(\(routingId)).didChangeContents")
    for observer in observers {
      observer.didChangeContents(frame: self)
    }
  }

  public func runScriptsAtDocumentElementAvailable() {
    //print("UIWebFrame(\(routingId)).runScriptsAtDocumentElementAvailable")
    for observer in observers {
      observer.runScriptsAtDocumentElementAvailable(frame: self)
    }
  }

  public func runScriptsAtDocumentReady(documentIsEmpty: Bool) {
    //print("UIWebFrame(\(routingId)).runScriptsAtDocumentReady")
    for observer in observers {
      observer.runScriptsAtDocumentReady(frame: self)
    }
  }

  public func runScriptsAtDocumentIdle() {
    //print("UIWebFrame.runScriptsAtDocumentIdle")
    for observer in observers {
      observer.runScriptsAtDocumentIdle(frame: self)
    }
  }

  public func forwardResourceTimingToParent() {
    //print("UIWebFrame.forwardResourceTimingToParent")
  }

  public func saveImageFromDataURL(url: String) {
    //print("UIWebFrame.saveImageFromDataURL")
  }

  public func didContainInsecureFormAction() {
    //print("UIWebFrame.didContainInsecureFormAction")
  }

  public func didDisplayContentWithCertificateErrors() {
    //print("UIWebFrame.didDisplayContentWithCertificateErrors")
  }

  public func didRunContentWithCertificateErrors() {
    //print("UIWebFrame.didRunContentWithCertificateErrors")
  }

  public func draggableRegionsChanged() {
    //print("UIWebFrame.draggableRegionsChanged")
  }

  public func scrollFocusedEditableElementIntoRect(_ rect: IntRect) {
    let autofillClient = frame!.autofillClient

    if hasScrolledFocusedEditableNodeIntoRect &&
        rect == rectForScrolledFocusedEditableNode && autofillClient != nil {
      autofillClient!.didCompleteFocusChangeInFrame()
      return
    }

    if !frame!.localRoot!.frameWidget!.scrollFocusedEditableElementIntoView() {
      return
    }

    rectForScrolledFocusedEditableNode = rect
    hasScrolledFocusedEditableNodeIntoRect = true

    if !window!.layerTreeView!.hasPendingPageScaleAnimation && autofillClient != nil {
      autofillClient!.didCompleteFocusChangeInFrame()
    }
  }

  public func scrollRectToVisibleInParentFrame(_ rect: IntRect) {
    //print("UIWebFrame.scrollRectToVisibleInParentFrame(\(routingId)): \(rect)")
  }

  public func willSendSubmitEvent(frame: WebFrame, element: WebFormElement) {
    //print("UIWebFrame.willSendSubmitEvent(\(routingId))")
  }

  public func willSubmitForm(frame: WebFrame, element: WebFormElement) {
    //print("UIWebFrame.willSubmitForm(\(routingId))")
  }

  public func didCreateDataSource(frame: WebFrame, data: WebDataSource) {
    //print("UIWebFrame.didCreateDataSource(\(routingId))")
  }

  public func didStartProvisionalLoad(loader documentLoader: WebDocumentLoader?, urlRequest: WebURLRequest) {
    //print("UIWebFrame.didStartProvisionalLoad(\(routingId))")
    guard let loader = documentLoader else {
      //print("UIWebFrame.didStartProvisionalLoad(\(routingId)): no document loader. cancelling")
      return
    }

    // TODO: we dont have this yet.. 
    // For this we need to use the "ExtraData" field
    // of DocumentLoader to embed some data we want to
    // extract later (like here, now)

    // let navigationState = NavigationState.fromDocumentLoader(loader)
    //if !navigationState.wasInitiatedInThisFrame {
      for observer in observers {
        observer.didStartNavigation(frame: self, url: loader.url, type: nil)
      }
    //}

    for observer in observers {
      observer.readyToCommitNavigation(frame: self, loader: loader)
    }

    let loadUrl: String = documentLoader!.request.url
    //print("UIWebFrame.didStartProvisionalLoad(\(routingId)): url = \(loadUrl)")
    window.sendDidStartProvisionalLoad(
      url: loadUrl,
      // TODO: this is not right, and we need to fix this.
      //       we need to embedd some state into the ExtraData section
      //       of the document loader and unwrap it here with our data
      navigationStart: TimeTicks.now)
  }
  
  public func didReceiveServerRedirectForProvisionalLoad(frame: WebFrame) {
    //print("UIWebFrame.didReceiveServerRedirectForProvisionalLoad(\(routingId))")
  }

  public func didFailProvisionalLoad(error: WebURLError, type: WebHistoryCommitType) {
    //print("UIWebFrame.didFailProvisionalLoad(\(routingId)): domain: \(error.domain) reason: \(error.reason), WebHistoryCommitType: \(type)")
    for observer in observers {
      observer.didFailProvisionalLoad(frame: self)//error)
    }

    guard let documentLoader = frame?.provisionalDocumentLoader else {
      return
    }
    
    let failedRequest: WebURLRequest = documentLoader.request

    // Notify the browser that we failed a provisional load with an error.
    window.sendDidFailProvisionalLoadWithError(
      url: failedRequest.url, 
      errorCode: error.reason,
      description: error.localizedDescription)

    if !shouldDisplayErrorPageForFailedLoad(error: error.reason) {
      return
    }

  //  let documentState: DocumentState = DocumentState.fromDocumentLoader(documentLoader)
   // let navigationState: NavigationState = documentState.navigationState

    // If this is a failed back/forward/reload navigation, then we need to do a
    // 'replace' load.  This is necessary to avoid messing up session history.
    // Otherwise, we do a normal load, which simulates a 'go' navigation as far
    // as session history is concerned.
    let replace = type != WebHistoryCommitType.StandardCommit

    // If we failed on a browser initiated request, then make sure that our error
    // page load is regarded as the same browser initiated request.
  //  if !navigationState.isContentInitiated {
  //    self.pendingNavigationParams =  PendingNavigationParams(
//          navigationState.commonParams, 
//          navigationState.requestParams,
  //        time: TimeTicks())  // not used for failed navigation.
  //  }

    // Load an error page.
    loadNavigationErrorPage(
      failedRequest: failedRequest, 
      error: error, 
      replace: replace, 
      errorPageContent: nil)
  }

  public func didCommitProvisionalLoad(item: WebHistoryItem, type: WebHistoryCommitType) {
    //print("UIWebFrame.didCommitProvisionalLoad(\(routingId))")
    if !committedFirstLoad {
      committedFirstLoad = true
    }

    if frameProxy != nil {
      if !swapIn() {
        return
      }
    }

    window.didNavigate()

    didCommitNavigationInternal(item: item, commitType: type, wasWithinSameDocument: false)
  }

  public func didCreateNewDocument() {
    //print("UIWebFrame.didCreateNewDocument(\(routingId))")
    for observer in observers {
      observer.didCreateNewDocument(frame: self)
    }
  }

  public func didClearWindowObject() {
    //print("UIWebFrame.didClearWindowObject")
    for observer in observers {
      observer.didClearWindowObject(frame: self)
    }
  }

  public func didCreateDocumentElement() {
    //print("UIWebFrame.didCreateDocumentElement(\(routingId))")
    if isMainFrame {
      window.sendDocumentAvailableInMainFrame(usesTemporaryZoomLevel: false)
    }
    for observer in observers {
      observer.didCreateDocumentElement(frame: self)
    }
  }

  public func didReceiveTitle(frame: WebFrame, title: String, direction: TextDirection) {
    //print("UIWebFrame.didReceiveTitle(\(routingId)): \"\(title)\"")
    window.sendUpdateTitle(title: title, direction: direction)
  }

  public func didChangeIcon(frame: WebFrame, type: WebIconUrlType) {
    //print("UIWebFrame.didChangeIcon")   
    sendUpdateFaviconUrls()
  }

  public func didFinishDocumentLoad() {
    //print("UIWebFrame.didFinishDocumentLoad(\(routingId))")
    for observer in observers {
      observer.didFinishDocumentLoad(frame: self)
    }
  }

  public func didHandleOnloadEvents() {
    //print("UIWebFrame.didHandleOnloadEvents")
    for observer in observers {
      observer.didHandleOnloadEvents(frame: self)
    }
  }

  public func didFailLoad(error: WebURLError, type: WebHistoryCommitType) {
    //print("\n\n *** LOAD FAILED: reason: \(error.reason)\ndata: \"\(error.domain)\" *** \n\n")
    for observer in observers {
      observer.didFailLoad(frame: self, error: error)
    }
  }

  public func didFinishLoad() {
    //print("UIWebFrame.didFinishLoad(\(routingId))")
    guard let localFrame = frame else {
      return
    }
    for observer in observers {
      observer.didFinishLoad(frame: self)
    }

    let documentLoader = localFrame.documentLoader
    window.sendDidFinishLoad(url: documentLoader.url)//routingId, documentLoader.url)
  }

  public func didNavigateWithinPage(frame: WebFrame, item: WebHistoryItem, type: WebHistoryCommitType, contentInitiated: Bool) {
    print("UIWebFrame.didNavigateWithinPage")
  }

  public func didUpdateCurrentHistoryItem(frame: WebFrame) {
    //print("UIWebFrame.didUpdateCurrentHistoryItem")
  }

  public func didChangeManifest(frame: WebFrame) {
    //print("UIWebFrame.didChangeManifest")
  }

  public func didChangeThemeColor() {
    //print("UIWebFrame.didChangeThemeColor")
  }

  public func dispatchLoad() {
    print("UIWebFrame.dispatchLoad(\(routingId))")
  }

  public func requestNotificationPermission(origin: WebSecurityOrigin, callback: WebNotificationPermissionCallback) {
    //print("UIWebFrame.requestNotificationPermission")
  }

  public func willCommitProvisionalLoad() {
    for observer in observers {
      observer.willCommitProvisionalLoad(frame: self)
    }
  }

  public func didChangeSelection(isSelectionEmpty: Bool) {
    //print("UIWebFrame.didChangeSelection")
  
    if isSelectionEmpty {
      selectionText.removeAll()
    }
    window.updateTextInputState()
  }

  public func createColorChooser(client: WebColorChooserClient?,
      color: Color,
      suggestion: [WebColorSuggestion]) -> WebColorChooser? {
    return nil
  }

  public func runModalAlertDialog(message: String) {

  }

  public func runModalConfirmDialog(message: String) -> Bool {
    return false
  }

  public func runModalPromptDialog(
      message: String, defaultValue: String,
      actualValue: String) -> Bool {
    return false
  }

  public func runModalBeforeUnloadDialog(isReload: Bool) -> Bool {
    return false
  }

  public func showContextMenu(data: WebContextMenuData) {
    //print("UIWebFrame.showContextMenu")
  }

  public func clearContextMenu() {

  }

  public func willSendRequest(
      frame: WebFrame, 
      request: WebURLRequest) {
    for observer in observers {
      observer.willSendRequest(frame: self, request: request)
    }
  }

  public func didReceiveResponse(
    frame: WebFrame, 
    response: WebURLResponse) {
    //print("UIWebFrame.didReceiveResponse(\(routingId)) - url: \(response.url) status: \(response.httpStatusCode) \(response.httpStatusText)")
    //print("UIWebFrame.didReceiveResponse")
    for observer in observers {
      observer.didReceiveResponse(frame: self, response: response)
    }
  }

  public func didChangeResourcePriority(
      frame: WebFrame, 
      identifier: Int, 
      priority: WebURLRequest.Priority, 
      n: Int) {
    //print("UIWebFrame.didChangeResourcePriority")
  }

  public func didFinishResourceLoad(frame: WebFrame, identifier: Int) {
    print("UIWebFrame.didFinishResourceLoad(\(routingId) id: (identifier))")
  }

  public func didLoadResourceFromMemoryCache(frame: WebFrame, request: WebURLRequest, response: WebURLResponse) {
    print("UIWebFrame.didLoadResourceFromMemoryCache(\(routingId))")
    //sender.sendDidLoadResourceFromMemoryCache()
  }

  public func didDisplayInsecureContent() {
    print("UIWebFrame.didDisplayInsecureContent(\(routingId))")
  }

  public func didRunInsecureContent(origin: WebSecurityOrigin, insecureURL: String) {
    print("UIWebFrame.didRunInsecureContent")
  }

  public func didDetectXSS(url: String, didBlockEntirePage: Bool) {
    //print("UIWebFrame.didDetectXSS")
  }

  public func didDispatchPingLoader(frame: WebFrame, url: String) {
    //print("UIWebFrame.didDispatchPingLoader")
  }

  public func didChangePerformanceTiming() {
    //print("UIWebFrame.didChangePerformanceTiming")
  }

  // public func didAbortLoading() {

  // }

  public func didCreateScriptContext(context: JavascriptContext, worldId: Int) {
    //print("didCreateScriptContext")
    for observer in observers {
      observer.didCreateScriptContext(frame: self, context: context, worldId: worldId)
    }
  }

  public func willReleaseScriptContext(context: JavascriptContext, worldId: Int) {
    for observer in observers {
      observer.willReleaseScriptContext(frame: self, context: context, worldId: worldId)
    }
  }

  public func didChangeScrollOffset() {
    for observer in observers {
      observer.didChangeScrollOffset(frame: self)
    }
  }

  public func willInsertBody(frame: WebFrame) {
    //print("UIWebFrame.willInsertBody(\(routingId))")
  }

  public func reportFindInPageMatchCount(identifier: Int, count: Int, finalUpdate: Bool) {

  }

  public func reportFindInFrameMatchCount(identifier: Int, count: Int, finalUpdate: Bool) {

  }

  public func reportFindInPageSelection(identifier: Int, activeMatchOrdinal: Int, selection: IntRect) {

  }

  public func requestStorageQuota(
      frame: WebFrame, type: WebStorageQuotaType,
      newQuotaInBytes: Int64,
      callbacks: WebStorageQuotaCallbacks) {

  }

  public func willOpenWebSocket(socket: WebSocket) {
    print("UIWebFrame.willOpenWebSocket")
  }

  public func willStartUsingPeerConnectionHandler(frame: WebFrame, handler: WebRTCPeerConnectionHandler) {
    print("UIWebFrame.willStartUsingPeerConnectionHandler")
  }

  public func willCheckAndDispatchMessageEvent(
      sourceFrame: WebFrame,
      targetFrame: WebFrame,
      target: WebSecurityOrigin,
      event: WebDOMMessageEvent) -> Bool {
    return false
  }

  public func userAgentOverride(frame: WebFrame) -> String {
    return String()
  }
  
  public func doNotTrackValue(frame: WebFrame) -> String {
    return String()
  }

  public func allowWebGL(frame: WebFrame, defaultValue: Bool) -> Bool {
    print("UIWebFrame.allowWebGL() -> Bool = true")
    return true
  }

  public func didLoseWebGLContext(frame: WebFrame, context: Int) {
    print("UIWebFrame.didLoseWebGLContext()")
  }

  public func postAccessibilityEvent(object: WebAXObject, event: WebAXEvent) {

  }

  public func handleAccessibilityFindInPageResult(
      identifier: Int,
      matchIndex: Int,
      startObject: WebAXObject,
      startOffset: Int,
      endObject: WebAXObject,
      endOffset: Int) {

  }

  public func isControlledByServiceWorker(source: WebDataSource) -> Bool {
    print("UIWebFrame.isControlledByServiceWorker(source: WebDataSource)?")
    return false
  }

  public func serviceWorkerId(source: WebDataSource) -> Int64 {
    print("UIWebFrame.serviceWorkerId")
    return -1
  }

  public func enterFullscreen() -> Bool {
    print("UIWebFrame.enterFullscreen")
    return true
  }

  public func exitFullscreen() -> Bool {
    print("UIWebFrame.exitFullscreen")
    return true
  }

  public func suddenTerminationDisablerChanged(present: Bool, type: WebFrameSuddenTerminationDisablerType) {
    //print("UIWebFrame.suddenTerminationDisablerChanged")
  }

  public func registerProtocolHandler(scheme: String, url: String, title: String) {
    print("UIWebFrame.registerProtocolHandler \(scheme)")
  }

  public func unregisterProtocolHandler(scheme: String, url: String) {
    print("UIWebFrame.unregisterProtocolHandler \(scheme)")
  }

  public func isProtocolHandlerRegistered(scheme: String, url: String) -> WebCustomHandlersState {
    print("UIWebFrame.isProtocolHandlerRegistered? \(scheme)")
    return WebCustomHandlersState.Registered
  }

  public func swapOut(windowId: Int32, loading: Bool) -> Bool {
    //print("UIWebFrame.swapOut(\(routingId))")
    if let localFrame = frame {
      // Swap this RenderFrame out so the frame can navigate to a page rendered by
      // a different process.  This involves running the unload handler and
      // clearing the page.  We also allow this process to exit if there are no
      // other active RenderFrames in it.

      // Send an UpdateState message before we get deleted.
      //sendUpdateState()
      window!.sendUpdateState()

      // There should always be a proxy to replace this RenderFrame.  Create it now
      // so its routing id is registered for receiving IPC messages.
      //CHECK_NE(proxy_routing_id, MSG_ROUTING_NONE);
      frameProxy = UIWebFrameProxy.createProxyToReplaceFrame(delegate: self, frameToReplace: self, routingId: routingId, scope: WebTreeScopeType.Document)//replicated_frame_state.scope)
         //RenderFrameProxy::CreateProxyToReplaceFrame(
          //this, proxy_routing_id, replicated_frame_state.scope);

      if isMainFrame {
        localFrame.dispatchUnloadEvent()
      }

      // Swap out and stop sending any IPC messages that are not ACKs.
      if isMainFrame {
        window!.isSwappedOut = true
      }
      
      // Now that all of the cleanup is complete and the browser side is notified,
      // start using the RenderFrameProxy.
      //
      // The swap call deletes this RenderFrame via frameDetached.  Do not access
      // any members after this call.
      //
      // TODO(creis): WebFrame::swap() can return false.  Most of those cases
      // should be due to the frame being detached during unload (in which case
      // the necessary cleanup has happened anyway), but it might be possible for
      // it to return false without detaching.  Catch any cases that the
      // RenderView's main_render_frame_ isn't cleared below (whether swap returns
      // false or not).
      let success = localFrame.swap(frame: frameProxy!.frame)

      // For main frames, the swap should have cleared the RenderView's pointer to
      // this frame.
      //if (is_main_frame)
      //  CHECK(!render_view->main_render_frame_);

      if !success {
        // The swap can fail when the frame is detached during swap (this can
        // happen while running the unload handlers). When that happens, delete
        // the proxy.
        frameProxy!.frameDetached(type: WebFrameDetachType.Swap)
        return false
      }

      if loading {
        frameProxy!.onDidStartLoading()
      }

      // Initialize the WebRemoteFrame with the replication state passed by the
      // process that is now rendering the frame.
      
      // TODO: implement
      
      //frameProxy!.replicatedState = replicatedFrameState

      // Safe to exit if no one else is using the process.
      // TODO(nasko): Remove the dependency on RenderViewImpl here and ref count
      // the process based on the lifetime of this RenderFrameImpl object.
      if isMainFrame {
        window!.wasSwappedOut()
      }

      window!.sendSwapOutAck()
      return success
    }
    return false
  }

  public func detach() {
    print("UIWebFrame.detach(\(routingId))")
    if let localFrame = frame {
      localFrame.detach()
    }
  }

  public func stop() {
    print("UIWebFrame.stop(\(routingId))")
    guard let localFrame = frame else {
      return
    }
    localFrame.stopLoading()
    for observer in observers {
      observer.onStop(frame: self)
    }
  }

  public func clientDroppedNavigation() {
    print("UIWebFrame.clientDroppedNavigation")
    hostSideNavigationPending = false
    hostSideNavigationPendingUrl = String()
    if let localFrame = frame {
      localFrame.clientDroppedNavigation()
    }
  }

  public func collapse(collapsed: Bool) {
    print("UIWebFrame.collapse")
    if let localFrame = frame {
      localFrame.collapse(collapsed: collapsed)
    }
  }

  public func swapIn() -> Bool {
    //print("UIWebFrame.swapIn(\(routingId))")
    guard let localFrame = frame else {
      return false
    }
    // NOTE: not really creating every time.. reusing the one with previousRoutingId
    // => UIWebFrameProxy.fromRoutingID(previousRoutingId)
    frameProxy = UIWebFrameProxy.fromRoutingID(routingId: routingId)//UIWebFrameProxy(delegate: self, window: window!)
    if !frameProxy!.frame.swap(frame: localFrame) {
      // detach "manually"
      frameProxy!.frameDetached(type: WebFrameDetachType.Swap)
      return false
    }
    // this is from new code (our version of blink dont have this)
    //if isMainFrame {
    //  window.webView!.didAttachLocalMainFrame()
    //}
    return true
  }

  public func copyImage(at: IntPoint) {
    if let localFrame = frame {
      localFrame.copyImage(at: IntPoint())
    }
  }
  
  public func saveImage(at: IntPoint) {
    if let localFrame = frame {
      localFrame.saveImage(at: IntPoint())
    }
  }

  public func advanceFocusInForm(type: WebFocusType) {
    if let localFrame = frame {
      localFrame.advanceFocusInForm(type: type)
    }
  }

  public func checkCompleted() {
    //print("UIWebFrame.checkCompleted")
    if let localFrame = frame {
      localFrame.checkCompleted()
    }
  }

  public func beforeUnload(isReload: Bool) {
    //print("UIWebFrame.beforeUnload(\(routingId)). isReload = \(isReload)")
    guard let localFrame = frame else {
      return
    }
    let beforeUnloadStartTime = TimeTicks.now
    let proceed = localFrame.dispatchBeforeUnloadEvent(isReload: isReload)
    let beforeUnloadEndTime = TimeTicks.now
    window.sendBeforeUnloadAck(
        proceed: proceed, 
        startTime: beforeUnloadStartTime, 
        endTime: beforeUnloadEndTime)
  }

  public func find(requestId: Int32, searchText: String, options: WebFindOptions) {
    if let localFrame = frame {
      localFrame.requestFind(requestId: requestId, searchText: searchText, options: options)
    }
  }

  public func clearActiveFindMatch() {
    if let localFrame = frame {
      let _ = localFrame.executeCommand(command: "CollapseSelection")
      localFrame.clearActiveFindMatch()
    }
  }

  public func stopFinding(action: WebFrameStopFindAction) {
    if let localFrame = frame {
      localFrame.stopFinding(action: action)
    }
  }

  public func notifyUserActivation() {
    //print("UIWebFrame.notifyUserActivation")
    if let localFrame = frame {
      localFrame.notifyUserActivation()
    }
  }

  public func textSurroundingSelectionRequest(maxLength: UInt32) {
    //print("UIWebFrame.textSurroundingSelectionRequest")
    guard let text = frame?.getSurroundingText(maxLength: maxLength) else {
      window.sendTextSurroundingSelectionResponse(content: String(), start: 0, end: 0)
      return
    }

    window.sendTextSurroundingSelectionResponse(
        content: text.textContent,
        start: text.startOffsetInTextContent,
        end: text.endOffsetInTextContent)
  }

  public func reload(bypassCache: Bool) {
    //print("UIWebFrame.reload")
    if let localFrame = frame {
      localFrame.reload(type: bypassCache ? WebFrameLoadType.ReloadBypassingCache
                                            : WebFrameLoadType.Reload)
    }
  }

  public func commitNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) {
    self.providerId = Int(providerId)
    prepareFrameForCommit()
    let commitStatus = CommitResult.Ok
    //let url = String("data://hello")
    //var continueNavigation: (() -> Void)?

    if commitStatus == CommitResult.Ok {
      let loadType: WebFrameLoadType = WebFrameLoadType.BackForward//WebFrameLoadType.Standard
      let isClientRedirect: Bool = false
          //!!(common_params.transition & ui::PAGE_TRANSITION_LIENT_REDIRECT)

      let shouldLoadDataUrl: Bool = false//!commonParams.baseUrlForDataUrl.isEmpty
//#if os(Android)
//      shouldLoadDataIrl |= !requestParams.dataUrlAsString.isEmpty
//#endif
      if isMainFrame && shouldLoadDataUrl {
        loadDataURL()//commonParams, 
                    //requestParams, 
                    //frame, 
                    //loadType,
                    //nil,//itemForHistoryNavigation,
                    //WebHistoryLoadType.DifferentDocumentLoad, 
                    //isClientRedirect)
      } else {
        requestForCommitNavigation = createURLRequestForCommit(url: url, keepAlive: keepAlive)
            //commonParams, requestParams, urlLoaderClientEndpoints,
            //head)

        frame!.commitNavigation(
          request: requestForCommitNavigation!,//commonParams.url, 
          loadType: loadType, 
          item: nil,//itemForHistoryNavigation,
          isClientRedirect: isClientRedirect)
     
        //let extraData: WebURLRequest.ExtraData = request.extraData
        //continueNavigation =
        //    extraData.takeContinueNavigationFunctionOwnerShip()
      }
    } else {
      if !frame!.isLoading {
        window!.sendDidStopLoading()
      }
    }

    frame!.documentLoader.resetSourceLocation()
    if let provisionalLoader = frame?.provisionalDocumentLoader {
      provisionalLoader.resetSourceLocation()
    }

    //if let callback = continueNavigation {
    //  callback()
    //}
    //print("UIWebFrame.commitNavigation end") 
  }

  public func commitSameDocumentNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) -> CommitResult {
    print("UIWebFrame.commitSameDocumentNavigation(\(routingId))")

    prepareFrameForCommit()

    let loadType: WebFrameLoadType = WebFrameLoadType.Standard // NavigationTypeToLoadType(
        //common_params.navigation_type, common_params.should_replace_current_entry,
        //request_params.page_state.IsValid())

    var commitStatus: CommitResult = CommitResult.Ok
    //var itemForHistoryNavigation: WebHistoryItem

    // if commonParams.navigationType ==
    //     FrameMsg_Navigate_Type::HISTORY_SAME_DOCUMENT) {
    //   commitStatus = prepareForHistoryNavigationCommit(
    //       common_params.navigation_type, request_params,
    //       &item_for_history_navigation, &load_type)
    // }

    if commitStatus == CommitResult.Ok {
      let isClientRedirect = false
          //!!(commonParams.transition & ui.PAGE_TRANSITION_LIENT_REDIRECT)
      // Load the request.
      
      commitStatus = frame!.commitSameDocumentNavigation(
          url: url,//String("http://www.hello.world"), 
          loadType: loadType, 
          item: nil,
          isClientRedirect: isClientRedirect)
    }

    if commitStatus != CommitResult.Ok {
      window!.sendDidStopLoading()
    }

    //print("UIWebFrame.commitSameDocumentNavigation end") 
    
    return commitStatus
  }

  public func commitFailedNavigation(
    errorCode: Int,
    errorPageContent: String?) {
    print("UIWebFrame.commitFailedNavigation(\(routingId))")
    //   bool is_reload =
    //     FrameMsg_Navigate_Type::IsReload(common_params.navigation_type);
    // RenderFrameImpl::PrepareRenderViewForNavigation(common_params.url,
    //                                                 request_params);

    // // Log a console message for subframe loads that failed due to a legacy
    // // Symantec certificate that has been distrusted or is slated for distrust
    // // soon. Most failed resource loads are logged in Blink, but Blink doesn't get
    // // notified when a subframe resource fails to load like other resources, so
    // // log it here.
    // if (frame_->Parent() && error_code == net::ERR_ERT_SYMANTEC_LEGACY) {
    //   ReportLegacySymantecCert(common_params.url, true /* did_fail */);
    // }

    // GetContentClient()->SetActiveURL(
    //     common_params.url, frame_->Top()->GetSecurityOrigin().ToString().Utf8());

    // SetupLoaderFactoryBundle(std::move(subresource_loader_factories),
    //                          base::nullopt /* subresource_overrides */);

    // pending_navigation_params_.reset(new PendingNavigationParams(
    //     common_params, request_params,
    //     base::TimeTicks()  // Not used for failed navigation.
    //     ));

    // // Send the provisional load failure.
    // WebURLError error(
    //     error_code, 0,
    //     has_stale_copy_in_cache ? WebURLError::HasCopyInCache::kTrue
    //                             : WebURLError::HasCopyInCache::kFalse,
    //     WebURLError::IsWebSecurityViolation::kFalse, common_params.url);
    // WebURLRequest failed_request = CreateURLRequestForNavigation(
    //     common_params, request_params,
    //     /*response_override=*/nullptr, frame_->IsViewSourceModeEnabled(),
    //     false);  // is_same_document_navigation

    // if (!ShouldDisplayErrorPageForFailedLoad(error_code, common_params.url)) {
    //   // The browser expects this frame to be loading an error page. Inform it
    //   // that the load stopped.
    //   Send(new FrameHostMsg_DidStopLoading(routing_id_));
    //   browser_side_navigation_pending_ = false;
    //   browser_side_navigation_pending_url_ = GURL();
    //   return;
    // }

    // // On load failure, a frame can ask its owner to render fallback content.
    // // When that happens, don't load an error page.
    // WebLocalFrame::FallbackContentResult fallback_result =
    //     frame_->MaybeRenderFallbackContent(error);
    // if (fallback_result != WebLocalFrame::NoFallbackContent) {
    //   if (fallback_result == WebLocalFrame::NoLoadInProgress) {
    //     // If the frame wasn't loading but was fallback-eligible, the fallback
    //     // content won't be shown. However, showing an error page isn't right
    //     // either, as the frame has already been populated with something
    //     // unrelated to this navigation failure. In that case, just send a stop
    //     // IPC to the browser to unwind its state, and leave the frame as-is.
    //     Send(new FrameHostMsg_DidStopLoading(routing_id_));
    //   }
    //   browser_side_navigation_pending_ = false;
    //   browser_side_navigation_pending_url_ = GURL();
    //   return;
    // }

    // // Make sure errors are not shown in view source mode.
    // frame_->EnableViewSourceMode(false);

    // // Replace the current history entry in reloads, and loads of the same url.
    // // This corresponds to Blink's notion of a standard commit.
    // // Also replace the current history entry if the browser asked for it
    // // specifically.
    // // TODO(clamy): see if initial commits in subframes should be handled
    // // separately.
    // bool replace = is_reload || common_params.url == GetLoadingUrl() ||
    //                common_params.should_replace_current_entry;
    // std::unique_ptr<HistoryEntry> history_entry;
    // if (request_params.page_state.IsValid())
    //   history_entry = PageStateToHistoryEntry(request_params.page_state);

    // // The load of the error page can result in this frame being removed.
    // // Use a WeakPtr as an easy way to detect whether this has occured. If so,
    // // this method should return immediately and not touch any part of the object,
    // // otherwise it will result in a use-after-free bug.
    // base::WeakPtr<RenderFrameImpl> weak_this = weak_factory_.GetWeakPtr();

    // // For renderer initiated navigations, we send out a didFailProvisionalLoad()
    // // notification.
    // bool had_provisional_document_loader = frame_->GetProvisionalDocumentLoader();
    // if (request_params.nav_entry_id == 0) {
    //   blink::WebHistoryCommitType commit_type =
    //       replace ? blink::kWebHistoryInertCommit : blink::kWebStandardCommit;
    //   if (error_page_content.has_value()) {
    //     DidFailProvisionalLoadInternal(error, commit_type, error_page_content);
    //   } else {
    //     // TODO(https://crbug.com/778824): We only have this branch because a
    //     // layout test expects DidFailProvisionalLoad() to be called directly,
    //     // rather than DidFailProvisionalLoadInternal(). Once the bug is fixed, we
    //     // should be able to call DidFailProvisionalLoadInternal() in all cases.
    //     DidFailProvisionalLoad(error, commit_type);
    //   }
    //   if (!weak_this)
    //     return;
    // }

    // // If we didn't call didFailProvisionalLoad or there wasn't a
    // // GetProvisionalDocumentLoader(), LoadNavigationErrorPage wasn't called, so
    // // do it now.
    // if (request_params.nav_entry_id != 0 || !had_provisional_document_loader) {
    //   LoadNavigationErrorPage(failed_request, error, replace, history_entry.get(),
    //                           error_page_content);
    //   if (!weak_this)
    //     return;
    // }

    // browser_side_navigation_pending_ = false;
    // browser_side_navigation_pending_url_ = GURL();
  }

  public func focusedNodeChanged(from: WebNode?, to node: WebNode?) {
    //print("UIWebFrame.focusedNodeChanged(\(routingId))")
    hasScrolledFocusedEditableNodeIntoRect = false
    //has_scrolled_focused_editable_node_into_rect_ = false;
    //bool is_editable = false;
    //gfx::Rect node_bounds;
    //if (!node.IsNull() && node.IsElementNode()) {
    //  WebElement element = const_cast<WebNode&>(node).To<WebElement>();
    //  blink::WebRect rect = element.BoundsInViewport();
    //  GetRenderUIWindow()->ConvertViewportToWindow(&rect);
    //  is_editable = element.IsEditable();
    //  node_bounds = gfx::Rect(rect);
    //}
    //Send(new FrameHostMsg_FocusedNodeChanged(routing_id_, is_editable,
    //                                         node_bounds));
    // Ensures that further text input state can be sent even when previously
    // focused input and the newly focused input share the exact same state.
    //GetRenderUIWindow()->ClearTextInputState();
    window!.clearTextInputState()

    for observer in observers {
      observer.focusedNodeChanged(frame: self, node: node)
    }
  }

  private func sendUpdateFaviconUrls() {
    guard let localFrame = frame else {
      return
    }
    let mask = WebIconUrlType.Favicon |
                WebIconUrlType.TouchPrecomposed |
                WebIconUrlType.Touch
    let urls = localFrame.iconUrls(iconTypesMask: mask.rawValue)
    guard urls.count != 0  else {
      return
    }
    window.sendUpdateFaviconUrl(urls: urls)
  }

  private func shouldDisplayErrorPageForFailedLoad(error: Int32) -> Bool {
    //if errorCode == .Aborted {
      return false
    //}
    //return true
  }

  private func loadNavigationErrorPage(
    failedRequest: WebURLRequest,
    error: WebURLError,
    replace: Bool,
    errorPageContent: String?) { 

  loadNavigationErrorPageInternal(
      errorHtml: errorPageContent ?? String(), 
      errorPageUrl: "data:,",
      errorUrl: error.unreachableURL ?? String(), 
      replace: replace)
  }

  private func loadNavigationErrorPageInternal(
    errorHtml: String,
    errorPageUrl: String,
    errorUrl: String,
    replace: Bool) {
    if let localFrame = frame {
      localFrame.loadData(string: errorHtml, 
                     mimeType: "text/html",
                     textEncoding: "UTF-8", 
                     baseURL: errorPageUrl, 
                     unreachableURL: errorUrl,
                     replace: replace)
    }
  }

  private func updateZoomLevel() {
    // TODO: implement
  }

  private func didCommitNavigationInternal(
    item: WebHistoryItem,
    commitType: WebHistoryCommitType,
    wasWithinSameDocument: Bool) {
    
    updateZoomLevel()

    if wasWithinSameDocument {
      window.sendDidCommitSameDocumentNavigation(
        params: makeDidCommitProvisionalLoadParams(commitType: commitType))
    } else {
      window.sendDidCommitProvisionalLoad(
        params: makeDidCommitProvisionalLoadParams(commitType: commitType))
    }
  
  }

  private func makeDidCommitProvisionalLoadParams(commitType: WebHistoryCommitType) -> DidCommitProvisionalLoadParams {
    var params = DidCommitProvisionalLoadParams()

    guard let localFrame = frame else {
      return params
    }

    let documentLoader = localFrame.documentLoader
    //let request: WebURLRequest = documentLoader.request
    let response: WebURLResponse = documentLoader.response
    
    params.httpStatusCode = response.httpStatusCode
    params.urlIsUnreachable = documentLoader.hasUnreachableUrl
    params.method = "GET"
  
    return params
  }

  // UIWebFrameProxyDelegate
  public func onFrameDetach() {
    //print("UIWebFrame.onFrameDetach -> helper to null out the proxy")
    // make sure we destroy the +1 ref-count here
    // to destroy the object
    frameProxy = nil

    // note: we only manage a "frame" for now.. 
    // so if/when we change this.. we will need to
    // change this, as other frames that are not the "main"
    // might call this method on their own detach
  }

  public func setOpener(_ opener: UIWebFrame) {
    if let localFrame = frame {
      localFrame.opener = opener.frame
    }
  }

  public func selectWordAroundCaret(start: inout Int, end: inout Int) -> Bool {
    //print("UIWebFrame.selectWordAroundCaret")
    var didSelect: Bool = false
    if let focusedFrame = window?.webView?.focusedFrame {
      let initialRange = focusedFrame.selectionRange
      if initialRange.length > 0 {
        didSelect = focusedFrame.selectWordAroundCaret()
      }
      if didSelect {
        let adjustedRange = focusedFrame.selectionRange
        start = adjustedRange.start - initialRange.start
        end = adjustedRange.end - initialRange.end
      }
    }
    return didSelect
  }

  public func didCloseContextMenu() {
    if let view = window?.webView {
      view.didCloseContextMenu()
    }
  }

  public func performCustomContextMenuAction(action: UInt) {
    if let view = window?.webView {
      view.performCustomContextMenuAction(action: action)
    }
  }

  public func advanceFocus(reverse: Bool) {
    if let view = window?.webView {
      view.advanceFocus(reverse: reverse)
    }
  }

  public func focusDocumentView() {
    if let view = window?.webView {
      view.focusDocumentView(frame: frame!)
    }
  }

  public func clearFocusedElement() {
    if let view = window?.webView {
      view.clearFocusedElement()
    }
  }

  public func didCommitAndDrawCompositorFrame() {
    
  }

  public func performMediaPlayerAction(action: WebMediaPlayerAction, location: IntPoint) {
    if let view = window?.webView {
      view.performMediaPlayerAction(action: action, location: location)
    }
  }

  // WebUIWindow
  public func didInvalidateRect(rect: IntRect) {
    //print("UIWebFrame.didInvalidateRect(\(routingId)). \(rect) not implemented")
    for observer in observers {
      observer.didInvalidateRect(frame: self, rect: rect)
    }
  }
  public func initializeLayerTreeView() -> WebLayerTreeView? {
    //print("UIWebFrame.initializeLayerTreeView(\(routingId)). calling window")
    return window!.initializeLayerTreeView()
  }
  public func scheduleAnimation() {
    //print("UIWebFrame.scheduleAnimation(\(routingId)). calling window")
    window.scheduleAnimation()
  }
  public func didMeaningfulLayout(layout: WebMeaningfulLayout) {
    //print("UIWebFrame.didMeaningfulLayout(\(routingId)) -> \(layout)")
    for observer in observers {
      observer.didMeaningfulLayout(frame: self, layout: layout)
    }
  }
  public func didFirstLayoutAfterFinishedParsing() {
    //print("UIWebFrame.didFirstLayoutAfterFinishedParsing(\(routingId)). not implemented")
  }
  public func didChangeCursor(cursor: WebCursorInfo) {
    //print("UIWebFrame.selectWordAroundCaret")
  }
  public func autoscrollStart(start: FloatPoint) {}
  public func autoscrollFling(velocity: FloatVec2) {}
  public func autoscrollEnd() {}
  public func closeUIWindowSoon() {
    //print("UIWebFrame.closeUIWindowSoon. not implemented")
  }
  public func show(policy: WebNavigationPolicy) {
    //print("UIWebFrame.show(\(routingId)). not implemented")
  }
  public func setToolTipText(text: String, hint: TextDirection) {
    //print("UIWebFrame.setToolTipText")
  }
  public func requestPointerLock() -> Bool {
    //print("UIWebFrame.requestPointerLock")
    return false
  }
  public func requestPointerUnlock() {}
  public func didHandleGestureEvent(event: WebGestureEvent, eventCancelled: Bool) {}
  public func setNeedsLowLatencyInput(_: Bool) {
    //print("UIWebFrame.setNeedsLowLatencyInput")
  }
  public func requestUnbufferedInputEvents() {
    //print("UIWebFrame.requestUnbufferedInputEvents")
  }
  public func setTouchAction(touchAction: TouchAction) {}

  public func convertViewportToWindow(_ r: inout IntRect) {
    //print("UIWebFrame.convertViewportToWindow(\(routingId)). r = \(r.width) , \(r.height)")
  }
  public func convertWindowToViewport(_ r: inout FloatRect) {
    //print("UIWebFrame.convertWindowToViewport(\(routingId)). not implemented. r = \(r.width) , \(r.height)")
  }

  public func startDragging(policy: WebReferrerPolicy,
                     dragData: WebDragData,
                     ops: DragOperation,
                     dragImage: ImageSkia?,
                     dragImageOffset: IntPoint) {}
  
  public func didOverscroll(overscrollDelta: FloatSize,
                     accumulatedOverscroll: FloatSize,
                     position: FloatPoint,
                     velocity: FloatSize,
                     overscrollBehavior: OverscrollBehavior) {}
  
  public func onWasShown() {
    //print("UIWebFrame.onWasShown(\(routingId))")
    for observer in observers {
      observer.onWasShown(frame: self)
    }
    if let frameWidget = frame?.frameWidget {
      frameWidget.setVisibilityState(WebPageVisibilityState.Visible)
    } else {
      //print("UIWebFrame.wasHidden: SEVERE. no frame.frameUIWindow")
    }
  }

  public func onWasHidden() {
    //print("UIWebFrame.onWasHidden(\(routingId))")
    for observer in observers {
      observer.onWasHidden(frame: self)
    }
    if let frameWidget = frame?.frameWidget {
      frameWidget.setVisibilityState(WebPageVisibilityState.Hidden)
    } else {
      //print("UIWebFrame.wasHidden: SEVERE. no frame.frameUIWindow")
    }
  }
  
  public func didChangeVisibleViewport() {
    //print("UIWebFrame.didChangeVisibleViewport(\(routingId))")
    hasScrolledFocusedEditableNodeIntoRect = false
  }
  
  public func willHandleMouseEvent(event: WebMouseEvent) {
    
  }

  public func willHandleGestureEvent(event: WebGestureEvent) {
    
  }

  public func willHandleKeyEvent(event: WebKeyboardEvent) {
    //print("UIWebFrame.willHandleKeyEvent")
  }

  public func setTextureLayerForHTMLCanvas(target: String, layer: Compositor.Layer) {
    window!.setTextureLayerForHTMLCanvas(target: target, layer: layer, frame: self)
  }

  private func createURLRequestForCommit(url: String, keepAlive: Bool) -> WebURLRequest { 
    //print("UIWebFrame.createURLRequestForCommit")
    //const CommonNavigationParams& common_params,
    //const RequestNavigationParams& request_params,
    //network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints,
    //const network::ResourceResponseHead& head) -> WebURLRequest {
    // This will override the url requested by the WebURLLoader, as well as
    // provide it with the response to the request.
    //   std::unique_ptr<NavigationResponseOverrideParameters> response_override(
    //       new NavigationResponseOverrideParameters());
    //   response_override->url_loader_client_endpoints =
    //       std::move(url_loader_client_endpoints);
    //   response_override->response = head;
    //   response_override->redirects = request_params.redirects;
    //   response_override->redirect_responses = request_params.redirect_response;
    //   response_override->redirect_infos = request_params.redirect_infos;

    //   WebURLRequest request = CreateURLRequestForNavigation(
    //       common_params, request_params, std::move(response_override),
    //       frame_->IsViewSourceModeEnabled(), false /* is_same_document */);
    //   request.SetFrameType(IsTopLevelNavigation(frame_)
    //                            ? network::mojom::RequestContextFrameType::kTopLevel
    //                            : network::mojom::RequestContextFrameType::kNested);

    //   if (common_params.post_data) {
    //     request.SetHTTPBody(GetWebHTTPBodyForRequestBody(*common_params.post_data));
    //     if (!request_params.post_content_type.empty()) {
    //       request.AddHTTPHeaderField(
    //           WebString::FromASCII(net::HttpRequestHeaders::kContentType),
    //           WebString::FromASCII(request_params.post_content_type));
    //     }
    //   }

    // #if defined(OS_ANDROID)
    //   request.SetHasUserGesture(common_params.has_user_gesture);
    // #endif

    //   // Make sure that Blink's loader will not try to use browser side navigation
    //   // for this request (since it already went to the browser).
    //   request.SetCheckForBrowserSideNavigation(false);

    //   request.SetNavigationStartTime(common_params.navigation_start);

    //   return request;
    let request = createURLRequestForNavigation(url: url, keepAlive: keepAlive)
    request.frameType = WebURLRequest.FrameType.TopLevel
    request.checkForBrowserSideNavigation = false
    request.setNavigationStartTime(TimeTicks.now)
    return request
  }

  private func createURLRequestForNavigation(url: String, keepAlive: Bool) -> WebURLRequest {
    //print("UIWebFrame.createURLRequestForNavigation")
    //const CommonNavigationParams& common_params,
    //const RequestNavigationParams& request_params,
    //std::unique_ptr<NavigationResponseOverrideParameters> response_override,
    //bool is_view_source_mode_enabled,
    //bool is_same_document_navigation) -> WebURLRequest {
    // Use the original navigation url to construct the WebURLRequest. The
    // WebURLloaderImpl will replay the redirects afterwards and will eventually
    // commit the final url.
    // const GURL navigation_url = !request_params.original_url.is_empty()
    //                                 ? request_params.original_url
    //                                 : common_params.url;
    // const std::string navigation_method = !request_params.original_method.empty()
    //                                           ? request_params.original_method
    //                                           : common_params.method;
    let request = WebURLRequest(url: url)
    request.httpMethod = "GET"//"POST"
    request.setIsSameDocumentNavigation(false)
    //request.previewsState = None
    request.wasDiscarded = false
    // request.SetHTTPMethod(WebString::FromUTF8(navigation_method));

    // if (is_view_source_mode_enabled)
    //   request.SetCacheMode(blink::mojom::FetchCacheMode::kForceCache);

    // WebString web_referrer;
    // if (common_params.referrer.url.is_valid()) {
    //   web_referrer = WebSecurityPolicy::GenerateReferrerHeader(
    //       common_params.referrer.policy, common_params.url,
    //       WebString::FromUTF8(common_params.referrer.url.spec()));
    //   request.SetHTTPReferrer(web_referrer, common_params.referrer.policy);
    //   if (!web_referrer.IsEmpty()) {
    //     request.SetHTTPOriginIfNeeded(
    //         WebSecurityOrigin(url::Origin::Create(common_params.referrer.url)));
    //   }
    // }

    // if (!web_referrer.IsEmpty() ||
    //     common_params.referrer.policy != blink::kWebReferrerPolicyDefault) {
    //   request.SetHTTPReferrer(web_referrer, common_params.referrer.policy);
    // }

    // request.SetIsSameDocumentNavigation(is_same_document_navigation);
    // request.SetPreviewsState(
    //     static_cast<WebURLRequest::PreviewsState>(common_params.previews_state));

    // auto extra_data = std::make_unique<RequestExtraData>();
    // extra_data->set_navigation_response_override(std::move(response_override));
    // extra_data->set_navigation_initiated_by_renderer(
    //     request_params.nav_entry_id == 0);
    // request.SetExtraData(std::move(extra_data));
    // request.SetWasDiscarded(request_params.was_discarded);

    // // Set the ui timestamp for this navigation. Currently the timestamp here is
    // // only non empty when the navigation was triggered by an Android intent. The
    // // timestamp is converted to a double version supported by blink. It will be
    // // passed back to the browser in the DidCommitProvisionalLoad and the
    // // DocumentLoadComplete IPCs.
    // base::TimeDelta ui_timestamp = common_params.ui_timestamp - base::TimeTicks();
    // request.SetUiStartTime(ui_timestamp.InSecondsF());
    // request.SetInputPerfMetricReportPolicy(
    //     static_cast<WebURLRequest::InputToLoadPerfMetricReportPolicy>(
    //         common_params.report_type));
    
    // NOTE: changed here
    // we should only use this in the case of 
    // a stream RPC method type
    
    //request.useStreamOnResponse = true
    if keepAlive {
      request.keepalive = true
    }
    
    //print("request.useStreamOnResponse ? \(request.useStreamOnResponse)")

    return request
  }

  private func loadDataURL() {
    //print("UIWebFrame.loadDataURL: calling loadHTML()")
    loadHTML()
  }

  internal func loadHTML() {
    //htmlData = WebData.fromAscii(HTMLStringMessage)
    if let localFrame = frame {
      //print("UIWebFrame.loadHTML: calling WebLocalFrame.loadData")
      localFrame.loadData(string: HTMLStringMessage,
                     mimeType: HTMLMimeType,
                     textEncoding: HTMLTextEncoding,
                     baseURL: HTMLBaseURL,
                     unreachableURL: nil,
                     replace: false)
    }
  }

  private func prepareFrameForCommit() {
    //print("UIWebFrame.prepareFrameForCommit")
    
    // apparently, theres not much in here
    // so its commented

    // browser_side_navigation_pending_ = false;
    // browser_side_navigation_pending_url_ = GURL();

    // GetContentClient()->SetActiveURL(
    //   pending_navigation_params_->common_params.url,
    //   frame_->Top()->GetSecurityOrigin().ToString().Utf8());

    // RenderFrameImpl::PrepareRenderViewForNavigation(
    //   pending_navigation_params_->common_params.url,
    //   pending_navigation_params_->request_params);

    // // Lower bound for browser initiated navigation start time.
    // base::TimeTicks renderer_navigation_start = base::TimeTicks::Now();

    // // Sanitize navigation start and store in |pending_navigation_params_|.
    // // It will be picked up in UpdateNavigationState.
    // pending_navigation_params_->common_params.navigation_start =
    //   SanitizeNavigationTiming(
    //       pending_navigation_params_->common_params.navigation_start,
    //       renderer_navigation_start);
  }
}

//fileprivate let HTMLStringMessage = "<html><body><div id=\"head\">hello world</div><div id=\"title\">hey, are you there?</div><div id=\"foot\">goodbye cruel world</div><div id=\"foot1\">maybe you like this</div><div id=\"foot2\">maybe not</div><div id=\"foot\">anyway..</div></body></html>"
//fileprivate let HTMLStringMessage = "hello world"
fileprivate let HTMLStringMessage = "<!DOCTYPE html><html><head><title>Texto em latim</title></head><body bgcolor='#990044'><pre id='log'></pre><div id='target' style='color: #F8C3D4;font-family: Input Mono; size: 20'><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris ut elit lacus, non convallis odio. Integer facilisis, dolor quis porttitor auctor, nisi tellus aliquet urna, a dignissim orci nisl in nunc. Vivamus elit risus, sagittis et lacinia quis, blandit ac elit. Suspendisse non turpis vitae lorem molestie imperdiet sit amet in justo. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In at quam sapien. Nam nunc eros, interdum ut commodo nec, sollicitudin ultrices magna. Mauris eu fringilla massa. Phasellus facilisis augue in lectus luctus scelerisque. Proin quis facilisis lacus. Morbi tempor, mauris vitae posuere scelerisque, turpis massa pulvinar tortor, quis congue dolor eros iaculis elit. Quisque blandit blandit elit, sed suscipit justo scelerisque ut. Aenean sed diam at ligula bibendum rhoncus quis in nunc. Suspendisse semper auctor dui vitae gravida. Fusce et risus in velit ullamcorper placerat. Pellentesque sollicitudin commodo porta. Nam eu enim orci, at euismod ipsum.</p></div></body></html>"
fileprivate let HTMLMimeType = "text/html"
fileprivate let HTMLTextEncoding = "US-ASCII"
fileprivate let HTMLBaseURL = "data:text/html"