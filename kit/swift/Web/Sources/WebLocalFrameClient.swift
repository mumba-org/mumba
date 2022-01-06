// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Javascript

public protocol WebLocalFrameClient : WebFrameClient {

    var bluetooth: WebBluetooth? { get }
    var usbClient: WebUSBClient? { get }
    var permissionClient: WebPermissionClient? { get }
    var webVRClient: WebVRClient? { get }
    var userMediaClient: WebUserMediaClient? { get } 
    var encryptedMediaClient: WebEncryptedMediaClient? { get }
    var webMIDIClient: WebMIDIClient? { get }
    var appBannerClient: WebAppBannerClient? { get }
    var wakeLockClient: WebWakeLockClient? { get }
    var geolocationClient: WebGeolocationClient? { get }
    var pushClient: WebPushClient? { get } 
    var shouldSearchSingleFrame: Bool { get }
    var handleCurrentKeyboardEvent: Bool { get }
    var shouldBlockWebGL: Bool { get }
    var visibilityState: WebPageVisibilityState { get }
    var routingId: Int { get }

    func bindToFrame(frame: WebLocalFrame)
    
    func createPlugin(params: WebPluginParams) -> WebPlugin?

    func createMediaPlayer(
        url: String, 
        client: WebMediaPlayerClient, 
        encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
        module: WebContentDecryptionModule?, 
        sinkId: String) -> WebMediaPlayer?

    func createMediaPlayer(
        descriptor: MediaStreamDescriptor,
        client: WebMediaPlayerClient, 
        encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
        module: WebContentDecryptionModule?, 
        sinkId: String) -> WebMediaPlayer?

    func createMediaSession() -> WebMediaSession?

    func createApplicationCacheHost(frame: WebFrame?, client: WebApplicationCacheHostClient?) -> WebApplicationCacheHost?

    func createServiceWorkerProvider(frame: WebFrame?) -> WebServiceWorkerProvider?

    func createWorkerContentSettingsClientProxy(frame: WebFrame?) -> WorkerContentSettingsClientProxy?

    func createExternalPopupMenu(info: WebPopupMenuInfo, client: WebExternalPopupMenuClient?) -> WebExternalPopupMenu?

    func cookieJar(frame: WebFrame) -> WebCookieJar?

    func canCreatePluginWithoutRenderer(mimeType: String) -> Bool

    func findFrame(name: String) -> WebFrame?

    func loadErrorPage(reason: Int)

    func allowContentInitiatedDataUrlNavigations(url: String) -> Bool

    func willCommitProvisionalLoad()

    func didChangeFramePolicy(childFrame: WebFrame?, flags: Int)

    func didSetFramePolicyHeaders()

    func didAddContentSecurityPolicies()

    func setHasReceivedUserGesture()
     
    func setHasReceivedUserGestureBeforeNavigation(_: Bool)

    func downloadURL(urlRequest: WebURLRequest)

    func didAccessInitialDocument(frame: WebFrame)

    func createChildFrame(parent: WebFrame, 
        type: WebTreeScopeType, 
        name: String, 
        flags: WebSandboxFlags, 
        properties: WebFrameOwnerProperties) -> WebFrame?

    //func willClose()
    func didEnforceInsecureRequestPolicy()
    func didEnforceInsecureNavigationsSet()
    func runScriptsAtDocumentElementAvailable()
    func runScriptsAtDocumentReady(documentIsEmpty: Bool)
    func runScriptsAtDocumentIdle()
    func didChangeName(name: String)
    func didChangeSandboxFlags(child: WebFrame, flags: WebSandboxFlags)
    func didChangeFrameOwnerProperties(child: WebFrame, properties: WebFrameOwnerProperties)
    func didMatchCSS(frame: WebFrame, newlyMatchingSelectors: [String], stoppedMatchingSelectors: [String]) 
    func shouldReportDetailedMessageForSource(source: String) -> Bool
    func didAddMessageToConsole(message: WebConsoleMessage, sourceName: String, sourceLine: Int, stackTrace: String)
    func loadURLExternally(request: WebURLRequest, policy: WebNavigationPolicy, downloadName: String, shouldReplaceCurrentEntry: Bool)
    func decidePolicyForNavigation(info: WebFrameNavigationPolicyInfo) -> WebNavigationPolicy
    func hasPendingNavigation() -> Bool
    func didStartLoading(toDifferentDocument: Bool)
    func didStopLoading()
    func didChangeLoadProgress(loadProgress: Double)
    func willSendSubmitEvent(frame: WebFrame, element: WebFormElement)
    func willSubmitForm(frame: WebFrame, element: WebFormElement)
    func didCreateDataSource(frame: WebFrame, data: WebDataSource)
    func didStartProvisionalLoad(loader: WebDocumentLoader?, urlRequest: WebURLRequest)
    func didReceiveServerRedirectForProvisionalLoad(frame: WebFrame)
    func didFailProvisionalLoad(error: WebURLError, type: WebHistoryCommitType)
    func didCommitProvisionalLoad(item: WebHistoryItem, type: WebHistoryCommitType)
    func didCreateNewDocument()
    func didClearWindowObject()
    func didCreateDocumentElement()
    func didCreateDocumentLoader(loader: WebDocumentLoader)
    func didReceiveTitle(frame: WebFrame, title: String, direction: TextDirection)
    func didChangeIcon(frame: WebFrame, type: WebIconUrlType)
    func didFinishDocumentLoad()
    func didHandleOnloadEvents()
    func didFailLoad(error: WebURLError, type: WebHistoryCommitType)
    func didFinishLoad()
    func didNavigateWithinPage(frame: WebFrame, item: WebHistoryItem, type: WebHistoryCommitType, contentInitiated: Bool)
    func didUpdateCurrentHistoryItem(frame: WebFrame)
    func didChangeManifest(frame: WebFrame)
    func didChangeThemeColor()
    func forwardResourceTimingToParent()
    func didBlockFramebust(url: String)
    func abortClientNavigation()
    func didChangeContents()
    func dispatchLoad()
    func requestNotificationPermission(origin: WebSecurityOrigin, callback: WebNotificationPermissionCallback)
    func didChangeSelection(isSelectionEmpty: Bool)
    func frameRectsChanged(rect: IntRect)

    func createColorChooser(client: WebColorChooserClient?,
        color: Color,
        suggestion: [WebColorSuggestion]) -> WebColorChooser?

    func runModalAlertDialog(message: String)

    func runModalConfirmDialog(message: String) -> Bool

    func runModalPromptDialog(
        message: String, defaultValue: String,
        actualValue: String) -> Bool

    func runModalBeforeUnloadDialog(isReload: Bool) -> Bool//, message: String) -> Bool

    func showContextMenu(data: WebContextMenuData)

    func clearContextMenu()

    func willSendRequest(
        frame: WebFrame, 
        request: WebURLRequest)
    
    func didReceiveResponse(
        frame: WebFrame,     
        response: WebURLResponse)

    func didChangeResourcePriority(
        frame: WebFrame, identifier: Int, priority: WebURLRequest.Priority, n: Int)

    func didFinishResourceLoad(frame: WebFrame, identifier: Int)

    func didLoadResourceFromMemoryCache(frame: WebFrame, request: WebURLRequest, response: WebURLResponse)

    func didDisplayInsecureContent()

    func didRunInsecureContent(origin: WebSecurityOrigin, insecureURL: String)

    func didDetectXSS(url: String, didBlockEntirePage: Bool)

    func didDispatchPingLoader(frame: WebFrame, url: String)

    func didChangePerformanceTiming()

    //func didAbortLoading()

    func didCreateScriptContext(context: JavascriptContext, worldId: Int)

    func willReleaseScriptContext(context: JavascriptContext, worldId: Int)

    func didChangeScrollOffset()

    func willInsertBody(frame: WebFrame)

    func reportFindInPageMatchCount(identifier: Int, count: Int, finalUpdate: Bool)

    func reportFindInFrameMatchCount(identifier: Int, count: Int, finalUpdate: Bool)

    func reportFindInPageSelection(identifier: Int, activeMatchOrdinal: Int, selection: IntRect)

    func requestStorageQuota(
        frame: WebFrame, type: WebStorageQuotaType,
        newQuotaInBytes: Int64,
        callbacks: WebStorageQuotaCallbacks)

    func willOpenWebSocket(socket: WebSocket)

    func willStartUsingPeerConnectionHandler(frame: WebFrame, handler: WebRTCPeerConnectionHandler)

    func willCheckAndDispatchMessageEvent(
        sourceFrame: WebFrame,
        targetFrame: WebFrame,
        target: WebSecurityOrigin,
        event: WebDOMMessageEvent) -> Bool

    func userAgentOverride(frame: WebFrame) -> String
    
    func doNotTrackValue(frame: WebFrame) -> String

    func allowWebGL(frame: WebFrame, defaultValue: Bool) -> Bool

    func didLoseWebGLContext(frame: WebFrame, context: Int)

    func postAccessibilityEvent(object: WebAXObject, event: WebAXEvent)

    func handleAccessibilityFindInPageResult(
        identifier: Int,
        matchIndex: Int,
        startObject: WebAXObject,
        startOffset: Int,
        endObject: WebAXObject,
        endOffset: Int)

    func isControlledByServiceWorker(source: WebDataSource) -> Bool

    func serviceWorkerId(source: WebDataSource) -> Int64

    func enterFullscreen() -> Bool
    func exitFullscreen() -> Bool

    func suddenTerminationDisablerChanged(present: Bool, type: WebFrameSuddenTerminationDisablerType)
    func registerProtocolHandler(scheme: String, url: String, title: String)
    func unregisterProtocolHandler(scheme: String, url: String)
    func isProtocolHandlerRegistered(scheme: String, url: String) ->  WebCustomHandlersState
    func saveImageFromDataURL(url: String)
    func didContainInsecureFormAction()
    func didDisplayContentWithCertificateErrors()
    func draggableRegionsChanged()
    func didRunContentWithCertificateErrors()
    func scrollRectToVisibleInParentFrame(_: IntRect)
}
