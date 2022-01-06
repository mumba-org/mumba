// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Text
import Graphics
import Compositor
import Web
import Javascript
import MumbaShims

public protocol UIWebWindowDelegate : UIWindowDelegate {
  func willHandleMouseEvent(event: WebMouseEvent)
  func willHandleGestureEvent(event: WebGestureEvent)
  func willHandleKeyEvent(event: WebKeyboardEvent)
  func setActive(active: Bool)
  func setBackgroundOpaque(opaque: Bool)
  func didStartLoading()
  func didStopLoading()
}

open class UIWebWindow : UIWindow,
                         UIDispatcherDelegate,
                         UIWebWindowCompositorDelegate,
                         UIWindowInputHandlerDelegate,
                         UIWindowMouseLockDispatcherDelegate,
                         WebWidgetClient,
                         WebViewClient {

  internal enum PaintFlags : Int32 {
    case ResizeAck = 1
    case RepaintAck = 4
  }

  // UIWindow impl
  public var cursorVisibility: Bool = true
  public var textDirection: TextDirection = TextDirection.LeftToRight
  public var isInert: Bool = false
  public var isActive: Bool = true
  public private(set) var selectionRange: TextRange?
  public var contentsPreferredMinimumSize: IntSize {
    return IntSize()
  }
  public var deviceScaleFactor: Float = 1.0
  public var isSelectionAnchorFirst: Bool {
    return false
  }

  public var isSwappedOut: Bool {
    didSet {
      if isSwappedOut {
        application!.addRefProcess()
      }
    }
  }

  public var screenInfo: ScreenInfo = ScreenInfo()
  public var originalScreenInfo: ScreenInfo {
    //if let sme = screenMetricsEmulator {
    //  return sme.originalScreenInfo
    //}
    return screenInfo
  }

  public var contentSourceId: UInt32 {
    return currentContentSourceId
  }

  public var nextPaintIsResizeAck: Bool {
    return (nextPaintFlags & PaintFlags.ResizeAck.rawValue) != 0
  }

  public var viewportVisibleRect: IntRect {
    return IntRect(size: compositorViewportPixelSize)
  }

  public var isHidden: Bool {
    didSet {
      guard oldValue != isHidden else {
        return
      }
      // 
      // RendererWindowTreeClient.get().isVisible = !isHidden

      if self.isHidden {
        //print("\n\napplicationInstance.windowHidden()\n\n")
        application!.windowHidden()
        firstUpdateVisualStateAfterHidden = true
      } else {
        //print("\n\napplicationInstance.windowRestored()\n\n")
        application!.windowRestored()      
      }
      
      //if let schedulingState = renderUIWindowSchedulingState {
      //  schedulingState.isHidden = isHidden
      //}
    }
  }

  public var inputMethodController: WebInputMethodController? {
    //if let widget = webFrameWidget {
    if let frame = mainFrame?.frame {
      //return widget.activeWebInputMethodController
      return frame.inputMethodController
    }
    return nil
  }

  // WebWidgetClient
  public var windowRect: IntRect { 
    get {
      if pendingWindowRectCount > 0 {
        return pendingWindowRect
      }
      return windowScreenRect
    }
    set {

    }
  }
  
  public var viewRect: IntRect {
    return viewScreenRect
  }

  public var layerTreeView: WebLayerTreeView? {
    return compositor!
  }
  
  public var allowsBrokenNullLayerTreeView: Bool {
    return false
  }

  public var focusedLocalFrameInWidget: WebLocalFrame? {
    if let widget = webFrameWidget {
      return widget.focusedLocalFrameInWidget
    }
    return nil
  }

  // WebViewClient

  public var acceptLanguages: String {
    return String()
  }
  
  public var acceptsLoadDrops: Bool {
    return true
  }

  public var shouldHandleImeEvents: Bool {
    return webWidget != nil && webWidget!.isWebFrameWidget && hasFocus
  }
  
  public var historyBackListCount: Int {
    //print("UIWebWindow.historyBackListCount -> 0")
    return 0
  }
  
  public var historyForwardListCount: Int {
    //print("UIWebWindow.historyForwardListCount -> 0")
    return 0
  }
  
  public var canHandleGestureEvent: Bool {
    //print("UIWebWindow.canHandleGestureEvent -> returning false")
    return true
  }
  
  public var canUpdateLayout: Bool {
    //print("UIWebWindow.canUpdateLayout -> returning true")
    return true
  }
  
  public var sessionStorageNamespaceId: String {
    return String()
  }
  
  public var rootWindowRect: IntRect {
    return windowRect
  }

  public var isFocused: Bool {
    guard let view = webView else {
      return false
    }
    return view.hasFocusedFrame
  }

  public var isPointerLocked: Bool {
    return mouseLockDispatcher.isMouseLockedTo(target: self.mouseLockTarget)
  }

  // UIWebHostCompositorDelegate
  public var isClosing: Bool {
   return hostIsClosing
  }

  public var suppressNextCharEvents: Bool = false

  public weak var delegate: UIWebWindowDelegate?

  public var hasTouchEventHandlers: Bool {
    didSet {
      if hasTouchEventHandlers == oldValue {
        return
      }
      //if let schedulingState = renderUIWindowSchedulingState {
      //  schedulingState.setHasTouchHandler(hasTouchEventHandlers)
      //}
      sendHasTouchEventHandlers(hasHandlers: hasTouchEventHandlers)
    }
  }

  public var nextRoutingId: Int {
    _nextRoutingId += 1
    return _nextRoutingId
  }

  public var webFrameWidget: WebFrameWidget? {
    guard let widget = webWidget else {
      return nil
    }

    if !widget.isWebFrameWidget {
      assert(false)
      return nil
    }

    return (widget as? WebFrameWidget)
  }

  public var mainWebFrame: WebLocalFrame? {
    return mainFrame?.frame
  }
  
  public private(set) var observers: ContiguousArray<UIWindowObserver>
  public private(set) var possibleDragEventInfo: DragEventSourceInfo
  public private(set) var webWidget: WebWidget?
  public private(set) var viewScreenRect: IntRect = IntRect()
  public private(set) var windowScreenRect: IntRect = IntRect()
  public private(set) var pendingWindowRectCount: Int = 0 
  public private(set) var pendingWindowRect: IntRect = IntRect()
  public private(set) var compositor: UIWebWindowCompositor?
  public private(set) var zoomLevel: Double = 1.0
  public private(set) var size: IntSize = IntSize()
  public private(set) var compositorViewportPixelSize: IntSize = IntSize()
  public private(set) var webView: WebView?

  internal var didShow: Bool = false

  // the webframe (at least top/main)
  // TODO: find a better way for this.. A PageManager(or FrameManager) perhaps
  public private(set) var mainFrame: UIWebFrame?
  // note: even the main should be 'owned' here on the array
  // while 'mainFrame' must be a reference to it.. 
  // TODO: create a 'currentFrame' that can represent Local and Remote frames
  private var frames: ContiguousArray<UIWebFrame>
  private var frameProxies: ContiguousArray<UIWebFrameProxy>
  private var _nextRoutingId: Int = 0
  private var initialRect: IntRect = IntRect()
  private var visibleViewportSize: IntSize = IntSize()
  private var autoResizeMode: Bool = false
  private var minSizeForAutoResize: IntSize = IntSize()
  private var maxSizeForAutoResize: IntSize = IntSize()
  private var compositorNeverVisible: Bool = false
  //private var isSwappedOut: Bool = false
  private var compositorVisibleRect: IntRect = IntRect()
  private var preferredSize: IntSize = IntSize()
  private var focusUrl: String = String()
  private var targetUrl: String = String()
  private var displayMode: WebDisplayMode = WebDisplayMode.Undefined
  private var childLocalSurfaceIdAllocator: LocalSurfaceIdAllocator
  private var compositorInitialized: Bool = false
  private var firstUpdateVisualStateAfterHidden = false
  private var nextPaintFlags: Int32 = 0
  private var nextPreviousFlags: TextInputFlags = TextInputFlags.None
  private var localSurfaceIdFromParent: LocalSurfaceId
  //private var latencyInfoSwapPromiseMonitor: LatencyInfoSwapPromiseMonitor?
  private var textInputType: WebTextInputType 
  private var textInputMode: WebTextInputMode
  private var textInputInfo: WebTextInputInfo
  private var canComposeInline: Bool = true
  private var compositionRange: TextRange
  private var compositionCharacterBounds: [IntRect]
  private var selectionFocusRect: IntRect
  private var selectionAnchorRect: IntRect
  private var currentCursor: WebCursorInfo
  private var isUseZoomForDSFEnabled: Bool = false
  private var sendPreferredSizeChanges: Bool = false
  private var textInputFlags: TextInputFlags = TextInputFlags.None
  private let focusController: FocusController
  private var mouseLockTarget: MouseLockDispatcherLockTarget
  private var lastCaptureSequenceNumber: UInt32 = 0
  private var hasFocus: Bool = false
  private var imeAcceptEvents: Bool = true
  private var currentContentSourceId: UInt32 = 0
  private var needResizeAckForAutoResize = false
  private var hostIsClosing: Bool = false
  private var wasShownTime: TimeTicks = TimeTicks()
  private var monitorCompositionInfo: Bool = false
  private var isFullscreenGranted: Bool = false
  private var isFirstVisualPropertySynchronization: Bool = true
  // for now this is not working.. we need to get this from the launching cmd line
  // we are using this on the frame sink id, so if we dont fix it
  // we will get collisions and probably gpu/viz invalidations along the way
  private var routingId: UInt32 = 0
  public var editCommands: [String : String]
  private var mouseLockDispatcher: UIWindowMouseLockDispatcher!
  private var inputHandler: UIWindowInputHandler!
  private var windowInputHandlerManager: UIWindowInputHandlerManager
  private var forceRedrawSwapPromise: AlwaysDrawSwapPromise?
  private var wasShownSwapPromiseMonitor: LatencyInfoSwapPromiseMonitor?
  // from WindowHost
  private var closing = false
  private var pageWasShown: Bool = false
  private var lastWindowScreenRect: IntRect?
  private var disableScrollbarsSizeLimit: IntSize = IntSize()
  private var initialized: Bool
  private var firstVisualPropertiesReceived: Bool
  private var firstNavigation: Bool
  private var isHeadless: Bool
  
  private weak var application: UIApplication?
  internal let dispatcher: UIDispatcher
  
  public init(application: UIApplication, dispatcher: UIDispatcher, delegate: UIWebWindowDelegate, headless: Bool, swappedOut: Bool = false) {
    initialized = false
    firstVisualPropertiesReceived = false
    firstNavigation = true
    observers = ContiguousArray<UIWindowObserver>()
    isSwappedOut = swappedOut
    isHeadless = headless
    self.delegate = delegate
    self.application = application
    self.dispatcher = dispatcher
    frames = ContiguousArray<UIWebFrame>()
    frameProxies = ContiguousArray<UIWebFrameProxy>()
    childLocalSurfaceIdAllocator = LocalSurfaceIdAllocator()
    localSurfaceIdFromParent = LocalSurfaceId()
    screenInfo = ScreenInfo()
    compositorViewportPixelSize = IntSize()
    compositorVisibleRect = IntRect()
    visibleViewportSize = IntSize()
    initialRect = IntRect()
    viewScreenRect = IntRect()
    windowScreenRect = IntRect()
    focusController = FocusController()
    textInputType = WebTextInputType.None 
    textInputMode = WebTextInputMode.Default
    textInputInfo = WebTextInputInfo()
    compositionRange = TextRange()
    compositionCharacterBounds = [IntRect]()
    selectionFocusRect = IntRect()
    selectionAnchorRect = IntRect()
    mouseLockTarget = LameMouseLockTarget()
    currentCursor = WebCursorInfo()
    editCommands = [:]
    windowInputHandlerManager = UIWindowInputHandlerManager()
    routingId = UInt32(application.routingId)
    possibleDragEventInfo = DragEventSourceInfo()
    hasTouchEventHandlers = true
    isHidden = true    
    didShow = false
    inputHandler = UIWindowInputHandler(delegate: self)
    mouseLockDispatcher = UIWindowMouseLockDispatcher(delegate: self)
    self.dispatcher.delegate = self

    if !swappedOut {
      self.application!.addRefProcess()
    }
  }

  public static func createWebFrameWidget(client: WebWidgetClient, frame: WebLocalFrame) -> WebFrameWidget {
    return WebFrameWidget.create(client: client, frame: frame)
  }

  private func initializeInternal() {
    let _ = initializeLayerTreeView()
    webView = WebView(client: self, visibility: isHidden ? WebPageVisibilityState.Hidden : WebPageVisibilityState.Visible, opener: nil)
    
    // NOTE: this is done(pre-fixed) on the runtime layer

    //webView!.setDisplayMode(mode: WebDisplayMode.Browser)
    
    //webView!.settings.isThreadedScrollingEnabled = true
    //webView!.setShowFPSCounter(show: true)
    //applyWebPreferencesInternal(webkitPreferences, webview(), compositor_deps_)
    //applyBlinkSettings(webview.settings)
    didShow = true
    //onSetRendererPrefs(params.rendererPreferences)
    application!.windowCreated()

    // this is a trick to make media elements work independently
    // if online or not
    // NOTE: a better/proper way should be found
    //print("\n\n forcing onNetworkConnectionChanged() to online \n\n")
    onNetworkConnectionChanged(
      connectionType: NetworkConnectionType.Ethernet, 
      maxBandwidthMbps: 10000.0)

    initialized = true
  }

  public func initializeVisualProperties(params: VisualProperties) {
    if firstVisualPropertiesReceived {
      return
    }
    // its important to set this here, because we will call 
    // onSynchronizeVisualProperties and as this method might get called 
    // from onSynchronizeVisualProperties by checking this flag
    // we will incur into a stack overflow midtke
    firstVisualPropertiesReceived = true
    if let parentSurfaceId = params.localSurfaceId { 
      localSurfaceIdFromParent = parentSurfaceId
    }
    screenInfo = params.screenInfo
    compositorViewportPixelSize = params.compositorViewportPixelSize
    compositorVisibleRect = IntRect(size: params.visibleViewportSize)
    visibleViewportSize = params.visibleViewportSize
    initialRect = IntRect(size: params.newSize)
    viewScreenRect = IntRect(size: params.newSize)
    windowScreenRect = IntRect(size: params.newSize)
    
    if !initialized {
      //print(" initializeVisualProperties: initializing compositor")
      initializeInternal()
    }

    mainFrame = UIWebFrame(window: self, params: params, routingId: nextRoutingId, isMainFrame: true)
    let widget = UIWebWindow.createWebFrameWidget(
                  client: self,
                  frame: mainFrame!.frame!)
    initializeWidget(
      webWidget: widget
    )
    
    onSynchronizeVisualProperties(params: params)
    updateWebViewWithDeviceScaleFactor()
    application!.sendWindowCreatedAck()

    // to be the last (was on UIWindowHost)
    if pageWasShown {
      onPageWasShown()
    }
    if let windowRect = lastWindowScreenRect {
      onUpdateWindowScreenRect(windowRect)      
    }
  }

  public func initializeWidget(webWidget: WebWidget) {
    // input_handler_ = std::make_unique<RenderUIWindowInputHandler>(this, this);

    // RenderThreadImpl* render_thread_impl = RenderThreadImpl::current();

    // widget_input_handler_manager_ = UIWindowInputHandlerManager::Create(
    //     weak_ptr_factory_.GetWeakPtr(),
    //     render_thread_impl && compositor_
    //         ? render_thread_impl->compositor_task_runner()
    //         : nullptr,
    //     render_thread_impl ? render_thread_impl->GetWebMainThreadScheduler()
    //                        : nullptr);

    // show_callback_ = show_callback;

    // webwidget_internal_ = web_widget;
    // webwidget_mouse_lock_target_.reset(
    //     new WebWidgetLockTarget(webwidget_internal_));
    // mouse_lock_dispatcher_.reset(new RenderUIWindowMouseLockDispatcher(this));

    // RenderThread::Get()->AddRoute(routing_id_, this);
    // // Take a reference on behalf of the RenderThread.  This will be balanced
    // // when we receive ViewMsg_lose.
    // AddRef();
    // if (RenderThreadImpl::current()) {
    //   RenderThreadImpl::current()->UIWindowCreated();
    //   if (is_hidden_)
    //     RenderThreadImpl::current()->UIWindowHidden();
    // }
    
    //if isHidden {
    //  application!.windowHidden()      
    //}
    self.webWidget = webWidget
  }

  // TODO: see how we can bind this better with Web
  // UIWebFrameDelegate
  public func setTextureLayerForHTMLCanvas(target: String, layer: Compositor.Layer, frame: UIWebFrame?) {
    target.withCString {
      _WindowSetTextureLayerForCanvas(dispatcher.state, $0, layer.reference)
    }
  }

  public func addObserver(_ observer: UIWindowObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: UIWindowObserver) {
    for (i, cur) in observers.enumerated() {
      if observer === cur {
        observers.remove(at: i)
      }
    }
  }

  public func beginNavigation(_ info: NavigationInfo) {
    //print("UIWebWindow: beginNavigation. NOT IMPLEMENTED")
  }

  public func didNavigate() {
    currentContentSourceId += 1
    compositor!.setContentSourceId(currentContentSourceId)
    compositor!.clearCachesOnNextCommit();

    //updateSurfaceAndScreenInfo(LocalSurfaceId(),
    //                           self.compositorViewportPixelSize, self.screenInfo)

    // If surface synchronization is on, navigation implicitly acks any resize
    // that has happened so far so we can get the next VisualProperties containing
    // the LocalSurfaceId that should be used after navigation.
    //if compositor!.isSurfaceSynchronizationEnabled && !autoResizeMode && nextPaintIsResizeAck {
    //  resetNextPaintIsResizeAck()
    //}
  }

  // UIWindow impl
  public func mouseCaptureLost() {
    if let widget = webWidget {
      widget.mouseCaptureLost()
    }
  }

  public func recordWheelAndTouchScrollingCount() {}
  public func resize(to: IntSize) {
    self.size = to
    resizeWebWidget()
  }
  public func resizeVisualViewport(to: IntSize) {
    if let widget = webWidget {
      widget.resizeVisualViewport(size: to)
    }
  }
  public func close() {
    sendCloseAck()
    application!.exit()
  }
  public func showContextMenu(sourceType: MenuSourceType, location: IntPoint) {
    //print("UIWebWindow.showContextMenu")
  }
  public func setRemoteViewportInserction(intersection: IntRect) {}
  public func updateRenderThrottlingStatus(throttling: Bool) {}
  public func dragTargetDragEnter(
    dropData: [DropData.Metadata],
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) -> DragOperation {
    return DragOperation.DragNone
  }
  
  public func dragTargetDragOver(
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) -> DragOperation {
    return DragOperation.DragNone
  }

  public func dragTargetDragLeave(clientPoint: FloatPoint, screenPoint: FloatPoint) {}
  public func dragTargetDrop(dropData: DropData,
                      client: FloatPoint,
                      screen: FloatPoint,
                      keyModifiers: Int) {}
  public func dragSourceEndedAt(
    client: FloatPoint,
    screen: FloatPoint,
    dragOperations: DragOperation) {}
  public func dragSourceSystemDragEnded() {}
  
  public func didEnterFullscreen() {
    sendEnterFullscreen()
  }
  public func didExitFullscreen() {
    sendExitFullscreen()
  }
  
  public func getSelectionTextDirection(focus: inout TextDirection, anchor: inout TextDirection) {
    if let frame = focusedLocalFrameInWidget {
      let _ = frame.selectionTextDirection(start: &focus, end: &anchor)
    }
  }
  
  public func setPageScaleFactor(pageScaleFactor: Float) {}
  public func setInitialFocus(reverse: Bool) {}
  public func hidePopups() {}
  public func didAcquirePointerLock() {}
  public func didNotAcquirePointerLock() {}
  public func didLosePointerLock() {}

  public func onSelectWordAroundCaret() {
    //print("UIWebWindow.onSelectWordAroundCaret")
    inputHandler.handlingInputEvent = true
    let _ = selectWordAroundCaret()
    inputHandler.handlingInputEvent = false
  }
  
  public func selectWordAroundCaret() -> Bool {
    var startAdjust: Int = 0
    var endAdjust: Int = 0
    let didSelect = mainFrame!.selectWordAroundCaret(start: &startAdjust, end: &endAdjust)
    sendSelectWordAroundCaretAck(didSelect: didSelect, start: startAdjust, end: endAdjust)
    return didSelect
  }
  
  // TODO: check if this is right, because both swapIn and swapOut
  //       are calling mainFrame.swap() in the end

  public func swapOut(windowId: Int32, loading: Bool) -> Bool {
    guard let frame = mainFrame else {
      return false
    }
    return frame.swapOut(windowId: windowId, loading: loading)
  }

  public func wasSwappedOut() {
    application!.releaseProcess()
  }
  
  public func swapIn() -> Bool {
    guard let frame = mainFrame else {
      return false
    }
    return frame.swapIn()
  }

  //public func selectionTextDirection(focus: TextDirection, anchor: TextDirection) {}

  public func onShowContextMenu(type: MenuSourceType, location: IntPoint) {
    //print("UIWebWindow.onShowContextMenu")
  }

  public func updateViewWithDeviceScaleFactor() {}

  // called on UIWindowHost.onFrameDelete()
  public func detach() {
    if let frame = mainFrame {
      frame.detach()
    }
  }

  public func stop() {
    if let frame = mainFrame {
      frame.stop()
    }
  }
  
  public func clientDroppedNavigation() {
    if let frame = mainFrame {
      frame.clientDroppedNavigation()
    }
  }

  public func collapse(collapsed: Bool) {
    if let frame = mainFrame {
      frame.collapse(collapsed: collapsed)
    }
  }
  
  public func contextMenuClosed() {
    if let frame = mainFrame {
      frame.didCloseContextMenu()
    }
  }
  
  public func customContextMenuAction(action: UInt32) {
    if let frame = mainFrame {
      frame.performCustomContextMenuAction(action: UInt(action))
    }
  }

  public func copyImage(at: IntPoint) {
    if let frame = mainFrame {
      frame.copyImage(at: IntPoint())
    }
  }
  
  public func saveImage(at: IntPoint) {
    if let frame = mainFrame {
      frame.saveImage(at: IntPoint())
    }
  }

  public func advanceFocus(type: WebFocusType, sourceRoutingId: Int32) {
    if let frame = mainFrame {
      frame.advanceFocus(reverse: type == WebFocusType.Backward)
    }
  }
  
  public func advanceFocusInForm(type: WebFocusType) {
    guard let frame = mainFrame else {
      return
    }
    // TODO: Check if this really works as intended,
    //       and uncomment, because only the native reference
    //       are the same, but the swift wrapper might be different
    //       so this will always return false as it will not compare
    //       the internal references to the native objects but the wrappers
    
    //guard webView!.focusedFrame === frame else {
    //  return
    //}

    frame.advanceFocusInForm(type: type)
  }

  public func setFocusedFrame() {
    if let frame = mainFrame {
      frame.focusDocumentView()
    }
  }

  public func checkCompleted() {
    if let frame = mainFrame {
      frame.checkCompleted()
    } 
  }

  public func reload(bypassCache: Bool) {
    print("UIWebWindow.reload")
    if let frame = mainFrame {
      frame.reload(bypassCache: bypassCache)
    }
  }

  public func textSurroundingSelectionRequest(maxLength: UInt32) {
    if let frame = mainFrame {
      frame.textSurroundingSelectionRequest(maxLength: maxLength)
    }
  }

  public func onDidStartLoading() {
    print("UIWebWindow.onDidStartLoading")
    if let d = delegate {
      d.didStartLoading()
    }
  }
  public func onDidStopLoading() {
    print("UIWebWindow.onDidStopLoading")
    if let d = delegate {
      d.didStopLoading()
    }
  }

  public func updateOpener(openerId: UInt32) {
    if let opener = resolveOpener(openerId: openerId), let frame = mainFrame {
      frame.setOpener(opener)
    }
  }

  public func focusChangeComplete() {
    guard let widget = webFrameWidget else {
      return
    }

    if let focusedFrame = widget.localRoot?.view.focusedFrame {
      focusedFrame.autofillClient?.didCompleteFocusChangeInFrame()
    }

  }

  public func cursorVisibilityChanged(visible: Bool) {
    //print("UIWebWindow.cursorVisibilityChanged")
    if let widget = webWidget {
      widget.setCursorVisibilityState(visible: visible)
    }
  }

  public func setEditCommandsForNextKeyEvent(
    editCommandName: [String],
    editCommandValue: [String],
    editCommandCount: Int) {
    //print("UIWebWindow.setEditCommandsForNextKeyEvent")
    for i in 0..<editCommandCount {
      editCommands[editCommandName[i]] = editCommandValue[i]
    }
  }
  public func imeSetComposition( 
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange, 
    selectionStart: Int,
    selectionEnd: Int) {
    //print("UIWebWindow.imeSetComposition")
    guard shouldHandleImeEvents else {
      return
    }
    defer {
      updateCompositionInfo(false /* not an immediate request */)
      updateSelectionBounds()
    }

    guard let controller = inputMethodController else {
      sendImeCancelComposition()
      return
    }

    if !controller.setComposition(
          text: text, 
          spans: spans,
          replacement: replacement,
          selectionStart: selectionStart, 
          selectionEnd: selectionEnd) {
      // If we failed to set the composition text, then we need to let the host
      // process to cancel the input method's ongoing composition session, to make
      // sure we are in a consistent state.
      sendImeCancelComposition()
    }
  }

  public func imeCommitText(
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    relativeCursorPosition: Int) {
    //print("UIWebWindow.imeCommitText")
    guard shouldHandleImeEvents else {
      return
    }
    defer {
      updateSelectionBounds()
    }
    inputHandler.handlingInputEvent = true
    if let controller = inputMethodController {
      let _ = controller.commitText(
        text: text, 
        spans: spans,
        replacement: replacement,
        caretPosition: relativeCursorPosition)
    }
    inputHandler.handlingInputEvent = false
    updateCompositionInfo(false /* not an immediate request */)
  }

  public func imeFinishComposingText(keepSelection: Bool) {
    //print("UIWebWindow.imeFinishComposingText")
    guard shouldHandleImeEvents else {
      return
    }
    
    defer {
      updateSelectionBounds()
    }

    inputHandler.handlingInputEvent = true
    if let controller = inputMethodController {
      let _ = controller.finishComposingText(
        selectionBehavior: (keepSelection ? .KeepSelection : .DoNotKeepSelection))
    }
    inputHandler.handlingInputEvent = false
    updateCompositionInfo(false /* not an immediate request */)
  }

  public func scrollRectToVisible(rect: IntRect) {
    //print("UIWebWindow.scrollRectToVisible")
  }

  public func didUpdateOrigin(origin: String) {}

  public func requestTextInputStateUpdate() {
    //print("UIWebWindow.requestTextInputStateUpdate")
#if os(Android)
    updateSelectionBounds()
    updateTextInputStateInternal(true /* reply_to_request */)
#endif
  }

  public func requestCompositionUpdates(immediateRequest: Bool, monitorRequest: Bool) {
    //print("UIWebWindow.requestCompositionUpdates")
    monitorCompositionInfo = monitorRequest
    guard immediateRequest else {
      return
    }
    updateCompositionInfo(true /* immediate request */);
  }

  public func onEvent(event: WebInputEvent) -> InputEventAckState {
    //print("UIWebWindow.onEvent")
    var processed = WebInputEvent.Result.notHandled
    if event.isKeyboardEvent {
      let keyEvent = event.asKeyboardEvent()
      //print("keyboard event: domKey: \(keyEvent.domKey) text: \(keyEvent.text) windowsKeyCode: \(keyEvent.windowsKeyCode) domCode: \(keyEvent.domCode)")
      let _ = willHandleKeyEvent(event: keyEvent)
      // if keyEvent.domKey == 4194312 {
      //   //print("sending 'Delete' command")
      //   let result = mainFrame!.frame!.executeCommand(command: "DeleteBackward")
      //   //print("'Delete' command -> \(result)")
      // }
    } else if event.isMouseEvent {
      let mouseEvent = event.asMouseEvent()
      let _ = willHandleMouseEvent(event: mouseEvent)
    } else if event.isGestureEvent {
      let gestureEvent = event.asGestureEvent()
      let _ = willHandleGestureEvent(event: gestureEvent)
    }

    if event.type != WebEventType.Char || !suppressNextCharEvents {
      suppressNextCharEvents = false
      if webWidget != nil && processed == WebInputEvent.Result.notHandled {
        processed = webWidget!.handleInputEvent(inputEvent: event)
      }
    }

    let isKeyboardShortcut: Bool =
        event.type == WebEventType.RawKeyDown &&
        event.asKeyboardEvent().isBrowserShortcut

    if processed == WebInputEvent.Result.notHandled && isKeyboardShortcut {
      //print("Event NotHandled and isKeyboardShortcut = true -> suppressNextCharEvents = true")
      suppressNextCharEvents = true
    }

    //if processed == WebInputEvent.Result.handledSuppressed && event.isKeyboardEvent {
    //  //print("Event handledSuppressed and key event. passing out to editor")
    //  let editor = mainFrame!.frame!.editor
    //  let result = editor.handleKeyboardEvent(event.asKeyboardEvent())
    //  //print("Editor returned \(result)")
    //}
    
    //print("UIWebWindow.onEvent: handleInputEvent(event) -> WebInputEvent.Result = \(processed) ")
    return InputEventAckState.fromWebInputEvent(processed)
  }
  public func onNonBlockingEvent(event: WebInputEvent) {
    //print("UIWebWindow.onNonBlockingEvent")
  }
  public func setCompositionFromExistingText(
    start: Int, 
    end: Int,
    spans: [WebImeTextSpan]) {
    //print("UIWebWindow.setCompositionFromExistingText")

    guard let webFrame = mainFrame?.frame else {
      return
    }

    webFrame.setCompositionFromExistingText(
      compositionStart: start, 
      compositionEnd: end, 
      spans: spans)

    updateSelectionBounds()
  }
  
  public func willEnterFullscreen() {
    print("UIWebWindow.willEnterFullscreen")
  }

  public func deleteSurroundingText(before: Int, after: Int) {
    //print("UIWebWindow.deleteSurroundingText")
    inputMethodController!.deleteSurroundingText(before: before, after: after)
  }
  
  public func deleteSurroundingTextInCodePoints(before: Int, after: Int){
    //print("UIWebWindow.deleteSurroundingTextInCodePoints")
    inputMethodController!.deleteSurroundingTextInCodePoints(before: before, after: after)
  }

  public func setEditableSelectionOffsets(start: Int, end: Int) {
    //print("UIWebWindow.setEditableSelectionOffsets")
    inputMethodController!.setEditableSelectionOffsets(range: TextRange(start: start, end: end))
  }

  public func extendSelectionAndDelete(before: Int, after: Int) {
    //print("UIWebWindow.extendSelectionAndDelete")
    guard let webFrame = mainFrame?.frame else {
      return
    }
    webFrame.extendSelectionAndDelete(before: before, after: after)
  }

  public func executeEditCommand(command: String, value: String) {
    //print("UIWebWindow.executeEditCommand")
    guard let webFrame = mainFrame?.frame else {
      return
    }
    webFrame.executeCommand(command: command, value: value)
  }

  public func executeEditCommand(_ command: String) {
    //print("UIWebWindow.executeEditCommand")
    guard let webFrame = mainFrame?.frame else {
      return
    }
    webFrame.executeCommand(command: command)
  }

  public func undo() {
    //print("UIWebWindow.undo")
    executeEditCommand("Undo")
  }

  public func redo() {
    //print("UIWebWindow.redo")
    executeEditCommand("Redo")
  }

  public func cut() {
    //print("UIWebWindow.cut")
    executeEditCommand("Cut")
  }

  public func copy() {
    //print("UIWebWindow.copy")
    executeEditCommand("Copy")
  }

  public func paste() {
    //print("UIWebWindow.paste")
    executeEditCommand("Paste")
  }

  public func delete() {
    //print("UIWebWindow.delete")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.frameSelection.clear()
  }

  public func selectAll() {
    //print("UIWebWindow.selectAll")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.frameSelection.selectAll()
  }

  public func collapseSelection() {
    //print("UIWebWindow.collapseSelection")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.frameSelection.selection.collapseToEnd()
  }

  public func replace(word: String) {
    //print("UIWebWindow.replace")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.replaceSelection(text: word)
  }

  public func selectRange(base: IntPoint, extent: IntPoint) {
    //print("UIWebWindow.selectRange")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.selectRange(base: base, extent: extent)
  }

  public func adjustSelectionByCharacterOffset(start: Int, end: Int, behavior: SelectionMenuBehavior) {
    //print("UIWebWindow.adjustSelectionByCharacterOffset")
    guard let frame = mainFrame?.frame else {
      return
    }

    let range = inputMethodController!.selectionOffsets
    if range.isNull {
      return
    }

    // Sanity checks to disallow empty and out of range selections.
    if start - end > range.length || range.start + start < 0 {
      return
    }

    //HandlingState handling_state(render_frame_, UpdateState::kIsSelectingRange);
    // A negative adjust amount moves the selection towards the beginning of
    // the document, a positive amount moves the selection towards the end of
    // the document.
    frame.selectRange(
        range: TextRange(start: range.start + start,
                         end: range.length + end - start),
        hide: behavior == SelectionMenuBehavior.Hide)
  }

  public func moveRangeSelectionExtent(extent: IntPoint) {
    //print("UIWebWindow.moveRangeSelectionExtent")
    guard let frame = mainFrame?.frame else {
      return
    }
    frame.frameSelection.moveRangeSelectionExtent(point: extent)
  }

  public func scrollFocusedEditableNodeIntoRect(rect: IntRect) {
    //print("UIWebWindow.scrollFocusedEditableNodeIntoRect")
    mainFrame!.scrollFocusedEditableElementIntoRect(rect)
  }
  
  public func moveCaret(position: IntPoint) {
    //print("UIWebWindow.moveCaret")
    mainFrame!.frame!.document.updateStyleAndLayoutTreeIgnorePendingStylesheets()
    let selectedRange = inputMethodController!.createRangeForSelection(start: position.x, end: position.x, textLength: 0)
    if selectedRange.isNull {
      return
    }
    inputMethodController!.setEditableSelectionOffsets(range: selectedRange)
  }
  
  public func onBeforeUnload(isReload: Bool) {
    if let frame = mainFrame {
      frame.beforeUnload(isReload: isReload)
    }
  }

  public func find(requestId: Int32, searchText: String, options: WebFindOptions) {
    if let frame = mainFrame {
      frame.find(requestId: requestId, searchText: searchText, options: options)
    }
  }
  
  public func clearActiveFindMatch() {
    if let frame = mainFrame {
      frame.clearActiveFindMatch()
    }
  }
  
  public func stopFinding(action: WebFrameStopFindAction) {
    if let frame = mainFrame {
      frame.stopFinding(action: action)
    }
  }
  
  public func clearFocusedElement() {
    if let frame = mainFrame {
      frame.clearFocusedElement()
    }
  }

  public func enableAutoResize(min: IntSize, max: IntSize) {}
  public func disableAutoResize() {}
  
  public func mediaPlayerAction(at: IntPoint, action: Int32, enable: Bool) {
    if let frame = mainFrame {
      frame.performMediaPlayerAction(
        action: WebMediaPlayerAction(type: WebMediaPlayerAction.Kind(rawValue: Int(action))!, enable: enable),
        location: at)
    }
  }

  public func notifyUserActivation() {
    if let frame = mainFrame {
      frame.notifyUserActivation()
    }
  }

  public func commitNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) {
    if let frame = mainFrame {
      frame.commitNavigation(url: url, keepAlive: keepAlive, providerId: providerId, routeId: routeId)
    }
  }

  public func commitSameDocumentNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) -> CommitResult {
    if let frame = mainFrame {
      return frame.commitSameDocumentNavigation(url: url, keepAlive: keepAlive, providerId: providerId, routeId: routeId)
    }
    return CommitResult.Aborted
  }

  public func commitFailedNavigation(
    errorCode: Int,
    errorPageContent: String?) {
    if let frame = mainFrame {
      frame.commitFailedNavigation(
        errorCode: errorCode, 
        errorPageContent: errorPageContent)
    }
  }

  public func didInvalidateRect(rect: IntRect) {
    //print("UIWebWindow.didInvalidateRect")
  }

  public func updateScreenInfo(_ screenInfo: ScreenInfo) {
    self.screenInfo = screenInfo
  }
  
  public func initializeLayerTreeView() -> WebLayerTreeView? {
    guard !compositorInitialized else {
      return compositor
    }

    self.compositor = UIWebWindowCompositor(delegate: self, runAllCompositorStagesBeforeDraw: isHeadless)

    let animationHost = AnimationHost.createMainInstance()
    let layerTreeHost = compositor!.createLayerTreeHost(animationHost: animationHost, screenInfo: screenInfo)
    compositor!.initialize(layerTreeHost: layerTreeHost, animationHost: animationHost)

    // We can get into this state if surface synchronization is on and the last
    // resize was initiated before navigation, in which case we don't have to ack
    // it.
    if compositor!.isSurfaceSynchronizationEnabled && !autoResizeMode &&
        nextPaintIsResizeAck && !localSurfaceIdFromParent.isValid {
      resetNextPaintIsResizeAck()
    }

    updateSurfaceAndScreenInfo(localSurfaceIdFromParent, compositorViewportPixelSize, screenInfo)
    // TODO: fix
    //compositor!.setRasterColorSpace(screenInfo.colorSpace.rasterColorSpace)
    let colorSpace = ColorSpace.createExtendedSRGB()
    compositor!.setRasterColorSpace(colorSpace.rasterColorSpace)
    compositor!.setContentSourceId(currentContentSourceId)
    startCompositor()

    let clientId = UInt32(application!.applicationProcessHostId)
    let sinkId = UInt32(application!.applicationWindowHostId)
    compositor!.setFrameSinkId(FrameSinkId(clientId: clientId, sinkId: sinkId))
        //viz::FrameSinkId(RenderThread::Get()->GetClientId(), routing_id_))

    //RenderThread* render_thread = RenderThread.current()
  
// TODO: implement    
//    inputEventQueue = MainThreadEventQueue(
//        self, appInstance.inputTaskRunner(),//render_thread->GetWebMainThreadScheduler()->InputTaskRunner(),
//        appInstance.mainThreadScheduler, true)
        //render_thread->GetWebMainThreadScheduler(), should_generate_frame_sink)

    //updateURLForCompositorUkm()
    //var settings = LayerSettings(type: .PictureLayer)
    //let client = DummyLayerClient()
    //let layer = try! compositor!.Layer(settings: settings, client: client)
    //layer.backgroundColor = Color.Yellow
    //layer.masksToBounds = true

    // NOTE: those are forced just for test
    //compositor!.backgroundColor = Color.Red
    //compositor!.setRootLayer(layer)
    //compositor!.isVisible = true
    //compositor!.viewportVisibleRect = IntRect(width: 400, height: 400)

    compositorInitialized = true
    return compositor 
  }

  public func startCompositor() {
    if !isHidden {
      compositor!.isVisible = true
    }
  }

  // UIWebWindowCompositorDelegate
  public func applyViewportDeltas(
      innerDelta: FloatVec2,
      outerDelta: FloatVec2,
      elasticOverscrollDelta: FloatVec2,
      pageScale: Float,
      topControlsDelta: Float) {

  }

  public func recordWheelAndTouchScrollingCount(
    hasScrolledByWheel: Bool, hasScrolledByTouch: Bool) {

  }

  public func beginMainFrame(frameTime: TimeTicks) {
    if let widget = webFrameWidget {
      widget.beginFrame(lastFrameTimeMonotonic: Double(frameTime.microseconds))
    }
  }

  public func requestNewLayerTreeFrameSink(callback: @escaping (_: LayerTreeFrameSink) -> Void) {
    application!.requestNewLayerTreeFrameSink(layerTreeHost: compositor!.layerTreeHost, callback: callback)
  }

  public func didCommitAndDrawCompositorFrame() {
    for observer in frames {
      observer.didCommitAndDrawCompositorFrame()
    }
  }

  public func didCommitCompositorFrame() {
    didResizeOrRepaintAck()
  }

  public func didCompletePageScaleAnimation() {}
  public func didReceiveCompositorFrameAck() {}

  public func requestScheduleAnimation() {
    scheduleAnimation()
  }

  public func updateVisualState(requestedUpdate: VisualStateUpdate) {
    let prePaintOnly = requestedUpdate == .PrePaint
    
    if let widget = webWidget {
      // TEMPORARY test: remove as soon as possible
      //webView!.setPageOverlayColor(color: Color.Magenta)
      widget.updateLifecycle(prePaintOnly ? WebLifecycleUpdate.PrePaint : WebLifecycleUpdate.All) 
    }
    
    if self.firstUpdateVisualStateAfterHidden && !prePaintOnly {
      firstUpdateVisualStateAfterHidden = false 
    }        
  }

  public func willBeginCompositorFrame() {
    updateTextInputState()
    updateSelectionBounds() 
  }

  public func requestCopyOfOutputForLayoutTest(request: CopyOutputRequest) -> ReportTimeSwapPromise? {
    return nil
  }

  public func didResizeOrRepaintAck() {
    var childAllocatedLocalSurfaceId: LocalSurfaceId?

    if nextPaintFlags == 0 && !needResizeAckForAutoResize {
      return
    }

    if childLocalSurfaceIdAllocator.currentLocalSurfaceId.isValid {
      childAllocatedLocalSurfaceId = childLocalSurfaceIdAllocator.currentLocalSurfaceId
    }

    sendResizeOrRepaintACK(
      viewSize: size, 
      flags: nextPaintFlags, 
      localSurfaceId: childAllocatedLocalSurfaceId)

    nextPaintFlags = 0
    needResizeAckForAutoResize = false
  }

  public func scheduleAnimation() {
    compositor!.setNeedsBeginFrame()
  }

  public func onUpdateWindowScreenRect(_ screenRect: IntRect) {
    guard initialized else {
      lastWindowScreenRect = screenRect
      return 
    }
    // self.windowScreenRect = screenRect

    // NOTE: i've added this here so we update both
    //       but maybe this will trigger a bad behaviour
    //       somewhere else. so watch for it..
    setScreenRects(viewScreen: screenRect,
                   windowScreen: screenRect)
  }

  public func onSetHistoryOffsetAndLength(historyOffset: Int32, historyLength: Int32) {
    //print("onSetHistoryOffsetAndLength: not implemented") 
  }

  public func onAudioStateChanged(isAudioPlaying: Bool) {
    //print("onAudioStateChanged: not implemented") 
  }

  public func onPausePageScheduledTasks(pause: Bool) {
    //print("onPausePageScheduledTasks: not implemented") 
  }

  public func onUpdateScreenInfo(_ screenInfo: ScreenInfo) {
    ////print("onUpdateScreenInfo: not updating screen info.. this is done o resize()") 
    updateScreenInfo(screenInfo)
  }

  public func onFreezePage() {
    //print("onFreezePage: not implemented") 
  }

  public func getWebFrame(routingId: Int) -> WebFrame? {
    for frame in frames {
      if frame.routingId == routingId {
        return frame.frame
      }
    }
    return nil
  }

  public func onClose() {
    guard !closing else {
      return
    }
    notifyOnClose()
    closing = true
    close()
  }

  public func onSetViewportIntersection(intersection: IntRect, visibleRect: IntRect) {
    //print("onSetViewportIntersection: not implemented") 
  }

  public func onUpdateRenderThrottlingStatus(isThrottled: Bool, subtreeThrottled: Bool) {}

  public func onForceRedraw(latency: LatencyInfo) {
    forceRedrawSwapPromise = AlwaysDrawSwapPromise(latencyInfo: latency, host: compositor!.layerTreeHost, callback: onForceRedrawSwapResult)
    compositor!.queueSwapPromise(swapPromise: forceRedrawSwapPromise!)
    compositor!.setNeedsForcedRedraw()
  }

  public func onDragTargetDragEnter(
    dropData: [DropData.Metadata],
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) {
    
    let operation = dragTargetDragEnter(
      dropData: dropData, 
      client: client, 
      screen: screen, 
      opsAllowed: opsAllowed, 
      keyModifiers: keyModifiers)

    sendUpdateDragCursor(dragOperation: operation)
  }

  public func onDragTargetDragOver(
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) {
    let operation = dragTargetDragOver(
      client: convertWindowPointToViewport(client), 
      screen: screen, 
      opsAllowed: opsAllowed,
      keyModifiers: keyModifiers)

    sendUpdateDragCursor(dragOperation: operation)
  }

  public func onDragTargetDragLeave(clientPoint: FloatPoint, sourcePoint: FloatPoint) {
    dragTargetDragLeave(
      clientPoint: convertWindowPointToViewport(clientPoint),
      screenPoint: sourcePoint)
  }

  public func onDragTargetDrop(dropData: DropData,
                      client: FloatPoint,
                      screen: FloatPoint,
                      keyModifiers: Int) {
    dragTargetDrop(
        dropData: dropData,
        client: convertWindowPointToViewport(client),
        screen: screen,
        keyModifiers: keyModifiers)
  }

  public func onDragSourceEnded(client: FloatPoint,
                       screen: FloatPoint,
                       dragOperations: DragOperation) {
    dragSourceEndedAt(
      client: convertWindowPointToViewport(client), 
      screen: screen, 
      dragOperations: dragOperations) 
  }

  public func onDragSourceSystemDragEnded() {
    dragSourceSystemDragEnded()
  }

  public func onSetFocusedWindow() {
    //print("onSetFocusedWindow: not implemented") 
  }

  public func onMouseLockLost() {
    didLosePointerLock()
  }

  public func onSwapOut(windowId: Int32, loading: Bool) {
    let _ = swapOut(windowId: windowId, loading: loading)
  }

  public func onUpdateTargetURLAck() {

  }

  public func onUpdateWebPreferences(webPreferences: WebPreferences) {

  }

  public func onMediaPlayerAction(at: IntPoint, action: Int32, enable: Bool) {
    mediaPlayerAction(at: at, action: action, enable: enable)
  }

  public func onMouseCaptureLost() {
    mouseCaptureLost()
  }

  public func onSetEditCommandsForNextKeyEvent(
    editCommandName: [String],
    editCommandValue: [String],
    editCommandCount: Int) {
    //print("UIWebWindow.onSetEditCommandsForNextKeyEvent")
    setEditCommandsForNextKeyEvent(
        editCommandName: editCommandName,
        editCommandValue: editCommandValue,
        editCommandCount: editCommandCount)
  }
  
  public func onCursorVisibilityChanged(visible: Bool) {
    //print("UIWebWindow.onCursorVisibilityChanged")
    cursorVisibilityChanged(visible: visible)
  }

  public func onImeSetComposition( 
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    selectionStart: Int, 
    selectionEnd: Int) {
    //print("UIWebWindow.onImeSetComposition")
    imeSetComposition( 
          text: text,
          spans: spans,
          replacement: replacement,
          selectionStart: selectionStart, 
          selectionEnd: selectionEnd)
  }

  public func onImeCommitText(
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    relativeCursorPosition: Int) {
    //print("UIWebWindow.onImeCommitText")
    
    imeCommitText(
        text: text,
        spans: spans,
        replacement: replacement,
        relativeCursorPosition: relativeCursorPosition)
  }

  public func onImeFinishComposingText(keepSelection: Bool) {
    //print("UIWebWindow.onImeFinishComposingText")
    imeFinishComposingText(keepSelection: keepSelection)
  }
  
  public func onRequestTextInputStateUpdate() {
    //print("UIWebWindow.onRequestTextInputStateUpdate")
    requestTextInputStateUpdate()
  }
  
  public func onRequestCompositionUpdates(immediateRequest: Bool, monitorRequest: Bool) {
    requestCompositionUpdates(immediateRequest: immediateRequest, monitorRequest: monitorRequest)
  }

  public func onDispatchEvent(event: WebInputEvent) -> InputEventAckState {
    return onEvent(event: event)
  }
  
  public func onDispatchNonBlockingEvent(event: WebInputEvent) {
    //print("UIWebWindow.onDispatchNonBlockingEvent")
    onNonBlockingEvent(event: event)
  }
  
  public func onSetCompositionFromExistingText(
    start: Int, 
    end: Int,
    spans: [WebImeTextSpan]) {
    //print("UIWebWindow.onSetCompositionFromExistingText")
    setCompositionFromExistingText(
        start: start, 
        end: end,
        spans: spans)
  }

  public func onExtendSelectionAndDelete(before: Int, after: Int) {
    extendSelectionAndDelete(before: before, after: after)
  }
  
  public func onDeleteSurroundingText(before: Int, after: Int) {
    deleteSurroundingText(before: before, after: after)
  }
  
  public func onDeleteSurroundingTextInCodePoints(before: Int, after: Int) {
    deleteSurroundingTextInCodePoints(before: before, after: after) 
  }
  
  public func onSetEditableSelectionOffsets(start: Int, end: Int) {
    setEditableSelectionOffsets(start: start, end: end)
  }
  
  public func onExecuteEditCommand(command: String, value: String) {
    //print("UIWebWindow.onExecuteEditCommand")
    executeEditCommand(command: command, value: value)
  }
  
  public func onUndo() {
    undo()
  }
  
  public func onRedo() {
    redo()
  }
  
  public func onCut() {
    cut()
  }
  
  public func onCopy() {
    copy()
  }
  
  public func onCopyToFindPboard() {
    copy()
  }
  
  public func onPaste() {
    paste()
  }
  
  public func onPasteAndMatchStyle() {
    paste()
  }
  
  public func onDelete() {
    delete()
  }
  
  public func onSelectAll() {
    selectAll()
  }
  
  public func onCollapseSelection() {
    collapseSelection()
  }
  
  public func onReplace(word: String) {
    replace(word: word)
  }
  
  public func onReplaceMisspelling(word: String) {}
  
  public func onSelectRange(base: IntPoint, extent: IntPoint) {
    selectRange(base: base, extent: extent)
  }
  
  public func onAdjustSelectionByCharacterOffset(start: Int, end: Int, behavior: SelectionMenuBehavior) {
    adjustSelectionByCharacterOffset(start: start, end: end, behavior: behavior)
  }

  public func onSetPageScale(pageScaleFactor: Float) {
    setPageScaleFactor(pageScaleFactor: pageScaleFactor)
  }
  
  public func onMoveRangeSelectionExtent(extent: IntPoint) {
    moveRangeSelectionExtent(extent: extent)
  }
  
  public func onScrollFocusedEditableNodeIntoRect(rect: IntRect) {
    scrollFocusedEditableNodeIntoRect(rect: rect)
  }
  
  public func onMoveCaret(position: IntPoint) {
    //print("UIWebWindow.onMoveCaret")
    moveCaret(position: position)
  }

  public func onIntrinsicSizingInfoOfChildChanged(
      size: FloatSize,
      aspectRatio: FloatSize, 
      hasWidth: Bool, 
      hasHeight: Bool) {

  }

  public func onViewChanged(frameSink: FrameSinkId?) {
    //print("UIWindowHost.onViewChanged: not implemented")
  }
  
  public func onSetChildFrameSurface(surfaceInfo: SurfaceInfo) {
    //print("UIWindowHost.onSetChildFrameSurface: not implemented")
  }
  
  public func onChildFrameProcessGone() {
    //print("UIWindowHost.onChildFrameProcessGone: not implemented")
  }
  
  public func onSwapIn() {
    let _ = swapIn()
  }
  
  public func onFrameDelete() {
    detach()
  }
  
  public func onStop() {
    stop()
  }
  
  public func onDroppedNavigation() {
    clientDroppedNavigation()
  }

  public func onCollapse(collapsed: Bool) {
    collapse(collapsed: collapsed)
  }
  
  public func onWillEnterFullscreen() {
    willEnterFullscreen()
  }
  
  public func onEnableAutoResize(min: IntSize, max: IntSize) {
    enableAutoResize(min: min, max: max)
  }
  
  public func onDisableAutoResize() {
    disableAutoResize()
  }
  
  public func onContextMenuClosed() {
    contextMenuClosed()
  }
  
  public func onCustomContextMenuAction(action: UInt32) {
    customContextMenuAction(action: action)
  }

  public func onDispatchLoad() {
    willEnterFullscreen()
  }
  
  public func onReload(bypassCache: Bool) {
    reload(bypassCache: bypassCache)
  }
  
  public func onReloadLoFiImages() {

  }
  
  public func onSnapshotAccessibilityTree() {

  }
  
  public func onUpdateOpener(routingId: UInt32) {
    updateOpener(openerId: routingId)
  }
  
  public func onSetFocusedFrame() {
    setFocusedFrame()
  }
  
  public func onCheckCompleted() {
    checkCompleted() 
  }
  
  public func onPostMessageEvent() {
    //print("UIWindowHost.onPostMessageEvent: not implemented")
  }
  
  public func onNotifyUserActivation() {
    notifyUserActivation()
  }
  
  public func onDidUpdateOrigin(origin: String) {
    didUpdateOrigin(origin: origin)
  }
  
  public func onScrollRectToVisible(rect: IntRect) {
    scrollRectToVisible(rect: rect)
  }

  public func onTextSurroundingSelectionRequest(maxLength: UInt32) {
    textSurroundingSelectionRequest(maxLength: maxLength)
  }
  
  public func onAdvanceFocus(type: WebFocusType, sourceRoutingId: Int32) {
    advanceFocus(type: type, sourceRoutingId: sourceRoutingId)
  }
  
  public func onAdvanceFocusInForm(type: WebFocusType) {
    advanceFocusInForm(type: type)
  }
  
  public func onFind(requestId: Int32, searchText: String, options: WebFindOptions) {
    find(requestId: requestId, searchText: searchText, options: options)
  }
  
  public func onClearActiveFindMatch() {
    clearActiveFindMatch()
  }
  
  public func onStopFinding(action: WebFrameStopFindAction) {
    stopFinding(action: action)
  }
  
  public func onClearFocusedElement() {
    clearFocusedElement()
  }
  
  public func onSetOverlayRoutingToken(token: UnguessableToken) {
    //print("UIWindowHost.onSetOverlayRoutingToken: not implemented")
  }

  public func onNetworkConnectionChanged(
    connectionType: NetworkConnectionType, 
    maxBandwidthMbps: Double) {
    
    let online = connectionType != NetworkConnectionType.None
    //print("UIWindowHost.onNetworkConnectionChanged: online ? \(online)")
    WebNetworkStateNotifier.setOnline(online)
    
    for observer in observers {
      observer.networkStateChanged(online: online)
    }
    
    WebNetworkStateNotifier.setWebConnection(
      connectionType: netConnectionTypeToWebConnectionType(connectionType), 
      maxBandwidthMbps: maxBandwidthMbps)
  }

  public func onCommitNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) {
    if firstNavigation {
      firstNavigation = false
    }
    commitNavigation(url: url, keepAlive: keepAlive, providerId: providerId, routeId: routeId)
  }

  public func onCommitSameDocumentNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) -> CommitResult {
    return commitSameDocumentNavigation(url: url, keepAlive: keepAlive, providerId: providerId, routeId: routeId)
  }

  public func onCommitFailedNavigation(
    errorCode: Int,
    errorPageContent: String?) {
    commitFailedNavigation(
        errorCode: errorCode,
        errorPageContent: errorPageContent)
  }

  private func notifyOnClose() {
    for observer in observers {
      observer.windowWillClose()
    }
  }
  
  // public func pageScaleFactorChanged() {
  //   //print("UIWebWindow.pageScaleFactorChanged")
  // }

  public func didMeaningfulLayout(layout: WebMeaningfulLayout) {
    mainFrame?.didMeaningfulLayout(layout: layout)
  }

  public func didFirstLayoutAfterFinishedParsing() {
    ////print("UIWebWindow.didFirstLayoutAfterFinishedParsing")
  }

  public func didChangeCursor(cursor: WebCursorInfo) {
    currentCursor = cursor
    sendSetCursor(cursor: cursor)
  }

  public func autoscrollStart(start: FloatPoint) {
    ////print("UIWebWindow.autoscrollStart")
  }

  public func autoscrollFling(velocity: FloatVec2) {
    ////print("UIWebWindow.autoscrollFling")
  }

  public func autoscrollEnd() {
    ////print("UIWebWindow.autoscrollEnd")
  }
  
  public func closeWidgetSoon() {
    ////print("UIWebWindow.closeWidgetSoon")
  }
  
  public func show(policy: WebNavigationPolicy) {
    ////print("UIWebWindow.show")
  }
  
  public func setToolTipText(text: String, hint: TextDirection) {
    //print("UIWebWindow.setToolTipText")
  }
  
  public func didHandleGestureEvent(event: WebGestureEvent, eventCancelled: Bool) {
    ////print("UIWebWindow.didHandleGestureEvent")
  }
  
  public func setNeedsLowLatencyInput(_: Bool) {
    //print("UIWebWindow.setNeedsLowLatencyInput")
  }
  
  public func requestUnbufferedInputEvents() {
    //print("UIWebWindow.requestUnbufferedInputEvents")
  }

  public func onLockMouseAck(succeeded: Bool) {
    if succeeded {
      didAcquirePointerLock()
    } else {
      didNotAcquirePointerLock()
    }
  }

  public func onVisualStateRequest(id: UInt64) {
    queueMessage(FrameSwapMessage.VisualStateResponse(id))
  }

  public func onCopyImage(at: FloatPoint) {
    var viewportPosition = IntRect(x: Int(at.x), y: Int(at.y), width: 0, height: 0)
    convertWindowToViewport(&viewportPosition)
    copyImage(at: IntPoint(x: viewportPosition.x, y: viewportPosition.y))
  }
  
  public func convertViewportToWindow(_ rect: inout IntRect) {
    if isUseZoomForDSFEnabled {
      let reverse: Float = 1.0 / originalScreenInfo.deviceScaleFactor
      let windowRect = scaleToEnclosingRect(rect: rect, xScale: reverse, yScale: reverse)
          //gfx::ScaleToEnclosedRect(gfx::Rect(*rect), reverse)
      rect.x = windowRect.x
      rect.y = windowRect.y
      rect.width = windowRect.width
      rect.height = windowRect.height
    }
  }

  public func convertWindowToViewport(_ rect: inout FloatRect) {
    if isUseZoomForDSFEnabled {
      rect.x *= originalScreenInfo.deviceScaleFactor
      rect.y *= originalScreenInfo.deviceScaleFactor
      rect.width *= originalScreenInfo.deviceScaleFactor
      rect.height *= originalScreenInfo.deviceScaleFactor
    }
  }

  public func convertWindowToViewport(_ rect: inout IntRect) {
    if isUseZoomForDSFEnabled {
      rect.x *= Int(originalScreenInfo.deviceScaleFactor)
      rect.y *= Int(originalScreenInfo.deviceScaleFactor)
      rect.width *= Int(originalScreenInfo.deviceScaleFactor)
      rect.height *= Int(originalScreenInfo.deviceScaleFactor)
    }
  }

  public func startDragging(policy: WebReferrerPolicy,
                            dragData: WebDragData,
                            ops: WebDragOperation,
                            dragImage: ImageSkia?, 
                            dragImageOffset: IntPoint) {
    //var offsetInWindow = IntRect(x: dragImageOffset.x, y: dragImageOffset.y, width: 0, height: 0)
    //convertViewportToWindow(&offsetInWindow)
    //dragData.referrerPolicy = policy
    //let imageOffset = IntVec2(x: offsetInWindow.x, y: offsetInWindow.y)
    //sendStartDragging(
    //  dropData: dragData, 
    //  opsAllowed: ops,
    //  image: dragImage.bitmap,
    //  imageOffset: imageOffset)
  }
  
  public func didOverscroll(overscrollDelta: FloatSize,
                            accumulatedOverscroll: FloatSize,
                            position: FloatPoint,
                            velocity: FloatSize,
                            overscrollBehavior: OverscrollBehavior) {
    ////print("UIWebWindow.didOverscroll")
  }

  public func fromWebFrame(_ webFrame: Web.WebFrame) -> UIWebFrame? {
    if let main = mainFrame {
      if main.frame == webFrame {
        return main  
      }
    }
    for frame in frames {
      if frame.frame == webFrame {
        return frame
      }
    }
    return nil
  }

  public func registerFrame(_ frame: UIWebFrame) {
    frames.append(frame)
    // fixme: for now its just true.. but once 
    // we support more frames..
    dispatcher.onWebFrameCreated(frame: frame.frame!, isMain: true)
  }

  public func unregisterFrame(_ frame: UIWebFrame) {
    for (i, item) in frames.enumerated() {
      if frame === item {
        frames.remove(at: i)
        return
      }
    }
  }

  public func registerFrameProxy(_ frame: UIWebFrameProxy) {
    frameProxies.append(frame)
  }

  public func unregisterFrameProxy(_ frame: UIWebFrameProxy) {
    for (i, item) in frameProxies.enumerated() {
      if frame === item {
        frameProxies.remove(at: i)
        return
      }
    }
  }

  public func onSetFocus(focused: Bool) {
    hasFocus = focused

    if focused {
      focusController.active = true
      imeAcceptEvents = true
    } else {
      imeAcceptEvents = false
    }

    if let widget = webWidget {
      widget.setFocus(focus: focused)
    }
    
    focusController.isFocused = focused
  
    for observer in frames {
      observer.setFocus(enable: focused)
    }
 
  }

  public func onRequestMoveAck() {
    pendingWindowRectCount -= 1
  }

  public func onSaveImage(at: FloatPoint) {
    var viewportPosition = IntRect(x: Int(at.x), y: Int(at.y), width: 0, height: 0)
    convertWindowToViewport(&viewportPosition)
    saveImage(at: IntPoint(x: viewportPosition.x, y: viewportPosition.y))
  }

  public func setTouchAction(touchAction action: TouchAction) {
    if !inputHandler.processTouchAction(action) {
      return
    }

    windowInputHandlerManager.processTouchAction(action)
  }

  private func resolveOpener(openerId: UInt32) -> UIWebFrame? {
    let currentId: Int = mainFrame?.routingId ?? 0
    if openerId == currentId {
      return mainFrame
    }
    for frame in frames {
      if frame.routingId == openerId {
        return frame
      }
    }
    return nil
  }

  private func setScreenRects(viewScreen: IntRect,
                              windowScreen: IntRect) {
    self.viewScreenRect = viewScreen
    self.windowScreenRect = windowScreen
  }

  private func updateSurfaceAndScreenInfo(
    _ newLocalSurfaceId: LocalSurfaceId,
    _ newCompositorViewportPixelSize: IntSize,
    _ newScreenInfo: ScreenInfo) {  
    let orientationChanged =
        self.screenInfo.orientationAngle != newScreenInfo.orientationAngle ||
        self.screenInfo.orientationType != newScreenInfo.orientationType
    let deviceScaleFactorChanged =
        self.screenInfo.deviceScaleFactor != newScreenInfo.deviceScaleFactor
    let previousOriginalScreenInfo: ScreenInfo = self.originalScreenInfo

    self.localSurfaceIdFromParent = newLocalSurfaceId
    self.compositorViewportPixelSize = newCompositorViewportPixelSize
    // check colorspace (we are receiving some null values)
    //let oldColorSpace = self.screenInfo.colorSpace
    self.screenInfo = newScreenInfo
    //if !self.screenInfo.colorSpace.isValid {
    //  self.screenInfo.colorSpace = oldColorSpace
    //}
  
    compositor!.viewportVisibleRect = self.viewportVisibleRect
    
    compositor!.setViewportSizeAndScale(
        viewport: self.compositorViewportPixelSize,
        scale: self.originalScreenInfo.deviceScaleFactor, 
        surfaceId: self.localSurfaceIdFromParent)
    
    if orientationChanged {
      onOrientationChange()
    }

    if previousOriginalScreenInfo != self.originalScreenInfo {
      for observer in frameProxies {
        observer.onScreenInfoChanged(screenInfo: self.originalScreenInfo)
      }
    }

    if deviceScaleFactorChanged {
      deviceScaleFactor = self.screenInfo.deviceScaleFactor
    }

  }

  public func onPageWasShown() {
    //print("UIWebWindow.onPageWasShown")
    //if let frame = mainFrame {
    //  frame.onPageWasShown()
    //}
    if let view = webView {
      view.setVisibilityState(visibilityState: WebPageVisibilityState.Visible, isInitialState: false) 
    }
    delegate!.onPageWasShown(self)
  }
  
  public func onPageWasHidden() {
    //print("UIWebWindow.onPageWasHidden")
    //if let frame = mainFrame {
    //  frame.onPageWasHidden() 
    //}
    if let view = webView {
      view.setVisibilityState(visibilityState: WebPageVisibilityState.Hidden, isInitialState: false)
    }
    delegate!.onPageWasHidden(self)
  }

  public func onWasShown(needsRepainting: Bool, latencyInfo: LatencyInfo) {
    //print("UIWebWindow.onWasShown")

    wasShownTime = TimeTicks.now
    isHidden = false
    
    // needs to be after isHidden
    if !initialized {
      //print(" onWasShown: initializing compositor")
      initializeInternal()
    }

    for observer in frames {
      observer.onWasShown()
    }

    compositor!.isVisible = true
    
    // NOTE: this part is done on the c++ runtime side now, given
    // it was not working as it supposed to be calling here 
    // from the swift side.

    //guard needsRepainting else {
    //  return
    //}

    //wasShownSwapPromiseMonitor = compositor!.createLatencyInfoSwapPromiseMonitor(latency: latencyInfo)
    // Force this SwapPromiseMonitor to trigger and insert a SwapPromise.
    //compositor!.setNeedsBeginFrame()
  }

  public func onWasHidden() {
    //print("UIWebWindow.onWasHidden")
    
    isHidden = true

    for observer in frames {
      observer.onWasHidden()
    }
    
    compositor!.isVisible = false

    didResizeOrRepaintAck() 
  }

  public func onRepaint(size paintSize: IntSize) {
    var sizeToPaint = paintSize
    if paintSize.isEmpty {
      sizeToPaint = size
    }
    setNextPaintIsRepaintAck()
    compositor!.setNeedsRedrawRect(damaged: IntRect(size: sizeToPaint))
  }

  public func onSynchronizeVisualProperties(params: VisualProperties) {
    //print("UIWebWindow.onSynchronizeVisualProperties")
    if !firstVisualPropertiesReceived {
      initializeVisualProperties(params: params)
      // initializeVisualProperties will call onSynchronizeVisualProperties()
      // back, so theres no need to keep
      return
    }
    
    let oldVisibleViewportSize = visibleViewportSize

    synchronizeVisualProperties(params: params)

    if oldVisibleViewportSize != visibleViewportSize {
      for observer in frames {
        observer.didChangeVisibleViewport()
      }
    }
  }

  public func onEnablePreferredSizeChangedMode() {
    guard !sendPreferredSizeChanges else {
      return
    }
    sendPreferredSizeChanges = true
    didUpdateLayout()
  }

  public func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect) {
    //if let sme = screenMetricsEmulator {
    //  sme.onUpdateScreenRects(viewScreen, windowScreen)
    //} else {
    setScreenRects(viewScreen: viewScreen, windowScreen: windowScreen)
    //}
    sendUpdateScreenRectsAck()

    //if let d = delegate {
    //  d.onUpdateScreenRects(viewScreen: viewScreen, windowScreen: windowScreen)
    //}
  }

  public func onOrientationChange() {

  }

  public func didUpdateLayout() {
    if !sendPreferredSizeChanges {
      return;
    }

    //if checkPreferredSizeTimer.isRunning {
    //  return
    //}

    //checkPreferredSizeTimer.start(TimeDelta.fromMilliseconds(0),
    //                              self.checkPreferredSize)
    checkPreferredSize()
  }

  public func redraw() {
    setNextPaintIsResizeAck()
    compositor!.setNeedsRedrawRect(damaged: IntRect(size: size))
  }

  public func onSetZoomLevel(zoomLevel: Double) {
    hidePopups()
    self.zoomLevel = zoomLevel
  }

  public func onSetRendererPrefs(prefs: RendererPrefs) {}

  public func onSetInitialFocus(reverse: Bool) {
    setInitialFocus(reverse: reverse)
  }

  public func onClosePage() {
    sendClosePageACK()
  }

  public func onMoveOrResizeStarted() {
    hidePopups()
  }

  public func onDisableScrollbarsForSmallWindows(disableScrollbarSizeLimit: IntSize) {
    self.disableScrollbarsSizeLimit = disableScrollbarSizeLimit
  }

  public func requestPointerLock() -> Bool {
    return mouseLockDispatcher.lockMouse(target: self.mouseLockTarget)
  }

  public func requestPointerUnlock() {
    let _ = mouseLockDispatcher.unlockMouse(target: self.mouseLockTarget)
  }

  public func getSelectionBounds(focus: inout IntRect, anchor: inout IntRect) {
    let _ = webWidget!.getSelectionBounds(anchor: &anchor, focus: &focus)
    convertViewportToWindow(&focus)
    convertViewportToWindow(&anchor)
  }

  public func clearTextInputState() {
    //print("UIWebWindow.clearTextInputState")
    self.textInputInfo = WebTextInputInfo()// TextInputInfo()//blink::WebTextInputInfo()
    self.textInputType = WebTextInputType.None
    self.textInputMode = WebTextInputMode.Default
    canComposeInline = false
    textInputFlags = TextInputFlags.None
    nextPreviousFlags = InvalidNextPreviousFlagsValue
  }

  public func updateTextInputState() {
    updateTextInputStateInternal(false)
  }

  public func onDidHandleKeyEvent() {
    //print("UIWebWindow.onDidHandleKeyEvent")
    clearEditCommands()
  }

  public func queueMessage(_ message: FrameSwapMessage) {
    let swapPromise: SwapPromise?
    switch message {
      case .VisualStateResponse(let id): 
        swapPromise = application!.queueVisualStateResponse(sourceFrameNumber: compositor!.sourceFrameNumber, id: id)
    }

    if let promise = swapPromise {
      compositor!.queueSwapPromise(swapPromise: promise)
    }
  }

  public func observeGestureEventAndResult(
      gestureEvent: Web.GestureEvent,
      unusedDelta: FloatVec2,
      overscrollBehavior: OverscrollBehavior,
      eventProcessed: Bool) {

  }

  public func onDidOverscroll(params: DidOverscrollParams) {
    //if let host = windowInputHandlerManager.widgetInputHandlerHost {
    //  host.didOverscroll(params: params)
    //}
    sendDidOverscroll(params: params)
  }

  public func setInputHandler(inputHandler: UIWindowInputHandler) {
    self.inputHandler = inputHandler
  }

  public func willHandleGestureEvent(event: WebGestureEvent) -> Bool {
    self.possibleDragEventInfo.eventSource = DragEventSource.Touch
    self.possibleDragEventInfo.eventLocation = IntPoint(event.positionInScreen)
    
    delegate!.willHandleGestureEvent(event: event)
    
    for observer in frames {
      observer.willHandleGestureEvent(event: event)
    }
    return false
  }

  public func willHandleMouseEvent(event: WebMouseEvent) -> Bool {
   delegate!.willHandleMouseEvent(event: event)

    for observer in frames {
      observer.willHandleMouseEvent(event: event)
    }

    self.possibleDragEventInfo.eventSource = DragEventSource.Mouse
    self.possibleDragEventInfo.eventLocation = IntPoint(event.positionInScreen)
    return mouseLockDispatcher.willHandleMouseEvent(event: event)
  }

  public func willHandleKeyEvent(event: WebKeyboardEvent) -> Bool {
    //print("UIWebWindow.willHandleKeyEvent")
    delegate!.willHandleKeyEvent(event: event)
    for observer in frames {
      observer.willHandleKeyEvent(event: event)
    }
    return false
  }

  public func createNewWindow() {
    print("createNewWindow")
  }

  public func didInitializeLayerTreeFrameSink() {
    sendLayerTreeFrameSinkInitialized()
    // if firstNavigation {
    //   print("didInitializeLayerTreeFrameSink: first navigation forcing commitNavigation()")
    //   commitNavigation(url: application!.initialUrl, keepAlive: false)
    // }
  }

  // WebView impl
  public func makeView(creator: WebFrame?,
                       request: WebURLRequest,
                       features: WebWindowFeatures,
                       name: String,
                       policy: WebNavigationPolicy,
                       suppressOpener: Bool) -> WebView? {
  //  //print("UIWebWindow.makeView(\(routingId)): returning a null view")
    return nil
  }
 
  public func makePopup(creator: WebFrame?, type: WebPopupType) -> WebView? {
  //  //print("UIWebWindow.makePopup: returning a null popup")
    return nil
  }
 
  public func printPage(frame: WebFrame) {

  }

  public func enumerateChosenDirectory(path: String, completion: WebFileChooserCompletion?) -> Bool {
    return false
  }

  public func openDateTimeChooser(params: WebDateTimeChooserParams, completion: WebDateTimeChooserCompletion?) -> Bool {
    return false
  }

  public func pageImportanceSignalsChanged() {}
  
  public func setMouseOverURL(url: String) {
    //print("UIWebWindow.setMouseOverURL")
  }
  
  public func setKeyboardFocusURL(url: String) {
    //print("UIWebWindow.setKeyboardFocusURL")
    focusUrl = url
    updateTargetURL(url: focusUrl)
  }

  public func updateTargetURL(url: String) {
    print("UIWebWindow.updateTargetURL url = \(url)")
    sendUpdateTargetURL(url: url)
    self.targetUrl = url
  }
  
  public func focusNext() {}
  
  public func focusPrevious() {}

  public func focusedNodeChanged(from: WebNode?, to: WebNode?) {
    if let frame = mainFrame {
      frame.focusedNodeChanged(from: from, to: to)
    }
  }
  
  public func didAutoResize(size newSize: IntSize) {
    //print("UIWebWindow.didAutoResize(\(routingId))")
    var newSizeInWindow = IntRect(x: 0, y: 0, width: newSize.width, height: newSize.height)
    convertViewportToWindow(&newSizeInWindow)
    if size.width != newSizeInWindow.width ||
       size.height != newSizeInWindow.height {
      size = IntSize(width: newSizeInWindow.width, height: newSizeInWindow.height)
      // if resizingModeSelector.isSynchronousMode {
      //   let newPos = IntRect(
      //     x: windowRect.x, y: windowRect.y, 
      //     width: size.width, height: size.height)
      //   self.viewScreenRect = newPos
      //   self.windowScreenRect = newPos
      // }

      // TODO(ccameron): Note that this destroys any information differentiating
      // |size_| from |compositor_viewport_pixel_size_|. Also note that the
      // calculation of |new_compositor_viewport_pixel_size| does not appear to
      // take into account device emulation.
      if let compositor = layerTreeView {
        compositor.requestNewLocalSurfaceId()
      }

      let newCompositorViewportPixelSize = IntSize.scaleToCeiled(size, scale: self.screenInfo.deviceScaleFactor)
      updateSurfaceAndScreenInfo(self.localSurfaceIdFromParent,
                                 newCompositorViewportPixelSize,
                                 self.screenInfo)
    }
  }
  
  public func didFocus(callingFrame: WebFrame) {
    ////print("UIWebWindow.didFocus(\(routingId))")
  }
  
  public func didTapMultipleTargets(visualViewportOffset: IntSize, touchRect: IntRect, targetRects: [IntRect]) -> Bool {
    return false
  }

  public func navigateBackForwardSoon(offset: Int) {}
  public func didUpdateInspectorSettings() {}
  public func didUpdateInspectorSetting(key: String, value: String) {}
  public func zoomLimitsChanged(minimumLevel: Double, maximumLevel: Double) {
    ////print("UIWebWindow.zoomLimitsChanged(\(routingId))")
  }
  public func pageScaleFactorChanged() {
    ////print("UIWebWindow.pageScaleFactorChanged(\(routingId))")
  }
  public func onSetBackgroundOpaque(opaque: Bool) {
    if let d = delegate {
      d.setBackgroundOpaque(opaque: opaque)
    }
  }

  public func onSetTextDirection(direction: TextDirection) {
    if let frame = focusedLocalFrameInWidget {
      frame.setTextDirection(direction)
    }
  }

  public func onSetActive(active: Bool) {
    self.isActive = active
    if let d = delegate {
      d.setActive(active: active)
    }
  }

  public func onSetIsInert(inert: Bool) {}

  public func onFrameAttached(_ frame: UIWebFrame) {
    delegate!.onFrameAttached(frame)
  }

  private func updateTextInputStateInternal(_ replyToRequest: Bool) {
    let newType: WebTextInputType = textInputType
    
    //if isDateTimeInput(newType) {
    //  return
    //}

    var newInfo = WebTextInputInfo()
    if let controller = inputMethodController {
      newInfo = controller.textInputInfo
    }
    
    let newMode: TextInputMode = TextInputMode(rawValue: newInfo.inputMode.rawValue)!//convertWebTextInputMode(newInfo.inputMode)
    let newCanComposeInline: Bool = canComposeInline

    if replyToRequest || self.textInputType != newType || 
       self.textInputMode != newInfo.inputMode || self.textInputInfo != newInfo ||
       self.canComposeInline != newCanComposeInline {
      var params = TextInputState()
      params.type = TextInputType(rawValue: newType.rawValue)!
      params.mode = newMode
      params.flags = TextInputFlags(rawValue: newInfo.flags)!
#if os(Android)
      if self.nextPreviousFlags == kInvalidNextPreviousFlagsValue {
        if let controller = inputMethodController {
          self.nextPreviousFlags = controller.computeWebTextInputNextPreviousFlags()
        } else {
          self.nextPreviousFlags = 0
        }
      }
#else
      self.nextPreviousFlags = TextInputFlags.None
#endif
      params.flags = TextInputFlags(rawValue: params.flags.rawValue | nextPreviousFlags.rawValue)!
      params.value = newInfo.value
      params.selectionStart = newInfo.selectionStart
      params.selectionEnd = newInfo.selectionEnd
      params.compositionStart = newInfo.compositionStart
      params.compositionEnd = newInfo.compositionEnd
      params.canComposeInline = newCanComposeInline
      params.showImeIfNeeded = false
      params.replyToRequest = replyToRequest

      sendTextInputStateChanged(textInputState: params)

      self.textInputInfo = newInfo
      self.textInputType = newInfo.type
      self.textInputMode = newInfo.inputMode
      self.canComposeInline = newCanComposeInline
      self.textInputFlags = TextInputFlags(rawValue: newInfo.flags)!
    }
  }

  private func updateCompositionInfo(_ immediateRequest: Bool) {
    if !self.monitorCompositionInfo && !immediateRequest {
      return  
    }

    var range = TextRange()
    var characterBounds = [IntRect]()

    if self.textInputType == .None {
      range = TextRange.InvalidRange
    } else {
      getCompositionRange(&range)
      getCompositionCharacterBounds(&characterBounds)
    }

    if !immediateRequest &&
        !shouldUpdateCompositionInfo(range: range, bounds: characterBounds) {
      return
    }
    self.compositionCharacterBounds = characterBounds
    self.compositionRange = range
    sendImeCompositionRangeChanged(range: self.compositionRange,
                               bounds: self.compositionCharacterBounds)
  }

  private func getCompositionRange(_ range: inout TextRange) {
    if let controller = inputMethodController {
      range = controller.compositionRange
      return
    }
    range = TextRange.InvalidRange
  }

  private func clearEditCommands() {
    editCommands.removeAll()
  }

  private func getCompositionCharacterBounds(_ bounds: inout [IntRect]) {
    guard let controller = inputMethodController else {
      return
    }
    
    guard let localBounds = controller.compositionCharacterBounds else {
      return
    }

    for var rect in localBounds {
      convertViewportToWindow(&rect)
      bounds.append(rect)
    }
  }

  private func shouldUpdateCompositionInfo(range: TextRange, bounds: [IntRect]) -> Bool {
    if !range.isValid {
      return false
    }
    if self.compositionRange != range {
      return true
    }
    if bounds.count != self.compositionCharacterBounds.count {
      return true
    }
    for i in 0..<bounds.count {
      if bounds[i] != self.compositionCharacterBounds[i] {
        return true
      }
    }
    return false
  }

  private func resetNextPaintIsResizeAck() {
    nextPaintFlags ^= PaintFlags.ResizeAck.rawValue
  }

  private func setNextPaintIsResizeAck() {
    nextPaintFlags |= PaintFlags.ResizeAck.rawValue
  }

  private func setNextPaintIsRepaintAck() {
    nextPaintFlags |= PaintFlags.RepaintAck.rawValue
  }

  private func synchronizeVisualProperties(params: VisualProperties) {
    let colorspace = params.screenInfo.colorSpace
    let workingColorSpace = ColorSpace.createExtendedSRGB()
    //print("synchronizeVisualProperties\n received colorpace valid? \(colorspace.isValid):\n   primaries: \(colorspace.primaries)\n   transfer: \(colorspace.transfer)\n   matrix: \(colorspace.matrix)\n   range: \(colorspace.range)\n   iccProfile: \(colorspace.iccProfileId)\n")
    //print("current colorspace\n   primaries: \(workingColorSpace.primaries)\n   transfer: \(workingColorSpace.transfer)\n   matrix: \(workingColorSpace.matrix)\n   range: \(workingColorSpace.range)\n   iccProfile: \(workingColorSpace.iccProfileId)")
    application!.setRenderingColorSpace(workingColorSpace)
    //application!.setRenderingColorSpace(params.screenInfo.colorSpace.isValid ? params.screenInfo.colorSpace : screenInfo.colorSpace)

    let newCompositorViewportPixelSize = //params.autoResizeEnabled ? 
       //IntSize.scaleToCeiled(size, scale: params.screenInfo.deviceScaleFactor) :
       params.compositorViewportPixelSize

    let localSurface = params.localSurfaceId ?? LocalSurfaceId()
    updateSurfaceAndScreenInfo(localSurface,
                               newCompositorViewportPixelSize,
                               params.screenInfo)
    
    updateCaptureSequenceNumber(params.captureSequenceNumber)
     
    //compositor!.setBrowserControlsHeight(
    //  params.topControlsHeight, 
    //  params.bottomControlsHeight,
    //  params.browserControlsShrinkBlinkSize)
    
    //TODO: fix
    //compositor!.setRasterColorSpace(params.screenInfo.colorSpace.rasterColorSpace)
    compositor!.setRasterColorSpace(workingColorSpace.rasterColorSpace)


    //if params.autoResizeEnabled {
    //  return
    //}

    self.visibleViewportSize = params.visibleViewportSize

    let fullscreenChange =
         self.isFullscreenGranted != params.isFullscreenGranted
     isFullscreenGranted = params.isFullscreenGranted
     self.displayMode = params.displayMode

    self.size = params.newSize

    resizeWebWidget()

    var visualViewportSize: IntSize

    if isUseZoomForDSFEnabled {
       visualViewportSize =
          IntSize.scaleToCeiled(params.visibleViewportSize, scale: originalScreenInfo.deviceScaleFactor)
    } else {
       visualViewportSize = self.visibleViewportSize
    }

    if let widget = webWidget {
      widget.resizeVisualViewport(size: visualViewportSize)
    }

    // // Send the Resize_ACK flag once we paint again if requested.
    if params.needsResizeAck {
      setNextPaintIsResizeAck()
    }

    if fullscreenChange {
      didToggleFullscreen()
    }

    if compositor!.isSurfaceSynchronizationEnabled &&
         params.needsResizeAck && !localSurfaceIdFromParent.isValid {
       resetNextPaintIsResizeAck()
    }

  }

  private func resizeWebWidget() {
    if let widget = webWidget {
      widget.resize(size: size)
      //it was sizeForWebWidget -> take isUseZoomForDSFEnabled into account
    }
  }

  private func updateSelectionBounds() {
    
    //guard !imeEventGuard else {
    //  return
    //}

    var params = SelectionBoundsParams()
    params.isAnchorFirst = false
    getSelectionBounds(focus: &params.focusRect, anchor: &params.anchorRect)
    if self.selectionAnchorRect != params.anchorRect ||
        self.selectionFocusRect != params.focusRect {
      self.selectionAnchorRect = params.anchorRect
      self.selectionFocusRect = params.focusRect
      if let focusedFrame = focusedLocalFrameInWidget {
        let _ = focusedFrame.selectionTextDirection(start: &params.focusDir,
                                                    end: &params.anchorDir)
        params.isAnchorFirst = focusedFrame.isSelectionAnchorFirst
      }
      sendSelectionBoundsChanged(params: params)
    }

    updateCompositionInfo(false)
  }

  private func updateCaptureSequenceNumber(_ captureSequenceNumber: UInt32) {
    if captureSequenceNumber == lastCaptureSequenceNumber {
      return
    }
    lastCaptureSequenceNumber = captureSequenceNumber

    for observer in frameProxies {
      observer.updateCaptureSequenceNumber(captureSequenceNumber: captureSequenceNumber)
    }
  }

  private func checkPreferredSize() {
    // We don't always want to send the change messages over IPC, only if we've
    // been put in that mode by getting a |ViewMsg_EnablePreferredSizeChangedMode|
    // message.
    guard let view = webView else {
      return
    }
    //if (!send_preferred_size_changes_ || !webview())
    //  return;
    let tmpSize = view.contentsPreferredMinimumSize
    var tmpRect = IntRect(x: 0, y: 0, width: tmpSize.width, height: tmpSize.height)
    convertViewportToWindow(&tmpRect)
    let size = IntSize(width: tmpRect.width, height: tmpRect.height)
    if size == preferredSize {
      return
    }
    self.preferredSize = size
    sendDidContentsPreferredSizeChange(size: self.preferredSize)
  }

  private func didToggleFullscreen() {
    if isFullscreenGranted {
      didEnterFullscreen()
    } else {
      didExitFullscreen()
    }
  }

  private func updateWebViewWithDeviceScaleFactor() {
    if let webview = webFrameWidget?.localRoot?.view {
      webview.setDeviceScaleFactor(screenInfo.deviceScaleFactor)
    }
      //if (IsUseZoomForDSFEnabled()) {
      //  webview.zoomFactorForDeviceScaleFactor = screenInfo.deviceScaleFactor
      //} else {
    //    webview.setDeviceScaleFactor(screenInfo.deviceScaleFactor)
      //}

      //webview->GetSettings()->SetPreferCompositingToLCDTextEnabled(
      //    PreferCompositingToLCDText(compositor_deps_,
      //                             GetWebScreenInfo().device_scale_factor));
    
  }

  private func onForceRedrawSwapResult(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
    forceRedrawSwapPromise = nil
  }

  private func onWasShownSwapResult(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
    wasShownSwapPromiseMonitor = nil
  }

  private func convertWindowPointToViewport(_ point: FloatPoint) -> FloatPoint {
    var pointInViewport = FloatRect(x: point.x, y: point.y, width: 0.0, height: 0.0)
    convertWindowToViewport(&pointInViewport)
    return FloatPoint(x: pointInViewport.x, y: pointInViewport.y)
  }

  private func convertWindowPointToViewport(_ point: IntPoint) -> IntPoint {
    return IntPoint.toRounded(point: convertWindowPointToViewport(FloatPoint(point)))
  }

}

extension UIWebWindow : UIDispatcherSender {
  
  public func sendHasTouchEventHandlers(hasHandlers: Bool) {
    dispatcher.hasTouchEventHandlers(hasHandlers: hasHandlers)
  }

  public func sendApplicationProcessGone(status: Int32, exitCode: Int32) {
    dispatcher.applicationProcessGone(status: status, exitCode: exitCode)
  }
  
  public func sendHittestData(surfaceId: SurfaceId, ignoredForHittest: Bool) {
    dispatcher.hittestData(surfaceId: surfaceId, ignoredForHittest: ignoredForHittest)
  }

  public func sendUpdateState() {
    dispatcher.updateState() 
  }
  
  public func sendClose() {
    dispatcher.close()
  }
  
  public func sendUpdateScreenRectsAck() {
    dispatcher.updateScreenRectsAck()
  }
  
  public func sendRequestMove(position: IntRect) {
    dispatcher.requestMove(position: position)
  }
  
  public func sendSetTooltipText(text: String, direction: TextDirection) {
    dispatcher.setTooltipText(text: text, direction: direction)
  }
  
  public func sendResizeOrRepaintACK(viewSize: IntSize, flags: Int32, localSurfaceId: LocalSurfaceId?) {
    dispatcher.resizeOrRepaintACK(viewSize: viewSize, flags: flags, localSurfaceId: localSurfaceId)
  }
  
  public func sendSetCursor(cursor: WebCursorInfo) {
    dispatcher.setCursor(cursor: cursor)
  }
  
  public func sendAutoscrollStart(start: FloatPoint) {
    dispatcher.autoscrollStart(start: start)
  }
  
  public func sendAutoscrollFling(velocity: FloatVec2) {
    dispatcher.autoscrollFling(velocity: velocity)
  }
  
  public func sendAutoscrollEnd() {
    dispatcher.autoscrollEnd()
  }
  
  public func sendTextInputStateChanged(textInputState: TextInputState) {
    dispatcher.textInputStateChanged(textInputState: textInputState)
  }
  
  public func sendLockMouse(userGesture: Bool, privileged: Bool) {
    dispatcher.lockMouse(userGesture: userGesture, privileged: privileged)
  }
  
  public func sendUnlockMouse() {
    dispatcher.unlockMouse()
  }
  
  public func sendSelectionBoundsChanged(params: SelectionBoundsParams) {
    dispatcher.selectionBoundsChanged(params: params)
  }

  public func sendFocusedNodeTouched(editable: Bool) {
    dispatcher.focusedNodeTouched(editable: editable)
  }
  
  public func sendStartDragging(
    dropData: DropData,
    opsAllowed: DragOperation,
    image: Bitmap,
    imageOffset: IntVec2) {
    var offsetInWindow = IntRect(x: imageOffset.x, y: imageOffset.y, width: 0, height: 0)
    convertViewportToWindow(&offsetInWindow)
    //var dropData = DropDataBuilder.build(data: dropData)
    let realImageOffset = IntVec2(x: offsetInWindow.x, y: offsetInWindow.y)
  
    dispatcher.startDragging(
      dropData: dropData, 
      opsAllowed: opsAllowed, 
      image: image, 
      imageOffset: realImageOffset,
      eventInfo: possibleDragEventInfo)
  }

  public func sendUpdateDragCursor(dragOperation: DragOperation) {
    dispatcher.updateDragCursor(dragOperation: dragOperation)
  }

  public func sendFrameSwapMessagesReceived(frameToken: UInt32) {
    dispatcher.frameSwapMessagesReceived(frameToken: frameToken)
  }
  
  public func sendShowWindow(routeId: Int32, initialRect: IntRect) {
    dispatcher.showWindow(routeId: routeId, initialRect: initialRect)
  }
  
  public func sendShowFullscreenWindow(routeId: Int32) {
    dispatcher.showFullscreenWindow(routeId: routeId)
  }
  
  public func sendUpdateTargetURL(url: String) {
    dispatcher.updateTargetURL(url: url)
  }
  
  public func sendDocumentAvailableInMainFrame(usesTemporaryZoomLevel: Bool) {
    dispatcher.documentAvailableInMainFrame(usesTemporaryZoomLevel: usesTemporaryZoomLevel)
  }
  
  public func sendDidContentsPreferredSizeChange(size: IntSize) {
    dispatcher.didContentsPreferredSizeChange(size: size)
  }
  
  public func sendRouteCloseEvent() {
    dispatcher.routeCloseEvent()
  }
  
  public func sendTakeFocus(reverse: Bool) {
    dispatcher.takeFocus(reverse: reverse)
  }
  
  public func sendClosePageACK() {
    dispatcher.closePageACK()
  }
  
  public func sendFocus() {
    dispatcher.focus()
  }
  
  public func sendCreateNewWindowOnHost(params: CreateNewWindowParams) {
    dispatcher.createNewWindowOnHost(params: params)
  }
  
  public func sendDidCommitProvisionalLoad(params: DidCommitProvisionalLoadParams) {
    dispatcher.didCommitProvisionalLoad(params: params)
  }

  public func sendDidCommitSameDocumentNavigation(params: DidCommitProvisionalLoadParams) {
    dispatcher.didCommitSameDocumentNavigation(params: params)
  }
  
  public func sendBeginNavigation(url: String) {
    dispatcher.beginNavigation(url: url)
  }
  
  public func sendDidChangeName(name: String) {
    dispatcher.didChangeName(name: name)
  }

  public func sendDidChangeOpener(opener: Int) {
    dispatcher.didChangeOpener(opener: opener)
  }

  public func sendDetachFrame(id: Int) {
    dispatcher.detachFrame(id: id)
  }
  
  public func sendFrameSizeChanged(size: IntSize) {
    dispatcher.frameSizeChanged(size: size)
  }
  
  public func sendOnUpdatePictureInPictureSurfaceId(surfaceId: SurfaceId, size: IntSize) {
    dispatcher.onUpdatePictureInPictureSurfaceId(surfaceId: surfaceId, size: size)
  }
  
  public func sendOnExitPictureInPicture() {
    dispatcher.onExitPictureInPicture()
  }
  
  public func sendOnSwappedOut() {
    dispatcher.onSwappedOut()
  }

  public func sendCancelTouchTimeout() {
    dispatcher.cancelTouchTimeout()
  }
  
  public func sendSetWhiteListedTouchAction(action: TouchAction, uniqueTouchEventId: UInt32, inputEventState: Int32) {
    dispatcher.setWhiteListedTouchAction(action: action, uniqueTouchEventId: uniqueTouchEventId, inputEventState: inputEventState)
  }
  
  public func sendDidOverscroll(params: DidOverscrollParams) {
    dispatcher.didOverscroll(params: params)
  }
  
  public func sendDidStopFlinging() {
    dispatcher.didStopFlinging()
  }
  
  public func sendDidStartScrollingViewport() {
    dispatcher.didStartScrollingViewport() 
  }
  
  public func sendImeCancelComposition() {
    dispatcher.imeCancelComposition()
  }
  
  public func sendImeCompositionRangeChanged(range: TextRange, bounds: [IntRect]) {
    dispatcher.imeCompositionRangeChanged(range: range, bounds: bounds)
  }

  public func sendSelectWordAroundCaretAck(didSelect: Bool, start: Int, end: Int) {
    dispatcher.selectWordAroundCaretAck(didSelect: didSelect, start: start, end: end)
  }

  public func sendSwapOutAck() {
    dispatcher.swapOutAck()
  }

  //public func sendDetach() {
  //  dispatcher.detach() 
  //}

  public func sendFrameFocused() {
    dispatcher.frameFocused()
  }

  public func sendDidStartProvisionalLoad(url: String, navigationStart: TimeTicks) {
    dispatcher.didStartProvisionalLoad(url: url, navigationStart: navigationStart)
  }

  public func sendDidFailProvisionalLoadWithError(url: String, errorCode: Int32, description: String) {
    dispatcher.didFailProvisionalLoadWithError(url: url, errorCode: errorCode, description: description)
  }

  public func sendDidFinishDocumentLoad() {
    dispatcher.didFinishDocumentLoad()
  }

  public func sendDidFailLoadWithError(url: String, errorCode: Int32, description: String) {
    dispatcher.didFailLoadWithError(url: url, errorCode: errorCode, description: description) 
  }
  
  public func sendDidStartLoading(toDifferentDocument: Bool) {
    dispatcher.didStartLoading(toDifferentDocument: toDifferentDocument)
  }

  public func sendDidStopLoading() {
    dispatcher.didStopLoading()
  }
  
  public func sendDidChangeLoadProgress(loadProgress: Double) {
    dispatcher.didChangeLoadProgress(loadProgress: loadProgress)
  }

  public func sendOpenURL(url: String) {
    dispatcher.openURL(url: url) 
  }

  public func sendDidFinishLoad(url: String) {
    dispatcher.didFinishLoad(url: url) 
  }
  
  public func sendDocumentOnLoadCompleted(timestamp: TimeTicks) {
    dispatcher.documentOnLoadCompleted(timestamp: timestamp) 
  }

  public func sendDidAccessInitialDocument() {
    dispatcher.didAccessInitialDocument() 
  }

  public func sendUpdateTitle(title: String, direction: TextDirection) {
    dispatcher.updateTitle(title: title, direction: direction) 
  }

  public func sendBeforeUnloadAck(
    proceed: Bool, 
    startTime: TimeTicks, 
    endTime: TimeTicks) {

    dispatcher.beforeUnloadAck(
      proceed: proceed,
      startTime: startTime,
      endTime: endTime)
  }

  public func sendSynchronizeVisualProperties(
    surface: SurfaceId, 
    screenInfo: ScreenInfo,
    autoResizeEnable: Bool,
    minSize: IntSize,
    maxSize: IntSize,
    screenSpaceRect: IntRect,
    localFrameSize: IntSize,
    captureSequenceNumber: Int32) {
    
    dispatcher.synchronizeVisualProperties(
      surface: surface, 
      screenInfo: screenInfo,
      autoResizeEnable: autoResizeEnable,
      minSize: minSize,
      maxSize: maxSize,
      screenSpaceRect: screenSpaceRect,
      localFrameSize: localFrameSize,
      captureSequenceNumber: captureSequenceNumber)
  }
  
  public func sendUpdateViewportIntersection(intersection: IntRect, visible: IntRect) {
    dispatcher.updateViewportIntersection(intersection: intersection, visible: visible)
  }
  
  public func sendVisibilityChanged(visible: Bool) {
    dispatcher.visibilityChanged(visible: visible)
  }
  
  public func sendUpdateRenderThrottlingStatus(isThrottled: Bool, subtreeThrottled: Bool) {
    dispatcher.updateRenderThrottlingStatus(isThrottled: isThrottled, subtreeThrottled: subtreeThrottled)
  }
  
  public func sendSetHasReceivedUserGesture() {
    dispatcher.setHasReceivedUserGesture() 
  }
  
  public func sendSetHasReceivedUserGestureBeforeNavigation(value: Bool) {
    dispatcher.setHasReceivedUserGestureBeforeNavigation(value: value) 
  }
  
  public func sendContextMenu() {
    dispatcher.contextMenu()
  }
  
  public func sendSelectionChanged(selection: String, offset: UInt32, range: TextRange) {
    dispatcher.selectionChanged(selection: selection, offset: offset, range: range)
  }
  
  public func sendVisualStateResponse(id: UInt64) {
    dispatcher.visualStateResponse(id: id) 
  }
  
  public func sendEnterFullscreen() {
    dispatcher.enterFullscreen() 
  }
  
  public func sendExitFullscreen() {
    dispatcher.exitFullscreen() 
  }
  
  public func sendDispatchLoad() {
    dispatcher.dispatchLoad()
  }
  
  public func sendCheckCompleted() {
    dispatcher.checkCompleted() 
  }
  
  public func sendUpdateFaviconUrl(urls faviconUrls: ContiguousArray<String>) {
    dispatcher.updateFaviconUrl(faviconUrls) 
  }
  
  public func sendScrollRectToVisibleInParentFrame(rect: IntRect) {
    dispatcher.scrollRectToVisibleInParentFrame(rect: rect) 
  }

  public func sendFrameDidCallFocus() {
    dispatcher.frameDidCallFocus() 
  }

  public func sendTextSurroundingSelectionResponse(content: String, start: UInt32, end: UInt32) {
    dispatcher.textSurroundingSelectionResponse(content: content, start: start, end: end)
  }

  public func sendLayerTreeFrameSinkInitialized() {
    dispatcher.layerTreeFrameSinkInitialized()
  }

  public func sendCloseAck() {
    dispatcher.closeAck()
  }

  public func sendOnMediaDestroyed(delegate: Int) {
    dispatcher.sendOnMediaDestroyed(delegate: delegate)
  }

  public func sendOnMediaPaused(delegate: Int, reachedEndOfStream: Bool) {
    dispatcher.sendOnMediaPaused(delegate: delegate, reachedEndOfStream: reachedEndOfStream)
  }
  
  public func sendOnMediaPlaying(delegate: Int, hasVideo: Bool, hasAudio: Bool, isRemote: Bool, contentType: MediaContentType) {
    dispatcher.sendOnMediaPlaying(delegate: delegate, hasVideo: hasVideo, hasAudio: hasAudio, isRemote: isRemote, contentType: contentType)
  }
  
  public func sendOnMediaMutedStatusChanged(delegate: Int, muted: Bool) {
    dispatcher.sendOnMediaMutedStatusChanged(delegate: delegate, muted: muted)
  }
  
  public func sendOnMediaEffectivelyFullscreenChanged(delegate: Int, status: WebFullscreenVideoStatus) {
    dispatcher.sendOnMediaEffectivelyFullscreenChanged(delegate: delegate, status: status)
  }
  
  public func sendOnMediaSizeChanged(delegate: Int, size: IntSize) {
    dispatcher.sendOnMediaSizeChanged(delegate: delegate, size: size)
  }

  public func sendOnPictureInPictureSourceChanged(delegate: Int) {
    dispatcher.sendOnPictureInPictureSourceChanged(delegate: delegate)
  }
  
  public func sendOnPictureInPictureModeEnded(delegate: Int) {
    dispatcher.sendOnPictureInPictureModeEnded(delegate: delegate)
  }

}

fileprivate func netConnectionTypeToWebConnectionType(_ type: NetworkConnectionType) -> WebConnectionType {
  switch type {
    case .Unknown:
      return WebConnectionType.Unknown
    case .Ethernet:
      return WebConnectionType.Ethernet
    case .Wifi:
      return WebConnectionType.Wifi
    case .Cellular2G:
      return WebConnectionType.Cellular2G
    case .Cellular3G:
      return WebConnectionType.Cellular3G
    case .Cellular4G:
      return WebConnectionType.Cellular4G
    case .None:
      return WebConnectionType.None
    case .Bluetooth:
      return WebConnectionType.Bluetooth
  }
}

fileprivate let InvalidNextPreviousFlagsValue = TextInputFlags.Invalid