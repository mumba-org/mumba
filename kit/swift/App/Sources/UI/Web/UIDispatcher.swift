// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Application
import Graphics
import Compositor
import Text
import Web

public typealias RendererPrefs = Int
public typealias WebPreferences = Int
public typealias InterfaceProvider = UnsafeMutableRawPointer

public enum SelectionMenuBehavior : Int {
  case Hide
  case Show
}

public enum InputEventAckState : Int {
  case Unknown = 0
  case Consumed = 1
  case NotConsumed = 2
  case ConsumedShouldBubble = 3
  case NoConsumerExists = 4
  case Ignored = 5
  case SetNonBlocking = 6
  case SetNonBlockingDueToFling = 7

  static func fromWebInputEvent(_ ev: WebInputEvent.Result) -> InputEventAckState {
    return ev == .notHandled ? InputEventAckState.NotConsumed : InputEventAckState.Consumed
  }
}

public protocol UIDispatcherSender : class {
  // sending methods (called by app to host)
  func sendApplicationProcessGone(status: Int32, exitCode: Int32)
  func sendHittestData(surfaceId: SurfaceId, ignoredForHittest: Bool)
  func sendClose()
  func sendUpdateState()
  func sendUpdateScreenRectsAck()
  func sendRequestMove(position: IntRect)
  func sendSetTooltipText(text: String, direction: TextDirection)
  func sendResizeOrRepaintACK(viewSize: IntSize, flags: Int32, localSurfaceId: LocalSurfaceId?)
  func sendSetCursor(cursor: WebCursorInfo)
  func sendAutoscrollStart(start: FloatPoint)
  func sendAutoscrollFling(velocity: FloatVec2)
  func sendAutoscrollEnd()
  func sendTextInputStateChanged(textInputState: TextInputState)
  func sendLockMouse(userGesture: Bool, privileged: Bool)
  func sendUnlockMouse()
  func sendSelectionBoundsChanged(params: SelectionBoundsParams)
  func sendFocusedNodeTouched(editable: Bool)
  func sendStartDragging(dropData: DropData,
                opsAllowed: DragOperation,
                image: Bitmap,
                imageOffset: IntVec2)
  func sendUpdateDragCursor(dragOperation: DragOperation)
  func sendFrameSwapMessagesReceived(frameToken: UInt32)
  func sendShowWindow(routeId: Int32, initialRect: IntRect)
  func sendShowFullscreenWindow(routeId: Int32)
  func sendUpdateTargetURL(url: String)
  func sendDocumentAvailableInMainFrame(usesTemporaryZoomLevel: Bool)
  func sendDidContentsPreferredSizeChange(size: IntSize)
  func sendRouteCloseEvent()
  func sendTakeFocus(reverse: Bool)
  func sendClosePageACK()
  func sendFocus()
  func sendCreateNewWindowOnHost(params: CreateNewWindowParams)
  func sendDidCommitProvisionalLoad(params: DidCommitProvisionalLoadParams)
  func sendDidCommitSameDocumentNavigation(params: DidCommitProvisionalLoadParams)
    //interfaceProviderRequest: InterfaceProvider)
  func sendBeginNavigation(url: String)
  func sendDidChangeName(name: String)
  func sendFrameSizeChanged(size: IntSize)
  func sendOnUpdatePictureInPictureSurfaceId(surfaceId: SurfaceId, size: IntSize)
  func sendOnExitPictureInPicture()
  func sendOnSwappedOut()
  func sendCancelTouchTimeout()
  func sendSetWhiteListedTouchAction(action: TouchAction, uniqueTouchEventId: UInt32, inputEventState: Int32)
  func sendDidOverscroll(params: DidOverscrollParams)
  func sendDidStopFlinging()
  func sendDidStartScrollingViewport()
  func sendImeCancelComposition()
  func sendImeCompositionRangeChanged(range: TextRange, bounds: [IntRect])
  func sendSwapOutAck()
  //func sendDetach()
  func sendFrameFocused()
  func sendDidStartProvisionalLoad(url: String, navigationStart: TimeTicks)
  func sendDidFailProvisionalLoadWithError(url: String, errorCode: Int32, description: String)
  func sendDidFinishDocumentLoad()
  func sendDidFailLoadWithError(url: String, errorCode: Int32, description: String)
  func sendDidStartLoading(toDifferentDocument: Bool)
  func sendDidStopLoading()
  func sendDidChangeLoadProgress(loadProgress: Double)
  func sendOpenURL(url: String)
  func sendDidFinishLoad(url: String)
  func sendDocumentOnLoadCompleted(timestamp: TimeTicks)
  func sendDidAccessInitialDocument()
  func sendUpdateTitle(title: String, direction: TextDirection)
  func sendBeforeUnloadAck(proceed: Bool, startTime: TimeTicks, endTime: TimeTicks)
  func sendSynchronizeVisualProperties(
    surface: SurfaceId, 
    screenInfo: ScreenInfo,
    autoResizeEnable: Bool,
    minSize: IntSize,
    maxSize: IntSize,
    screenSpaceRect: IntRect,
    localFrameSize: IntSize,
    captureSequenceNumber: Int32)
  func sendUpdateViewportIntersection(intersection: IntRect, visible: IntRect)
  func sendVisibilityChanged(visible: Bool)
  func sendUpdateRenderThrottlingStatus(isThrottled: Bool, subtreeThrottled: Bool)
  func sendSetHasReceivedUserGesture()
  func sendSetHasReceivedUserGestureBeforeNavigation(value: Bool)
  func sendContextMenu()
  func sendSelectionChanged(selection: String, offset: UInt32, range: TextRange)
  func sendVisualStateResponse(id: UInt64)
  func sendEnterFullscreen()
  func sendExitFullscreen()
  func sendDispatchLoad()
  func sendCheckCompleted()
  func sendUpdateFaviconUrl(urls: ContiguousArray<String>)
  func sendScrollRectToVisibleInParentFrame(rect: IntRect)
  func sendFrameDidCallFocus()
  func sendSelectWordAroundCaretAck(didSelect: Bool, start: Int, end: Int)
  func sendTextSurroundingSelectionResponse(content: String, start: UInt32, end: UInt32)
  func sendDidChangeOpener(opener: Int)
  func sendDetachFrame(id: Int)
  func sendHasTouchEventHandlers(hasHandlers: Bool)
  func sendLayerTreeFrameSinkInitialized()
  func sendCloseAck()
  func sendOnMediaDestroyed(delegate: Int)
  func sendOnMediaPaused(delegate: Int, reachedEndOfStream: Bool)
  func sendOnMediaPlaying(delegate: Int, hasVideo: Bool, hasAudio: Bool, isRemote: Bool, contentType: MediaContentType)
  func sendOnMediaMutedStatusChanged(delegate: Int, muted: Bool)
  func sendOnMediaEffectivelyFullscreenChanged(delegate: Int, status: WebFullscreenVideoStatus)
  func sendOnMediaSizeChanged(delegate: Int, size: IntSize) 
  func sendOnPictureInPictureSourceChanged(delegate: Int)
  func sendOnPictureInPictureModeEnded(delegate: Int)
}

public protocol UIDispatcherDelegate : class {
  var compositor: UIWebWindowCompositor? { get }
  var mainWebFrame: WebLocalFrame? { get }
  var webView: WebView? { get }
  var webFrameWidget: WebFrameWidget? { get }
  //var hasTouchEventHandlers: Bool { get }
  
  // receiving methods (from host to app)
  func getWebFrame(routingId: Int) -> WebFrame?
  func onSetPageScale(pageScaleFactor: Float)
  func onSetInitialFocus(reverse: Bool)
  func onSetBackgroundOpaque(opaque: Bool)
  func onUpdateTargetURLAck()
  func onUpdateWebPreferences(webPreferences: WebPreferences)
  func onClosePage()
  func onMoveOrResizeStarted()
  func onSetRendererPrefs(prefs: RendererPrefs)
  func onEnablePreferredSizeChangedMode()
  func onDisableScrollbarsForSmallWindows(disableScrollbarSizeLimit: IntSize)
  func onForceRedraw(latency: LatencyInfo)
  func onSelectWordAroundCaret()
  func onUpdateWindowScreenRect(_ windowScreenRect: IntRect)
  func onPageWasHidden()  
  func onPageWasShown()
  func onSetHistoryOffsetAndLength(historyOffset: Int32, historyLength: Int32)
  func onAudioStateChanged(isAudioPlaying: Bool)
  func onPausePageScheduledTasks(pause: Bool)
  func onUpdateScreenInfo(_ screenInfo: ScreenInfo)
  func onFreezePage()
  func onSetActive(active: Bool)
  func onShowContextMenu(type: MenuSourceType, location: IntPoint)
  func onClose()
  func onSetZoomLevel(zoomLevel: Double)
  func onSetTextDirection(direction: TextDirection)
  func onSetIsInert(inert: Bool)
  func onSynchronizeVisualProperties(params: VisualProperties)
  func onWasHidden()
  func onWasShown(needsRepainting: Bool, latencyInfo: LatencyInfo)
  func onRepaint(size: IntSize)
  func onRequestMoveAck()
  func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect)
  func onSetViewportIntersection(intersection: IntRect, visibleRect: IntRect)
  func onUpdateRenderThrottlingStatus(isThrottled: Bool, subtreeThrottled: Bool)
  func onDragTargetDragEnter(dropData: [DropData.Metadata],
                           client: FloatPoint,
                           screen: FloatPoint,
                           opsAllowed: DragOperation,
                           keyModifiers: Int)
  func onDragTargetDragOver(client: FloatPoint,
                          screen: FloatPoint,
                          opsAllowed: DragOperation,//Int, // DragOperationMask
                          keyModifiers: Int)
  func onDragTargetDragLeave(clientPoint: FloatPoint, sourcePoint: FloatPoint)
  func onDragTargetDrop(dropData: DropData,
                      client: FloatPoint,
                      screen: FloatPoint,
                      keyModifiers: Int)
  func onDragSourceEnded(client: FloatPoint,
                       screen: FloatPoint,
                       dragOperations: DragOperation)
  func onDragSourceSystemDragEnded()
  func onMediaPlayerAction(at: IntPoint, action: Int32, enable: Bool)
  func onSetFocusedWindow()
  func onLockMouseAck(succeeded: Bool)
  func onMouseLockLost()
  func onCopyImage(at: FloatPoint)
  func onSaveImage(at: FloatPoint)
  func onSwapOut(windowId: Int32, loading: Bool)

  func onSetFocus(focused: Bool)
  func onMouseCaptureLost()
  func onSetEditCommandsForNextKeyEvent(
    editCommandName: [String],
    editCommandValue: [String],
    editCommandCount: Int)
  func onCursorVisibilityChanged(visible: Bool)
  func onImeSetComposition( 
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    selectionStart: Int, 
    selectionEnd: Int)
  func onImeCommitText(
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    relativeCursorPosition: Int)

  func onImeFinishComposingText(keepSelection: Bool)
  func onRequestTextInputStateUpdate()
  func onRequestCompositionUpdates(immediateRequest: Bool, monitorRequest: Bool)
  func onDispatchEvent(event: WebInputEvent) -> InputEventAckState
  func onDispatchNonBlockingEvent(event: WebInputEvent)
  func onSetCompositionFromExistingText(
    start: Int, 
    end: Int,
    spans: [WebImeTextSpan])
  func onExtendSelectionAndDelete(before: Int, after: Int)
  func onDeleteSurroundingText(before: Int, after: Int)
  func onDeleteSurroundingTextInCodePoints(before: Int, after: Int)
  func onSetEditableSelectionOffsets(start: Int, end: Int)
  func onExecuteEditCommand(command: String, value: String)
  func onUndo()
  func onRedo()
  func onCut()
  func onCopy()
  func onCopyToFindPboard()
  func onPaste()
  func onPasteAndMatchStyle()
  func onDelete()
  func onSelectAll()
  func onCollapseSelection()
  func onReplace(word: String)
  func onReplaceMisspelling(word: String)
  func onSelectRange(base: IntPoint, extent: IntPoint)
  func onAdjustSelectionByCharacterOffset(start: Int, end: Int, behavior: SelectionMenuBehavior)
  func onMoveRangeSelectionExtent(extent: IntPoint)
  func onScrollFocusedEditableNodeIntoRect(rect: IntRect)
  func onMoveCaret(position: IntPoint)

  func onIntrinsicSizingInfoOfChildChanged(
      size: FloatSize,
      aspectRatio: FloatSize, 
      hasWidth: Bool, 
      hasHeight: Bool)
  func onBeforeUnload(isReload: Bool)
  func onViewChanged(frameSink: FrameSinkId?)
  func onSetChildFrameSurface(surfaceInfo: SurfaceInfo)
  func onChildFrameProcessGone()
  func onSwapIn()
  func onFrameDelete()
  func onStop()
  func onDroppedNavigation()
  func onDidStartLoading()
  func onDidStopLoading()
  func onCollapse(collapsed: Bool)
  func onWillEnterFullscreen()
  func onEnableAutoResize(min: IntSize, max: IntSize)
  func onDisableAutoResize()
  func onContextMenuClosed()
  func onCustomContextMenuAction(action: UInt32)
  func onVisualStateRequest(id: UInt64)
  func onDispatchLoad()
  func onReload(bypassCache: Bool)
  func onReloadLoFiImages()
  func onSnapshotAccessibilityTree()
  func onUpdateOpener(routingId: UInt32)
  func onSetFocusedFrame()
  func onCheckCompleted()
  func onPostMessageEvent()
  func onNotifyUserActivation()
  func onDidUpdateOrigin(origin: String)
  func onScrollRectToVisible(rect: IntRect)
  func onTextSurroundingSelectionRequest(maxLength: UInt32)
  func onAdvanceFocus(type: WebFocusType, sourceRoutingId: Int32)
  func onAdvanceFocusInForm(type: WebFocusType)
  func onFind(requestId: Int32, searchText: String, options: WebFindOptions)
  func onClearActiveFindMatch()
  func onStopFinding(action: WebFrameStopFindAction)
  func onClearFocusedElement()
  func onSetOverlayRoutingToken(token: UnguessableToken)
  func onCommitNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int)
  func onCommitSameDocumentNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) -> CommitResult
  func onCommitFailedNavigation(
    errorCode: Int,
    errorPageContent: String?)
  func onNetworkConnectionChanged(
    connectionType: NetworkConnectionType, 
    maxBandwidthMbps: Double)
}

public class UIDispatcher {
  
  internal var unmanagedSelf: UnsafeMutableRawPointer? {
    return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  }

  internal weak var delegate: UIDispatcherDelegate?
  internal var state: WindowRef?
  internal var serviceWorkerNetworkProvider: WebServiceWorkerNetworkProvider?
  private let emptyBlinkCallbacks: CBlinkPlatformCallbacks = CBlinkPlatformCallbacks()
  private let emptyResponseCallbacks: CResponseHandler = CResponseHandler()
  
  public static func createCallbacks() -> CWindowCallbacks {
    var callbacks = CWindowCallbacks()
    memset(&callbacks, 0, MemoryLayout<CWindowCallbacks>.stride)

    callbacks.SetPageScale = { (handle: UnsafeMutableRawPointer?, pageScaleFactor: Float) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetPageScale(pageScaleFactor: pageScaleFactor)
    }

    callbacks.SetInitialFocus = { (handle: UnsafeMutableRawPointer?, reverse: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetInitialFocus(reverse: Bool(reverse))
    }
    
    callbacks.UpdateTargetURLAck = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateTargetURLAck()
    }
    
    callbacks.UpdateWebPreferences = { (handle: UnsafeMutableRawPointer?, webPreferences: UnsafeMutableRawPointer?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateWebPreferences(webPreferences: 0)
    }
    
    callbacks.ClosePage = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onClosePage()
    }
    
    callbacks.MoveOrResizeStarted = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onMoveOrResizeStarted()
    }
    
    callbacks.SetBackgroundOpaque = { (handle: UnsafeMutableRawPointer?, opaque: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetBackgroundOpaque(opaque: opaque != 0)
    }
    
    callbacks.EnablePreferredSizeChangedMode = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onEnablePreferredSizeChangedMode()
    }
    
    callbacks.DisableScrollbarsForSmallWindows = { (handle: UnsafeMutableRawPointer?, width: CInt, height: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDisableScrollbarsForSmallWindows(disableScrollbarSizeLimit: IntSize(width: Int(width), height: Int(height)))
    }
    
    callbacks.SetRendererPrefs = { (handle: UnsafeMutableRawPointer?, prefs: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetRendererPrefs(prefs: 0)
    }
    
    callbacks.SetActive = { (handle: UnsafeMutableRawPointer?, active: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetActive(active: active != 0)
    }
    
    callbacks.ForceRedraw = { (handle: UnsafeMutableRawPointer?,
       traceName: UnsafePointer<Int8>?,// const char*,
       traceId: Int64,
       ukmSourceId: CInt,
       coalesced: CInt,
       began: CInt,
       terminated: CInt,
       sourceEventType: CInt,
       scrollUpdateDelta: Float,
       predictedScrollUpdateDelta: Float,
       latencyComponentsSize: Int,
       componentTypes: UnsafeMutablePointer<Int32>?, 
       eventTime: UnsafeMutablePointer<Int64>?) in 

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      
      var latencyInfo = LatencyInfo()    
      latencyInfo.traceId = traceId
      latencyInfo.traceName = String(cString: traceName!)
      latencyInfo.ukmSourcedId = Int64(ukmSourceId)
      latencyInfo.coalesced = Bool(coalesced)
      latencyInfo.began = Bool(began)
      latencyInfo.terminated = Bool(terminated)
      latencyInfo.sourceEventType = SourceEventType(rawValue: Int(sourceEventType))!
      latencyInfo.scrollUpdateDelta = scrollUpdateDelta
      latencyInfo.predictedScrollUpdateDelta = predictedScrollUpdateDelta
      for n in 0..<latencyComponentsSize {
        let componentType = LatencyComponentType(rawValue: Int(componentTypes![n]))!
        latencyInfo.components[componentType] = TimeTicks(microseconds: eventTime![n])
      }
      state.delegate?.onForceRedraw(latency: latencyInfo)
    }

    callbacks.SelectWordAroundCaret = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSelectWordAroundCaret()
    }
    
    callbacks.UpdateWindowScreenRect = { (handle: UnsafeMutableRawPointer?, rx: CInt, ry: CInt, rw: CInt, rh: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateWindowScreenRect(IntRect(x: Int(rx), y: Int(ry), width: Int(rw), height: Int(rh)))
    }
    
    callbacks.SetZoomLevel = { (handle: UnsafeMutableRawPointer?, zoomLevel: Double) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetZoomLevel(zoomLevel: zoomLevel)
    }
    
    callbacks.PageWasHidden = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPageWasHidden()
    }
    
    callbacks.PageWasShown = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPageWasShown()
    }
    
    callbacks.SetHistoryOffsetAndLength = { (handle: UnsafeMutableRawPointer?, historyOffset: Int32, historyLength: Int32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetHistoryOffsetAndLength(historyOffset: historyOffset, historyLength: historyLength)
    }
    
    callbacks.AudioStateChanged = { (handle: UnsafeMutableRawPointer?, isAudioPlaying: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onAudioStateChanged(isAudioPlaying: Bool(isAudioPlaying))
    }
    
    callbacks.PausePageScheduledTasks = { (handle: UnsafeMutableRawPointer?, pause: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPausePageScheduledTasks(pause: Bool(pause))
    }
    
    callbacks.UpdateScreenInfo = { (
      handle: UnsafeMutableRawPointer?, 
      scale: Float,
      depth: UInt32, 
      depthPerComponent: UInt32,
      monochrome: CInt,
      rx: CInt,
      ry: CInt, 
      rw: CInt,
      rh: CInt,
      avrx: CInt,
      avry: CInt, 
      avrw: CInt,
      avrh: CInt,
      orientationType: CInt,
      orientationAngle: UInt16) in 

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      var screen = ScreenInfo()

      screen.deviceScaleFactor = scale
      screen.depth = depth
      screen.depthPerComponent = depthPerComponent
      screen.isMonochrome = monochrome != 0
      screen.rect = IntRect(x: Int(rx), y: Int(ry), width: Int(rw), height: Int(rh))
      screen.availableRect = IntRect(x: Int(avrx), y: Int(avry), width: Int(avrw), height: Int(avrh))
      screen.orientationType = ScreenOrientationValues(rawValue: Int(orientationType))!
      screen.orientationAngle = orientationAngle
      state.delegate?.onUpdateScreenInfo(screen)
    }
    
    callbacks.FreezePage = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onFreezePage()
    }
    
    callbacks.ShowContextMenu = { (handle: UnsafeMutableRawPointer?, type: CInt, px: CInt, py: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onShowContextMenu(type: MenuSourceType(rawValue: Int(type))!, location: IntPoint(x: Int(px), y: Int(py)))
    }
    
    callbacks.Close = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onClose()
    }
    
    callbacks.SynchronizeVisualProperties = { 
     (handle: UnsafeMutableRawPointer?, 
      surfaceIdParentSequenceNumber: UInt32,
      surfaceIdChildSequenceNumber: UInt32,
      surfaceIdTokenHigh: UInt64, 
      surfaceIdTokenLow: UInt64,
      screenInfoDeviceScaleFactor: Float,
      screenInfoColorSpacePrimaries: UInt8,
      screenInfoColorSpaceTransfer: UInt8,
      screenInfoColorSpaceMatrix: UInt8,
      screenInfoColorSpaceRange: UInt8,
      screenInfocolorSpaceIccProfile: Int64,
      screenInfoDepth: UInt32,
      screenInfoDepthPerComponent: UInt32,
      screenInfoIsMonochrome: CInt,
      screenInfoRectX: CInt,
      screenInfoRectY: CInt,
      screenInfoRectW: CInt,
      screenInfoRectH: CInt,
      screenInfoAvailableRectX: CInt,
      screenInfoAvailableRectY: CInt,
      screenInfoAvailableRectW: CInt,
      screenInfoAvailableRectH: CInt,
      screenInfoOrientationType: CInt,
      screenInfoOrientationAngle: UInt16,
      autoResizeEnabled: CInt,
      minSizeForAutoResizeW: CInt, 
      minSizeForAutoResizeH: CInt, 
      maxSizeForAutoResizeW: CInt, 
      maxSizeForAutoResizeH: CInt,
      newSizeW: CInt, 
      newSizeH: CInt,
      compositorViewportSizeW: CInt,
      compositorViewportSizeH: CInt,   
      visibleViewportSizeW: CInt,
      visibleViewportSizeH: CInt,
      captureSequenceNumber: Int32) in 
      
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      var properties = VisualProperties()
      properties.screenInfo.deviceScaleFactor = screenInfoDeviceScaleFactor
      properties.screenInfo.depth = screenInfoDepth
      properties.screenInfo.depthPerComponent = screenInfoDepthPerComponent
      properties.screenInfo.isMonochrome = screenInfoIsMonochrome != 0
      properties.screenInfo.colorSpace = ColorSpace(
        primaries: ColorSpace.PrimaryId(rawValue: screenInfoColorSpacePrimaries)!,
        transfer: ColorSpace.TransferId(rawValue: screenInfoColorSpaceTransfer)!,
        matrix: ColorSpace.MatrixId(rawValue: screenInfoColorSpaceMatrix)!,
        range: ColorSpace.RangeId(rawValue: screenInfoColorSpaceRange)!,
        iccProfile: screenInfocolorSpaceIccProfile
      )
      properties.screenInfo.rect = IntRect(x: Int(screenInfoRectX), y: Int(screenInfoRectY), width: Int(screenInfoRectW), height: Int(screenInfoRectH))
      properties.screenInfo.availableRect = IntRect(x: Int(screenInfoAvailableRectX), y: Int(screenInfoAvailableRectY), width: Int(screenInfoAvailableRectW), height: Int(screenInfoAvailableRectH))
      properties.screenInfo.orientationType = ScreenOrientationValues(rawValue: Int(screenInfoOrientationType))!
      properties.screenInfo.orientationAngle = screenInfoOrientationAngle
      properties.autoResizeEnabled = autoResizeEnabled != 0
      properties.minSizeForAutoResize = IntSize(width: Int(minSizeForAutoResizeW), height: Int(minSizeForAutoResizeH))
      properties.maxSizeForAutoResize = IntSize()
      properties.newSize = IntSize(width: Int(newSizeW), height: Int(newSizeH))
      properties.compositorViewportPixelSize = IntSize(width: Int(compositorViewportSizeW), height: Int(compositorViewportSizeH))
      properties.localSurfaceId = LocalSurfaceId()
      properties.localSurfaceId!.parentSequenceNumber = surfaceIdParentSequenceNumber
      properties.localSurfaceId!.childSequenceNumber = surfaceIdChildSequenceNumber
      properties.localSurfaceId!.token = UnguessableToken(high: surfaceIdTokenHigh, low: surfaceIdTokenLow)
      properties.visibleViewportSize = IntSize(width: Int(visibleViewportSizeW), height: Int(visibleViewportSizeH))
      properties.captureSequenceNumber = UInt32(captureSequenceNumber)
      
      state.delegate?.onSynchronizeVisualProperties(params: properties)
    }
    
    callbacks.WasHidden = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onWasHidden()
    }
    
    callbacks.WasShown = { (handle: UnsafeMutableRawPointer?,
       needsRepainting: CInt,
       traceName: UnsafePointer<Int8>?,
       traceId: Int64,
       ukmSourceId: CInt,
       coalesced: CInt,
       began: CInt,
       terminated: CInt,
       sourceEventType: CInt,
       scrollUpdateDelta: Float,
       predictedScrollUpdateDelta: Float,
       latencyComponentsSize: Int,
       componentTypes: UnsafeMutablePointer<Int32>?, 
       eventTime: UnsafeMutablePointer<Int64>?) in

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      
      var latencyInfo = LatencyInfo()    
      latencyInfo.traceId = traceId
      latencyInfo.traceName = String(cString: traceName!)
      latencyInfo.ukmSourcedId = Int64(ukmSourceId)
      latencyInfo.coalesced = Bool(coalesced)
      latencyInfo.began = Bool(began)
      latencyInfo.terminated = Bool(terminated)
      latencyInfo.sourceEventType = SourceEventType(rawValue: Int(sourceEventType))!
      latencyInfo.scrollUpdateDelta = scrollUpdateDelta
      latencyInfo.predictedScrollUpdateDelta = predictedScrollUpdateDelta

      for n in 0..<latencyComponentsSize {
        let componentType = LatencyComponentType(rawValue: Int(componentTypes![n]))!
        latencyInfo.components[componentType] = TimeTicks(microseconds: eventTime![n])
      }

      state.delegate?.onWasShown(
        needsRepainting: Bool(needsRepainting),
        latencyInfo: latencyInfo)
    }

    //LayerTreeHostRef (*GetLayerTreeHost)(void* state) 
    callbacks.GetLayerTreeHost = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      if let layerTreeHost = state.delegate?.compositor?.layerTreeHost {
        return layerTreeHost.reference
      }
      return nil
    }

    // WebFrameRef (*GetMainWebFrame)(void* state)
    callbacks.GetMainWebFrame = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      if let frame = state.delegate?.mainWebFrame {
        return frame.reference
      }
      return nil
    }
    
    // WebFrameRef (*GetWebFrame)(void* state, int id)
    callbacks.GetWebFrame = { (handle: UnsafeMutableRawPointer?, id: CInt) -> UnsafeMutableRawPointer? in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      if let frame = state.delegate?.getWebFrame(routingId: Int(id)) {
        return frame.reference
      }
      return nil
    }

    // WebWidgetRef (*GetWebWidget)(void* state)
    callbacks.GetWebWidget = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      if let widget = state.delegate?.webFrameWidget {
        return widget.reference
      }
      return nil
    }

    // WebWidgetClientRef (*GetWebViewClient)(void* state)
    callbacks.GetWebViewClient = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      if let widget = state.delegate?.webView {
        return widget.nativeWebViewClient
      }
      return nil
    }
    
    callbacks.Repaint = { (handle: UnsafeMutableRawPointer?, w: CInt, h: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onRepaint(size: IntSize(width: Int(w), height: Int(h)))
    }
    
    callbacks.SetTextDirection = { (handle: UnsafeMutableRawPointer?, direction: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetTextDirection(direction: TextDirection(rawValue: Int(direction))!) 
    }
    
    callbacks.MoveAck = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onRequestMoveAck()
    }
    
    callbacks.UpdateScreenRects = { (handle: UnsafeMutableRawPointer?, vx: CInt, vy: CInt, vw: CInt, vh: CInt, wx: CInt, wy: CInt, ww: CInt, wh: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateScreenRects(viewScreen: IntRect(x: Int(vx), y: Int(vy), width: Int(vw), height: Int(vh)), windowScreen: IntRect(x: Int(wx), y: Int(wy), width: Int(ww), height: Int(wh)))
    }
    
    callbacks.SetViewportIntersection = { (handle: UnsafeMutableRawPointer?, ix: CInt, iy: CInt, iw: CInt, ih: CInt, vx: CInt, vy: CInt, vw: CInt, vh: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetViewportIntersection(intersection: IntRect(x: Int(ix), y: Int(iy), width: Int(iw), height: Int(ih)), visibleRect: IntRect(x: Int(vx), y: Int(vy), width: Int(vw), height: Int(vh)))
    }
    
    callbacks.SetIsInert = { (handle: UnsafeMutableRawPointer?, inert: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetIsInert(inert: Bool(inert))
    }
    
    callbacks.UpdateRenderThrottlingStatus = { (handle: UnsafeMutableRawPointer?, isThrottled: CInt, subtreeThrottled: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateRenderThrottlingStatus(isThrottled: Bool(isThrottled), subtreeThrottled: Bool(subtreeThrottled))
    }
 

    callbacks.DragTargetDragEnter = { (handle: UnsafeMutableRawPointer?,
                                       dropDataSize: Int, 
                                       dropDataKind: UnsafeMutablePointer<Int32>?,
                                       dropDataMime: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
                                       dropDataFilename: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
                                       dropDataFileSystemUrl: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
                                       cx: Float, cy: Float,
                                       sx: Float, sy: Float,
                                       opsAllowed: CInt,
                                       keyModifiers: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      let metadata: [DropData.Metadata] = []
      state.delegate?.onDragTargetDragEnter(
        dropData: metadata,
        client: FloatPoint(x: cx, y: cy),
        screen: FloatPoint(x: sx, y: sy),
        opsAllowed: DragOperation(rawValue: Int(opsAllowed))!,
        keyModifiers: Int(keyModifiers))
    }
    
    callbacks.DragTargetDragOver = { (handle: UnsafeMutableRawPointer?,
                                      cx: Float, cy: Float,
                                      sx: Float, sy: Float,
                                      opsAllowed: CInt,
                                      keyModifiers: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDragTargetDragOver(
        client: FloatPoint(x: cx, y: cy),
        screen: FloatPoint(x: sx, y: sy),
        opsAllowed: DragOperation(rawValue: Int(opsAllowed))!,
        keyModifiers: Int(keyModifiers))
    }
    
    callbacks.DragTargetDragLeave = { (handle: UnsafeMutableRawPointer?, cx: Float, cy: Float, sx: Float, sy: Float) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDragTargetDragLeave(
        clientPoint: FloatPoint(x: cx, y: cy), 
        sourcePoint: FloatPoint(x: sx, y: sy))
    }

    callbacks.DragTargetDrop = { (handle: UnsafeMutableRawPointer?, 
                                  dropDataViewId: Int32, 
                                  dropDataDidOriginateFromRenderer: Int32, 
                                  dropDataUrlString: UnsafePointer<Int8>?, 
                                  dropDataUrlTitle: UnsafePointer<Int8>?, 
                                  dropDataDownloadNetadata: UnsafePointer<Int8>?, 
                                  dropDataFilenamesSize: Int32, 
                                  dropDataFilenames: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  dropDataFileMimeTypes_size: Int32, 
                                  dropDataFileMimeTypes: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  dropDataFilesystemId: UnsafePointer<Int8>?, 
                                  dropDataFileSystemFilesCount: Int32, 
                                  dropDataFileSystemFilesUrl: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  dropDataFileSystemFilesFilesize: UnsafeMutablePointer<Int32>?, 
                                  dropDataFileSystemFilesFilesystemId: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  dropDataText: UnsafePointer<Int8>?, 
                                  dropDataHtml: UnsafePointer<Int8>?, 
                                  dropDataHtmlBaseUrl: UnsafePointer<Int8>?, 
                                  dropDataFileContents: UnsafePointer<Int8>?, 
                                  dropDataFileContentsSourceUrl: UnsafePointer<Int8>?, 
                                  dropDataFileContentsFilenameExtension: UnsafePointer<Int8>?, 
                                  dropDataFileContentsContentDisposition: UnsafePointer<Int8>?, 
                                  dropDataCustomDataSize: Int32, 
                                  dropDataCustomDataKeys: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  dropDataCustomDataValues: UnsafeMutablePointer<UnsafePointer<Int8>?>?, 
                                  cx: Float, cy: Float,
                                  sx: Float, sy: Float,
                                  keyModifiers: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDragTargetDrop(
        dropData: DropData(),
        client: FloatPoint(x: cx, y: cy),
        screen: FloatPoint(x: sx, y: sy),
        keyModifiers: Int(keyModifiers))
    }
    callbacks.DragSourceEnded = { (handle: UnsafeMutableRawPointer?, cx: Float , cy: Float,
                                   px: Float, py: Float, dragOperations: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDragSourceEnded(
        client: FloatPoint(x: cx, y: cy),
        screen: FloatPoint(x: px, y: py),
        dragOperations: DragOperation(rawValue: Int(dragOperations))!)
    }
    
    callbacks.DragSourceSystemDragEnded = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDragSourceSystemDragEnded()
    }

    callbacks.MediaPlayerActionAt = { (handle: UnsafeMutableRawPointer?, px: CInt, py: CInt, action: CInt, enable: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onMediaPlayerAction(at: IntPoint(x: Int(px), y: Int(py)), action: Int32(action), enable: enable != 0)
    }

    callbacks.SetFocusedWindow = { (handle: UnsafeMutableRawPointer?) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onSetFocusedWindow()
    }

    callbacks.LockMouseAck = { (handle: UnsafeMutableRawPointer?, succeeded: CInt) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onLockMouseAck(succeeded: succeeded != 0)
    }

    callbacks.MouseLockLost = { (handle: UnsafeMutableRawPointer?) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onMouseLockLost()
    }
    
    callbacks.CopyImageAt = { (handle: UnsafeMutableRawPointer?, px: Float, py: Float) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onCopyImage(at: FloatPoint(x: px, y: py))
    }
    
    callbacks.SaveImageAt = { (handle: UnsafeMutableRawPointer?, px: Float, py: Float) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onSaveImage(at: FloatPoint(x: px, y: py))
    }

    callbacks.SwapOut = { (handle: UnsafeMutableRawPointer?, windowId: Int32, loading: CInt) in 
     guard handle != nil else {
       return
     }
     let state = unsafeBitCast(handle, to: UIDispatcher.self)
     state.delegate?.onSwapOut(windowId: windowId, loading: loading != 0)
    }

    callbacks.SetFocus = { (handle: UnsafeMutableRawPointer?, focused: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetFocus(focused: focused != 0) 
    }
    
    callbacks.MouseCaptureLost = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onMouseCaptureLost() 
    }

    callbacks.SetEditCommandsForNextKeyEvent = { 
      (handle: UnsafeMutableRawPointer?,
       editCmdName: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
       editCmdValue: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
       editCmdCount: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetEditCommandsForNextKeyEvent(
        editCommandName: [], 
        editCommandValue: [],
        editCommandCount: 0) 
    }

    callbacks.CursorVisibilityChanged = { (handle: UnsafeMutableRawPointer?, visible: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCursorVisibilityChanged(visible: visible != 0)  
    }
    
    callbacks.ImeSetComposition = { 
      (handle: UnsafeMutableRawPointer?,
       text: UnsafePointer<UInt16>?, 
       tspanType: UnsafeMutablePointer<CInt>?,
       tspanStartOffset: UnsafeMutablePointer<UInt32>?,
       tspanEndOffset: UnsafeMutablePointer<UInt32>?,
       tspanUnderlineColor: UnsafeMutablePointer<CInt>?,
       tspanThickness: UnsafeMutablePointer<CInt>?,
       tspanBackgroundColor: UnsafeMutablePointer<CInt>?,
       tspanCount: CInt,
       rangeStart: UInt32, 
       rangeEnd: UInt32,
       start: Int32, 
       end: Int32) in 

      var textSpans: [WebImeTextSpan] = []

      guard handle != nil else {
        return
      }
      
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      
      for i in 0..<Int(tspanCount) {
        var ts = WebImeTextSpan()
        ts.type = WebImeTextSpanType(rawValue: Int(tspanType![i]))!
        ts.startOffset = Int(tspanStartOffset![i])
        ts.endOffset = Int(tspanEndOffset![i])
        ts.thickness = WebImeTextSpanThickness(rawValue: Int(tspanThickness![i]))!
        ts.underlineColor = Color(Int(tspanUnderlineColor![i]))
        ts.backgroundColor = Color(Int(tspanBackgroundColor![i]))
        textSpans.append(ts)
      }

      state.delegate?.onImeSetComposition(
        text: String(decodingCString: text!, as: UTF16.self),
        spans: textSpans,
        replacement: TextRange(start: Int(rangeStart), end: Int(rangeEnd)),
        selectionStart: Int(start), 
        selectionEnd: Int(end))
    }

    callbacks.ImeCommitText = { 
      (handle: UnsafeMutableRawPointer?,
      text: UnsafePointer<UInt16>?, 
      tspanType: UnsafeMutablePointer<CInt>?,
      tspanStartOffset: UnsafeMutablePointer<UInt32>?,
      tspanEndOffset: UnsafeMutablePointer<UInt32>?,
      tspanUnderlineColor: UnsafeMutablePointer<CInt>?,
      tspanThickness: UnsafeMutablePointer<CInt>?,
      tspanBackgroundColor: UnsafeMutablePointer<CInt>?,
      tspanCount: CInt,
      rangeStart: UInt32, 
      rangeEnd: UInt32,
      relativeCursorPosition: Int32) in 

      var textSpans: [WebImeTextSpan] = []

      guard handle != nil else {
        return
      }
      
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      
      for i in 0..<Int(tspanCount) {
        var ts = WebImeTextSpan()
        ts.type = WebImeTextSpanType(rawValue: Int(tspanType![i]))!
        ts.startOffset = Int(tspanStartOffset![i])
        ts.endOffset = Int(tspanEndOffset![i])
        ts.thickness = WebImeTextSpanThickness(rawValue: Int(tspanThickness![i]))!
        ts.underlineColor = Color(Int(tspanUnderlineColor![i]))
        ts.backgroundColor = Color(Int(tspanBackgroundColor![i]))
        textSpans.append(ts)
      }
      
      state.delegate?.onImeCommitText(
        text: String(decodingCString: text!, as: UTF16.self),
        spans: textSpans,
        replacement: TextRange(start: Int(rangeStart), end: Int(rangeEnd)),
        relativeCursorPosition: Int(relativeCursorPosition))
    }

    callbacks.ImeFinishComposingText = { (handle: UnsafeMutableRawPointer?, keepSelection: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onImeFinishComposingText(keepSelection: keepSelection != 0)
    }
  
    callbacks.RequestTextInputStateUpdate = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onRequestTextInputStateUpdate()
    }
    
    callbacks.RequestCompositionUpdates = { (handle: UnsafeMutableRawPointer?, immediateRequest: CInt, monitorRequest: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onRequestCompositionUpdates(immediateRequest: immediateRequest != 0, monitorRequest: monitorRequest != 0)
    }
    
    callbacks.DispatchEvent = { (handle: UnsafeMutableRawPointer?, inputEvent: UnsafeMutableRawPointer?) -> CInt in 
      guard handle != nil else {
        return CInt(InputEventAckState.NotConsumed.rawValue)
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      guard let result = state.delegate?.onDispatchEvent(event: WebInputEvent(reference: inputEvent!)).rawValue else {
        return -1
      }
      return CInt(result)
    }
    
    callbacks.DispatchNonBlockingEvent = { (handle: UnsafeMutableRawPointer?, inputEvent: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDispatchNonBlockingEvent(event: WebInputEvent(reference: inputEvent!))
    }

    callbacks.SetCompositionFromExistingText = { (
      handle: UnsafeMutableRawPointer?, 
      start: Int32, 
      end: Int32,
      tspanType: UnsafeMutablePointer<CInt>?,
      tspanStartOffset: UnsafeMutablePointer<UInt32>?,
      tspanEndOffset: UnsafeMutablePointer<UInt32>?,
      tspanUnderlineColor: UnsafeMutablePointer<CInt>?,
      tspanThickness: UnsafeMutablePointer<CInt>?,
      tspanBackgroundColor: UnsafeMutablePointer<CInt>?,
      tspanCount: CInt) in 

      var textSpans: [WebImeTextSpan] = []

      guard handle != nil else {
        return
      }
      
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      
      for i in 0..<Int(tspanCount) {
        var ts = WebImeTextSpan()
        ts.type = WebImeTextSpanType(rawValue: Int(tspanType![i]))!
        ts.startOffset = Int(tspanStartOffset![i])
        ts.endOffset = Int(tspanEndOffset![i])
        ts.underlineColor = Color(Int(tspanUnderlineColor![i]))
        ts.thickness = WebImeTextSpanThickness(rawValue: Int(tspanThickness![i]))!
        ts.backgroundColor = Color(Int(tspanBackgroundColor![i]))
        textSpans.append(ts)
      }
      
      state.delegate?.onSetCompositionFromExistingText(
        start: Int(start), 
        end: Int(end),
        spans: textSpans)

    }
    
    callbacks.ExtendSelectionAndDelete = { (handle: UnsafeMutableRawPointer?, before: Int32, after: Int32) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onExtendSelectionAndDelete(before: Int(before), after: Int(after))
    }
    
    callbacks.DeleteSurroundingText = { (handle: UnsafeMutableRawPointer?, before: Int32, after: Int32) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDeleteSurroundingText(before: Int(before), after: Int(after))
    }
    
    callbacks.DeleteSurroundingTextInCodePoints = { (handle: UnsafeMutableRawPointer?, before: Int32, after: Int32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDeleteSurroundingTextInCodePoints(before: Int(before), after: Int(after))
    }
    
    callbacks.SetEditableSelectionOffsets = { (handle: UnsafeMutableRawPointer?, start: Int32, end: Int32) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetEditableSelectionOffsets(start: Int(start), end: Int(end))
    }
    
    callbacks.ExecuteEditCommand = { 
      (handle: UnsafeMutableRawPointer?, 
       command: UnsafePointer<Int8>?, 
       value: UnsafePointer<UInt16>?) in

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onExecuteEditCommand(
        command: String(cString: command!), 
        value: String(decodingCString: value!, as: UTF16.self)
      )
    }
    
    callbacks.Undo = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUndo()
    }
    
    callbacks.Redo = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onRedo()
    }
    
    callbacks.Cut = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCut()
    }
    
    callbacks.Copy = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCopy()
    }
    
    callbacks.CopyToFindPboard = { (handle: UnsafeMutableRawPointer?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCopyToFindPboard()
    }
    
    callbacks.Paste = { (handle: UnsafeMutableRawPointer?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPaste()
    }
    
    callbacks.PasteAndMatchStyle = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPasteAndMatchStyle()
    }
    
    callbacks.Delete = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDelete()
    }
    
    callbacks.SelectAll = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSelectAll()
    }
    
    callbacks.CollapseSelection = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCollapseSelection()
    }
    
    callbacks.Replace = { (handle: UnsafeMutableRawPointer?, word: UnsafePointer<UInt16>?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onReplace(word: String(decodingCString: word!, as: UTF16.self))
    }
    
    callbacks.ReplaceMisspelling = { (handle: UnsafeMutableRawPointer?, word: UnsafePointer<UInt16>?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onReplaceMisspelling(word: String(decodingCString: word!, as: UTF16.self))
    }
    
    callbacks.SelectRange = { (handle: UnsafeMutableRawPointer?, baseX: CInt, baseY: CInt, extentX: CInt, extentY: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSelectRange(base: IntPoint(x: Int(baseX), y: Int(baseY)), extent: IntPoint(x: Int(baseX), y: Int(baseY)))
    }
    
    callbacks.AdjustSelectionByCharacterOffset = { (handle: UnsafeMutableRawPointer?, start: Int32, end: Int32, selectMenuBehavior: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onAdjustSelectionByCharacterOffset(start: Int(start), end: Int(end), behavior: SelectionMenuBehavior(rawValue: Int(selectMenuBehavior))!)
    }
    
    callbacks.MoveRangeSelectionExtent = { (handle: UnsafeMutableRawPointer?, extentX: CInt, extentY: CInt)  in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onMoveRangeSelectionExtent(extent: IntPoint(x: Int(extentX), y: Int(extentY)))
    }
    
    callbacks.ScrollFocusedEditableNodeIntoRect = { (handle: UnsafeMutableRawPointer?, rx: CInt, ry: CInt, rw: CInt, rh: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onScrollFocusedEditableNodeIntoRect(rect: IntRect(x: Int(rx), y: Int(ry), width: Int(rw), height: Int(rh)))
    }
    
    callbacks.MoveCaret = { (handle: UnsafeMutableRawPointer?, px: CInt, py: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onMoveCaret(position: IntPoint(x: Int(px), y: Int(py)))
    }

    callbacks.IntrinsicSizingInfoOfChildChanged = { 
      (handle: UnsafeMutableRawPointer?, 
       sizeW: Float, 
       sizeH: Float, 
       aspectRatioW: Float, 
       aspectRatioH: Float, 
       hasWidth: CInt, 
       hasHeight: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onIntrinsicSizingInfoOfChildChanged(
        size: FloatSize(width: sizeW, height: sizeH),
        aspectRatio: FloatSize(width: aspectRatioW, height: aspectRatioH),
        hasWidth: hasWidth != 0,
        hasHeight: hasHeight != 0)
    }
    
    callbacks.BeforeUnload = { (handle: UnsafeMutableRawPointer?, isReload: CInt) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onBeforeUnload(isReload: isReload != 0)
    }
    
    callbacks.ViewChanged = { 
      (handle: UnsafeMutableRawPointer?, 
       hasFrameSinkId: CInt, 
       frameSinkIdClientId: UInt32, 
       frameSinkIdRouteId: UInt32) in 

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onViewChanged(frameSink: hasFrameSinkId == 1 ? 
          FrameSinkId(clientId: frameSinkIdClientId, sinkId: frameSinkIdRouteId) : 
          nil)
    }

    callbacks.SetChildFrameSurface = { 
      (handle: UnsafeMutableRawPointer?,
       surfaceInfoClientId: UInt32, 
       surfaceInfoSinkId: UInt32,
       surfaceInfoParentSequenceNumber: UInt32,
       surfaceInfoChildSequenceNumber: UInt32,
       surfaceInfoTokenHigh: UInt64, 
       surfaceInfoTokenLow: UInt64,
       deviceScaleFactor: Float,
       sizeWidth: CInt,
       sizeHeight: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetChildFrameSurface(
        surfaceInfo: SurfaceInfo(
          id: SurfaceId(
            frameSinkId: FrameSinkId(
              clientId: surfaceInfoClientId, 
              sinkId: surfaceInfoSinkId),
            localSurfaceId: LocalSurfaceId(
              parent: surfaceInfoParentSequenceNumber, 
              child: surfaceInfoChildSequenceNumber, 
              token: UnguessableToken(high: surfaceInfoTokenHigh, low: surfaceInfoTokenLow))),
          deviceScaleFactor: deviceScaleFactor,
          sizeInPixels: IntSize(width: Int(sizeWidth), height: Int(sizeHeight)))
      )
    }
    
    callbacks.ChildFrameProcessGone = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onChildFrameProcessGone()
    }
    
    callbacks.SwapIn = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSwapIn()
    }
    
    callbacks.FrameDelete = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onFrameDelete()
    }
    
    callbacks.Stop = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onStop()
    }
    
    callbacks.DroppedNavigation = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDroppedNavigation()
    }

    callbacks.DidStartLoading = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDidStartLoading()
    }
    
    callbacks.DidStopLoading = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDidStopLoading()
    }
    
    callbacks.Collapse = { (handle: UnsafeMutableRawPointer?, collapsed: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCollapse(collapsed: collapsed != 0)
    }
    
    callbacks.WillEnterFullscreen = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onWillEnterFullscreen()
    }
    
    callbacks.EnableAutoResize = { 
      (handle: UnsafeMutableRawPointer?, 
       minSizeW: CInt, 
       minSizeH: CInt, 
       maxSizeW: CInt, 
       maxSizeH: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onEnableAutoResize(min: IntSize(width: Int(minSizeW), height: Int(minSizeH)), max: IntSize(width: Int(maxSizeW), height: Int(maxSizeH)))
    }

    callbacks.DisableAutoResize = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDisableAutoResize()
    }
    
    callbacks.ContextMenuClosed = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onContextMenuClosed()
    }
    
    callbacks.CustomContextMenuAction = { (handle: UnsafeMutableRawPointer?, action: UInt32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCustomContextMenuAction(action: action)
    }
    
    callbacks.VisualStateRequest = { (handle: UnsafeMutableRawPointer?, id: UInt64) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onVisualStateRequest(id: id)
    }
    
    callbacks.DispatchLoad = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDispatchLoad()
    } 
    
    callbacks.Reload = { (handle: UnsafeMutableRawPointer?, bypassCache: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onReload(bypassCache: bypassCache != 0)
    }
    
    callbacks.ReloadLoFiImages = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onReloadLoFiImages()
    }
    
    callbacks.SnapshotAccessibilityTree = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSnapshotAccessibilityTree()
    }
    
    callbacks.UpdateOpener = { (handle: UnsafeMutableRawPointer?, openerRoutingId: Int32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onUpdateOpener(routingId: UInt32(openerRoutingId))
    }
    
    callbacks.SetFocusedFrame = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetFocusedFrame()
    }
    
    callbacks.CheckCompleted = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCheckCompleted()
    }
    
    callbacks.PostMessageEvent = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onPostMessageEvent()
    }
    
    callbacks.NotifyUserActivation = { (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onNotifyUserActivation()
    }
    
    callbacks.DidUpdateOrigin = { (handle: UnsafeMutableRawPointer?, origin: UnsafePointer<Int8>?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onDidUpdateOrigin(origin: String(cString: origin!))
    }
    
    callbacks.ScrollRectToVisible = { 
      (handle: UnsafeMutableRawPointer?, 
       rectToScrollX: CInt, 
       rectToScrollY: CInt, 
       rectToScrollW: CInt, 
       rectToScrollH: CInt) in

      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onScrollRectToVisible(rect: IntRect(x: Int(rectToScrollX), y: Int(rectToScrollY), width: Int(rectToScrollW), height: Int(rectToScrollH)))
    }

    callbacks.TextSurroundingSelectionRequest = { 
      (handle: UnsafeMutableRawPointer?,
       maxLen: UInt32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onTextSurroundingSelectionRequest(maxLength: maxLen)
    }
  
    callbacks.AdvanceFocus = { 
      (handle: UnsafeMutableRawPointer?, 
       type: CInt, 
       sourceRoutingId: Int32) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onAdvanceFocus(type: WebFocusType(rawValue:Int(type))!, sourceRoutingId: sourceRoutingId)
    }
    
    callbacks.AdvanceFocusInForm = { 
      (handle: UnsafeMutableRawPointer?, 
       type: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onAdvanceFocusInForm(type: WebFocusType(rawValue:Int(type))!)
    }
    
    callbacks.Find = { 
      (handle: UnsafeMutableRawPointer?, 
       requestId: Int32,
       searchText: UnsafePointer<UInt16>?, 
       forward: CInt,
       matchCase: CInt,
       findNext: CInt,
       wordStart: CInt,
       medialCapitalAsWordStart: CInt,
       force: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onFind(
        requestId: requestId, 
        searchText: String(decodingCString: searchText!, as: UTF16.self),
        options: WebFindOptions(
          forward: forward != 0,
          matchCase: matchCase != 0,
          findNext: findNext != 0,
          wordStart: wordStart != 0,
          medialCapitalAsWordStart: medialCapitalAsWordStart != 0,
          force: force != 0))
    }
    
    callbacks.ClearActiveFindMatch = { 
      (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onClearActiveFindMatch()
    }
    
    callbacks.StopFinding = { 
      (handle: UnsafeMutableRawPointer?, 
       stopFindAction: CInt) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onStopFinding(action: WebFrameStopFindAction(rawValue: Int(stopFindAction))!)
    }
    
    callbacks.ClearFocusedElement = { 
      (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onClearFocusedElement()
    }
    
    callbacks.SetOverlayRoutingToken = { 
      (handle: UnsafeMutableRawPointer?, 
       tokenHigh: UInt64, 
       tokenLow: UInt64) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onSetOverlayRoutingToken(token: UnguessableToken(high: tokenHigh, low: tokenLow))
    }

    // void (*OnNetworkConnectionChanged)(void* state, int connection_type, double max_bandwidth_mbps);
  
    callbacks.OnNetworkConnectionChanged = { 
      (handle: UnsafeMutableRawPointer?, 
       connectionType: CInt, 
       maxBandwidthMbps: Double) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onNetworkConnectionChanged(connectionType: NetworkConnectionType(rawValue: Int(connectionType))!, maxBandwidthMbps: maxBandwidthMbps)
    }

    callbacks.CommitNavigation = { 
      (handle: UnsafeMutableRawPointer?,
       url: UnsafePointer<Int8>?,
       keepalive: CInt,
       provider: Int32, 
       route: CInt) in
      ////print("UIDispatcher.CommitNavigation callback") 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      state.delegate?.onCommitNavigation(url: String(cString: url!), keepAlive: keepalive != 0, providerId: Int(provider), routeId: Int(route))
    }

    callbacks.CommitSameDocumentNavigation = { 
      (handle: UnsafeMutableRawPointer?,
       url: UnsafePointer<Int8>?,
       keepalive: CInt,
       provider: Int32,
       route: CInt) -> CInt in
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      let status = CInt(state.delegate?.onCommitSameDocumentNavigation(url: String(cString: url!), keepAlive: keepalive != 0, providerId: Int(provider), routeId: Int(route)).rawValue ?? -1)
      return status
    }

    callbacks.CommitFailedNavigation = { 
      (handle: UnsafeMutableRawPointer?) in 
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      let errCode = 1
      let errPageContent = String("hello failed navigation")
      state.delegate?.onCommitFailedNavigation(
        errorCode: errCode,
        errorPageContent: errPageContent)
    }

    callbacks.CreateURLLoader = { (handle: UnsafeMutableRawPointer?, req: UnsafeMutableRawPointer?, cbs: UnsafeMutablePointer<CBlinkPlatformCallbacks>?) -> UnsafeMutableRawPointer? in 
	  	let state = unsafeBitCast(handle, to: UIDispatcher.self)
      let loader = state.createURLLoader(request: WebURLRequest(reference: req!)) as? WebURLLoaderImpl
      if cbs != nil {
        cbs?.pointee = loader?.createCallbacks() ?? state.emptyBlinkCallbacks
      }
      return loader?.unmanagedSelf
	  }

    callbacks.CountResponseHandler = { (handle: UnsafeMutableRawPointer?) -> CInt in 
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      return CInt(state.serviceWorkerNetworkProvider?.handlers.count ?? 0)
    }

    callbacks.GetResponseHandlerAt = { (handle: UnsafeMutableRawPointer?, index: CInt, cbs: UnsafeMutablePointer<CResponseHandler>?) -> UnsafeMutableRawPointer? in 
      let state = unsafeBitCast(handle, to: UIDispatcher.self)
      let offset = Int(index)
      guard offset < (state.serviceWorkerNetworkProvider?.handlers.endIndex ?? 0) else {
        print("GetResponseHandlerAt: returning null")
        return nil
      }
      let responseHandler = state.serviceWorkerNetworkProvider?.handlers[offset]
      if cbs != nil {
        cbs?.pointee = responseHandler?.createCallbacks() ?? state.emptyResponseCallbacks
      }
      return responseHandler?.unmanagedSelf
    }

    return callbacks
  }

  public init() {
    
  }

  deinit {
    _WindowDestroy(state) 
  }

  public func applicationProcessGone(status: Int32, exitCode: Int32) {
    ////print("ApplicationWindowHost.applicationProcessGone()")
    _WindowApplicationProcessGone(state, status, exitCode)
  }


  public func createURLLoader(request: WebURLRequest) -> WebURLLoader? {
    return serviceWorkerNetworkProvider?.createURLLoader(request: request)
  }

  public func addHandler(_ handler: WebResponseHandler) {
    serviceWorkerNetworkProvider?.addHandler(handler)
  }

  public func removeHandler(_ handler: WebResponseHandler) {
    serviceWorkerNetworkProvider?.removeHandler(handler) 
  }
  
  public func hittestData(surfaceId: SurfaceId, ignoredForHittest: Bool) {
    ////print("ApplicationWindowHost.hittestData()")
    
    _WindowHittestData(state, 
      surfaceId.frameSinkId.clientId, 
      surfaceId.frameSinkId.sinkId,
      surfaceId.localSurfaceId.parentSequenceNumber,
      surfaceId.localSurfaceId.childSequenceNumber,
      surfaceId.localSurfaceId.token.high,
      surfaceId.localSurfaceId.token.low,
      ignoredForHittest ? 1 : 0)
  }
  
  public func close() {
    ////print("ApplicationWindowHost.close()")
    _WindowClose(state)
  }
  
  public func updateScreenRectsAck() {
    ////print("ApplicationWindowHost.updateScreenRectsAck()")
    _WindowUpdateScreenRectsAck(state)  
  }
  
  public func requestMove(position: IntRect) {
    ////print("ApplicationWindowHost.requestMove()")
    _WindowRequestMove(state, CInt(position.x), CInt(position.y), CInt(position.width), CInt(position.height))
  }
  
  public func setTooltipText(text: String, direction: TextDirection) {
    ////print("ApplicationWindowHost.setTooltipText()")
    _WindowSetTooltipText(state, text, CInt(direction.rawValue))
  }
  
  public func resizeOrRepaintACK(viewSize: IntSize, flags: Int32, localSurfaceId: LocalSurfaceId?) {
    ////print("ApplicationWindowHost.resizeOrRepaintACK()")
    
    if let surface = localSurfaceId {
      _WindowResizeOrRepaintACK(state, 
        CInt(viewSize.width), 
        CInt(viewSize.height), 
        flags, 
        1,
        surface.parentSequenceNumber,
        surface.childSequenceNumber,
        surface.token.high,
        surface.token.low)
    } else {
      _WindowResizeOrRepaintACK(state, 
        CInt(viewSize.width), 
        CInt(viewSize.height), 
        flags, 
        0,
        0,
        0,
        0,
        0)
    }
  }
  
  public func setCursor(cursor: WebCursorInfo) {
    ////print("ApplicationWindowHost.setCursor()")
    _WindowSetCursor(state,
      CInt(cursor.type.rawValue),
      CInt(cursor.hotSpot.x), 
      CInt(cursor.hotSpot.y), 
      cursor.imageScaleFactor, 
      cursor.customImage != nil ? cursor.customImage!.reference : nil)
  }
  
  public func autoscrollStart(start: FloatPoint) {
    ////print("ApplicationWindowHost.autoscrollStart()")
    
    _WindowAutoscrollStart(state, start.x, start.y)
  }
  
  public func autoscrollFling(velocity: FloatVec2) {
    ////print("ApplicationWindowHost.autoscrollFling()")
    _WindowAutoscrollFling(state, velocity.x, velocity.y) 
  }
  
  public func autoscrollEnd() {
    ////print("ApplicationWindowHost.autoscrollEnd()")
    _WindowAutoscrollEnd(state) 
  }

  public func updateState() {
    ////print("ApplicationWindowHost.updateState()")
    _WindowUpdateState(state) 
  }
  
  public func textInputStateChanged(textInputState: TextInputState) {
    var valuePtr: UnsafePointer<Int8>?
    
    textInputState.value.withCString {
      valuePtr = $0
    }

    _WindowTextInputStateChanged(
      state, 
      CInt(textInputState.type.rawValue),
      CInt(textInputState.mode.rawValue),
      CInt(textInputState.flags.rawValue),
      valuePtr,
      CInt(textInputState.selectionStart),
      CInt(textInputState.selectionEnd),
      CInt(textInputState.compositionStart),
      CInt(textInputState.compositionEnd),
      textInputState.canComposeInline ? 1 : 0,
      textInputState.showImeIfNeeded ? 1 : 0,
      textInputState.replyToRequest ? 1 : 0)
  }
  
  public func lockMouse(userGesture: Bool, privileged: Bool) {
    _WindowLockMouse(state, userGesture ? 1 : 0, privileged ? 1 : 0)
  }
  
  public func unlockMouse() {
    _WindowUnlockMouse(state)
  }
  
  public func selectionBoundsChanged(params: SelectionBoundsParams) {
    _WindowSelectionBoundsChanged(
      state, 
      CInt(params.anchorRect.x),
      CInt(params.anchorRect.y),
      CInt(params.anchorRect.width),
      CInt(params.anchorRect.height),
      CInt(params.anchorDir.rawValue),
      CInt(params.focusRect.x),
      CInt(params.focusRect.y),
      CInt(params.focusRect.width),
      CInt(params.focusRect.height),
      CInt(params.focusDir.rawValue),
      params.isAnchorFirst ? 1 : 0)
  }

  public func focusedNodeTouched(editable: Bool) {
    _WindowFocusedNodeTouched(state, editable ? 1 : 0)
  }
  
  public func startDragging(
    dropData: DropData,
    opsAllowed: DragOperation,
    image: Bitmap,
    imageOffset: IntVec2,
    eventInfo: DragEventSourceInfo) {

    var urlPtr: UnsafePointer<Int8>?
    var urlTitlePtr: UnsafePointer<Int8>?
    var downloadMetadataPtr: UnsafePointer<Int8>?
    
    dropData.url.withCString {
      urlPtr = $0
    }
    
    dropData.urlTitle.withCString {
      urlTitlePtr = $0
    }

    dropData.downloadMetadata.withCString {
      downloadMetadataPtr = $0
    }
    
    _WindowStartDragging(state, 
      CInt(dropData.viewId),
      urlPtr,
      urlTitlePtr,
      downloadMetadataPtr, 
      CInt(opsAllowed.rawValue), 
      image.reference, 
      CInt(imageOffset.x), 
      CInt(imageOffset.y), 
      CInt(eventInfo.eventLocation.x),
      CInt(eventInfo.eventLocation.y),
      CInt(eventInfo.eventSource.rawValue))
  }

  public func onWebFrameCreated(frame: WebLocalFrame, isMain: Bool) {
    _WindowOnWebFrameCreated(state, frame.reference, isMain ? 1 : 0)
  }

  public func updateDragCursor(dragOperation: DragOperation) {
    _WindowUpdateDragCursor(state, CInt(dragOperation.rawValue))
  }
  
  public func frameSwapMessagesReceived(frameToken: UInt32) {
    _WindowFrameSwapMessagesReceived(state, frameToken)
  }
  
  public func showWindow(routeId: Int32, initialRect: IntRect) {
    _WindowShowWindow(state, routeId, CInt(initialRect.x), CInt(initialRect.y), CInt(initialRect.width), CInt(initialRect.height)) 
  }
  
  public func showFullscreenWindow(routeId: Int32) {
    _WindowShowFullscreenWindow(state, routeId)
  }
  
  public func updateTargetURL(url: String) {
    url.withCString {
      _WindowUpdateTargetURL(state, $0)
    }
  }
  
  public func documentAvailableInMainFrame(usesTemporaryZoomLevel: Bool) {
    _WindowDocumentAvailableInMainFrame(state, usesTemporaryZoomLevel ? 1 : 0) 
  }
  
    public func didContentsPreferredSizeChange(size: IntSize) {
    _WindowDidContentsPreferredSizeChange(state, CInt(size.width), CInt(size.height))
  }
  
  public func routeCloseEvent() {
    _WindowRouteCloseEvent(state)
  }

  public func selectWordAroundCaretAck(didSelect: Bool, start: Int, end: Int) {
    _WindowSelectWordAroundCaretAck(state, didSelect ? 1 : 0, CInt(start), CInt(end))
  }
  
  public func takeFocus(reverse: Bool) {
    _WindowTakeFocus(state, reverse ? 1 : 0)
  }
  
  public func closePageACK() {
    _WindowClosePageACK(state)
  }
  
  public func focus() {
    _WindowFocus(state)
  }
  
  public func createNewWindowOnHost(params: CreateNewWindowParams) {
    var windowNamePtr: UnsafePointer<Int8>?
    var targetUrlPtr: UnsafePointer<Int8>?
    
    params.windowName.withCString {
      windowNamePtr = $0
    }
    params.targetUrl.withCString {
      targetUrlPtr = $0
    }
    _WindowCreateNewWindowOnHost(
      state, 
      params.userGesture ? 1 : 0,
      CInt(params.windowContainerType.rawValue),
      windowNamePtr,
      params.openerSuppressed ? 1 : 0,
      CInt(params.windowDisposition.rawValue),
      targetUrlPtr,
      CInt(params.windowId),
      params.swappedOut ? 1 : 0,
      params.hidden ? 1 : 0,
      params.neverVisible ? 1 : 0,
      params.enableAutoResize ? 1 : 0,
      CInt(params.size.width),
      CInt(params.size.height),
      params.zoomLevel,
      params.windowFeatures.x ?? -1.0,
      params.windowFeatures.y ?? -1.0,
      params.windowFeatures.width ?? -1.0,
      params.windowFeatures.height ?? -1.0)
  }
  
  public func didCommitProvisionalLoad(params: DidCommitProvisionalLoadParams) {
    params.method.withCString {
      _WindowDidCommitProvisionalLoad(state,
        CInt(params.httpStatusCode),
        params.urlIsUnreachable ? 1 : 0,
        $0)
    }
  }

  public func didCommitSameDocumentNavigation(params: DidCommitProvisionalLoadParams) {
    _WindowDidCommitSameDocumentNavigation(state)//, params)
  }
  
  public func beginNavigation(url: String) {
    url.withCString {
      _WindowBeginNavigation(state, $0)
    }
  }
  
  public func didChangeName(name: String) {
    name.withCString {
      _WindowDidChangeName(state, $0)
    }
  }

  public func didChangeOpener(opener: Int) {
    _WindowDidChangeOpener(state, CInt(opener))
  }

  public func detachFrame(id: Int) {
    _WindowDetachFrame(state, CInt(id))
  }
  
  public func frameSizeChanged(size: IntSize) {
    _WindowFrameSizeChanged(state, CInt(size.width), CInt(size.height))
  }
  
  public func onUpdatePictureInPictureSurfaceId(surfaceId: SurfaceId, size: IntSize) {
    _WindowOnUpdatePictureInPictureSurfaceId(state, 
      surfaceId.frameSinkId.sinkId, 
      surfaceId.frameSinkId.clientId,
      surfaceId.localSurfaceId.parentSequenceNumber,
      surfaceId.localSurfaceId.childSequenceNumber,
      surfaceId.localSurfaceId.token.high,
      surfaceId.localSurfaceId.token.low,
      CInt(size.width), 
      CInt(size.height)) 
  }
  
  public func onExitPictureInPicture() {
    _WindowOnExitPictureInPicture(state)
  }
  
  public func onSwappedOut() {
    _WindowOnSwappedOut(state)
  }

  public func cancelTouchTimeout() {
    _WindowCancelTouchTimeout(state)
  }

  public func setWhiteListedTouchAction(
    action: TouchAction,
    uniqueTouchEventId: UInt32,
    inputEventState: Int32) {
    _WindowSetWhiteListedTouchAction(
       state,
       CInt(action.rawValue),
       uniqueTouchEventId,
       inputEventState)
  }
  
  public func didOverscroll(params: DidOverscrollParams) {
    _WindowDidOverscroll(
      state,
      params.accumulatedOverscroll.x,
      params.accumulatedOverscroll.y,
      params.latestOverscrollDelta.x,
      params.latestOverscrollDelta.y,
      params.currentFlingVelocity.x,
      params.currentFlingVelocity.y,
      params.causalEventViewportPoint.x,
      params.causalEventViewportPoint.y,
      CInt(params.overscrollBehavior.x.rawValue),
      CInt(params.overscrollBehavior.y.rawValue))
  }
  
  public func didStopFlinging() {
    _WindowDidStopFlinging(state)
  }
  
  public func didStartScrollingViewport() {
    _WindowDidStartScrollingViewport(state)
  }
  
  public func imeCancelComposition() {
    _WindowImeCancelComposition(state)
  }
  
  public func imeCompositionRangeChanged(range: TextRange, bounds: [IntRect]) {
    var x = ContiguousArray<CInt>(repeating: 0, count: bounds.count)
    var y = ContiguousArray<CInt>(repeating: 0, count: bounds.count)
    var w = ContiguousArray<CInt>(repeating: 0, count: bounds.count)
    var h = ContiguousArray<CInt>(repeating: 0, count: bounds.count)

    for i in 0..<bounds.count {
      x[i] = CInt(bounds[i].x)
      y[i] = CInt(bounds[i].y)
      w[i] = CInt(bounds[i].width)
      h[i] = CInt(bounds[i].height)
    }
   
    var xptr: UnsafeMutablePointer<Int32>?
    var yptr: UnsafeMutablePointer<Int32>?
    var wptr: UnsafeMutablePointer<Int32>?
    var hptr: UnsafeMutablePointer<Int32>?

    x.withUnsafeMutableBufferPointer { xbuf in 
      xptr = xbuf.baseAddress
    }
    y.withUnsafeMutableBufferPointer { ybuf in 
      yptr = ybuf.baseAddress
    }
    w.withUnsafeMutableBufferPointer { wbuf in 
      wptr = wbuf.baseAddress
    }
    h.withUnsafeMutableBufferPointer { hbuf in 
      hptr = hbuf.baseAddress
    }

    _WindowImeCompositionRangeChanged(
      state,
      UInt32(range.start), 
      UInt32(range.end),
      xptr,
      yptr,
      wptr,
      hptr,
      CInt(bounds.count))
  }
  
  public func hasTouchEventHandlers(hasHandlers: Bool) {
    _WindowHasTouchEventHandlers(state, hasHandlers ? 1 : 0)
  }

  public func swapOutAck() {
    _WindowSwapOutAck(state)
  }

  // public func detach() {
  //   _WindowDetach(state)
  // }

  public func frameFocused() {
    _WindowFrameFocused(state) 
  }

  public func didStartProvisionalLoad(url: String, navigationStart: TimeTicks) {
    url.withCString {
      _WindowDidStartProvisionalLoad(state, $0, navigationStart.microseconds)
    }
  }

  public func didFailProvisionalLoadWithError(url: String, errorCode: Int32, description: String) {
    let utf16Arr = ContiguousArray(description.utf16)
    utf16Arr.withUnsafeBufferPointer { utf16buf in
      url.withCString { cUrl in
        _WindowDidFailProvisionalLoadWithError(state, errorCode, description.isEmpty ? nil : utf16buf.baseAddress!, cUrl)
      }
    }
  }

  public func didFinishDocumentLoad() {
    _WindowDidFinishDocumentLoad(state)
  }

  public func didFailLoadWithError(url: String, errorCode: Int32, description: String) {
    let utf16Arr = ContiguousArray(description.utf16)
    utf16Arr.withUnsafeBufferPointer { utf16buf in
      url.withCString { cUrl in
        _WindowDidFailLoadWithError(state, cUrl, errorCode, description.isEmpty ? nil : utf16buf.baseAddress!)
      }
    }
  }
  
  public func didStartLoading(toDifferentDocument: Bool) {
    _WindowDidStartLoading(state, toDifferentDocument ? 1 : 0)
  }

  public func didStopLoading() {
    _WindowSendDidStopLoading(state)
  }
  
  public func didChangeLoadProgress(loadProgress: Double) {
    _WindowDidChangeLoadProgress(state, loadProgress)
  }

  public func openURL(url: String) {
    url.withCString {
      _WindowOpenURL(state, $0)
    }
  }

  public func layerTreeFrameSinkInitialized() {
    _WindowLayerTreeFrameSinkInitialized(state)
  }

  public func didFinishLoad(url: String) {
    url.withCString {
      _WindowDidFinishLoad(state, $0)
    }
  }
  
  public func documentOnLoadCompleted(timestamp: TimeTicks) {
    _WindowDocumentOnLoadCompleted(state, timestamp.microseconds)
  }

  public func didAccessInitialDocument() {
    _WindowDidAccessInitialDocument(state)
  }

  public func updateTitle(title: String, direction: TextDirection) {
    if title.count > 0 {
      title.withCString {
        _WindowUpdateTitle(state, $0, CInt(title.count), Int32(direction.rawValue))
      }
    } else {
      _WindowUpdateTitle(state, nil, 0, Int32(direction.rawValue))
    }
    
  }

  public func beforeUnloadAck(
    proceed: Bool, 
    startTime: TimeTicks, 
    endTime: TimeTicks) {
    _WindowBeforeUnloadAck(state, proceed ? 1 : 0, startTime.microseconds, endTime.microseconds)
  }

  public func synchronizeVisualProperties(
    surface: SurfaceId, 
    screenInfo: ScreenInfo,
    autoResizeEnable: Bool,
    minSize: IntSize,
    maxSize: IntSize,
    screenSpaceRect: IntRect,
    localFrameSize: IntSize,
    captureSequenceNumber: Int32) {
    _WindowSynchronizeVisualProperties(
       state,
       surface.frameSinkId.clientId,
       surface.frameSinkId.sinkId,
       surface.localSurfaceId.parentSequenceNumber,
       surface.localSurfaceId.childSequenceNumber,
       surface.localSurfaceId.token.high, 
       surface.localSurfaceId.token.low,
       screenInfo.deviceScaleFactor,
       CInt(screenInfo.colorSpace.primaries.rawValue),
       CInt(screenInfo.colorSpace.transfer.rawValue),
       CInt(screenInfo.colorSpace.matrix.rawValue),
       CInt(screenInfo.colorSpace.range.rawValue),
       screenInfo.colorSpace.iccProfileId,
       screenInfo.depth,
       screenInfo.depthPerComponent,
       screenInfo.isMonochrome ? 1 : 0,
       CInt(screenInfo.rect.x),
       CInt(screenInfo.rect.y),
       CInt(screenInfo.rect.width),
       CInt(screenInfo.rect.height),
       CInt(screenInfo.availableRect.x),
       CInt(screenInfo.availableRect.y),
       CInt(screenInfo.availableRect.width),
       CInt(screenInfo.availableRect.height),
       CInt(screenInfo.orientationType.rawValue),
       screenInfo.orientationAngle,
       autoResizeEnable ? 1 : 0, 
       CInt(minSize.width), 
       CInt(minSize.height), 
       CInt(maxSize.width), 
       CInt(maxSize.height),
       CInt(screenSpaceRect.x), 
       CInt(screenSpaceRect.y),
       CInt(screenSpaceRect.width),
       CInt(screenSpaceRect.height),   
       CInt(localFrameSize.width),
       CInt(localFrameSize.height),
       captureSequenceNumber)
  }
  
  public func updateViewportIntersection(intersection: IntRect, visible: IntRect) {
    _WindowUpdateViewportIntersection(
      state, 
      CInt(intersection.x), 
      CInt(intersection.y), 
      CInt(intersection.width), 
      CInt(intersection.height), 
      CInt(visible.x), 
      CInt(visible.y), 
      CInt(visible.width), 
      CInt(visible.height))
  }
  
  public func visibilityChanged(visible: Bool) {
    _WindowVisibilityChanged(state, visible ? 1 : 0)
  }
  
  public func updateRenderThrottlingStatus(isThrottled: Bool, subtreeThrottled: Bool) {
    _WindowSendUpdateRenderThrottlingStatus(state, isThrottled ? 1 : 0, subtreeThrottled ? 1 : 0)
  }
  
  public func setHasReceivedUserGesture() {
    _WindowSetHasReceivedUserGesture(state)
  }
  
  public func setHasReceivedUserGestureBeforeNavigation(value: Bool) {
    _WindowSetHasReceivedUserGestureBeforeNavigation(state, value ? 1 : 0)
  }
  
  public func contextMenu() {
    _WindowContextMenu(state)
  }
  
  public func selectionChanged(selection: String, offset: UInt32, range: TextRange) {
    let utf16Arr = ContiguousArray(selection.utf16)
    utf16Arr.withUnsafeBufferPointer { utf16buf in
      _WindowSelectionChanged(state, selection.isEmpty ? nil : utf16buf.baseAddress!, offset, CInt(range.start), CInt(range.end))
    }
  }
  
  public func visualStateResponse(id: UInt64) {
    _WindowVisualStateResponse(state, id)
  }
  
  public func enterFullscreen() {
    _WindowEnterFullscreen(state)
  }
  
  public func exitFullscreen() {
    _WindowExitFullscreen(state)
  }
  
  public func dispatchLoad() {
    _WindowSendDispatchLoad(state)
  }
  
  public func checkCompleted() {
    _WindowSendCheckCompleted(state)
  }
  
  public func updateFaviconUrl(_ faviconUrls: ContiguousArray<String>) {
    var cStringUrls = ContiguousArray<UnsafePointer<Int8>?> ()
    for url in faviconUrls {
      url.withCString {
        cStringUrls.append($0)
      }
    }
    cStringUrls.withUnsafeMutableBufferPointer { buf in
      _WindowUpdateFaviconURL(state, buf.baseAddress, CInt(faviconUrls.count))
    }
  }
  
  public func scrollRectToVisibleInParentFrame(rect: IntRect) {
    _WindowScrollRectToVisibleInParentFrame(state, CInt(rect.x), CInt(rect.y), CInt(rect.width), CInt(rect.height))
  }

  public func frameDidCallFocus() {
    _WindowFrameDidCallFocus(state)
  }

  public func textSurroundingSelectionResponse(content: String, start: UInt32, end: UInt32) {
    let utf16Arr = ContiguousArray(content.utf16)
    utf16Arr.withUnsafeBufferPointer {
      _WindowTextSurroundingSelectionResponse(
        state,
        $0.baseAddress!,
        start, 
        end)
    }
  }

  public func closeAck() {
    _WindowCloseAck(state)
  }

  public func sendOnMediaDestroyed(delegate: Int) {
    _WindowSendOnMediaDestroyed(state, CInt(delegate))
  }

  public func sendOnMediaPaused(delegate: Int, reachedEndOfStream: Bool) {
    _WindowSendOnMediaPaused(state, CInt(delegate), reachedEndOfStream ?  1: 0)
  }
  
  public func sendOnMediaPlaying(delegate: Int, hasVideo: Bool, hasAudio: Bool, isRemote: Bool, contentType: MediaContentType) {
    _WindowSendOnMediaPlaying(
      state, 
      CInt(delegate), 
      hasVideo ? 1 : 0,
      hasAudio ? 1 : 0,
      isRemote ? 1 : 0,
      CInt(contentType.rawValue))
  }
  
  public func sendOnMediaMutedStatusChanged(delegate: Int, muted: Bool) {
    _WindowSendOnMediaMutedStatusChanged(state, CInt(delegate), muted ? 1 : 0)
  }
  
  public func sendOnMediaEffectivelyFullscreenChanged(delegate: Int, status: WebFullscreenVideoStatus) {
    _WindowSendOnMediaEffectivelyFullscreenChanged(state, CInt(delegate), CInt(status.rawValue))
  }
  
  public func sendOnMediaSizeChanged(delegate: Int, size: IntSize) {
    _WindowSendOnMediaSizeChanged(state, CInt(delegate), CInt(size.width), CInt(size.height))
  }

  public func sendOnPictureInPictureSourceChanged(delegate: Int) {
    _WindowSendOnPictureInPictureSourceChanged(state, CInt(delegate))
  }
  
  public func sendOnPictureInPictureModeEnded(delegate: Int) {
    _WindowSendOnPictureInPictureModeEnded(state, CInt(delegate))
  }
 
}