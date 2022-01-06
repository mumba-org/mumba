// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Text
import Web

public enum FrameSwapMessage {
  case VisualStateResponse(_: UInt64)
}

// public protocol InputMethodController {
//   var textInputInfo: TextInputState { get }
//   var compositionRange: TextRange { get }
//   func getCompositionCharacterBounds(_ bounds: inout [IntRect]) -> Bool
// }

public struct DidCommitProvisionalLoadParams {
  
  public var navEntryId: Int32 = -1
  public var itemSequenceNumber: Int64 = -1
  public var documentSequenceNumber: Int64 = -1
  public var url: String = String()
  public var baseUrl: String = String()
  public var referrer: String = String()
  public var redirects: [String] = []
  public var shouldUpdateHistory: Bool = false
  public var contentsMimeType: String = String()
  public var socketAddress: String = String()
  public var didCreateNewEntry: Bool = false
  public var shouldReplaceCurrentEntry: Bool = false
  public var method: String = String()
  public var postId: Int64 = -1
  public var httpStatusCode: Int = -1
  public var urlIsUnreachable: Bool = false
  //public var pageState: PageState
  public var originalRequestUrl: String = String()
  public var isOverridingUserAgent: Bool = false
  public var historyListWasCleared: Bool = false
  public var origin: String = String()
  public var uiTimestamp: TimeTicks = TimeTicks()
  public var hasPotentiallyTrustworthyUniqueOrigin: Bool = false
  public var contentSourceId: UInt32 = 0

  public init() {}
} 

public protocol UIWindowDelegate : class {
  func onFrameAttached(_ : UIWebFrame)
  func onPageWasShown(_ : UIWindow)
  func onPageWasHidden(_ : UIWindow)
  //func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect)
}

public protocol UIWindow : class {

  var cursorVisibility: Bool { get set }
  var textDirection: TextDirection { get set }
  var isInert: Bool { get set }
  var isActive: Bool { get set }
  var isFocused: Bool { get }
  var selectionRange: TextRange? { get }
  var contentsPreferredMinimumSize: IntSize { get }
  var deviceScaleFactor: Float { get set }
  var isSelectionAnchorFirst: Bool { get }
  var inputMethodController: WebInputMethodController? { get }
  var hasTouchEventHandlers: Bool { get }
  var possibleDragEventInfo: DragEventSourceInfo { get }
  var compositor: UIWebWindowCompositor? { get }

  func initializeVisualProperties(params: VisualProperties)
  func mouseCaptureLost()
  func recordWheelAndTouchScrollingCount()
  //func updateVisualState(state: VisualStateUpdate)
  func resize(to: IntSize)
  func resizeVisualViewport(to: IntSize)
  func close()
  func showContextMenu(sourceType: MenuSourceType, location: IntPoint)
  func setRemoteViewportInserction(intersection: IntRect)
  func updateRenderThrottlingStatus(throttling: Bool)
  func dragTargetDragEnter(
    dropData: [DropData.Metadata],
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) -> DragOperation
  func dragTargetDragOver(
    client: FloatPoint,
    screen: FloatPoint,
    opsAllowed: DragOperation,
    keyModifiers: Int) -> DragOperation
  func dragTargetDragLeave(clientPoint: FloatPoint, screenPoint: FloatPoint)
  func dragTargetDrop(dropData: DropData,
                      client: FloatPoint,
                      screen: FloatPoint,
                      keyModifiers: Int)
  func dragSourceEndedAt(
    client: FloatPoint,
    screen: FloatPoint,
    dragOperations: DragOperation)
  func dragSourceSystemDragEnded()
  func didEnterFullscreen()
  func didExitFullscreen()
  func getSelectionBounds(focus: inout IntRect, anchor: inout IntRect)
  func getSelectionTextDirection(focus: inout TextDirection, anchor: inout TextDirection)
  func setPageScaleFactor(pageScaleFactor: Float)
  func setInitialFocus(reverse: Bool)
  func hidePopups()
  func applyViewportDeltas(
      innerDelta: FloatVec2,
      outerDelta: FloatVec2,
      elasticOverscrollDelta: FloatVec2,
      pageScale: Float,
      topControlsDelta: Float)
  func didAcquirePointerLock()
  func didNotAcquirePointerLock()
  func didLosePointerLock()
  func copyImage(at: IntPoint)
  func saveImage(at: IntPoint)
  func selectWordAroundCaret() -> Bool
  func swapOut(windowId: Int32, loading: Bool) -> Bool
  func swapIn() -> Bool
  func onOrientationChange()
  func onShowContextMenu(type: MenuSourceType, location: IntPoint)
  func updateViewWithDeviceScaleFactor()
  func detach()
  func stop()
  func clientDroppedNavigation()
  func collapse(collapsed: Bool)
  func contextMenuClosed()
  func customContextMenuAction(action: UInt32)
  func reload(bypassCache: Bool)
  func onDidStartLoading()
  func onDidStopLoading()
  func updateOpener(openerId: UInt32)
  func focusChangeComplete()
  func cursorVisibilityChanged(visible: Bool)
  func setEditCommandsForNextKeyEvent(
    editCommandName: [String],
    editCommandValue: [String],
    editCommandCount: Int)
  func imeSetComposition( 
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange, 
    selectionStart: Int, 
    selectionEnd: Int)
  func scrollRectToVisible(rect: IntRect)
  func didUpdateOrigin(origin: String)
  func imeCommitText(
    text: String,
    spans: [WebImeTextSpan],
    replacement: TextRange,
    relativeCursorPosition: Int)
  func imeFinishComposingText(keepSelection: Bool)
  func setCompositionFromExistingText(
    start: Int, 
    end: Int,
    spans: [WebImeTextSpan])
  func extendSelectionAndDelete(before: Int, after: Int)
  func deleteSurroundingText(before: Int, after: Int)
  func requestTextInputStateUpdate()
  func requestCompositionUpdates(immediateRequest: Bool, monitorRequest: Bool)
  func onEvent(event: WebInputEvent) -> InputEventAckState
  func onNonBlockingEvent(event: WebInputEvent)
  func willEnterFullscreen()
  func deleteSurroundingTextInCodePoints(before: Int, after: Int)
  func setEditableSelectionOffsets(start: Int, end: Int)
  func executeEditCommand(command: String, value: String)
  func undo()
  func redo()
  func cut()
  func copy()
  func paste()
  func delete()
  func selectAll()
  func collapseSelection()
  func replace(word: String)
  func selectRange(base: IntPoint, extent: IntPoint)
  func adjustSelectionByCharacterOffset(start: Int, end: Int, behavior: SelectionMenuBehavior)
  func moveRangeSelectionExtent(extent: IntPoint)
  func scrollFocusedEditableNodeIntoRect(rect: IntRect)
  func moveCaret(position: IntPoint)
  func onBeforeUnload(isReload: Bool)
  func enableAutoResize(min: IntSize, max: IntSize)
  func disableAutoResize()
  func setFocusedFrame()
  func mediaPlayerAction(at: IntPoint, action: Int32, enable: Bool)
  func notifyUserActivation()
  func textSurroundingSelectionRequest(maxLength: UInt32)
  func advanceFocus(type: WebFocusType, sourceRoutingId: Int32)
  func advanceFocusInForm(type: WebFocusType)
  func find(requestId: Int32, searchText: String, options: WebFindOptions)
  func clearActiveFindMatch()
  func stopFinding(action: WebFrameStopFindAction)
  func clearFocusedElement()
  func checkCompleted()
  func createNewWindow()
  func commitNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int)
  func commitSameDocumentNavigation(url: String, keepAlive: Bool, providerId: Int, routeId: Int) -> CommitResult
  func commitFailedNavigation(
    errorCode: Int,
    errorPageContent: String?)
  func didCommitAndDrawCompositorFrame()
  func onUpdateWindowScreenRect(_: IntRect)
  func onUpdateScreenRects(viewScreen: IntRect, windowScreen: IntRect)
  func onWasShown(needsRepainting: Bool, latencyInfo: LatencyInfo)
  func onRepaint(size: IntSize)
  func onWasHidden()
  func onPageWasShown()
  func onPageWasHidden()
  func onSynchronizeVisualProperties(params: VisualProperties)
  func onEnablePreferredSizeChangedMode()
  func onForceRedraw(latency: LatencyInfo)
  func onSetZoomLevel(zoomLevel: Double)
  func requestPointerLock() -> Bool
  func requestPointerUnlock()
  func onSetFocus(focused: Bool)
  func onCopyImage(at: FloatPoint)
  func onLockMouseAck(succeeded: Bool)
  func onVisualStateRequest(id: UInt64)
  func onDidHandleKeyEvent()
  func convertWindowToViewport(_ rect: inout FloatRect)
  func convertViewportToWindow(_: inout IntRect)
  func onRequestMoveAck()
  func onSaveImage(at: FloatPoint)
  func onSelectWordAroundCaret()
  func updateScreenInfo(_: ScreenInfo)
  func setTextureLayerForHTMLCanvas(target: String, layer: Compositor.Layer, frame: UIWebFrame?)
}