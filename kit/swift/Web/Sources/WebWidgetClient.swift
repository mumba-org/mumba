// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

public protocol WebWidgetClient : class {
  
  var windowRect: IntRect { get set }
  var viewRect: IntRect { get }
  var layerTreeView: WebLayerTreeView? { get }
  var allowsBrokenNullLayerTreeView: Bool { get }
  var screenInfo: ScreenInfo { get }
  var isPointerLocked: Bool { get }
  var hasTouchEventHandlers: Bool { get set }

  func didInvalidateRect(rect: IntRect)
  func initializeLayerTreeView() -> WebLayerTreeView?
  func scheduleAnimation()
  func didMeaningfulLayout(layout: WebMeaningfulLayout)
  func didFirstLayoutAfterFinishedParsing()
  func didChangeCursor(cursor: WebCursorInfo)
  func autoscrollStart(start: FloatPoint)
  func autoscrollFling(velocity: FloatVec2)
  func autoscrollEnd()
  func closeWidgetSoon()
  func show(policy: WebNavigationPolicy)
  func setToolTipText(text: String, hint: TextDirection)
  func requestPointerLock() -> Bool
  func requestPointerUnlock()
  func didHandleGestureEvent(event: WebGestureEvent, eventCancelled: Bool)
  func setNeedsLowLatencyInput(_: Bool)
  func requestUnbufferedInputEvents()
  func setTouchAction(touchAction: TouchAction)
  func convertViewportToWindow(_: inout IntRect)
  func convertWindowToViewport(_: inout FloatRect)
  func startDragging(policy: WebReferrerPolicy,
                     dragData: WebDragData,
                     ops: WebDragOperation,
                     dragImage: ImageSkia?,
                     dragImageOffset: IntPoint)
  func didOverscroll(overscrollDelta: FloatSize,
                     accumulatedOverscroll: FloatSize,
                     position: FloatPoint,
                     velocity: FloatSize,
                     overscrollBehavior: OverscrollBehavior)
  
}