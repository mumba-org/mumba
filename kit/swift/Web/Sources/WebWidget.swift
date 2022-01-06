// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public struct WebFrameTimingEvent {
    public var sourceFrame: UInt
    public var startTime: Double
    public var finishTime: Double
}

public enum WebFrameTimingEventType : Int {
    case CompositeEvent = 0
    case RenderEvent = 1
}

public protocol WebWidget : class {

    var size: IntSize { get }
    var pagePopup: WebPagePopup? { get }
    var isWebView: Bool { get }
    var isWebFrameWidget: Bool { get }
    var isPagePopup: Bool { get }
    var backgroundColor: Color { get }
    var isAcceleratedCompositingActive: Bool { get } 

    func setFocus(focus: Bool)
    func close()
    func resize(size: IntSize)
    func resizeVisualViewport(size: IntSize)
    func didEnterFullScreen()
    func didExitFullScreen()
    func beginFrame(lastFrameTimeMonotonic: Double)
    func updateLifecycle(_: WebLifecycleUpdate)
    func updateAllLifecyclePhases()
    func paint(canvas: Canvas, viewport: IntRect)
    func layoutAndPaintAsync(callback: WebLayoutAndPaintAsyncCallback)
    func compositeAndReadbackAsync(callback: WebCompositeAndReadbackAsyncCallback)
    func themeChanged()
    func handleInputEvent(inputEvent: WebInputEvent) -> WebInputEvent.Result
    func setCursorVisibilityState(visible: Bool)
    func applyViewportDeltas(
        visualViewportDelta: FloatSize,
        layoutViewportDelta: FloatSize,
        elasticOverscrollDelta: FloatSize,
        scaleFactor: Float,
        topControlsShownRatioDelta: Float)
    func mouseCaptureLost()
    func getSelectionBounds(anchor: inout IntRect, focus: inout IntRect) -> Bool
    func willCloseLayerTreeView()
    func didAcquirePointerLock()
    func didNotAcquirePointerLock()
    func didLosePointerLock()
}