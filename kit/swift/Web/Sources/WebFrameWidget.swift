// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base
import Compositor
import MumbaShims

public class WebFrameWidget {

    public var activeWebInputMethodController: WebInputMethodController? {
        if let frame = focusedLocalFrameInWidget {
            return frame.inputMethodController
        }
        return nil
    }

    public var focusedLocalFrameInWidget: WebLocalFrame? {
        let ref = _WebFrameWidgetGetFocusedWebLocalFrameInWidget(reference)
        return ref != nil ? WebLocalFrame(reference: ref!) : nil
    }

    public internal(set) var reference: WebWidgetRef?
    internal var client: WebWidgetClient?

    public var localRoot: WebLocalFrame? {
        let ref = _WebFrameWidgetGetLocalRoot(reference)
        return ref != nil ? WebLocalFrame(reference: ref!) : nil
    }

    public static func create(client: WebWidgetClient, frame: WebLocalFrame) -> WebFrameWidget {
        return WebFrameWidget(client: client, frame: frame)
    }

    internal init(client: WebWidgetClient, frame: WebLocalFrame) {
        self.client = client
        var callbacks = WebViewClientCbs()
        memset(&callbacks, 0, MemoryLayout<WebViewClientCbs>.stride)

        callbacks.didInvalidateRect = { (handle: UnsafeMutableRawPointer?, 
            x: Int32, 
            y: Int32, 
            width: Int32, 
            height: Int32) in
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.didInvalidateRect(rect: IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height)))
            }
        }
       
        callbacks.initializeLayerTreeView = { (handle: UnsafeMutableRawPointer?, compositor_state: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, cbs: UnsafeMutablePointer<WebLayerTreeViewCbs>?) in 
            //print("WebView.initializeLayerTreeView callback")
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            if let client = view.client {
                //print("WebView.initializeLayerTreeView callback: view.client found: setting layerTreeView")
                if let layerTreeView = client.initializeLayerTreeView() {
                    //print("WebView.initializeLayerTreeView callback: setting compositor state pointer")
                    compositor_state!.pointee = layerTreeView.unretainedReference
                    //layerTreeView.withUnretainedReference { [compositor_state]
                    //    compositor_state!.pointee = $0
                    //}
                    //print("WebView.initializeLayerTreeView callback: setting the callbacks pointer") 
                    cbs!.pointee = layerTreeView.createLayerTreeViewCallbacks()
                }
            }
        }

        // typedef void (*WebViewClientConvertViewportToWindowCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
        callbacks.convertViewportToWindow = { (
            handle: UnsafeMutableRawPointer?,
            x: UnsafeMutablePointer<CInt>?,
            y: UnsafeMutablePointer<CInt>?,
            w: UnsafeMutablePointer<CInt>?,
            h: UnsafeMutablePointer<CInt>?) in       
          let view = unsafeBitCast(handle, to: WebFrameWidget.self)
          if let client = view.client {
            var rect = IntRect()
            client.convertViewportToWindow(&rect)
            x!.pointee = CInt(rect.x)
            y!.pointee = CInt(rect.y)
            w!.pointee = CInt(rect.width)
            h!.pointee = CInt(rect.height)
          }
        }
        
        // typedef void (*WebViewClientConvertWindowToViewport)(void* peer, float* rx, float* ry, float* rw, float* rh);
        callbacks.convertWindowToViewport = { (
            handle: UnsafeMutableRawPointer?,
            x: UnsafeMutablePointer<Float>?,
            y: UnsafeMutablePointer<Float>?,
            w: UnsafeMutablePointer<Float>?,
            h: UnsafeMutablePointer<Float>?) in
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            if let client = view.client {
              var rect = FloatRect()
              client.convertWindowToViewport(&rect)
              x!.pointee = rect.x
              y!.pointee = rect.y
              w!.pointee = rect.width
              h!.pointee = rect.height
            }
        }

        callbacks.scheduleAnimation = { (handle: UnsafeMutableRawPointer?) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.scheduleAnimation()
            }
        }

        callbacks.didMeaningfulLayout = { (handle: UnsafeMutableRawPointer?, 
            layout: WebMeaningfulLayoutTypeEnum) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.didMeaningfulLayout(layout: WebMeaningfulLayout(rawValue: Int(layout.rawValue))!)
            }

        }

        callbacks.didFirstLayoutAfterFinishedParsing = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.didFirstLayoutAfterFinishedParsing()
            }
        }

        callbacks.didChangeCursor = { (handle: UnsafeMutableRawPointer?,
            type: WebCursorEnum, 
            hotSpotX: Int32, 
            hotSpotY: Int32, 
            imageScaleFactor: Float, 
            customImage: ImageRef?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                
                let info = WebCursorInfo(
                    type: WebCursorInfo.CursorType(rawValue: Int(type.rawValue))!,
                    hotSpot: IntPoint(x: Int(hotSpotX), y: Int(hotSpotY)),
                    imageScaleFactor: imageScaleFactor,
                    customImage: nil)// customImage == nil ? nil : ImageSkia(reference: customImage!))

                client.didChangeCursor(cursor: info)
            }
        }

        callbacks.closeWidgetSoon = { (handle: UnsafeMutableRawPointer?) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.closeWidgetSoon()
            }
        }

        callbacks.show = { (handle: UnsafeMutableRawPointer?, policy: WebNavigationPolicyEnum) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.show(policy: WebNavigationPolicy(rawValue: Int(policy.rawValue))!)
            }
        }
        
        callbacks.windowRect = { (handle: UnsafeMutableRawPointer?, 
            rx: UnsafeMutablePointer<Int32>?, 
            ry: UnsafeMutablePointer<Int32>?, 
            rw: UnsafeMutablePointer<Int32>?, 
            rh: UnsafeMutablePointer<Int32>?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                let rect = client.windowRect
                var x = Int32(rect.x)
                var y = Int32(rect.y)
                var w = Int32(rect.width)
                var h = Int32(rect.height)
                
                rx!.assign(from: &x, count: 1)
                ry!.assign(from: &y, count: 1)
                rw!.assign(from: &w, count: 1)
                rh!.assign(from: &h, count: 1)
            }
        }
        
        callbacks.setWindowRect = { (handle: UnsafeMutableRawPointer?, 
            rx: Int32, 
            ry: Int32, 
            rw: Int32, 
            rh: Int32) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.windowRect = IntRect(x: Int(rx), y: Int(ry), width: Int(rw), height: Int(rh))
            }
        }

        callbacks.setToolTipText = { (handle: UnsafeMutableRawPointer?, 
            text: UnsafePointer<CChar>?, 
            hint: WebTextDirectionEnum) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.setToolTipText(text: String(cString: text!), hint: TextDirection(rawValue: Int(hint.rawValue))!)
            }
        }

        callbacks.screenInfo = { (handle: UnsafeMutableRawPointer?, 
            deviceScaleFactor: UnsafeMutablePointer<Float>?, 
            depth: UnsafeMutablePointer<Int32>?, 
            depthPerComponent: UnsafeMutablePointer<Int32>?, 
            isMonochrome: UnsafeMutablePointer<Int32>?, 
            rx: UnsafeMutablePointer<Int32>?, 
            ry: UnsafeMutablePointer<Int32>?, 
            rw: UnsafeMutablePointer<Int32>?, 
            rh: UnsafeMutablePointer<Int32>?,
            availableX: UnsafeMutablePointer<Int32>?, 
            availableY: UnsafeMutablePointer<Int32>?, 
            availableW: UnsafeMutablePointer<Int32>?, 
            availableH: UnsafeMutablePointer<Int32>?, 
            orientationType: UnsafeMutablePointer<WebScreenOrientationEnum>?, 
            orientationAngle: UnsafeMutablePointer<UInt16>?) in
            
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                
                var info = client.screenInfo
                var _depth = Int32(info.depth)
                var _depthPerComponent = Int32(info.depthPerComponent)
                var _isMonochrome: Int32 = info.isMonochrome ? 1 : 0
                
                var _rx = Int32(info.rect.x)
                var _ry = Int32(info.rect.y)
                var _rw = Int32(info.rect.width)
                var _rh = Int32(info.rect.height)

                var _ax = Int32(info.availableRect.x)
                var _ay = Int32(info.availableRect.y)
                var _aw = Int32(info.availableRect.width)
                var _ah = Int32(info.availableRect.height)

                var ot = WebScreenOrientationEnum(rawValue: UInt32(info.orientationType.rawValue))

                deviceScaleFactor!.assign(from: &info.deviceScaleFactor, count: 1)
                depth!.assign(from: &_depth, count: 1)
                depthPerComponent!.assign(from: &_depthPerComponent, count: 1)
                isMonochrome!.assign(from: &_isMonochrome, count: 1)
                
                rx!.assign(from: &_rx, count: 1)
                ry!.assign(from: &_ry, count: 1)
                rw!.assign(from: &_rw, count: 1)
                rh!.assign(from: &_rh, count: 1)

                availableX!.assign(from: &_ax, count: 1)
                availableY!.assign(from: &_ay, count: 1)
                availableW!.assign(from: &_aw, count: 1)
                availableH!.assign(from: &_ah, count: 1)

                orientationType!.assign(from: &ot, count: 1)
                orientationAngle!.assign(from: &info.orientationAngle, count: 1)
            }
        }

        callbacks.requestPointerLock = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                return client.requestPointerLock() ? 1 : 0
            }
            return 0
        }

        callbacks.requestPointerUnlock = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.requestPointerUnlock()
            }

        }   

        callbacks.isPointerLocked = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                return client.isPointerLocked ? 1 : 0
            }
            return 0
        }

        callbacks.didHandleGestureEvent = { (handle: UnsafeMutableRawPointer?, 
            rawEvent: UnsafeMutableRawPointer?,
            eventCancelled: Int32) in 
            
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                let event = WebGestureEvent(reference: rawEvent!)
                client.didHandleGestureEvent(
                    event: event, 
                    eventCancelled: eventCancelled == 0 ? false : true)
            }

        }

        callbacks.didOverscroll = { (handle: UnsafeMutableRawPointer?, 
                unusedDeltaWidth: Float, 
                unusedDeltaHeight: Float, 
                accumulatedRootOverScrollWidth: Float, 
                accumulatedRootOverScrollHeight: Float, 
                posX: Float, posY: Float, 
                velocityWidth: Float, velocityHeight: Float,
                overscrollBehaviorTypeX: CInt, overscrollBehaviorTypeY: CInt) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.didOverscroll(
                    overscrollDelta: FloatSize(width: unusedDeltaWidth, height: unusedDeltaHeight), 
                    accumulatedOverscroll: FloatSize(width: accumulatedRootOverScrollWidth, height: accumulatedRootOverScrollHeight), 
                    position: FloatPoint(x: posX, y: posY),
                    velocity: FloatSize(width: velocityWidth, height: velocityHeight),
                    overscrollBehavior: OverscrollBehavior(x: OverscrollBehaviorType(rawValue: Int(overscrollBehaviorTypeX))!, y: OverscrollBehaviorType(rawValue: Int(overscrollBehaviorTypeY))!))
            }
        }

        callbacks.hasTouchEventHandlers = { (handle: UnsafeMutableRawPointer?, handlers: Int32) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.hasTouchEventHandlers = handlers == 0 ? false : true
            }
        }

        callbacks.setTouchAction = { (handle: UnsafeMutableRawPointer?, touchAction: WebTouchActionEnum) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.setTouchAction(touchAction: TouchAction(rawValue: Int(touchAction.rawValue))!)
            }
        }

        callbacks.startDragging = { (
            handle: UnsafeMutableRawPointer?, 
            policy: WebReferrerPolicyEnum, 
            data: WebDragDataRef?, 
            mask: WebDragOperationEnum, 
            image: ImageRef?, 
            dragImageOffsetX: Int32, 
            dragImageOffsetY: Int32) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebFrameWidget.self)
            
            if let client = view.client {
                client.startDragging(
                    policy: WebReferrerPolicy(rawValue: Int(policy.rawValue))!, 
                    dragData: WebDragData(reference: data!), 
                    ops: WebDragOperation(rawValue: Int(mask.rawValue)), 
                    dragImage: image == nil ? nil : ImageSkia(reference: image!), 
                    dragImageOffset: IntPoint(x: Int(dragImageOffsetX), y: Int(dragImageOffsetY)))
            }

        }

        let clientPeer = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        self.reference = _WebFrameWidgetCreate(clientPeer, callbacks, frame.reference)!     
    }

    public init(reference: WebWidgetRef) {
        self.reference = reference
    }

}

extension WebFrameWidget : WebWidget {
    
    public var size: IntSize { 
        var width: Int32 = 0, height: Int32 = 0
        _WebWidgetSize(reference, &width, &height)
        return IntSize(width: Int(width), height: Int(height))
    }
    
    public var pagePopup: WebPagePopup? { 
        let ref = _WebWidgetPagePopup(reference)
        if ref == nil {
            return nil
        }
        return WebPagePopup(reference: ref!)
    }
    
    public var isWebView: Bool { 
        return _WebWidgetIsWebView(reference) == 0 ? false : true
    }

    public var isWebFrameWidget: Bool { 
        return _WebWidgetIsWebFrameWidget(reference) == 0 ? false : true   
    }
    
    public var isPagePopup: Bool { 
        return _WebWidgetIsPagePopup(reference) == 0 ? false : true
    }
    
    public var backgroundColor: Color { 
        return Color(Int(_WebWidgetBackgroundColor(reference)))
    }
    
    public var isAcceleratedCompositingActive: Bool { 
        return _WebWidgetIsAcceleratedCompositingActive(reference) == 0 ? false : true
    }
    
    // TODO: we should probably use a property for this
    public func setFocus(focus: Bool) {
        _WebWidgetSetFocus(reference, focus ? 1 : 0)
    }

    public func close() {
        _WebWidgetClose(reference)
    }
    
    public func resize(size: IntSize) {
        _WebWidgetResize(reference, Int32(size.width), Int32(size.height))
    }

    public func resizeVisualViewport(size: IntSize) {
        _WebWidgetResizeVisualViewport(reference, Int32(size.width), Int32(size.height))
    }

    public func didEnterFullScreen() {
        _WebWidgetDidEnterFullScreen(reference)
    }

    public func didExitFullScreen() {
        _WebWidgetDidExitFullScreen(reference)
    }

    public func beginFrame(lastFrameTimeMonotonic: Double) {
        _WebWidgetBeginFrame(reference, lastFrameTimeMonotonic)
    }
    
    public func updateLifecycle(_ update: WebLifecycleUpdate) {
        _WebWidgetUpdateLifecycle(reference, WebLifecycleUpdateEnum(rawValue: UInt32(update.rawValue)))
    }

    public func updateAllLifecyclePhases() {
        _WebWidgetUpdateAllLifecyclePhases(reference)
    }

    public func paint(canvas: Canvas, viewport: IntRect) {
        _WebWidgetPaint(reference, canvas.nativeCanvas.reference, Int32(viewport.x), Int32(viewport.y), Int32(viewport.width), Int32(viewport.height))
    }

    public func layoutAndPaintAsync(callback: WebLayoutAndPaintAsyncCallback) {
        _WebWidgetLayoutAndPaintAsync(reference, { () -> Void in
         // TODO: implement    
        })
    }

    // TODO: implement
    public func compositeAndReadbackAsync(callback: WebCompositeAndReadbackAsyncCallback) {
        assert(false)
        //Builtin.unreachable()
        //_WebWidgetCompositeAndReadbackAsync(reference, { (bitmap: BitmapRef) -> Void in
        //})
    }

    public func themeChanged() {
        _WebWidgetThemeChanged(reference)
    }

    public func handleInputEvent(inputEvent: WebInputEvent) ->  WebInputEvent.Result {
        return WebInputEvent.Result(rawValue: Int(_WebWidgetHandleInputEvent(reference, inputEvent.reference)))!
    }

    public func setCursorVisibilityState(visible: Bool) {
        _WebWidgetSetCursorVisibilityState(reference, visible ? 1 : 0)
    }

    public func applyViewportDeltas(
        visualViewportDelta: FloatSize,
        layoutViewportDelta: FloatSize,
        elasticOverscrollDelta: FloatSize,
        scaleFactor: Float,
        topControlsShownRatioDelta: Float) {

        _WebWidgetApplyViewportDeltas(reference, 
            visualViewportDelta.width,
            visualViewportDelta.height,
            layoutViewportDelta.width,
            layoutViewportDelta.height,
            elasticOverscrollDelta.width,
            elasticOverscrollDelta.height,
            scaleFactor, 
            topControlsShownRatioDelta)

    }

    public func mouseCaptureLost() {
        _WebWidgetMouseCaptureLost(reference)
    }

    public func scrollFocusedEditableElementIntoView() -> Bool {
        return _WebFrameWidgetScrollFocusedEditableElementIntoView(reference) != 0
    }

    public func getSelectionBounds(anchor: inout IntRect, focus: inout IntRect) -> Bool {
        var ax: CInt = CInt(anchor.x)
        var ay: CInt = CInt(anchor.y)
        var aw: CInt = CInt(anchor.width)
        var ah: CInt = CInt(anchor.height)

        var fx: CInt = CInt(focus.x)
        var fy: CInt = CInt(focus.y)
        var fw: CInt = CInt(focus.width)
        var fh: CInt = CInt(focus.height)

        let r = _WebWidgetSelectionBounds(
            reference, 
            &ax, &ay, &aw, &ah,
            &fx, &fy, &fw, &fh)
        if r != 0 {
            anchor = IntRect(x: Int(ax),
                             y: Int(ay),
                             width: Int(aw),
                             height: Int(ah))

            focus = IntRect(x: Int(fx), 
                            y: Int(fy),
                            width: Int(fw),
                            height: Int(fh))
        }
        return r != 0
    }

    public func willCloseLayerTreeView() {
        _WebWidgetWillCloseLayerTreeView(reference)
    }

    public func didAcquirePointerLock() {
        _WebWidgetDidAcquirePointerLock(reference)
    }

    public func didNotAcquirePointerLock() {
        _WebWidgetDidNotAcquirePointerLock(reference)
    }

    public func didLosePointerLock() {
        _WebWidgetDidLosePointerLock(reference)
    }

    public func didCloseContextMenu() {
        _WebViewDidCloseContextMenu(reference)   
    }

    public func setVisibilityState(_ visibility: WebPageVisibilityState) {
      _WebFrameWidgetSetVisibilityState(reference, WebPageVisibilityStateEnum(rawValue: UInt32(visibility.rawValue)))
    }
}