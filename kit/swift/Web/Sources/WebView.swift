// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor
import Graphics
import Base
import MumbaShims

public struct WebWindowFeatures {
    
    public var x: Float = 0.0
    public var xSet: Bool = false
    public var y: Float = 0.0
    public var ySet: Bool = false
    public var width: Float = 0.0
    public var widthSet: Bool = false
    public var height: Float = 0.0
    public var heightSet: Bool = false
    public var menuBarVisible: Bool = true
    public var statusBarVisible: Bool = true
    public var toolBarVisible: Bool = true
    public var locationBarVisible: Bool = true
    public var scrollbarsVisible: Bool = true
    public var resizable: Bool = true
    public var fullscreen: Bool = false
    public var dialog: Bool = false
    public var additionalFeatures: [String] = []

}

public enum WebMeaningfulLayout : Int {
    case VisuallyNonEmpty = 0
    case FinishedParsing = 1
    case FinishedLoading = 2
}

public enum WebPageVisibilityState : Int {
  case Visible = 0
  case Hidden = 1
  case Prerender = 2
}

public class WebCompositedDisplayList {
    
    var reference: WebCompositedDisplayListRef

    init(reference: WebCompositedDisplayListRef) {
        self.reference = reference
    }

}

public class WebPageImportanceSignals {

    var reference: WebPageImportanceSignalsRef

    init(reference: WebPageImportanceSignalsRef) {
        self.reference = reference
    }
}

public class WebView {
    
    public var settings: WebSettings { 
        let ref = _WebViewSettings(reference)
        return WebSettings(reference: ref!)
    }
    
    public var pageEncoding: String { 
        var len: CInt = 0
        let cstr = _WebViewPageEncoding(reference, &len)
        return cstr != nil ? String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }

    // public var isTransparent: Bool { 
        
    //     get {
    //         return _WebViewIsTransparent(reference) == 0 ? false : true
    //     }
        
    //     set (transparent) {
    //         _WebViewSetIsTransparent(reference, transparent ? 1 : 0)
    //     }

    // }
    
    public var tabsToLinks: Bool { 
        
        get {
            return _WebViewTabsToLinks(reference) == 0 ? false : true
        }
        
        set (value) {
            _WebViewSetTabsToLinks(reference, value ? 1 : 0)
        }

    }
    
    public var tabKeyCyclesThroughElements: Bool { 
        
        get {
            return _WebViewTabKeyCyclesThroughElements(reference) == 0 ? false : true
        }

        set (value) {
            _WebViewSetTabKeyCyclesThroughElements(reference, value ? 1 : 0)
        }
    }
    
    public var isActive : Bool { 
        
        get {
            return _WebViewIsActive(reference) == 0 ? false : true 
        }
        
        set (active) {
            _WebViewSetIsActive(reference, active ? 1 : 0)    
        }
    }
    
    public var mainFrame: WebFrame? { 
        let ref = _WebViewMainFrame(reference)
        if ref == nil {
            return nil
        }
        return WebFrame(reference: ref!)
    }

    // not in the original WebView, a cheaper
    // way to test if theres a focused frame
    // without the need to instantiate a new swift temp object
    public var hasFocusedFrame: Bool {
      return _WebViewHasFocusedFrame(reference) != 0
    }
    
    public var focusedFrame: WebLocalFrame? { 
        
        get {
            let ref = _WebViewFocusedFrame(reference)
            if ref == nil {
                return nil
            }
            return WebLocalFrame(reference: ref!)
        }
        
        set (maybeFrame) {
            if let frame = maybeFrame {
                _WebViewSetFocusedFrame(reference, frame.reference)
            } else {
                _WebViewSetFocusedFrame(reference, nil)
            }
        }

    }
    
    public var zoomLevel: Double { 
        
        get {
            return _WebViewZoomLevel(reference)
        }
        
        set (level) {
            _WebViewSetZoomLevel(reference, level)
        }

    }
    
    public var textZoomFactor: Float { 
        
        get {
            return _WebViewTextZoomFactor(reference)
        }
        
        set (factor) {
            _WebViewSetTextZoomFactor(reference, factor)
        }

    }
    
    public var pageScaleFactor: Float { 
        
        get {
            return _WebViewPageScaleFactor(reference)
        }
        
        set {
            _WebViewSetPageScaleFactor(reference, newValue)
        }

    }
    
    public var visualViewportOffset: FloatPoint { 
        
        get {
            var x: Float = 0, y: Float = 0
            _WebViewVisualViewportOffset(reference, &x, &y)
            return FloatPoint(x: x, y: y)
        }
        
        set (offset) {
            _WebViewSetVisualViewportOffset(reference, offset.x, offset.y)
        }

    }
    
    public func setDeviceScaleFactor(_ scaleFactor: Float) { 
        _WebViewSetDeviceScaleFactor(reference, scaleFactor)
    }
    
    public var visualViewportSize: FloatSize { 
        var width: Float = 0, height: Float = 0
        _WebViewVisualViewportSize(reference, &width, &height)
        return FloatSize(width: width, height: height)
    }
    
    // public var accessibilityObject: WebAXObject? { 
    //     let ref = _WebViewGetAccessibilityObject(reference)
    //     if ref == nil {
    //         return nil
    //     }
    //     return WebAXObject(reference: ref!)
    // }
    
    public var contentsPreferredMinimumSize: IntSize { 
        var width: Int32 = 0, height: Int32 = 0
        _WebViewContentsPreferredMinimumSize(reference, &width, &height)
        return IntSize(width: Int(width), height: Int(height))
    }
    
    public static func make(client: WebViewClient, visibility: WebPageVisibilityState, opener: WebView?) -> WebView {
        return WebView(client: client, visibility: visibility, opener: opener)
    }
  
    public static func zoomLevelToZoomFactor(level: Double) -> Double { 
        return _WebViewZoomLevelToZoomFactor(level)
    }
  
    public static func zoomFactorToZoomLevel(factor: Double) -> Double { 
        return _WebViewZoomFactorToZoomLevel(factor)
    }
  
    public static func willEnterModalLoop() {
        _WebViewWillEnterModalLoop()
    }
  
    public static func didExitModalLoop() {
        _WebViewDidExitModalLoop()
    }
  
    public static func setUseExternalPopupMenus(use: Bool) {
        _WebViewSetUseExternalPopupMenus(use ? 1 : 0)
    }
  
    public static func updateVisitedLinkState(hash: UInt64) {
        _WebViewUpdateVisitedLinkState(hash)
    }
  
    public static func resetVisitedLinkState(invalidateVisitedLinkHashes: Bool) {
        _WebViewResetVisitedLinkState(invalidateVisitedLinkHashes ? 1 : 0)
    }

    public private(set) var nativeWebViewClient: UnsafeMutableRawPointer?
    
    var client: WebViewClient?
    var reference: WebWidgetRef!

    init(reference: WebWidgetRef, client: WebViewClient?) {
        self.reference = reference
        self.client = client
    }

    public init(client: WebViewClient, visibility: WebPageVisibilityState, opener: WebView?) {
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didInvalidateRect(rect: IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height)))
            }
        }

        callbacks.didAutoResize = { (handle: UnsafeMutableRawPointer?, width: Int32, height: Int32) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didAutoResize(size: IntSize(width: Int(width), height: Int(height)))
            }
        }
       
        // callbacks.didUpdateLayoutSize = { (handle: UnsafeMutableRawPointer?, width: Int32, height: Int32) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.didUpdateLayoutSize(to: IntSize(width: Int(width), height: Int(height)))
        //     }
        // }

        callbacks.initializeLayerTreeView = { (handle: UnsafeMutableRawPointer?, compositor_state: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, cbs: UnsafeMutablePointer<WebLayerTreeViewCbs>?) in 
            //print("WebView.initializeLayerTreeView callback")
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebView.self)
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

        // callbacks.layerTreeView = { (handle: UnsafeMutableRawPointer?) -> WebLayerTreeViewRef? in 
            
        //     guard handle != nil else {
        //         return nil
        //     }
            
        //     // TODO: implement

        //     //let view = unsafeBitCast(handle, to: WebView.self)
            
        //     //if let client = view.client {
        //     //    if let treeView = client.layerTreeView {
        //     //        assert(false)
        //     //        return nil
        //     //        return treeView.reference
        //     //    }
        //     //}
        //     return nil
        // }

        // typedef void (*WebViewClientConvertViewportToWindowCb)(void* peer, int* rx, int* ry, int* rw, int* rh);
        callbacks.convertViewportToWindow = { (
            handle: UnsafeMutableRawPointer?,
            x: UnsafeMutablePointer<CInt>?,
            y: UnsafeMutablePointer<CInt>?,
            w: UnsafeMutablePointer<CInt>?,
            h: UnsafeMutablePointer<CInt>?) in       
          let view = unsafeBitCast(handle, to: WebView.self)
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
            let view = unsafeBitCast(handle, to: WebView.self)
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.scheduleAnimation()
            }
        }

        callbacks.didMeaningfulLayout = { (handle: UnsafeMutableRawPointer?, 
            layout: WebMeaningfulLayoutTypeEnum) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didMeaningfulLayout(layout: WebMeaningfulLayout(rawValue: Int(layout.rawValue))!)
            }

        }

        callbacks.didFirstLayoutAfterFinishedParsing = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didFirstLayoutAfterFinishedParsing()
            }
        }

        callbacks.canUpdateLayout = { (handle: UnsafeMutableRawPointer?) -> CInt in
            let view = unsafeBitCast(handle, to: WebView.self)
            if let client = view.client {
                return client.canUpdateLayout ? 1 : 0
            }
            return 0  
        }

        callbacks.didFocus = { (handle: UnsafeMutableRawPointer?, callingFrame: WebFrameRef?) in 
            
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didFocus(callingFrame: WebFrame(reference: callingFrame!))
            }
        }

        // callbacks.didBlur = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.didBlur()
        //     }
        // }

        callbacks.didChangeCursor = { (handle: UnsafeMutableRawPointer?,
            type: WebCursorEnum, 
            hotSpotX: Int32, 
            hotSpotY: Int32, 
            imageScaleFactor: Float, 
            customImage: ImageRef?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                
                let info = WebCursorInfo(
                    type: WebCursorInfo.CursorType(rawValue: Int(type.rawValue))!,
                    hotSpot: IntPoint(x: Int(hotSpotX), y: Int(hotSpotY)),
                    imageScaleFactor: imageScaleFactor,
                    customImage: nil)//customImage ==  nil ? nil : ImageSkia(reference: customImage!))

                client.didChangeCursor(cursor: info)
            }
        }

        callbacks.closeWidgetSoon = { (handle: UnsafeMutableRawPointer?) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.closeWidgetSoon()
            }
        }

        callbacks.show = { (handle: UnsafeMutableRawPointer?, policy: WebNavigationPolicyEnum) in 
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.setToolTipText(text: String(cString: text!), hint: TextDirection(rawValue: Int(hint.rawValue))!)
            }
        }

        // callbacks.windowResizerRect = { (handle: UnsafeMutableRawPointer?, 
        //     rx: UnsafeMutablePointer<Int32>?, 
        //     ry: UnsafeMutablePointer<Int32>?, 
        //     rw: UnsafeMutablePointer<Int32>?, 
        //     rh: UnsafeMutablePointer<Int32>?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
                
        //         let rect = client.windowResizerRect
                
        //         var x = Int32(rect.x)
        //         var y = Int32(rect.y)
        //         var w = Int32(rect.width)
        //         var h = Int32(rect.height)
                
        //         rx!.assign(from: &x, count: 1)
        //         ry!.assign(from: &y, count: 1)
        //         rw!.assign(from: &w, count: 1)
        //         rh!.assign(from: &h, count: 1)
        //     }
        // }   

        callbacks.rootWindowRect = { (handle: UnsafeMutableRawPointer?, 
            rx: UnsafeMutablePointer<Int32>?, 
            ry: UnsafeMutablePointer<Int32>?, 
            rw: UnsafeMutablePointer<Int32>?, 
            rh: UnsafeMutablePointer<Int32>?) in 
            
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                
                let rect = client.rootWindowRect
                
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

            let view = unsafeBitCast(handle, to: WebView.self)
            
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

        // callbacks.resetInputMethod = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.resetInputMethod()
        //     }

        // }

        callbacks.requestPointerLock = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                return client.requestPointerLock() ? 1 : 0
            }
            return 0
        }

        callbacks.requestPointerUnlock = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.requestPointerUnlock()
            }

        }   

        callbacks.isPointerLocked = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
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

            let view = unsafeBitCast(handle, to: WebView.self)
            
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.hasTouchEventHandlers = handlers == 0 ? false : true
            }
        }

        callbacks.setTouchAction = { (handle: UnsafeMutableRawPointer?, touchAction: WebTouchActionEnum) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.setTouchAction(touchAction: TouchAction(rawValue: Int(touchAction.rawValue))!)
            }
        }

        // callbacks.didUpdateTextOfFocusedElementByNonUserInput = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.didUpdateTextOfFocusedElementByNonUserInput()
        //     }
        // }   

        // callbacks.showImeIfNeeded = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.showImeIfNeeded()
        //     }
        // }

        // callbacks.showUnhandledTapUIIfNeeded = { (handle: UnsafeMutableRawPointer?, 
        //     tappedPositionX: Int32,
        //     tappedPositionY: Int32, 
        //     tappedNode: WebNodeRef?,
        //     pageChanged: Int32) in
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client, let node = tappedNode {
        //         client.showUnhandledTapUIIfNeeded(
        //             tappedPosition: IntPoint(x: Int(tappedPositionX), y: Int(tappedPositionY)), 
        //             tappedNode: WebNode(reference: node),
        //             pageChanged: pageChanged == 0 ? false : true)
        //     }
        // }

        // callbacks.onMouseDown = { (handle: UnsafeMutableRawPointer?, mouseDownNode: WebNodeRef?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client, let node = mouseDownNode {
        //         client.onMouseDown(mouseDownNode: WebNode(reference: node))
        //     }

        // }

        callbacks.createView = { (handle: UnsafeMutableRawPointer?, 
                    creator: WebFrameRef?,
                    request: WebURLRequestRef?,
                    x: Float, 
                    xSet: Int32, 
                    y: Float, 
                    ySet: Int32, 
                    width: Float,
                    widthSet: Int32, 
                    height: Float, 
                    heightSet: Int32, 
                    menuBarVisible: Int32, 
                    statusBarVisible: Int32, 
                    toolBarVisible: Int32, 
                    locationBarVisible: Int32, 
                    scrollbarsVisible: Int32, 
                    resizable: Int32, 
                    fullscreen: Int32, 
                    dialog: Int32,
                    name: UnsafePointer<CChar>?,
                    policy: WebNavigationPolicyEnum,
                    suppressOpener: Int32) -> WebWidgetRef? in 
            
            guard handle != nil else {
                return nil
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {

                var features = WebWindowFeatures()
                features.x = x 
                features.xSet = xSet == 0 ? false : true 
                features.y = y 
                features.ySet = ySet == 0 ? false : true
                features.width = width
                features.widthSet = widthSet == 0 ? false : true 
                features.height = height 
                features.heightSet = heightSet == 0 ? false : true
                features.menuBarVisible = menuBarVisible == 0 ? false : true 
                features.statusBarVisible = statusBarVisible == 0 ? false : true
                features.toolBarVisible = toolBarVisible == 0 ? false : true
                features.locationBarVisible = locationBarVisible == 0 ? false : true
                features.scrollbarsVisible = scrollbarsVisible == 0 ? false : true
                features.resizable = resizable == 0 ? false : true 
                features.fullscreen = fullscreen == 0 ? false : true
                features.dialog = dialog == 0 ? false : true

                if let view = client.makeView(
                    creator: WebFrame(reference: creator!),
                    request: WebURLRequest(reference: request!),
                    features: features, 
                    name: String(cString: name!),
                    policy: WebNavigationPolicy(rawValue: Int(policy.rawValue))!, 
                    suppressOpener: suppressOpener == 0 ? false : true) {
                    
                    return view.reference
                }
            }
            return nil
        }

        // callbacks.createPopupMenu = { (handle: UnsafeMutableRawPointer?, type: WebPopupTypeEnum) -> WebWidgetRef! in 
            
        //     guard handle != nil else {
        //         return nil
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let widget = view.client?.makePopupMenu(type: WebPopupType(rawValue: Int(type.rawValue))!) as? WebView {
        //         return widget.reference
        //     }
        //     return nil
        // }

        // callbacks.createSessionStorageNamespace = { (handle: UnsafeMutableRawPointer?) -> WebStorageNamespaceRef? in 
            
        //     guard handle != nil else {
        //         return nil
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client?.makeSessionStorageNamespace() {
        //         return client.reference
        //     }
        //     return nil
        // }

        callbacks.printPage = { (handle: UnsafeMutableRawPointer?, frame: WebFrameRef?) in 
            
            guard handle != nil else {
                return
            }

            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client, let frameRef = frame {
                client.printPage(frame: WebFrame(reference: frameRef))
            }

        }

        callbacks.enumerateChosenDirectory = { (handle: UnsafeMutableRawPointer?, 
            path: UnsafePointer<CChar>?, 
            completion: WebFileChooserCompletionRef?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }

            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                let result = client.enumerateChosenDirectory(path: String(cString: path!), completion: completion != nil ? WebFileChooserCompletion(reference: completion!) : nil)
                return result ? 1 : 0
            }
            return 0

        }

        // callbacks.saveImageFromDataURL = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.saveImageFromDataURL(url: String(cString: url!))
        //     }

        // }

        callbacks.pageImportanceSignalsChanged = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.pageImportanceSignalsChanged()
            }

        }

        // callbacks.didCancelCompositionOnSelectionChange = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.didCancelCompositionOnSelectionChange()
        //     }
        // }

        // callbacks.didChangeContents = { (handle: UnsafeMutableRawPointer?) in 
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.didChangeContents()
        //     }
        // }

        // callbacks.handleCurrentKeyboardEvent = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
        //     guard handle != nil else {
        //         return 0
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         return client.handleCurrentKeyboardEvent() ? 1 : 0
        //     }
        //     return 0
        // }

        // callbacks.runFileChooser = { (handle: UnsafeMutableRawPointer?,
        //     multiSelect: Int32,
        //     directory: Int32,
        //     saveAs: Int32,
        //     title: UnsafePointer<CChar>?,
        //     initialValue: UnsafePointer<CChar>?,
        //     acceptTypes: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
        //     selectedFiles: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
        //     capture: UnsafePointer<CChar>?,
        //     useMediaCapture: Int32,
        //     needLocalPath: Int32,
        //     requestor: UnsafePointer<CChar>?, 
        //     completion: WebFileChooserCompletionRef?) -> Int32 in 
            
        //     guard handle != nil else {
        //         return 0
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         var params = WebFileChooserParams()
                
        //         params.multiSelect = multiSelect == 0 ? false : true
        //         params.directory = directory == 0 ? false : true
        //         params.saveAs = saveAs == 0 ? false : true
        //         params.title = String(cString: title!)
        //         params.initialValue = String(cString: initialValue!)
        //         // params.acceptTypes =
        //         // params.selectedFiles = 
        //         params.capture = String(cString: capture!)
        //         params.useMediaCapture = useMediaCapture == 0 ? false : true
        //         params.needLocalPath = needLocalPath == 0 ? false : true
        //         params.requestor = URL(string: String(cString: requestor!))!
        //        //params.completion = WebFileChooserCompletion(reference: completion!)

        //         let result = client.runFileChooser(
        //             params: params,
        //             completion: WebFileChooserCompletion(reference: completion!))
        //         return result ? 1 : 0
        //     }
        //     return 0
        // }

        callbacks.openDateTimeChooser = { (handle: UnsafeMutableRawPointer?,
            type: WebDateTimeInputTypeEnum,
            anchorRectInScreenX: Int32, 
            anchorRectInScreenY: Int32, 
            anchorRectInScreenW: Int32, 
            anchorRectInScreenH: Int32,
            doubleValue: Double,
            minimum: Double,
            maximum: Double,
            step: Double,
            stepBase: Double,
            isRequired: Int32,
            isAnchorElementRTL: Int32, 
            completion: WebDateTimeChooserCompletionRef?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                let params = WebDateTimeChooserParams(
                        type: WebDateTimeInputType(rawValue: Int(type.rawValue))!,
                        anchorRectInScreen: IntRect(
                            x: Int(anchorRectInScreenX),
                            y: Int(anchorRectInScreenY),
                            width: Int(anchorRectInScreenW),
                            height: Int(anchorRectInScreenH)),
                        doubleValue: doubleValue,
                        minimum: minimum,
                        maximum: maximum,
                        step: step,
                        stepBase: stepBase,
                        isRequired: isRequired == 0 ? false : true,
                        isAnchorElementRTL: isAnchorElementRTL == 0 ? false : true)
                
                return client.openDateTimeChooser(params: params, 
                    completion: WebDateTimeChooserCompletion(reference: completion!)) ? 1 : 0
            }
            return 0
        }

        // callbacks.showValidationMessage = { (
        //     handle: UnsafeMutableRawPointer?,
        //     anchorInViewportX: Int32, 
        //     anchorInViewportY: Int32, 
        //     anchorInViewportW: Int32, 
        //     anchorInViewportH: Int32, 
        //     mainText: UnsafePointer<CChar>?, 
        //     mainTextDir: WebTextDirectionEnum, 
        //     supplementalText: UnsafePointer<CChar>?, 
        //     supplementalTextDir: WebTextDirectionEnum) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.showValidationMessage(
        //             anchorInViewport: IntRect(x: Int(anchorInViewportX), 
        //                                    y: Int(anchorInViewportY), 
        //                                    width: Int(anchorInViewportW), 
        //                                    height: Int(anchorInViewportH)), 
        //             mainText: String(cString: mainText!),
        //             mainTextDir: TextDirection(rawValue: Int(mainTextDir.rawValue))!, 
        //             supplementalText: String(cString: supplementalText!), 
        //             supplementalTextDir: TextDirection(rawValue: Int(supplementalTextDir.rawValue))!)
        //     }
        // }

        // callbacks.hideValidationMessage = { (handle: UnsafeMutableRawPointer?) in 
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.hideValidationMessage()
        //     }
        // }

        // callbacks.moveValidationMessage = { (handle: UnsafeMutableRawPointer?, 
        //     anchorInViewportX: Int32, 
        //     anchorInViewportY: Int32, 
        //     anchorInViewportW: Int32, 
        //     anchorInViewportH: Int32) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.moveValidationMessage(anchorInViewport: IntRect(
        //                 x: Int(anchorInViewportX), 
        //                 y: Int(anchorInViewportY), 
        //                 width: Int(anchorInViewportW),
        //                 height: Int(anchorInViewportH)))
        //     }
        // }

        // callbacks.setStatusText = { (handle: UnsafeMutableRawPointer?, text: UnsafePointer<CChar>?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.setStatusText(text: String(cString: text!))
        //     }
        // }

        callbacks.setMouseOverURL = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.setMouseOverURL(url: String(cString: url!))
            }

        }

        callbacks.setKeyboardFocusURL = { (handle: UnsafeMutableRawPointer?, url: UnsafePointer<CChar>?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.setKeyboardFocusURL(url: String(cString: url!))
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
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.startDragging(
                    policy: WebReferrerPolicy(rawValue: Int(policy.rawValue))!, 
                    dragData: WebDragData(reference: data!), 
                    ops: WebDragOperation(rawValue: Int(mask.rawValue)), 
                    dragImage: ImageSkia(reference: image!),
                    dragImageOffset: IntPoint(x: Int(dragImageOffsetX), y: Int(dragImageOffsetY)))
            }

        }

        callbacks.acceptsLoadDrops = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                return client.acceptsLoadDrops ? 0 : 1
            }
            return 0
        }
        
        callbacks.focusNext = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.focusNext()
            }

        }

        callbacks.focusPrevious = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.focusPrevious()
            }

        }

        callbacks.focusedNodeChanged = { (handle: UnsafeMutableRawPointer?, 
            fromNode: WebNodeRef?, 
            toNode: WebNodeRef?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.focusedNodeChanged(from: fromNode == nil ? nil : WebNode(reference: fromNode!), to: toNode == nil ? nil : WebNode(reference: toNode!))
            }

        }

        callbacks.didUpdateLayout = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didUpdateLayout()
            }

        }

        callbacks.didTapMultipleTargets = { (
            handle: UnsafeMutableRawPointer?, 
            pinchViewportOffsetX: Int32,
            pinchViewportOffsetY: Int32, 
            tx: Int32,
            ty: Int32,
            tw: Int32,
            th: Int32,
            targetX: UnsafeMutablePointer<Int32>?, 
            targetY: UnsafeMutablePointer<Int32>?, 
            targetW: UnsafeMutablePointer<Int32>?, 
            targetH: UnsafeMutablePointer<Int32>?, 
            targetLen: Int32) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                var rects: [IntRect] = []
                
                for i in 0...Int(targetLen) {
                    rects.insert(IntRect(x: Int(targetX![i]), y: Int(targetY![i]), width: Int(targetW![i]), height: Int(targetH![i])), at: i)
                }
                
                return client.didTapMultipleTargets(
                     visualViewportOffset: IntSize(width: Int(pinchViewportOffsetX), height: Int(pinchViewportOffsetY)),
                     touchRect: IntRect(x: Int(tx), y: Int(ty), width: Int(tw), height: Int(th)), 
                     targetRects: rects) ? 1 : 0
            }
            return 0
        }

        callbacks.acceptLanguages = { (handle: UnsafeMutableRawPointer?) -> UnsafePointer<CChar>? in 
            
            guard handle != nil else {
                return nil
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let languages = view.client?.acceptLanguages {
                // lifetime of ptr binded to view client lifetime
                return languages.withCString { langcstr -> UnsafePointer<CChar> in
                    return langcstr
                }
            }

            return nil
        }

        callbacks.navigateBackForwardSoon = { (handle: UnsafeMutableRawPointer?, offset: Int32) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.navigateBackForwardSoon(offset: Int(offset))
            }

        }

        callbacks.historyBackListCount = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                return Int32(client.historyBackListCount)
            }
            return 0
        }

        callbacks.historyForwardListCount = { (handle: UnsafeMutableRawPointer?) -> Int32 in 
            
            guard handle != nil else {
                return 0
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                return Int32(client.historyForwardListCount)
            }
            return 0
        }

        callbacks.didUpdateInspectorSettings = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didUpdateInspectorSettings()
            }

        }

        callbacks.didUpdateInspectorSetting = { (handle: UnsafeMutableRawPointer?, 
            key: UnsafePointer<CChar>?, 
            value: UnsafePointer<CChar>?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.didUpdateInspectorSetting(key: String(cString: key!), value: String(cString: value!))
            }

        }

        // callbacks.speechRecognizer = { (handle: UnsafeMutableRawPointer?) -> WebSpeechRecognizerRef? in 
            
        //     guard handle != nil else {
        //         return nil
        //     }
            
        //     //let view = unsafeBitCast(handle, to: WebView.self)
            
        //     //if let client = view.client {
        //     //    if let recognizer = client.speechRecognizer {
        //             // TODO: implement
        //             //assert(false)
        //             //return nil
        //             //return recognizer.reference
        //     //    }
        //     //}
        //     return nil
        // }

        callbacks.zoomLimitsChanged = { (handle: UnsafeMutableRawPointer?, 
            minimumLevel: Double, 
            maximumLevel: Double) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.zoomLimitsChanged(minimumLevel: minimumLevel, maximumLevel: maximumLevel)
            }

        }

        callbacks.pageScaleFactorChanged = { (handle: UnsafeMutableRawPointer?) in 
            
            guard handle != nil else {
                return
            }
            
            let view = unsafeBitCast(handle, to: WebView.self)
            
            if let client = view.client {
                client.pageScaleFactorChanged()
            }

        }

        // callbacks.visibilityState = { (handle: UnsafeMutableRawPointer?) -> WebPageVisibilityStateEnum in 
            
        //     guard handle != nil else {
        //         return WebPageVisibilityStateHidden
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         return WebPageVisibilityStateEnum(rawValue: UInt32(client.visibilityState.rawValue))
        //     }
        //     return WebPageVisibilityStateHidden
        // }

        // callbacks.detectContentAround = { (handle: UnsafeMutableRawPointer?, 
        //     result: WebHitTestResultRef?, 
        //     range: WebRangeRef?,
        //     string: UnsafeMutablePointer<UnsafePointer<CChar>?>?,
        //     intent: UnsafeMutablePointer<UnsafePointer<CChar>?>?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         // TODO: We need to fix this to proper handle params
        //         let result = client.detectContentAround(result: WebHitTestResult(reference: result!))
        //         if let r = range {
        //             r.initializeMemory(as: WebRangeRef.self, to: result.range.reference)
        //         }
        //         result.string.withCString { strbuf in
        //             string!.pointee! = strbuf   
        //         }
        //         result.intent.absoluteString.withCString { intentbuf in
        //             intent!.pointee! = intentbuf
        //         }
        //     }

        // }

        // callbacks.scheduleContentIntent = { (handle: UnsafeMutableRawPointer?, 
        //     url: UnsafePointer<CChar>?, 
        //     isMainFrame: Int32) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //         client.scheduleContentIntent(url: URL(string: String(cString: url!))!, isMainFrame: isMainFrame == 0 ? false : true)
        //     }

        // }

        // callbacks.cancelScheduledContentIntents = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }

        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //      client.cancelScheduledContentIntents()
        //     }

        // }

        // callbacks.draggableRegionsChanged = { (handle: UnsafeMutableRawPointer?) in 
            
        //     guard handle != nil else {
        //         return
        //     }
            
        //     let view = unsafeBitCast(handle, to: WebView.self)
            
        //     if let client = view.client {
        //      client.draggableRegionsChanged()
        //     }

        // }

        // This will probably break because super.init was not called at this point
        
        let clientPeer = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        // TODO: we need to create this version where we pass the peer and the callback
        // to be used by the WebClient code on the c++ side
        var nativeHandle: UnsafeMutableRawPointer?
        let handle = _WebViewCreate(clientPeer, callbacks, WebPageVisibilityStateEnum(UInt32(visibility.rawValue)), opener != nil ? opener!.reference : nil, &nativeHandle)
        self.reference = handle!
        self.nativeWebViewClient = nativeHandle
        //self.webViewClientRef = clientRef!
        ////print("WebView (swift): self.webViewClientRef = \(webViewClientRef)")
    }
    
    // BAD: Views instantiate with this constructor will lack a client
    //      so when the callbacks trigger this will not handle the callbacks
    //      as it should, as it will test client and it will not be set
    //      in this case

    init(reference: WebWidgetRef) {
        self.reference = reference
    }

    deinit {
        _WebViewDestroy(reference)
    }

    // public func setCredentialManagerClient(manager: WebCredentialManagerClient) {
    //     _WebViewSetCredentialManagerClient(reference, nil)
    // }
    
    public func setPrerendererClient(client: WebPrerendererClient) {
        _WebViewSetPrerendererClient(reference, nil)
    }
    
    // public func setSpellCheckClient(client: WebSpellCheckClient) {
    //     _WebViewSetSpellCheckClient(reference, nil)
    // }

    // public func setBaseBackgroundColor(color: Color) {
    //     _WebViewSetBaseBackgroundColor(reference, color.value)
    // }

    public func setDomainRelaxationForbidden(forbidden: Bool, scheme: String) {
        scheme.withCString { schemeBuf in
            _WebViewSetDomainRelaxationForbidden(reference, forbidden ? 1 : 0, schemeBuf)
        }
    }

    public func setWindowFeatures(features: WebWindowFeatures) {
        _WebViewSetWindowFeatures(reference,
            features.x, 
            features.xSet ? 1 : 0, 
            features.y,
            features.ySet ? 1 : 0,
            features.width,
            features.widthSet ? 1 : 0,
            features.height,
            features.heightSet ? 1 : 0,
            features.menuBarVisible ? 1 : 0,
            features.statusBarVisible ? 1 : 0, 
            features.toolBarVisible ? 1 : 0, 
            features.locationBarVisible ? 1 : 0, 
            features.scrollbarsVisible ? 1 : 0, 
            features.resizable ? 1 : 0, 
            features.fullscreen ? 1 : 0, 
            features.dialog ? 1 : 0)
    }

    public func setOpenedByDOM() {
        _WebViewSetOpenedByDOM(reference)
    }

    // public func findFrameByName(name: String, relativeToFrame: WebFrame?) -> WebFrame? {
    //     var result: WebFrame? = nil
    //     name.withCString { namebuf in
    //         let ref = _WebViewFindFrameByName(reference, namebuf, relativeToFrame != nil ? relativeToFrame!.reference : nil)
    //         if ref != nil {
    //             result = WebFrame(reference: ref!)
    //         }
    //     }
    //     return result
    // }

    public func focusDocumentView(frame: WebFrame) {
        _WebViewFocusDocumentView(reference, frame.reference)
    }

    public func setInitialFocus(reverse: Bool) {
        _WebViewSetInitialFocus(reference, reverse ? 1 : 0)
    }

    public func clearFocusedElement() {
        _WebViewClearFocusedElement(reference)
    }

    // public func scrollFocusedNodeIntoRect(rect: IntRect) -> Bool {
    //     return _WebViewScrollFocusedNodeIntoRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height)) == 0 ? false : true 
    // }

    public func smoothScroll(x: Int, y: Int, duration: Int64) {
        _WebViewSmoothScroll(reference, Int32(x), Int32(y), duration)
    }
  
    public func advanceFocus(reverse: Bool) {
        _WebViewAdvanceFocus(reference, reverse ? 1 : 0)
    }

    public func zoomToMultipleTargetsRect(rect: IntRect) -> Bool {
        return _WebViewZoomToMultipleTargetsRect(reference, Int32(rect.x), Int32(rect.y), Int32(rect.width), Int32(rect.height)) == 0 ? false : true
    }

    public func zoomLimitsChanged(min: Double, max: Double) {
        _WebViewZoomLimitsChanged(reference, min, max)
    }
   
    public func setDefaultPageScaleLimits(minScale: Float, maxScale: Float) {
        _WebViewSetDefaultPageScaleLimits(reference, minScale, maxScale)
    }

    public func setInitialPageScaleOverride(scale: Float) {
        _WebViewSetInitialPageScaleOverride(reference, scale) 
    }

    public func setMaximumLegibleScale(scale: Float) {
        _WebViewSetMaximumLegibleScale(reference, scale)
    }

    public func resetScrollAndScaleState() {
        _WebViewResetScrollAndScaleState(reference)
    }

    public func setIgnoreViewportTagScaleLimits(ignore: Bool) {
        _WebViewSetIgnoreViewportTagScaleLimits(reference, ignore ? 1 : 0)
    }

    public func setDisplayMode(mode: WebDisplayMode) {
        _WebViewSetDisplayMode(reference, WebDisplayModeEnum(rawValue: UInt32(mode.rawValue)))
    }

    public func setZoomFactorForDeviceScaleFactor(factor: Float) {
        _WebViewSetZoomFactorForDeviceScaleFactor(reference, factor)
    }
    
    // public func setDeviceColorProfile(profile: inout [Int8]) {
        
    //     let length = profile.count

    //     profile.withUnsafeMutableBufferPointer { buf in
    //         _WebViewSetDeviceColorProfile(reference, buf.baseAddress, length)
    //     }

    // }
    
    // public func resetDeviceColorProfile() {
    //     _WebViewResetDeviceColorProfile(reference)
    // }

    public func enableAutoResizeMode(min: IntSize, max: IntSize) {
        _WebViewEnableAutoResizeMode(reference, Int32(min.width), Int32(min.height), Int32(max.width), Int32(max.height))
    }

    public func disableAutoResizeMode() {
        _WebViewDisableAutoResizeMode(reference)
    }

    public func performMediaPlayerAction(action: WebMediaPlayerAction, location: IntPoint) {
        _WebViewPerformMediaPlayerAction(reference, WebMediaPlayerActionEnum(rawValue: UInt32(action.type.rawValue)), action.enable ? 1 : 0, Int32(location.x), Int32(location.y))
    }

    public func performPluginAction(action: WebPluginAction, location: IntPoint) {
        _WebViewPerformPluginAction(reference, WebPluginActionEnum(rawValue: UInt32(action.type.rawValue)), action.enable ? 1 : 0, Int32(location.x), Int32(location.y))
    }

    public func hitTestResult(at point: IntPoint) -> WebHitTestResult? {
        if let ref = _WebViewHitTestResultAt(reference, Int32(point.x), Int32(point.y)) {
            return WebHitTestResult(reference: ref)
        }
        return nil
    }

    public func hitTestResultForTap(point: IntPoint, area: IntSize) ->  WebHitTestResult?  {
        if let ref = _WebViewHitTestResultForTap(reference, Int32(point.x), Int32(point.y), Int32(area.width), Int32(area.height)) {
            return WebHitTestResult(reference: ref)   
        }
        return nil
    }

    // public func copyImage(at point: IntPoint) {
    //    _WebViewCopyImageAt(reference, Int32(point.x), Int32(point.y))         
    // }

    // public func saveImage(at point: IntPoint) {
    //    _WebViewSaveImageAt(reference, Int32(point.x), Int32(point.y))
    // }

    // public func dragSourceEndedAt(
    //     client: IntPoint, screen: IntPoint,
    //     operation: WebDragOperation) {

    //    _WebViewDragSourceEndedAt(
    //         reference, 
    //         Int32(client.x), 
    //         Int32(client.y), 
    //         Int32(screen.x), 
    //         Int32(screen.y), 
    //         WebDragOperationEnum(rawValue: UInt32(operation.rawValue)))
    // }

    // public func dragSourceSystemDragEnded() {
    //    _WebViewDragSourceSystemDragEnded(reference)
    // }

    // public func dragTargetDragEnter(
    //     data: WebDragData,
    //     client: IntPoint, 
    //     screen: IntPoint,
    //     allowed: WebDragOperationsMask,
    //     modifiers: Int) -> WebDragOperation {
        
    //     let result = _WebViewDragTargetDragEnter(reference, 
    //         data.reference, 
    //         Int32(client.x), 
    //         Int32(client.y), 
    //         Int32(screen.x), 
    //         Int32(screen.y), 
    //         WebDragOperationEnum(rawValue: UInt32(allowed.rawValue)), 
    //         Int32(modifiers))

    //     return WebDragOperation(rawValue: Int(result.rawValue))!
    // }

    // public func dragTargetDragOver(
    //     client: IntPoint, 
    //     screen: IntPoint,
    //     allowed: WebDragOperationsMask,
    //     modifiers: Int) -> WebDragOperation {

    //     let mask = _WebViewDragTargetDragOver(reference, Int32(client.x), Int32(client.y), Int32(screen.x), Int32(screen.y), WebDragOperationEnum(rawValue: UInt32(allowed.rawValue)), Int32(modifiers))
    //     return WebDragOperation(rawValue: Int(mask.rawValue))!
    // }

    // public func dragTargetDragLeave() {
    //     _WebViewDragTargetDragLeave(reference)
    // }

    // public func dragTargetDrop(client: IntPoint, screen: IntPoint, modifiers: Int) {
    //     _WebViewDragTargetDrop(reference, Int32(client.x), Int32(client.y), Int32(screen.x), Int32(screen.y), Int32(modifiers))
    // }

    // public func getSpellingMarkers() -> [UInt32]{
    //     // warning: this is a hardcoded limit 
    //     // (we are trying to avoid to call the C function twice, one for size and other for allocation)
    //     let maxlen = 10000
    //     var buflen: Int = 0
    //     var local: [UInt32] = []
    //     // Grow up the internal buffer to a arbitray maximum
    //     // so the C side can allocate the markers 
    //     local.reserveCapacity(maxlen)

    //     local.withUnsafeMutableBufferPointer { buf in
    //         _WebViewSpellingMarkers(reference, buf.baseAddress, &buflen, maxlen)
    //     }
        
    //     return Array<UInt32>(local[0...buflen])
    //  }

    // public func removeSpellingMarkersUnderWords(words: [String]) {
    //     var cwords: [UnsafePointer<CChar>?] = []

    //     cwords.reserveCapacity(words.count)
        
    //     for word in words {
    //         word.withCString { cstr in
    //             cwords.append(cstr)
    //         }
    //     }

    //     cwords.withUnsafeMutableBufferPointer { buf in
    //         _WebViewRemoveSpellingMarkersUnderWords(reference, buf.baseAddress, words.count)
    //     }
    // }

    public func createUniqueIdentifierForRequest() -> UInt64 {
        return UInt64(_WebViewCreateUniqueIdentifierForRequest(reference))
    }

    public func enableDeviceEmulation(params: WebDeviceEmulationParams) {
        _WebViewEnableDeviceEmulation(reference,
            WebScreenPosition(rawValue: UInt32(params.screenPosition.rawValue)),
            Int32(params.screenSize.width),
            Int32(params.screenSize.height),
            Int32(params.viewPosition.x),
            Int32(params.viewPosition.y),
            params.deviceScaleFactor,
            Int32(params.viewSize.width),
            Int32(params.viewSize.height),
            params.offset.x,
            params.offset.y,
            params.scale)
    }

    public func disableDeviceEmulation() {
        _WebViewDisableDeviceEmulation(reference)
    }

    public func performCustomContextMenuAction(action: UInt) {
        _WebViewPerformCustomContextMenuAction(reference, UInt32(action))
    }

    // public func showContextMenu() {
    //     _WebViewShowContextMenu(reference)
    // }

    // public func extractSmartClipData(initRect r: IntRect, text: String, html: String) -> IntRect {
    //     var rx: Int32 = 0, ry: Int32 = 0, rw: Int32 = 0, rh: Int32 = 0
        
    //     text.withCString { textbuf in
    //      html.withCString { htmlbuf in
    //         _WebViewExtractSmartClipData(reference, Int32(r.x), Int32(r.y), Int32(r.width), Int32(r.height), textbuf, htmlbuf, &rx, &ry, &rw, &rh)
    //      }
    //     }

    //     return IntRect(x: Int(rx), y: Int(ry), width: Int(rw), height: Int(rh))
    // }

    public func hidePopups() {
        _WebViewHidePopups(reference)
    }

    public func setSelectionColors(activeBackgroundColor: Color,
                                   activeForegroundColor: Color,
                                   inactiveBackgroundColor: Color,
                                   inactiveForegroundColor: Color) {
       _WebViewSetSelectionColors(reference, CInt(activeBackgroundColor.value), CInt(activeForegroundColor.value), CInt(inactiveBackgroundColor.value), CInt(inactiveForegroundColor.value))
    }

    // public func transferActiveWheelFlingAnimation(params: WebActiveWheelFlingParameters) {
    //     _WebViewTransferActiveWheelFlingAnimation(reference,
    //         Int32(params.delta.x), 
    //         Int32(params.delta.y),
    //         Int32(params.point.x), 
    //         Int32(params.point.y),
    //         Int32(params.globalPoint.x),
    //         Int32(params.globalPoint.y),
    //         Int32(params.modifiers),
    //         WebGestureDeviceEnum(rawValue: UInt32(params.sourceDevice.rawValue)),
    //         Int32(params.cumulativeScroll.width), 
    //         Int32(params.cumulativeScroll.height),
    //         params.startTime)
    // }

    // public func endActiveFlingAnimation() -> Bool {
    //     return _WebViewEndActiveFlingAnimation(reference) == 0 ? false : true
    // }

    public func setShowPaintRects(show: Bool) {
        _WebViewSetShowPaintRects(reference, show ? 1 : 0)
    }
    
    public func setShowFPSCounter(show: Bool) {
        _WebViewSetShowFPSCounter(reference, show ? 1 : 0)
    }
    
    public func setShowScrollBottleneckRects(show: Bool) {
        _WebViewSetShowScrollBottleneckRects(reference, show ? 1 : 0)
    }

    public func setVisibilityState(visibilityState: WebPageVisibilityState,
                                   isInitialState: Bool) {

      _WebViewSetVisibilityState(reference, WebPageVisibilityStateEnum(rawValue: UInt32(visibilityState.rawValue)), isInitialState ? 1 : 0)
    }

    // public func compositedDisplayList() -> WebCompositedDisplayList? { 
    //   let ref = _WebViewGetCompositedDisplayList(reference)
    //   if ref == nil {
    //     return nil
    //   }
    //   return WebCompositedDisplayList(reference: ref!)
    // }

    public func setPageOverlayColor(color: Color) {
      _WebViewSetPageOverlayColor(reference, color.a, color.r, color.g, color.b)
    }

    public func pageImportanceSignals() -> WebPageImportanceSignals? { 
      let ref = _WebViewGetPageImportanceSignals(reference)
      if ref == nil {
        return nil
      }
      return WebPageImportanceSignals(reference: ref!)
    }

    public func acceptLanguagesChanged() {
       _WebViewAcceptLanguagesChanged(reference)
    }
}

extension WebView : WebWidget {
    
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
    
    // public var textInputInfo: WebTextInputInfo { 
    //      var type: WebTextInputTypeEnum = WebTextInputTypeNone
    //      var flags: Int32 = 0
    //      var selectionStart: Int32 = 0
    //      var selectionEnd: Int32 = 0
    //      var compositionStart: Int32 = 0
    //      var compositionEnd: Int32 = 0
    //      var value: UnsafePointer<Int8>?
    //      var inputMode: UnsafePointer<Int8>?
         
    //      //value.withCString { (valuebuf: UnsafeMutablePointer<CChar>) in
    //      //   inputMode.withCString { (inpubuf: UnsafeMutablePointer<CChar>) in
    //             _WebWidgetTextInputInfo(reference, 
    //                 &type, 
    //                 &flags, 
    //                 &value, 
    //                 &selectionStart, 
    //                 &selectionEnd, 
    //                 &compositionStart, 
    //                 &compositionEnd, 
    //                 &inputMode)
    //      //   }
    //      //}

    //      return WebTextInputInfo(
    //         type: WebTextInputType(rawValue: Int(type.rawValue))!,
    //         flags: Int(flags),
    //         value: String(cString: value!),
    //         selectionStart: Int(selectionStart),
    //         selectionEnd: Int(selectionEnd),
    //         compositionStart: Int(compositionStart),
    //         compositionEnd: Int(compositionEnd),
    //         inputMode: String(cString: inputMode!))
    // }
    
    // public var textInputType: WebTextInputType { 
    //     return WebTextInputType(rawValue: Int(_WebWidgetTextInputType(reference).rawValue))!
    // }
    
    public var isAcceleratedCompositingActive: Bool { 
        return _WebWidgetIsAcceleratedCompositingActive(reference) == 0 ? false : true
    }
    
    // public var isSelectionAnchorFirst: Bool { 
    //     return _WebWidgetIsSelectionAnchorFirst(reference) == 0 ? false : true
    // }

    // TODO: we should probably use a property for this
    public func setFocus(focus: Bool) {
        _WebWidgetSetFocus(reference, focus ? 1 : 0)
    }

    public func close() {
        _WebWidgetClose(reference)
    }

    // public func willStartLiveResize() {
    //     _WebWidgetWillStartLiveResize(reference)
    // }

    public func resize(size: IntSize) {
        _WebWidgetResize(reference, Int32(size.width), Int32(size.height))
    }

    public func resizeVisualViewport(size: IntSize) {
        _WebWidgetResizeVisualViewport(reference, Int32(size.width), Int32(size.height))
    }

    // public func willEndLiveResize() {
    //     _WebWidgetWillEndLiveResize(reference)
    // }

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

    // public func paintCompositedDeprecated(canvas: Canvas, viewport: IntRect) {
    //     _WebWidgetPaintCompositedDeprecated(reference, canvas.reference, Int32(viewport.x), Int32(viewport.y), Int32(viewport.width), Int32(viewport.height))
    // }

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

    public func handleInputEvent(inputEvent: WebInputEvent) -> WebInputEvent.Result {
        return WebInputEvent.Result(rawValue: Int(_WebWidgetHandleInputEvent(reference, inputEvent.reference)))!
    }

    public func setCursorVisibilityState(visible: Bool) {
        _WebWidgetSetCursorVisibilityState(reference, visible ? 1 : 0)
    }

    // public func hasTouchEventHandlers(at p: IntPoint) -> Bool {
    //     return  _WebWidgetHasTouchEventHandlersAt(reference, Int32(p.x), Int32(p.y)) == 0 ? false : true
    // }

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

    // public func recordFrameTimingEvent(eventType: WebFrameTimingEventType, rectId: Int64, events: [WebFrameTimingEvent]) {
        
    //     var sourceFrame: [UInt32] = [] 
    //     var startTime: [Double] = []
    //     var finishTime: [Double] = []

    //     for event in events {
    //         sourceFrame.append(UInt32(event.sourceFrame))
    //         startTime.append(event.startTime)
    //         finishTime.append(event.finishTime)
    //     }
        
    //     sourceFrame.withUnsafeMutableBufferPointer { frameBuf in
    //         startTime.withUnsafeMutableBufferPointer { startBuf in
    //             finishTime.withUnsafeMutableBufferPointer { finishBuf in
    //                 _WebWidgetRecordFrameTimingEvent(reference, 
    //                     WebViewFrameTimingEventEnum(rawValue: UInt32(eventType.rawValue)),
    //                     rectId,
    //                     frameBuf.baseAddress,
    //                     startBuf.baseAddress,
    //                     finishBuf.baseAddress,
    //                     Int32(events.count))
    //             }
    //         }
    //     }
    // }

    public func mouseCaptureLost() {
        _WebWidgetMouseCaptureLost(reference)
    }

    // public func setComposition(
    //     text: String,
    //     underlines: [WebCompositionUnderline],
    //     selectionStart: Int,
    //     selectionEnd: Int) -> Bool {
        
    //     var start = ContiguousArray<UInt32>()
    //     var end = ContiguousArray<UInt32>()
    //     var color = ContiguousArray<UInt32>()
    //     var tick = ContiguousArray<Int32>()
    //     var bg = ContiguousArray<UInt32>()

    //     for underline in underlines {
    //         start.append(UInt32(underline.startOffset))
    //         end.append(UInt32(underline.endOffset))
    //         color.append(UInt32(underline.color.value))
    //         tick.append(underline.tick ? 1 : 0)
    //         bg.append(UInt32(underline.backgroundColor.value))
    //     }

    //     var startPtr: UnsafeMutableBufferPointer<UInt32>?
    //     var endPtr: UnsafeMutableBufferPointer<UInt32>?
    //     var colorPtr: UnsafeMutableBufferPointer<UInt32>?
    //     var tickPtr: UnsafeMutableBufferPointer<Int32>?
    //     var bgPtr: UnsafeMutableBufferPointer<UInt32>?


    //     start.withUnsafeMutableBufferPointer { startPtr = $0}
        
    //     end.withUnsafeMutableBufferPointer { endPtr = $0 }
        
    //     color.withUnsafeMutableBufferPointer { colorPtr = $0 }
        
    //     tick.withUnsafeMutableBufferPointer { tickPtr = $0 }

    //     bg.withUnsafeMutableBufferPointer { bgPtr = $0 }

    //     let result = text.withCString { (textbuf: UnsafePointer<CChar>)-> Bool in
    //         return  _WebWidgetSetComposition(
    //                    reference, 
    //                     textbuf,
    //                     startPtr.baseAddress,
    //                     endPtr.baseAddress,
    //                     colorPtr.baseAddress,
    //                     tickPtr.baseAddress,
    //                     bgPtr.baseAddress,
    //                     Int32(underlines.count), 
    //                     Int32(selectionStart),
    //                     Int32(selectionEnd)) == 0 ? false : true
    //     }

    //     return result      
    // }

    // public func confirmComposition() -> Bool {
    //     return _WebWidgetConfirmComposition(reference) == 0 ? false : true
    // }

    // public func confirmComposition(selectionBehavior: WebConfirmCompositionBehavior) -> Bool {
    //     return _WebWidgetConfirmCompositionConfirm(reference, WebViewConfirmCompositionBehaviorEnum(rawValue: UInt32(selectionBehavior.rawValue))) == 0 ? false : true
    // }

    // public func confirmComposition(text: String) -> Bool {
    //     var result = false
    //     text.withCString { textbuf in
    //         result = _WebWidgetConfirmCompositionText(reference, textbuf) == 0 ? false : true
    //     }
    //     return result
    // }

    // public func compositionRange(location: inout Int, length: inout Int) -> Bool {
    //     var outloc: Int = 0, outlen: Int = 0

    //     let result = _WebWidgetCompositionRange(reference, &outloc, &outlen) == 0 ? false : true
        
    //     location = Int(outloc)
    //     length = Int(outlen)
        
    //     return result
    // }

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

    //public func selectionTextDirection() -> (TextDirection, TextDirection) {
    //    var start: WebTextDirectionEnum = WebTextDirectionDefault, end: WebTextDirectionEnum = WebTextDirectionDefault 
    //    let _ = _WebWidgetSelectionTextDirection(reference, &start, &end) == 0 ? false : true
    //    return (TextDirection(rawValue: Int(start.rawValue))!, TextDirection(rawValue: Int(end.rawValue))!)
    //}

    //public func caretOrSelectionRange(location: inout Int, length: inout Int) -> Bool {
    //    return _WebWidgetCaretOrSelectionRange(reference, &location, &length) == 0 ? false : true   
    //}

    //public func setTextDirection(direction: TextDirection) {
    //    _WebWidgetSetTextDirection(reference,  WebTextDirectionEnum(rawValue: UInt32(direction.rawValue)))
    //}

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

    //public func didChangeWindowResizerRect() {
    //    _WebWidgetDidChangeWindowResizerRect(reference)
    //}

    //public func setTopControlsHeight(height: Float, topControlsShrinkLayoutSize: Bool) {
    //    _WebWidgetSetTopControlsHeight(reference, height, topControlsShrinkLayoutSize ? 1 : 0)
    //}

    //public func updateTopControlsState(constraints: WebTopControlsState, current: WebTopControlsState, animate: Bool) {
    //    _WebWidgetUpdateTopControlsState(reference, WebTopControlsStateEnum(rawValue: UInt32(constraints.rawValue)), WebTopControlsStateEnum(rawValue: UInt32(current.rawValue)), animate ? 1 : 0)
    //}
}