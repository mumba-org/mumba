// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import MumbaShims

public typealias WebCompositeAndReadbackAsyncCallback = () -> Void
public typealias WebLayoutAndPaintAsyncCallback = () -> Void

public typealias WebCompositorAnimationPlayerClient = Int

public struct WebCompositorAnimationTimeline {
    
    public var animationTimeline: AnimationTimeline

    public init(animationTimeline: AnimationTimeline) {
      self.animationTimeline = animationTimeline
    }

    public func playerAttached(client: WebCompositorAnimationPlayerClient) {}
    public func playerDestroyed(client: WebCompositorAnimationPlayerClient) {}  
}


public struct WebScrollBlocksOn : OptionSet {
    
    static let None = WebScrollBlocksOn(rawValue: 0x0)
    static let StartTouch = WebScrollBlocksOn(rawValue: 0x1)
    static let WheelEvent = WebScrollBlocksOn(rawValue: 0x2)
    static let ScrollEvent = WebScrollBlocksOn(rawValue: 0x4)

    public var rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }
}

public struct WebLayerPositionConstraint {
    public var isFixedPosition: Bool
    public var isFixedToRightEdge: Bool
    public var isFixedToBottomEdge: Bool 
}

public protocol WebLayerScrollClient {
    func didScroll()
}
 
public protocol WebLayerTreeView : class {

    var viewportSize: IntSize { get }
    var deviceScaleFactor: Float { get }
    var backgroundColor: Color { get set}
    var isVisible: Bool { get set }
    var layerTreeId: Int { get }
    var hasPendingPageScaleAnimation: Bool { get }
    var frameSinkId: FrameSinkId? { get }
    var haveScrollEventHandlers: Bool { get set }
    //var showFPSCounter: Bool { get }
    //var showPaintRects: Bool { get }    
    //var showDebugBorders: Bool { get }
    //var showScrollBottleneckRects: Bool { get }
    var compositorAnimationHost: AnimationHost? { get }
    var layerTreeSettings: LayerTreeSettings { get }
   
    // return a unretained reference of itself to pass back to C code
    var unretainedReference: UnsafeMutableRawPointer? { get }
    func createLayerTreeViewCallbacks() -> WebLayerTreeViewCbs
    func setRootLayer(_ layer: Layer)
    func clearRootLayer()
    func setPageScaleFactorAndLimits(scaleFactor: Float, minimum: Float, maximum: Float)
    func startPageScaleAnimation(destination: IntPoint, useAnchor: Bool, newPageScale: Float, duration: Double)
    func heuristicsForGpuRasterizationUpdated(heuristics: Bool)
    func setBrowserControlsShownRatio(ratio: Float)
    func updateBrowserControlsState(constraints: InputTopControlsState, current: InputTopControlsState, animate: Bool)
    func setBrowserControlsHeight(topHeight: Float, bottomHeight: Float, shrinkViewport: Bool)
    func setNeedsBeginFrame()
    func setOverscrollBehavior(behavior: OverscrollBehavior)
    func didStopFlinging()
    //func layoutAndPaintAsync(_: @escaping () -> Void)
    func layoutAndPaintAsync(callbackState: UnsafeMutableRawPointer?, callback: (@convention(c) (UnsafeMutableRawPointer?) -> Void)?)
    func compositeAndReadbackAsync(_: @escaping (_: Bitmap) -> Void)
    func synchronouslyCompositeNoRasterForTesting()
    func compositeWithRasterForTesting()
    func setDeferCommits(deferCommits: Bool)
    func registerViewportLayers(
        overscrollElasticityLayer: Compositor.Layer?,
        pageScaleLayer: Compositor.Layer?,
        innerViewportContainerLayer: Compositor.Layer?,
        outerViewportContainerLayer: Compositor.Layer?,
        innerViewportScrollLayer: Compositor.Layer?,
        outerViewportScrollLayer: Compositor.Layer?)
    func clearViewportLayers()
    func registerSelection(selection: LayerSelection)
    func clearSelection()
    func setMutatorClient(_ client: Compositor.LayerTreeMutator)
    func forceRecalculateRasterScales()
    func requestDecode(image: ImageSkia, callback: @escaping (_: Bool) -> Void)
    func requestBeginMainFrameNotExpected(newState: Bool)
    func updateEventRectsForSubframeIfNecessary()
    func notifySwapTime(_: @escaping (_: Bool, _: DidNotSwapReason, _: Double) -> Void)
    func withUnretainedReference(_: (_: UnsafeMutableRawPointer?) -> Void)
    func setEventListenerProperties(_: EventListenerClass, _: EventListenerProperties)
    //func eventListenerProperties(_: WebEventListenerClass) -> WebEventListenerProperties 
    func requestNewLocalSurfaceId()
    //func didNavigate()
    func clearCachesOnNextCommit()
}

//public class WebLayerClient {}

// extension WebLayerClient : LayerClient {
  
//   public var fillsBoundsCompletely: Bool {
    
//     get {
//         return false
//     }

//     set {

//     }
//   }

//   public var paintableRegion: IntRect {
//     return IntRect()
//   }

//   public func paintLayer(
//     displayList: DisplayItemList,
//     clip: IntRect,
//     paintingStatus: PaintingControlSetting) {

//   }

//   public func paintContentsToDisplayList(paintingStatus: Compositor.PaintingControlSetting) -> Graphics.DisplayItemList {
//     return Graphics.DisplayItemList()
//   }

//   public func prepareTransferableResource(bitmapRegistrar: Compositor.TextureLayer, transferableResource: Compositor.TransferableResource, releaseCallback: inout SingleReleaseCallback?) -> Bool {
//     return false
//   }

//   public func prepareTextureMailbox(
//       mailbox: inout TextureMailbox,
//       releaseCallback: inout SingleReleaseCallback,
//       useSharedMemory: Bool) -> Bool {
//     return false
//   }

//   public func getApproximateUnsharedMemoryUsage() -> Int {
//     return 0
//   }

// }

// public struct WebLayer {
    
//     public typealias FrameTimingRequest = (Int64, IntRect)

//     public var id: Int {
//         return Int(cclayer.id)
//     }

//     public var bounds: IntSize { 
    
//         get {
//             return cclayer.bounds
//         } 
    
//         set {
//             cclayer.bounds = newValue
//         } 
//     }
    
//     public var masksToBounds: Bool { 
    
//         get {
//             return cclayer.masksToBounds
//         } 
    
//         set {
//             cclayer.masksToBounds = newValue
//         } 
//     }
    
//     public var maskLayer: WebLayer? { 
    
//         get {
//             if let mask = cclayer.maskLayer {
//                 return WebLayer(layer: mask)
//             }
//             return nil
//         } 
    
//         set {
//             if let layer = newValue {
//                 cclayer.maskLayer = layer.cclayer
//             }
//         } 
//     }
    
//     public var replicaLayer: WebLayer? { 
    
//         get {
//             return nil
//         } 

//         set {

//         } 
    
//     }
    
//     public var isOpaque: Bool { 
    
//         get {
//             return false
//         } 

//         set {

//         } 
    
//     }
    
//     public var opacity: Float { 
    
//         get {
//             return 0
//         } 
    
//         set {

//         } 
//     }
    
//     public var blendMode: BlendMode { 
        
//         get {
//             return .SrcOver
//         } 
        
//         set {

//         } 
//     }
    
//     public var isRootForIsolatedGroup: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var position: FloatPoint { 
        
//         get {
//             return FloatPoint()
//         } 
        
//         set {

//         } 
//     }   
    
//     public var transform: Transform { 
        
//         get {
//             return Transform()
//         } 
        
//         set {

//         } 
//     }
    
//     public var transformOrigin: IntPoint3 { 
        
//         get {
//             return IntPoint3()
//         } 
        
//         set {

//         } 
//     }
    
//     public var drawsContent: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var backgroundColor: Color { 
        
//         get {
//             return Color.Black
//         } 
        
//         set {

//         } 
//     }
    
//     public var hasActiveAnimation: Bool {
//         return false
//     }
    
//     public var isOrphan: Bool {
//         return false
//     }
    
//     public var filters: FilterOperations { 
    
//         get {
//             return FilterOperations()
//         } 
    
//         set {

//         } 
//     }
    
//     public var backgroundFilters: FilterOperations { 
        
//         get {
//             return FilterOperations()
//         } 
        
//         set {

//         } 
//     }
    
//     public var useParentBackfaceVisibility: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var shouldFlattenTransform: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var renderingContext: Int { 
        
//         get {
//             return 0
//         } 
        
//         set {

//         } 
//     }
    
//     public var animationDelegate:  WebCompositorAnimationDelegate? { 
        
//         get {
//             return nil
//         } 
        
//         set {

//         } 
//     }
    
//     public var scrollPositionDouble: FloatPoint { 
        
//         get {
//             return FloatPoint()
//         } 

//         set {

//         } 
//     }
    
//     public var haveWheelEventHandlers: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 

//     }
    
//     public var haveScrollEventHandlers: Bool { 
        
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var shouldScrollOnMainThread: Bool { 
//         get {
//             return false
//         } 
        
//         set {

//         } 
//     }
    
//     public var nonFastScrollableRegion: [IntRect] { 
        
//         get {
//             return []
//         } 
        
//         set {

//         } 
//     }
    
//     public var touchEventHandlerRegion: [IntRect] { 
    
//         get {
//             return []
//         } 
        
//         set {

//         } 
//     }
    
//     public var scrolllable: Bool { 
//         return false
//     }
    
//     public var userScrollableHorizontal: Bool {
//         return false
//     }
    
//     public var userScrollableVertical: Bool {
//         return false
//     }  
    
//     public var frameTimingRequests: [FrameTimingRequest] { 
        
//         get {
//             return []
//         } 

//         set {

//         } 
//     }
    
//     public var scrollBlocksOn: WebScrollBlocksOn { 
    
//         get {
//             return WebScrollBlocksOn.None
//         } 
//         set {

//         } 
//     }
    
//     public var isContainerForFixedPositionLayers: Bool { 
//         get {
//             return false
//         } 
//         set {

//         } 
//     }
    
//     public var positionConstraint: WebLayerPositionConstraint { 
//         get {
//             return WebLayerPositionConstraint(isFixedPosition: false, isFixedToRightEdge: false, isFixedToBottomEdge: false)
//         } 
//         set {

//         } 
//     }

//     var cclayer: Layer

//     public init() throws {
//         let settings = LayerSettings(type: .None)
//         let client = WebLayerClient()
//         try cclayer = Layer(settings: settings, client: client)
//     }

//     public init(layer: Layer) {
//         cclayer = layer
//     }

//     public func invalidateRect(rect: IntRect) {

//     }
    
//     public func invalidate() {

//     }
    
//     public func addChild(_ child: WebLayer) {

//     }
    
//     public func insertChild(_ child: WebLayer, at: Int) {

//     }
    
//     public func replaceChild(_ child: WebLayer, with: WebLayer) {

//     }
    
//     public func removeFromParent() {

//     }
    
//     public func removeAllChildren() {

//     }
    
//     public func addAnimation(animation: WebCompositorAnimation) -> Bool {
//         return false
//     }
    
//     public func removeAnimation(id: Int) {

//     }
    
//     public func removeAnimation(id: Int, property: WebAnimationTargetProperty) {

//     }
    
//     public func pauseAnimation(id: Int, timeOffset: Double) {

//     }
    
//     public func setScrollParent(parent: WebLayer) {

//     }
    
//     public func setClipParent(parent: WebLayer) {

//     }
    
//     public func setScrollClient(client: WebLayerScrollClient) {

//     }
    
//     public func setForceRenderSurface(force: Bool) {

//     }
    
//     public func setUserScrollable(horizontal: Bool, vertical: Bool) {

//     }
    
//     public func setScrollCompensationAdjustment(point: FloatPoint) {

//     }
    
//     public func setScrollClipLayer(layer: WebLayer) {

//     }
// }