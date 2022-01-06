// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Foundation
import Base
import Gpu
import MumbaShims

public enum ScrollbarAnimator {
 case NoAnimator
 case LinearFade
 case Thining
}

public enum EventListenerClass : Int {
  case TouchStartOrMove = 0
  case MouseWheel
  case TouchEndOrCancel
}

public enum EventListenerProperties : Int {
  case None = 0
  case Passive
  case Blocking
  case BlockingAndPassive
}


public struct LayerTreeDebugState {
  public var showFPSCounter: Bool = false
  public var showPaintRects: Bool = false
  public var showDebugBorders: Bool = false
  public var showTouchEventHandlerRects: Bool = false
  public var showWheelEventHandlerRects: Bool = false
  public var showNonFastScrollableRects: Bool = false
  public var rasterizeOnlyVisibleContent: Bool = false
}

public struct ManagedMemoryPolicy {
  public var bytesLimitWhenVisible: Int = 512 * 1000 * 1000
  public var priorityCutoffWhenVisible: PriorityCutoff = PriorityCutoff.allowEverything
  public var numResourcesLimit: Int = 10 * 1000 * 1000

  public init() {}

  public init(bytesLimitWhenVisible: Int) {
    self.bytesLimitWhenVisible = bytesLimitWhenVisible
  }
}

public struct LayerTreeSettings {
  public var singleThreadProxyScheduler: Bool = true
  public var mainFrameBeforeActivationEnabled: Bool = false
  public var usingSynchronousRendererCompositor: Bool = false
  public var enableEarlyDamageCheck: Bool = false
  public var damagedFrameLimit: Int = 3
  public var enableLatencyRecovery: Bool = true
  public var canUseLcdText: Bool = true
  public var gpuRasterizationForced: Bool = false
  public var gpuRasterizationMsaaSampleCount: Int = 0
  public var gpuRasterizationSkewportTargetTimeInSeconds: Float = 0.2
  public var createLowResTiling: Bool = false
  public var useStreamVideoDrawQuad: Bool = false
  public var scrollbarFadeDelay: TimeDelta = TimeDelta()
  public var scrollbarFadeDuration: TimeDelta = TimeDelta()
  public var scrollbarThinningDuration: TimeDelta = TimeDelta()
  public var scrollbarFlashAfterAnyScrollUpdate: Bool = false
  public var scrollbarFlashWhenMouseEnter: Bool = false
  public var solidColorScrollbarColor: Color?
  public var timeoutAndDrawWhenAnimationCheckerboards: Bool = true
  public var layerTransformsShouldScaleLayerContents: Bool = false
  public var layersAlwaysAllowedLcdText: Bool = false
  public var minimumContentsScale: Float = 0.0625
  public var lowResContentsScaleFactor: Float = 0.25
  public var topControlsShowThreshold: Float = 0.5
  public var topControlsHideThreshold: Float = 0.5
  public var backgroundAnimationRate: Double = 1.0
  public var defaultTileSize: IntSize = IntSize()
  public var maxUntiledLayerSize: IntSize = IntSize()
  public var maxGpuRasterTileSize: IntSize = IntSize()
  public var minimumOcclusionTrackingSize: IntSize = IntSize()
  public var tilingInterestAreaPadding: Int = 3000
  public var skewportTargetTimeInSeconds: Float = 1.0
  public var skewportExtrapolationLimitInScreenPixels: Int = 2000
  public var maxMemoryForPrepaintPercentage: Int = 100
  public var useZeroCopy: Bool = false
  public var usePartialRaster: Bool = false
  public var enableElasticOverscroll: Bool = false
  public var ignoreRootLayerFlings: Bool = false
  public var scheduledTasterTaskLimit: Int = 32
  public var useOcclusionForTilePrioritization: Bool = false
  public var useLayerLists: Bool = false
  public var maxStagingBufferUsageInBytes: Int = 32 * 1024 * 1024
  public var memoryPolicy: ManagedMemoryPolicy = ManagedMemoryPolicy()
  public var decodedImageWorkingSetBudgetBytes: Int = 128 * 1024 * 1024
  public var maxPrerasterDistanceInScreenPixels: Int = 1000
  public var useRgba4444: Bool = false
  public var unpremultiplyAndDitherLowBitDepthTiles: Bool = false
  public var enableMaskTiling: Bool = true
  public var enableCheckerImaging: Bool = false
  public var minImageBytesToChecker = 1 * 1024 * 1024  // 1MB.
  public var onlyCheckerImagesWithGpuRaster: Bool = false
  public var enableSurfaceSynchronization: Bool = false
  public var isLayerTreeForSubframe: Bool = false 
  public var disallowNonExactResourceReuse: Bool = false
  public var waitForAllPipelineStagesBeforeDraw: Bool = false
  public var commitToActiveTree: Bool = true
  public var enableOopRasterization: Bool = false
  public var enableImageAnimationResync: Bool = true
  public var enableEdgeAntiAliasing: Bool = true
  public var alwaysRequestPresentationTime: Bool = false
  public var usePaintedDeviceScaleFactor: Bool = false

  public init() {}
}

public enum LayerTreeType : Int32 {
 case Active = 0
 case Pending = 1
}

public protocol QueueImageDecodeHandlerDelegate : class {
  func onDone(handler: QueueImageDecodeHandler)
}

public class QueueImageDecodeHandler {
  
  private var callback: (_: Bool) -> Void  
  
  private weak var delegate: QueueImageDecodeHandlerDelegate!
  
  public init(delegate: QueueImageDecodeHandlerDelegate, callback: @escaping (_: Bool) -> Void) {
    self.delegate = delegate
    self.callback = callback
  }

  public func onImageDecode(result: Bool) {
    callback(result)
    delegate.onDone(handler: self)
  }
}

public protocol NewLayerTreeFrameSinkHandlerDelegate : class {
  func onDone(handler: NewLayerTreeFrameSinkHandler)
}

public class NewLayerTreeFrameSinkHandler {
  
  private var callback: () -> Void  
  
  private weak var delegate: NewLayerTreeFrameSinkHandlerDelegate!
  
  public init(delegate: NewLayerTreeFrameSinkHandlerDelegate, callback: @escaping () -> Void) {
    self.delegate = delegate
    self.callback = callback
  }

  public func onNewLayerTreeFrameSink() {
    callback()
    delegate.onDone(handler: self)
  }
}

public class LayerTreeHost {

  public struct InitParams {
    public var settings: LayerTreeSettings = LayerTreeSettings()
    public var animationHost: AnimationHost?
    public var mainTaskRunner: SingleThreadTaskRunner?
    public var client: LayerTreeHostSingleThreadClient?
    //public var sharedBitmapManager: SharedBitmapManager?
    //public var gpuMemoryBufferManager: GpuMemoryBufferManager?
    //public var taskGraphRunner: TaskGraphRunner?
    public var isSingleThreaded: Bool = false

    public init() {}
  }

  private(set) public var client: LayerTreeHostSingleThreadClient?

  public var debugState: LayerTreeDebugState = LayerTreeDebugState()
  public var inputHandler: InputHandler?
  public var settings: LayerTreeSettings = LayerTreeSettings()

  public var id: Int {
    return Int(_LayerTreeHostId(reference))
  }

  public var viewportSize: IntSize {
    //get {
      var width: Int32 = 0
      var height: Int32 = 0
      _LayerTreeHostDeviceViewportSize(reference, &width, &height)
      return IntSize(width: Int(width), height: Int(height))
    //}
    // set (size) {
    //   _LayerTreeHostSetViewportSize(reference, Int32(size.width), Int32(size.height))
    // }
  }

  public var isVisible: Bool {
   get {
    return Bool(_LayerTreeHostIsVisible(reference))
   }
   set {
    _LayerTreeHostSetVisible(reference, newValue.intValue)
   }
  }

  public var rootLayer: Layer? {
   get {
    let layer = _LayerTreeHostRootLayer(reference)
    if layer == nil {
     return nil
    }
    return Layer(reference: layer!)
   }
   set {
    guard let layer = newValue else {
      _LayerTreeHostClearRootLayer(reference)
      return
    }
    _LayerTreeHostSetRootLayer(reference, layer.reference)
   }
  }

  public var overscrollElasticityLayer: Layer? {
   let layer = _LayerTreeHostOverscrollElasticityLayer(reference)
   if layer == nil {
    return nil
   }
   return Layer(reference: layer!)
  }

  public var haveScrollEventHandlers: Bool {
    get {
      return _LayerTreeHostGetHaveScrollEventHandlers(reference) != 0
    } 
    set {
      _LayerTreeHostSetHaveScrollEventHandlers(reference, newValue ? 1 : 0)
    }
  }

  public var pageScaleLayer: Layer? {
    let layer = _LayerTreeHostPageScaleLayer(reference)
    if layer == nil {
      return nil
    }
    return Layer(reference: layer!)
  }

  public var innerViewportScrollLayer: Layer? {
    let layer = _LayerTreeHostInnerViewportScrollLayer(reference)
    if layer == nil {
      return nil
    }
    return Layer(reference: layer!)
  }

  public var outerViewportScrollLayer: Layer? {
    let layer = _LayerTreeHostOuterViewportScrollLayer(reference)
    if layer == nil {
      return nil
    }
    return Layer(reference: layer!)
  }

  public var hasGpuRasterizationTrigger: Bool {
    get {
      return Bool(_LayerTreeHostHasGpuRasterizationTrigger(reference))
    }
    set {
      _LayerTreeHostSetHasGpuRasterizationTrigger(reference, newValue.intValue)
    }
  }

  public var backgroundColor: Color {
    get {
      var a: UInt8 = 0, r: UInt8 = 0, g: UInt8 = 0, b: UInt8 = 0
      _LayerTreeHostBackgroundColor(reference, &a, &r, &g, &b)
      return Color(a: a, r: r, g: g, b: b)
    }
    set(color) {
      _LayerTreeHostSetBackgroundColor(reference, color.a, color.r, color.g, color.b)
    }
  }

  public var pageScaleFactor: Float {
    return _LayerTreeHostPageScaleFactor(reference)
  }

  public var hasPendingPageScaleAnimation: Bool {
    return _LayerTreeHostHasPendingPageScaleAnimation(reference) != 0 
  }

  public var elasticOverscroll: FloatVec2 {
    var x: Float = 0, y: Float = 0
    _LayerTreeHostElasticOverscroll(reference, &x , &y)
    return FloatVec2(x: x, y: y)
  }

  public var propertyTrees: PropertyTrees? {
    let property = _LayerTreeHostPropertyTrees(reference)
    if property == nil {
        return nil
    }
    return PropertyTrees(reference: property!)
  }

  public var localSurfaceId: LocalSurfaceId {
    get {
      var p: UInt32 = 0
      var c: UInt32 = 0
      var h: UInt64 = 0
      var l: UInt64 = 0
      _LayerTreeHostGetLocalSurfaceId(reference, &p, &c, &h, &l)
      return LocalSurfaceId(parent: p, child: c, token: UnguessableToken(high: h, low: l))
    }
    set {
      _LayerTreeHostSetLocalSurfaceId(
        reference, 
        newValue.parentSequenceNumber,
        newValue.childSequenceNumber,
        newValue.token.high,
        newValue.token.low)
    }
  }

  //public var rasterColorSpace: ColorSpace {
//    get {
      //var type: CInt = 0
      //_LayerTreeHostGetRasterColorSpace(
//        reference, &type)
      //assert(type == 0)
      //return ColorSpace.createSRGB()
    //}
    //set {
//      let type: CInt = 0 // SRGB
  //    _LayerTreeHostSetRasterColorSpace(
        //reference, 
        //type)
    //}
  //}

  public var deviceViewportSize: IntSize {
    var w: CInt = 0
    var h: CInt = 0
    _LayerTreeHostGetDeviceViewportSize(reference, &w, &h)
    return IntSize(width: Int(w), height: Int(h))
  }

  public var recordingScaleFactor: Float {
    get {
      return _LayerTreeHostGetRecordingScaleFactor(reference)
    } 
    set {
      _LayerTreeHostSetRecordingScaleFactor(reference, newValue)
    }
  }

  public var sourceFrameNumber: Int {
    return Int(_LayerTreeHostSourceFrameNumber(reference))
  }

  public var deviceScaleFactor: Float {
    //get {
    return _LayerTreeHostDeviceScaleFactor(reference)
    //}
    // set (scale) {
    //   _LayerTreeHostSetDeviceScaleFactor(reference, scale)
    // }
  }

  public var viewportVisibleRect: IntRect {
    get {
      var x: CInt = 0
      var y: CInt = 0
      var w: CInt = 0
      var h: CInt = 0      
      _LayerTreeHostGetViewportVisibleRect(reference, &x, &y, &w, &h)
      return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
    }
    set {
      _LayerTreeHostSetViewportVisibleRect(reference, CInt(newValue.x), CInt(newValue.y), CInt(newValue.width), CInt(newValue.height))
    }
  }

  // public var animationRegistrar: AnimationRegistrar? {
  //   let registrar = _LayerTreeHostAnimationRegistrar(reference)
  //   if registrar == nil {
  //     return nil
  //   }
  //   return AnimationRegistrar(reference: registrar!)
  // }

  // public var animationHost: AnimationHost? {
  //   let host = _LayerTreeHostAnimationHost(reference)
  //   if host == nil {
  //     return nil
  //   }
  //   return AnimationHost(reference: host!)
  // }

  public var animationHost: AnimationHost?

  public var inPaintLayerContents: Bool {
    return Bool(_LayerTreeHostInPaintLayerContents(reference))
  }

  private var requestPresentationTimeCallback: Optional<(_: TimeTicks, _: TimeDelta, _: UInt32) -> Void>

  // public var usingSharedMemoryResources: Bool {
  //   return Bool(_LayerTreeHostUsingSharedMemoryResources(reference))
  // }

  // public var needsMetaInfoRecomputation: Bool {
  //   return Bool(_LayerTreeHostNeedsMetaInfoRecomputation(reference))
  // }

  // public var hasTransparentBackground: Bool {
  //   //get {
  //   return _hasTransparentBackground
  //   //}
  //   //set {
  //  //   _hasTransparentBackground = newValue
  //  //   _LayerTreeHostSetHasTransparentBackground(reference, newValue ? 1 : 0)
  //  // }
  // }

  public var reference: LayerTreeHostRef!
  var isWeak: Bool = false

  private var queueImageDecodeHandlers: ContiguousArray<QueueImageDecodeHandler> = ContiguousArray<QueueImageDecodeHandler>()
  private var newLayerTreeFrameSinkHandlers: ContiguousArray<NewLayerTreeFrameSinkHandler> = ContiguousArray<NewLayerTreeFrameSinkHandler>()

  public init(params: InitParams) {//throws {

    guard params.client != nil else {
     //print("LayerTreeHost construction: params.client is null. failed")
     return 
     //throw CompositorError.OnCreateLayerTreeHost(exception: CompositorException.ClientMissing)
    }

    guard let animHost = params.animationHost else {
      //print("LayerTreeHost construction: params.animationHost is null. failed")
     
      return
      //throw CompositorError.OnCreateLayerTreeHost(exception: CompositorException.AnimationHostMissing)
    }

    var callbacks = CLayerTreeHostSingleThreadClientCbs()

    // cc::LayerTreeHostClient

    callbacks.willBeginMainFrame = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.willBeginMainFrame()
    }

    callbacks.beginMainFrame = { (clientHandle: UnsafeMutableRawPointer?, 
      sourceId: UInt64,
      sequenceNumber: UInt64,
      frameTime: Int64, 
      deadline: Int64, 
      interval: Int64) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      var args = BeginFrameArgs()
      args.sourceId = sourceId
      args.sequenceNumber = sequenceNumber
      args.frameTime = TimeTicks(microseconds: frameTime)
      args.deadline = TimeTicks(microseconds: deadline)
      args.interval = TimeDelta(microseconds: interval)
      p.client!.beginMainFrame(args: args)
    }

    callbacks.beginMainFrameNotExpectedSoon = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.beginMainFrameNotExpectedSoon()
    }

    callbacks.beginMainFrameNotExpectedUntil = { (clientHandle: UnsafeMutableRawPointer?, time: Int64) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.beginMainFrameNotExpectedUntil(time: TimeTicks(microseconds: time))
    }

    callbacks.didBeginMainFrame = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didBeginMainFrame()
    }

    callbacks.updateLayerTreeHost = { (clientHandle: UnsafeMutableRawPointer?, update: Int32) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.updateLayerTreeHost(requestedUpdate: toVisualStateUpdate(update))
    }

    callbacks.applyViewportDeltas = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      // WOW: we need to fix this and pass the actual values
      p.client!.applyViewportDeltas(
            innerDelta: FloatVec2(),
            outerDelta: FloatVec2(),
            elasticOverscrollDelta: FloatVec2(),
            pageScale: 0,
            topControlsDelta: 0)
    }
    
    callbacks.requestNewLayerTreeFrameSink = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.requestNewLayerTreeFrameSink()
    }

    callbacks.didInitializeLayerTreeFrameSink = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didInitializeLayerTreeFrameSink()
    }

    callbacks.didFailToInitializeLayerTreeFrameSink = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didFailToInitializeLayerTreeFrameSink()
    }
    
    callbacks.willCommit = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.willCommit()
    }

    callbacks.didCommit = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didCommit()
    }

    callbacks.didCommitAndDrawFrame = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didCommitAndDrawFrame()
    }

    callbacks.didReceiveCompositorFrameAck = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didReceiveCompositorFrameAck()
    }

    callbacks.didCompletePageScaleAnimation = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didCompletePageScaleAnimation()
    }

    callbacks.isForSubframe = { (clientHandle: UnsafeMutableRawPointer?) -> Int32 in
      guard clientHandle != nil else {
        return 0
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      return p.client!.isForSubframe ? 1 : 0
    }

    // cc::LayerTreeHostSingleThreadClient
    callbacks.didSubmitCompositorFrame = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didSubmitCompositorFrame()
    }

    callbacks.didLoseLayerTreeFrameSink = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.didLoseLayerTreeFrameSink()
    }

    callbacks.requestScheduleComposite = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.requestScheduleComposite()
    }

    callbacks.requestScheduleAnimation = { (clientHandle: UnsafeMutableRawPointer?) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      p.client!.requestScheduleAnimation()
    }
    
    self.client = params.client
    self.settings = params.settings
    self.debugState = LayerTreeDebugState()
   // _hasTransparentBackground = false
    self.animationHost = animHost

    let scrollbarColorA: UInt8 = self.settings.solidColorScrollbarColor != nil ? self.settings.solidColorScrollbarColor!.a : 255
    let scrollbarColorR: UInt8 = self.settings.solidColorScrollbarColor != nil ? self.settings.solidColorScrollbarColor!.r : 255
    let scrollbarColorG: UInt8 = self.settings.solidColorScrollbarColor != nil ? self.settings.solidColorScrollbarColor!.g : 255
    let scrollbarColorB: UInt8 = self.settings.solidColorScrollbarColor != nil ? self.settings.solidColorScrollbarColor!.b : 255
    
    let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    let ptr = _LayerTreeHostCreate(
      selfptr,
      animHost.reference, 
      callbacks,
      params.isSingleThreaded ? 1 : 0,
      params.settings.singleThreadProxyScheduler ? 1 : 0,
      params.settings.mainFrameBeforeActivationEnabled ? 1 : 0,
      params.settings.usingSynchronousRendererCompositor ? 1 : 0,
      params.settings.enableEarlyDamageCheck ? 1 : 0,
      CInt(params.settings.damagedFrameLimit),
      params.settings.enableLatencyRecovery ? 1 : 0,
      params.settings.canUseLcdText ? 1 : 0,
      params.settings.gpuRasterizationForced ? 1 : 0,
      CInt(params.settings.gpuRasterizationMsaaSampleCount),
      params.settings.gpuRasterizationSkewportTargetTimeInSeconds,
      params.settings.createLowResTiling ? 1 : 0,
      params.settings.useStreamVideoDrawQuad ? 1 : 0,
      params.settings.scrollbarFadeDelay.microseconds,
      params.settings.scrollbarFadeDuration.microseconds,
      params.settings.scrollbarThinningDuration.microseconds,
      params.settings.scrollbarFlashAfterAnyScrollUpdate ? 1 : 0,
      params.settings.scrollbarFlashWhenMouseEnter ? 1 : 0,
      scrollbarColorA,
      scrollbarColorR,
      scrollbarColorG,
      scrollbarColorB,
      params.settings.timeoutAndDrawWhenAnimationCheckerboards ? 1 : 0,
      params.settings.layerTransformsShouldScaleLayerContents ? 1 : 0,
      params.settings.layersAlwaysAllowedLcdText ? 1 : 0,
      params.settings.minimumContentsScale,
      params.settings.lowResContentsScaleFactor,
      params.settings.topControlsShowThreshold,
      params.settings.topControlsHideThreshold,
      params.settings.backgroundAnimationRate,
      CInt(params.settings.defaultTileSize.width),
      CInt(params.settings.defaultTileSize.height),
      CInt(params.settings.maxUntiledLayerSize.width),
      CInt(params.settings.maxUntiledLayerSize.height),
      CInt(params.settings.maxGpuRasterTileSize.width),
      CInt(params.settings.maxGpuRasterTileSize.height),
      CInt(params.settings.minimumOcclusionTrackingSize.width),
      CInt(params.settings.minimumOcclusionTrackingSize.height),
      CInt(params.settings.tilingInterestAreaPadding),
      params.settings.skewportTargetTimeInSeconds,
      CInt(params.settings.skewportExtrapolationLimitInScreenPixels),
      CInt(params.settings.maxMemoryForPrepaintPercentage),
      params.settings.useZeroCopy ? 1 : 0,
      params.settings.usePartialRaster ? 1 : 0,
      params.settings.enableElasticOverscroll ? 1 : 0,
      params.settings.ignoreRootLayerFlings ? 1 : 0,
      CInt(params.settings.scheduledTasterTaskLimit),
      params.settings.useOcclusionForTilePrioritization ? 1 : 0,
      params.settings.useLayerLists ? 1 : 0,
      CInt(params.settings.maxStagingBufferUsageInBytes),
      CInt(settings.memoryPolicy.bytesLimitWhenVisible),
      CInt(settings.memoryPolicy.priorityCutoffWhenVisible.rawValue),
      CInt(params.settings.decodedImageWorkingSetBudgetBytes),
      CInt(params.settings.maxPrerasterDistanceInScreenPixels),
      params.settings.useRgba4444 ? 1 : 0,
      params.settings.unpremultiplyAndDitherLowBitDepthTiles ? 1 : 0,
      params.settings.enableMaskTiling ? 1 : 0,
      params.settings.enableCheckerImaging ? 1 : 0,
      CInt(params.settings.minImageBytesToChecker),
      params.settings.onlyCheckerImagesWithGpuRaster ? 1 : 0,
      params.settings.enableSurfaceSynchronization ? 1 : 0,
      params.settings.isLayerTreeForSubframe ? 1 : 0,
      params.settings.disallowNonExactResourceReuse ? 1 : 0,
      params.settings.waitForAllPipelineStagesBeforeDraw ? 1 : 0,
      params.settings.commitToActiveTree ? 1 : 0,
      params.settings.enableOopRasterization ? 1 : 0,
      params.settings.enableImageAnimationResync ? 1 : 0,
      params.settings.enableEdgeAntiAliasing ? 1 : 0,
      params.settings.alwaysRequestPresentationTime ? 1 : 0,
      params.settings.usePaintedDeviceScaleFactor ? 1 : 0)
    
    if ptr == nil {
      //print("LayerTreeHost construction: error while creating native handle. failed")
      return
      //throw CompositorError.OnCreateLayerTreeHost(exception: CompositorException.NativeLayerTreeHost)
    }

    self.reference = ptr!
  }

  public init(reference: LayerTreeHostRef, isWeak: Bool = false) {
    self.reference = reference
    self.isWeak = isWeak
    debugState = LayerTreeDebugState()
    // TODO: We need to reflect the real settings of the LayerTree we are
    //       hosting here
    settings = LayerTreeSettings()
  }

  deinit {
    if !isWeak {
      _LayerTreeHostDestroy(reference)
    }
  }

  public func willBeginMainFrame() {
    //_LayerTreeHostWillBeginMainFrame(reference)
    client!.willBeginMainFrame()
  }

  public func didBeginMainFrame() {
    //_LayerTreeHostDidBeginMainFrame(reference)
    client!.didBeginMainFrame()
  }
  
  // TODO: this probably has changed
  public func beginMainFrame(frameTime: TimeTicks, deadline: TimeTicks, interval: TimeDelta) {
    
    let args = BeginFrameArgs(
        sourceId: 0,
        sequenceNumber: 0,
        //frameTime: TimeTicks(microseconds: frameTime),
        //deadline: TimeTicks(microseconds: deadline),
        //interval: TimeDelta(microseconds: interval),
        frameTime: frameTime,
        deadline: deadline,
        interval: interval,
        type: .normal)
    
    client!.beginMainFrame(args: args)
    //_LayerTreeHostBeginMainFrame(reference, frameTime, deadline, interval)
  }

  public func beginMainFrameNotExpectedSoon() {
    //_LayerTreeHostBeginMainFrameNotExpectedSoon(reference)
    client!.beginMainFrameNotExpectedSoon()
  }

  public func animateLayers(monotonicFrameBeginTime: TimeInterval) {
    _LayerTreeHostAnimateLayers(reference, monotonicFrameBeginTime)
  }

  public func didStopFlinging() {
    _LayerTreeHostDidStopFlinging(reference)
  }

  public func requestMainFrameUpdate(requestedUpdate: VisualStateUpdate) {
    client!.updateLayerTreeHost(requestedUpdate: requestedUpdate)
    //_LayerTreeHostRequestMainFrameUpdate(reference)
  }

  public func willCommit() {
    _LayerTreeHostWillCommit(reference)
  }

  public func commitComplete() {
    _LayerTreeHostCommitComplete(reference)
  }

  // public func setOutputSurface(outputSurface: OutputSurface) {
  //   _LayerTreeHostSetOutputSurface(reference, outputSurface.reference)
  // }

  // public func releaseOutputSurface() -> OutputSurface? {
  //   let surface = _LayerTreeHostReleaseOutputSurface(reference)
  //   if surface == nil {
  //     return nil
  //   }
  //   return OutputSurface(reference: surface!)
  // }

  // public func requestNewOutputSurface() {
  //   client!.requestNewOutputSurface()
  //   //_LayerTreeHostRequestNewOutputSurface(reference)
  // }

  // public func didInitializeOutputSurface() {
  //   _LayerTreeHostDidInitializeOutputSurface(reference)
  // }

  // public func didFailToInitializeOutputSurface() {
  //   _LayerTreeHostDidFailToInitializeOutputSurface(reference)
  // }

  // public func didLoseOutputSurface() {
  //   _LayerTreeHostDidLoseOutputSurface(reference)
  // }

  // public func outputSurfaceLost() -> Bool {
  //   return Bool(_LayerTreeHostOutputSurfaceLost(reference))
  // }

  public func didCommitAndDrawFrame() {
    _LayerTreeHostDidCommitAndDrawFrame(reference)
  }

  // public func didCompleteSwapBuffers() {
  //   _LayerTreeHostDidCompleteSwapBuffers(reference)
  // }

  public func updateLayers() -> Bool {
    return Bool(_LayerTreeHostUpdateLayers(reference))
  }

  public func didCompletePageScaleAnimation() {
    _LayerTreeHostDidCompletePageScaleAnimation(reference)
  }

  public func notifyInputThrottledUntilCommit() {
    _LayerTreeHostNotifyInputThrottledUntilCommit(reference)
  }

  public func layoutAndUpdateLayers() {
    _LayerTreeHostLayoutAndUpdateLayers(reference)
  }

  public func composite(frameBeginTime: TimeTicks, raster: Bool) {
    _LayerTreeHostComposite(reference, frameBeginTime.microseconds, raster.intValue)
  }

  public func setRasterColorSpace(_ colorSpace: ColorSpace) {
    _LayerTreeHostSetRasterColorSpace(reference, 
      colorSpace.primaries.rawValue,
      colorSpace.transfer.rawValue,
      colorSpace.matrix.rawValue,
      colorSpace.range.rawValue,
      colorSpace.iccProfileId)
  }

  // public func finishAllRendering() {
  //   _LayerTreeHostFinishAllRendering(reference)
  // }

  public func setDeferCommits(deferCommits: Bool) {
    _LayerTreeHostSetDeferCommits(reference, deferCommits.intValue)
  }

  // public func metaInformationSequenceNumber() -> Int {
  //   return Int(_LayerTreeHostMetaInformationSequenceNumber(reference))
  // }

  // public func incrementMetaInformationSequenceNumber() {
  //   _LayerTreeHostIncrementMetaInformationSequenceNumber(reference)
  // }

  public func setNeedsDisplayOnAllLayers() {
    _LayerTreeHostSetNeedsDisplayOnAllLayers(reference)
  }

  public func setNeedsAnimate() {
    _LayerTreeHostSetNeedsAnimate(reference)
  }

  public func setNeedsUpdateLayers() {
    _LayerTreeHostSetNeedsUpdateLayers(reference)
  }

  public func setNeedsCommit() {
    ////print("LayerTreeHost.setNeedsCommit")
    _LayerTreeHostSetNeedsCommit(reference)
  }

  public func setNeedsCommitWithForcedRedraw() {
    _LayerTreeHostSetNeedsCommitWithForcedRedraw(reference)
  }

  public func setNeedsFullTreeSync() {
    _LayerTreeHostSetNeedsFullTreeSync(reference)
  }

  // public func setNeedsMetaInfoRecomputation(needsMetaInfoRecomputation: Bool) {
  //   _LayerTreeHostSetNeedsMetaInfoRecomputation(reference, needsMetaInfoRecomputation.intValue)
  // }

  // public func setNeedsRedraw() {
  //   _LayerTreeHostSetNeedsRedraw(reference)
  // }

  public func setNeedsRedrawRect(damaged: IntRect) {
    _LayerTreeHostSetNeedsRedrawRect(reference, Int32(damaged.x), Int32(damaged.y), Int32(damaged.width), Int32(damaged.height))
  }

  public func commitRequested() -> Bool {
    return Bool(_LayerTreeHostCommitRequested(reference))
  }

  // public func beginMainFrameRequested() -> Bool {
  //   return Bool(_LayerTreeHostBeginMainFrameRequested(reference))
  // }

  public func setNextCommitWaitsForActivation() {
    _LayerTreeHostSetNextCommitWaitsForActivation(reference)
  }

  // public func setNextCommitForcesRedraw() {
  //   _LayerTreeHostSetNextCommitForcesRedraw(reference)
  // }

  // // unimplemented for now
  // public func setAnimationEvents(events: [AnimationEvent]) {
  //  //events.withUnsafeBufferPointer({ (ptr: UnsafeBufferPointer<AnimationEvent>) in
  //  //   _LayerTreeHostSetAnimationEvents(reference, ptr, events.count)
  //  //})
  // }

  public func registerViewportLayers(
    overscrollElasticityLayer: Layer?,
    pageScaleLayer: Layer?,
    innerViewportContainerLayer: Layer?,
    outerViewportContainerLayer: Layer?,
    innerViewportScrollLayer: Layer?,
    outerViewportScrollLayer: Layer?) {

    _LayerTreeHostRegisterViewportLayers(
      reference,
      overscrollElasticityLayer != nil ? overscrollElasticityLayer!.reference : nil,
      pageScaleLayer != nil ? pageScaleLayer!.reference : nil,
      innerViewportContainerLayer != nil ? innerViewportContainerLayer!.reference : nil,
      outerViewportContainerLayer != nil ? outerViewportContainerLayer!.reference : nil,
      innerViewportScrollLayer != nil ? innerViewportScrollLayer!.reference : nil,
      outerViewportScrollLayer != nil ? outerViewportScrollLayer!.reference : nil)
  }

  public func queueSwapPromiseForMainThreadScrollUpdate(swapPromise: SwapPromise) {
    assert(false)
  }

  public func queueSwapPromise(swapPromise: SwapPromise) {
    _LayerTreeHostQueueSwapPromise(reference, swapPromise.reference)
  }

  //public func composite(_ when: TimeTicks, raster: Bool) {
   // _LayerTreeHostComposite(reference,
   //   when.internalValue,
    //  raster ? 1 : 0) 
  //}

  public func requestPresentationTimeForNextFrame(_ callback: @escaping (_: TimeTicks, _: TimeDelta, _: UInt32) -> Void) {
    let cb: CLayerTreeHostRequestPresentationCallback = { (clientHandle: UnsafeMutableRawPointer?, ticks: Int64, delta: Int64, i: UInt32) in
      guard clientHandle != nil else {
        return
      }
      let p = unsafeBitCast(clientHandle, to: LayerTreeHost.self)
      if let toRun = p.requestPresentationTimeCallback {
        toRun(TimeTicks(microseconds: ticks), TimeDelta.from(microseconds: delta), i)
      }
    }
    let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    self.requestPresentationTimeCallback = callback
    _LayerTreeHostRequestPresentationTimeForNextFrame(reference, selfptr, cb)
  }

  public func releaseLayerTreeFrameSink() {
    _LayerTreeHostReleaseLayerTreeFrameSink(reference)
  }

  // public func setTopControlsHeight(height: Float, shrink: Bool) {
  //   _LayerTreeHostSetTopControlsHeight(reference, height, shrink.intValue)
  // }

  // public func setTopControlsShownRatio(ratio: Float) {
  //   _LayerTreeHostSetTopControlsShownRatio(reference, ratio)
  // }

  // public func applyPageScaleDeltaFromImplSide(pageScaleDelta: Float) {
  //   _LayerTreeHostApplyPageScaleDeltaFromImplSide(reference, pageScaleDelta)
  // }

  public func setPageScaleFactorAndLimits(pageScaleFactor: Float,
    minPageScaleFactor: Float,
    maxPageScaleFactor: Float) {
    _LayerTreeHostSetPageScaleFactorAndLimits(reference, pageScaleFactor, minPageScaleFactor, maxPageScaleFactor)
  }

  public func setEventListenerProperties(eventClass: EventListenerClass, eventProperties: EventListenerProperties) {
    _LayerTreeHostSetEventListenerProperties(reference, CInt(eventClass.rawValue), CInt(eventProperties.rawValue))
  }

  public func setLayerTreeFrameSink(surface: LayerTreeFrameSink) {
    let surfaceRef = surface.reference
    // the ownership is lost here
    surface.reference = nil
    _LayerTreeHostSetLayerTreeFrameSink(reference, surfaceRef)
  }

  public func setContentSourceId(_ id: UInt32) {
    _LayerTreeHostSetContentSourceId(reference, id) 
  }

  // public func setThrottleFrameProduction(throttle: Bool) {
  //   _LayerTreeHostSetThrottleFrameProduction(reference, throttle.intValue)
  // }

  public func startPageScaleAnimation(targetOffset: IntVec2,
    useAnchor: Bool,
    scale: Float,
    duration: TimeInterval) {
    _LayerTreeHostStartPageScaleAnimation(reference, Int32(targetOffset.x), Int32(targetOffset.y), useAnchor.intValue, scale, duration)
  }

  public func setViewportSizeAndScale(viewport: IntSize, scale: Float, surfaceId: LocalSurfaceId) {
    _LayerTreeHostSetViewportSizeAndScale(
      reference, 
      CInt(viewport.width), 
      CInt(viewport.height), 
      scale,
      surfaceId.parentSequenceNumber,
      surfaceId.childSequenceNumber,
      surfaceId.token.high,
      surfaceId.token.low)
  }

  public func requestNewLocalSurfaceId() {
    _LayerTreeHostRequestNewLocalSurfaceId(reference)
  }

  // public func didNavigate() {
  //   _LayerTreeHostDidNavigate(reference)
  // }

  public func clearCachesOnNextCommit() {
    _LayerTreeHostClearCachesOnNextCommit(reference)
  }

  public func applyScrollAndScale(info: ScrollAndScaleSet) {
    _LayerTreeHostApplyScrollAndScale(reference)
  }

  public func setTransform(transform: Transform) {
    // TODO: use the matrix44 handle now
    _LayerTreeHostSetTransform(reference,
      transform[0,0], // col1row1
      transform[0,1], // col2row1
      transform[0,2], // col3row1
      transform[0,3], // col4row1
      transform[1,0], // col1row2
      transform[1,1], // col2row2
      transform[1,2], // col3row2
      transform[1,3], // col4row2
      transform[2,0], // col1row3
      transform[2,1], // col2row3
      transform[2,2], // col3row3
      transform[2,3], // col4row3
      transform[3,0], // col1row4
      transform[3,1], // col2row4
      transform[3,2], // col3row4
      transform[3,3]  // col4row4
    )
  }

  // public func setPaintedDeviceScaleFactor(paintedDeviceScaleFactor: Float) {
  //   _LayerTreeHostSetPaintedDeviceScaleFactor(reference, paintedDeviceScaleFactor)
  // }

  // public func updateTopControlsState(constraints: InputTopControlsState,
  //   current: InputTopControlsState,
  //   animate: Bool) {
  //   _LayerTreeHostUpdateTopControlsState(reference, constraints.rawValue, current.rawValue, animate.intValue)
  // }

  // public func setSurfaceIdNamespace(idNamespace: UInt) {
  //   _LayerTreeHostSetSurfaceIdNamespace(reference, UInt32(idNamespace))
  // }

  // public func createSurfaceSequence() -> SurfaceSequence? {
  //   var namespace: UInt32 = 0, sequence: UInt32 = 0
  //   _LayerTreeHostCreateSurfaceSequence(reference, &namespace, &sequence)
  //   return SurfaceSequence(namespace: namespace, sequence: sequence)
  // }

  // // SetChildrenNeedBeginFrames ...
  // public func setChildrenNeedBeginFrames(childrenNeedBeginFrames: Bool) {
  //   _LayerTreeHostSetChildrenNeedBeginFrames(reference, childrenNeedBeginFrames.intValue)
  // }

  // public func sendBeginFramesToChildren(args: BeginFrameArgs) {
  //   _LayerTreeHostSendBeginFramesToChildren(reference, args.frameTime, args.deadline, args.interval)
  // }

  // public func setAuthoritativeVSyncInterval(interval: TimeInterval) {
  //   _LayerTreeHostSetAuthoritativeVsyncInterval(reference, interval)
  // }

  public func layerByID(id: Int) -> Layer? {
    let layer = _LayerTreeHostLayerById(reference, Int32(id))
    if layer == nil {
      return nil
    }
    return Layer(reference: layer!)
  }

  public func registerLayer(layer: Layer) {
    _LayerTreeHostRegisterLayer(reference, layer.reference)
  }

  public func unregisterLayer(layer: Layer) {
    _LayerTreeHostUnregisterLayer(reference, layer.reference)
  }

  // public func isLayerInTree(layerId: Int, treeType: LayerTreeType) -> Bool {
  //   return Bool(_LayerTreeHostIsLayerInTree(reference, Int32(layerId), treeType.rawValue))
  // }

  public func registerSelection(selection: LayerSelection) {
    
    _LayerTreeHostRegisterSelection(reference, 
        Int32(selection.start.type.rawValue),
        Int32(selection.start.edgeTop.x),
        Int32(selection.start.edgeTop.y),
        Int32(selection.start.edgeBottom.x),
        Int32(selection.start.edgeBottom.y),
        Int32(selection.start.layerId),
        Int32(selection.start.hidden.intValue),
        Int32(selection.end.type.rawValue),
        Int32(selection.end.edgeTop.x),
        Int32(selection.end.edgeTop.y),
        Int32(selection.end.edgeBottom.x),
        Int32(selection.end.edgeBottom.y),
        Int32(selection.end.layerId),
        Int32(selection.end.hidden.intValue))//,
//        Int32(selection.isEditable ? 1 : 0),
//        Int32(selection.isEmptyTextFormControl ? 1 : 0)) 
  }

  public func setMutatorsNeedCommit() {
    _LayerTreeHostSetMutatorsNeedCommit(reference)
  }

  public func setMutatorsNeedRebuildPropertyTrees() {
    _LayerTreeHostSetMutatorsNeedRebuildPropertyTrees(reference)
  }

  public func setLayerTreeMutator(_ mutator: LayerTreeMutator) {
    _LayerTreeHostSetLayerTreeMutator(reference, mutator.reference) 
  }

  public func setNeedsRecalculateRasterScales() {
    _LayerTreeHostSetNeedsRecalculateRasterScales(reference)  
  }

  public func setOverscrollBehavior(behavior: OverscrollBehavior) {
    _LayerTreeHostSetOverscrollBehavior(reference, CInt(behavior.x.rawValue), CInt(behavior.y.rawValue))
  }

  // public func setLayerFilterMutated(layerId: Int,
  //   treeType: LayerTreeType,
  //   filters: FilterOperations) {
  //   //_LayerTreeHostSetLayerFilterMutated(reference, Int32(layerId), treeType.rawValue)
  // }

  // public func setLayerOpacityMutated(layerId: Int, treeType: LayerTreeType, opacity: Float) {
  //   _LayerTreeHostSetLayerOpacityMutated(reference, Int32(layerId), treeType.rawValue, opacity)
  // }

  // public func setLayerTransformMutated(layerId: Int, treeType: LayerTreeType, transform: Transform) {
  //   // TODO: pass the matrix44 handle directly
  //   _LayerTreeHostSetLayerTransformMutated(reference, Int32(layerId), treeType.rawValue,
  //   transform[0,0], // col1row1
  //   transform[0,1], // col2row1
  //   transform[0,2], // col3row1
  //   transform[0,3], // col4row1
  //   transform[1,0], // col1row2
  //   transform[1,1], // col2row2
  //   transform[1,2], // col3row2
  //   transform[1,3], // col4row2
  //   transform[2,0], // col1row3
  //   transform[2,1], // col2row3
  //   transform[2,2], // col3row3
  //   transform[2,3], // col4row3
  //   transform[3,0], // col1row4
  //   transform[3,1], // col2row4
  //   transform[3,2], // col3row4
  //   transform[3,3]  // col4row4
  //   )
  // }

  // public func setLayerScrollOffsetMutated(layerId: Int, treeType: LayerTreeType, scrollOffset: ScrollOffset) {
  //   _LayerTreeHostSetLayerScrollOffsetMutated(reference, Int32(layerId),
  //     treeType.rawValue,
  //     scrollOffset.x,
  //     scrollOffset.y)
  // }

  // public func layerTransformIsPotentiallyAnimatingChanged(layerId: Int, treeType: LayerTreeType, isAnimating: Bool) {
  //   _LayerTreeHostLayerTransformIsPotentiallyAnimatingChanged(reference,
  //     Int32(layerId),
  //     treeType.rawValue,
  //     isAnimating.intValue)
  // }

  public func scrollOffsetAnimationFinished() {
    _LayerTreeHostScrollOffsetAnimationFinished(reference)
  }

  // public func getScrollOffsetForAnimation(layerId: Int) -> ScrollOffset {
  //   var xd: Double = 0, yd: Double = 0
  //   _LayerTreeHostGetScrollOffsetForAnimation(reference, Int32(layerId), &xd, &yd)
  //   return ScrollOffset(x: xd, y: yd)
  // }

  // public func scrollOffsetAnimationWasInterrupted(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostScrollOffsetAnimationWasInterrupted(reference, layer.reference))
  // }

  // public func isAnimatingFilterProperty(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostIsAnimatingFilterProperty(reference, layer.reference))
  // }

  // public func isAnimatingOpacityProperty(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostIsAnimatingOpacityProperty(reference, layer.reference))
  // }

  // public func isAnimatingTransformProperty(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostIsAnimatingTransformProperty(reference, layer.reference))
  // }

  // public func hasPotentiallyRunningFilterAnimation(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasPotentiallyRunningFilterAnimation(reference, layer.reference))
  // }

  // public func hasPotentiallyRunningOpacityAnimation(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasPotentiallyRunningOpacityAnimation(reference, layer.reference))
  // }

  // public func hasPotentiallyRunningTransformAnimation(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasPotentiallyRunningTransformAnimation(reference, layer.reference))
  // }

  // public func hasOnlyTranslationTransforms(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasOnlyTranslationTransforms(reference, layer.reference))
  // }

  // public func maximumTargetScale(layer: Layer, scale: inout Float) -> Bool {
  //   return Bool(_LayerTreeHostMaximumTargetScale(reference, layer.reference, &scale))
  // }

  // public func animationStartScale(layer: Layer, scale: inout Float) -> Bool {
  //   return Bool(_LayerTreeHostAnimationStartScale(reference, layer.reference, &scale))
  // }

  // public func hasAnyAnimationTargetingProperty(layer: Layer, property: AnimationTargetProperty) -> Bool {
  //   return Bool(_LayerTreeHostHasAnyAnimationTargetingProperty(reference, layer.reference, property.rawValue))
  // }

  // public func animationsPreserveAxisAlignment(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostAnimationsPreserveAxisAlignment(reference, layer.reference))
  // }

  // public func hasAnyAnimation(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasAnyAnimation(reference, layer.reference))
  // }

  // public func hasActiveAnimation(layer: Layer) -> Bool {
  //   return Bool(_LayerTreeHostHasActiveAnimation(reference, layer.reference))
  // }

  public func requestBeginMainFrameNotExpected(newState: Bool) {
    _LayerTreeHostRequestBeginMainFrameNotExpected(reference, newState ? 1 : 0)
  }

  public func queueImageDecode(image: ImageSkia, callback: @escaping (_: Bool) -> Void ) {
    let handler = QueueImageDecodeHandler(delegate: self, callback: callback)
    queueImageDecodeHandlers.append(handler)
    let handlerRaw = unsafeBitCast(Unmanaged.passUnretained(handler).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _LayerTreeHostQueueImageDecode(reference, handlerRaw, image.reference, { 
      (imageDecodeHandler: UnsafeMutableRawPointer?, value: CInt) in 
        let x = unsafeBitCast(imageDecodeHandler, to: QueueImageDecodeHandler.self) 
        x.onImageDecode(result: value != 0)
      }
    )
  }

  /*
   * Helper functions
   */

  public func synchronouslyCompositeHelper(raster: Bool, swapPromise: SwapPromise?) {
    _LayerTreeHostHelperSynchronouslyComposite(reference, raster ? 1 : 0, swapPromise != nil ? swapPromise!.reference : nil)
  }

  public func beginMainFrameHelper(args: BeginFrameArgs) {
    _LayerTreeHostHelperBeginMainFrame(
      reference, 
      args.sourceId,
      args.sequenceNumber,
      args.frameTime.microseconds, 
      args.deadline.microseconds, 
      args.interval.microseconds)
  }

  public func beginMainFrameNotExpectedSoonHelper() {
    _LayerTreeHostHelperBeginMainFrameNotExpectedSoon(reference)
  }

  public func beginMainFrameNotExpectedUntilHelper(time: TimeTicks) {
    _LayerTreeHostHelperBeginMainFrameNotExpectedUntil(reference, time.microseconds)
  }

  public func requestNewLayerTreeFrameSinkHelper(callback: @escaping () -> Void) {
    let handler = NewLayerTreeFrameSinkHandler(delegate: self, callback: callback)
    newLayerTreeFrameSinkHandlers.append(handler)
    let handlerRaw = unsafeBitCast(Unmanaged.passUnretained(handler).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _LayerTreeHostHelperRequestNewLayerTreeFrameSink(reference, handlerRaw, { 
      (newFrameSinkHandler: UnsafeMutableRawPointer?) in 
        let x = unsafeBitCast(newFrameSinkHandler, to: NewLayerTreeFrameSinkHandler.self) 
        x.onNewLayerTreeFrameSink()
      }
    )
  }

  public func didCommitFrameToCompositorHelper() {
    _LayerTreeHostHelperDidCommitFrameToCompositor(reference)
  }
}

extension LayerTreeHost : QueueImageDecodeHandlerDelegate {
  
  public func onDone(handler: QueueImageDecodeHandler) {
    for (i, cur) in self.queueImageDecodeHandlers.enumerated() {
      if handler === cur {
        queueImageDecodeHandlers.remove(at: i)
      }
    }
  }
}

extension LayerTreeHost : NewLayerTreeFrameSinkHandlerDelegate {
  
  public func onDone(handler: NewLayerTreeFrameSinkHandler) {
    for (i, cur) in self.newLayerTreeFrameSinkHandlers.enumerated() {
      if handler === cur {
        newLayerTreeFrameSinkHandlers.remove(at: i)
      }
    }
  }
}

extension Bool {
  public init(_ i: Int32) {
    self.init(i != 0)
  }

  public init(_ i: Int) {
    self.init(i != 0)
  }

  public var intValue: Int32 {
    if self == true {
      return Int32(1)
    } else {
      return Int32(0)
    }
  }
}

fileprivate func toVisualStateUpdate(_ value: Int32) -> VisualStateUpdate {
  return value == 0 ? VisualStateUpdate.PrePaint : VisualStateUpdate.All
}