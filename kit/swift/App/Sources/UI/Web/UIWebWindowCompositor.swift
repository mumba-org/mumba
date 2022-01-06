// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Web
import MumbaShims

public protocol UIWebWindowCompositorDelegate : class {
  var isClosing: Bool { get }
  func applyViewportDeltas(
      innerDelta: FloatVec2,
      outerDelta: FloatVec2,
      elasticOverscrollDelta: FloatVec2,
      pageScale: Float,
      topControlsDelta: Float)
  func recordWheelAndTouchScrollingCount(
    hasScrolledByWheel: Bool, hasScrolledByTouch: Bool)
  func beginMainFrame(frameTime: TimeTicks)
  func requestNewLayerTreeFrameSink(callback: @escaping (_: LayerTreeFrameSink) -> Void)
  func didCommitAndDrawCompositorFrame()
  func didCommitCompositorFrame()
  func didCompletePageScaleAnimation()
  func didReceiveCompositorFrameAck()
  func requestScheduleAnimation()
  func updateVisualState(requestedUpdate: VisualStateUpdate)
  func willBeginCompositorFrame()
  // requestCopyOfOutputForLayoutTest:
  //   Note: Originally the return was 'SwapPromise'
  //    but our layerTreeHost.queueSwapPromise expects a 'ReportTimeSwapPromise'. 
  //    Change if this assumption is wrong in this case
  func requestCopyOfOutputForLayoutTest(request: CopyOutputRequest) -> ReportTimeSwapPromise?
  func didInitializeLayerTreeFrameSink()
}

public protocol UIWebWindowCompositorObserver : class {
  func beginMainFrame(args: BeginFrameArgs)
  func updateLayerTreeHost(requestedUpdate: VisualStateUpdate)
  func didCommit()
  func didReceiveCompositorFrameAck()
  func didSubmitCompositorFrame()
}

public typealias NotifySwapCallback = (_: Bool, _: DidNotSwapReason, _: Double) -> Void

public struct NotifySwapTimeSwapPromise {
  public let id: Int
  public let callback: NotifySwapCallback
  public let promise: ReportTimeSwapPromise

  public init(id: Int, callback: @escaping NotifySwapCallback, promise: ReportTimeSwapPromise) {
    self.id = id
    self.callback = callback
    self.promise = promise
  }

}


public class UIWebWindowCompositor : LayerTreeHostClient,
                                     LayerTreeHostSingleThreadClient,
                                     WebLayerTreeView {


  public var hasPendingPageScaleAnimation: Bool {
    return layerTreeHost.hasPendingPageScaleAnimation
  }

  public var unretainedReference: UnsafeMutableRawPointer? {
    return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  }

  public var hasGpuRasterizationTrigger: Bool {
    get {
      return layerTreeHost.hasGpuRasterizationTrigger
    }
    set {
      layerTreeHost.hasGpuRasterizationTrigger = newValue
    }
  }

  public var viewportVisibleRect: IntRect {
    get {
      return layerTreeHost.viewportVisibleRect
    }
    set {
      layerTreeHost.viewportVisibleRect = newValue
    }
  }

  public var deviceScaleFactor: Float  {
    get {
      return layerTreeHost.deviceScaleFactor
    }
    set {

    }
  }

  public var backgroundColor: Color { 
    get {
      return layerTreeHost.backgroundColor
    }
    set {
      let color = newValue
      layerTreeHost.backgroundColor = color
    }
  }

  public var haveScrollEventHandlers: Bool {
    get {
      return layerTreeHost.haveScrollEventHandlers
    }
    set {
      layerTreeHost.haveScrollEventHandlers = newValue
    }
  }

  public var rootLayer: Compositor.Layer? {
    return layerTreeHost.rootLayer
  }

  public var compositeIsSynchronous: Bool {
    // we never use a single threaded compositor/layer tree host here
    return false
  }

  public var sourceFrameNumber: Int {
    return layerTreeHost.sourceFrameNumber
  }

  public var inputHandler: InputHandler? {
    return layerTreeHost.inputHandler
  }

  public var viewportSize: IntSize {
    return layerTreeHost.deviceViewportSize
  }

  public var isSurfaceSynchronizationEnabled: Bool {
    return true//layerTreeHost.settings.enableSurfaceSynchronization
  }

  public var isVisible: Bool {
    get {
      return layerTreeHost.isVisible
    }
    set {      
      layerTreeHost.isVisible = newValue
      if newValue && layerTreeFrameSinkRequestFailedWhileInvisible {
        didFailToInitializeLayerTreeFrameSink()
      }
    }
  }

  public var isForSubframe: Bool {
    return false
  }

  public var layerTreeId: Int {
    return layerTreeHost.id
  }

  public var compositorAnimationHost: AnimationHost? {
    return animationHost!
  }

  public var layerTreeSettings: LayerTreeSettings {
    return settings
  }

  public var runAllCompositorStagesBeforeDraw = false
  public var enableSlimmingPaintV2 = true

  public private(set) var animationHost: AnimationHost?
  public private(set) var frameSinkId: FrameSinkId?
 
  internal var layerTreeHost: LayerTreeHost!
  private var layerTreeFrameSinkRequestFailedWhileInvisible: Bool = false
  private var inSynchronousCompositorUpdate: Bool = false
  //private var swapPromiseMonitor: LatencyInfoSwapPromiseMonitor?
  //private var layoutAndPaintAsyncCallback: (() -> Void)?
  private var layoutAndPaintAsyncCallback: (@convention(c) (UnsafeMutableRawPointer?) -> Void)?
  private var layoutAndPaintAsyncCallbackState: UnsafeMutableRawPointer?
  private var layerTreeFrameSink: Compositor.LayerTreeFrameSink?
  private var notifySwapTimeSwapPromiseCounter: Int = 0
  private var notifySwapTimeList: ContiguousArray<NotifySwapTimeSwapPromise>
  private var observers: ContiguousArray<UIWebWindowCompositorObserver>
  private var settings: LayerTreeSettings
  private weak var delegate: UIWebWindowCompositorDelegate!

  public init(delegate: UIWebWindowCompositorDelegate, runAllCompositorStagesBeforeDraw: Bool) {
    self.delegate = delegate
    observers = ContiguousArray<UIWebWindowCompositorObserver>()
    notifySwapTimeList = ContiguousArray<NotifySwapTimeSwapPromise>()
    settings = LayerTreeSettings()
    self.runAllCompositorStagesBeforeDraw = runAllCompositorStagesBeforeDraw
    //Compositor.initialize(singleThreaded: false)
  }

  public func initialize(layerTreeHost: LayerTreeHost, animationHost: AnimationHost) {
    self.layerTreeHost = layerTreeHost
    self.animationHost = animationHost
  }

  public func createLayerTreeHost(animationHost: AnimationHost, screenInfo: ScreenInfo) -> LayerTreeHost { 
    settings.singleThreadProxyScheduler = false
    settings.usingSynchronousRendererCompositor = false
    settings.enableEarlyDamageCheck = false
    settings.damagedFrameLimit = 3
    settings.canUseLcdText = true
    settings.gpuRasterizationForced = true
    settings.gpuRasterizationMsaaSampleCount = -1
    settings.gpuRasterizationSkewportTargetTimeInSeconds = 0.2
    settings.createLowResTiling = false
    settings.useStreamVideoDrawQuad = true
    settings.scrollbarFadeDelay = TimeDelta.from(milliseconds: 300)
    settings.scrollbarFadeDuration = TimeDelta.from(milliseconds: 300)
    settings.scrollbarThinningDuration = TimeDelta()
    settings.scrollbarFlashAfterAnyScrollUpdate = false
    settings.scrollbarFlashWhenMouseEnter = false
    settings.solidColorScrollbarColor = Color(a: 128, r: 128, g: 128, b: 128)
    settings.timeoutAndDrawWhenAnimationCheckerboards = true
    settings.layerTransformsShouldScaleLayerContents = true
    settings.layersAlwaysAllowedLcdText = false
    settings.minimumContentsScale = 0.0625
    settings.lowResContentsScaleFactor = 0.25
    settings.topControlsShowThreshold = 0.5
    settings.topControlsHideThreshold = 0.5
    settings.backgroundAnimationRate = 1.0
    // NOTE: 256 is a default, but we should calculate it better
    //       according to platforms and variables
    settings.defaultTileSize = IntSize(width: 256, height: 256)
    settings.maxUntiledLayerSize = IntSize()
    settings.maxGpuRasterTileSize = IntSize()
    settings.minimumOcclusionTrackingSize = IntSize()
    settings.tilingInterestAreaPadding = 3000
    settings.skewportTargetTimeInSeconds = 1.0
    settings.skewportExtrapolationLimitInScreenPixels = 2000
    settings.maxMemoryForPrepaintPercentage = 100
    settings.useZeroCopy = true
    settings.usePartialRaster = true
    settings.enableElasticOverscroll = false
    settings.ignoreRootLayerFlings = false
    settings.scheduledTasterTaskLimit = 32
    settings.useOcclusionForTilePrioritization = false
    
    // NOTE: behind cc::switches::kEnableLayerLists 
    //       & cc::switches::kEnableMainFrameBeforeActivation
    //       we are activating them as a experimental feature
    //       obs: on Chrome its called 'Slimming Paint v2'
    if enableSlimmingPaintV2 {
      settings.useLayerLists = true
      settings.mainFrameBeforeActivationEnabled = true
    } else {
      settings.useLayerLists = false
      // NOTE: just testing here
      //settings.useLayerLists = true
      settings.mainFrameBeforeActivationEnabled = false      
    }
    
    settings.maxStagingBufferUsageInBytes = 32 * 1024 * 1024
    settings.memoryPolicy = ManagedMemoryPolicy()
    settings.decodedImageWorkingSetBudgetBytes = 128 * 1024 * 1024
    settings.maxPrerasterDistanceInScreenPixels = 1000
    settings.useRgba4444 = false
    settings.unpremultiplyAndDitherLowBitDepthTiles = false
    settings.enableMaskTiling = true
    
    // TODO: to enable this we need to provide a specialized thread task runner
    // settings.enableCheckerImaging = true
    settings.enableCheckerImaging = false
#if os(Android)
    settings.minImageBytesToChecker = 512 * 1024  // 512kB
    settings.onlyCheckerImagesWithGpuRaster = true
#else
    settings.minImageBytesToChecker = 1 * 1024 * 1024  // 1MB.
    settings.onlyCheckerImagesWithGpuRaster = false
#endif
    // behind features::IsSurfaceSynchronizationEnabled()
    settings.enableSurfaceSynchronization = true
    //features::IsVizHitTestingSurfaceLayerEnabled()
    
    // settings.buildHitTestData = true
    
    // note: for a out-of-process-frame this is true
    settings.isLayerTreeForSubframe = false
    settings.disallowNonExactResourceReuse = false
    
    if runAllCompositorStagesBeforeDraw {
      settings.waitForAllPipelineStagesBeforeDraw = true
      settings.enableLatencyRecovery = false      
    } else {
      settings.waitForAllPipelineStagesBeforeDraw = false
      settings.enableLatencyRecovery = true
    }

    settings.commitToActiveTree = false
    settings.enableOopRasterization = true
    settings.enableImageAnimationResync = true
    settings.enableEdgeAntiAliasing = true
    settings.alwaysRequestPresentationTime = false

    // behind IsUseZoomForDSFEnabled() = true -> true
    settings.usePaintedDeviceScaleFactor = false//true

    var params = LayerTreeHost.InitParams()
    params.client = self
    params.settings = settings
    params.animationHost = animationHost
    params.isSingleThreaded = false
    return LayerTreeHost(params: params)
  }

  public func addObserver(_ observer: UIWebWindowCompositorObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: UIWebWindowCompositorObserver) {
    for (i, elem) in observers.enumerated() {
      if elem === observer {
        observers.remove(at: i)
        return
      }
    }
  }

  public func setNeedsBeginFrame() {
    layerTreeHost.setNeedsAnimate()
  }

  public func requestNewLocalSurfaceId() {
    layerTreeHost.requestNewLocalSurfaceId()
  }

  // public func didNavigate() {
  //   layerTreeHost.didNavigate()
  // }
  
  public func clearCachesOnNextCommit() {
    layerTreeHost.clearCachesOnNextCommit()
  }

  public func setNeedsRedrawRect(damaged: IntRect) {
    layerTreeHost.setNeedsRedrawRect(damaged: damaged)
  }

  public func setPageScaleFactorAndLimits(scaleFactor: Float,
                                          minimum: Float,
                                          maximum: Float) {
    layerTreeHost.setPageScaleFactorAndLimits(
      pageScaleFactor: scaleFactor, 
      minPageScaleFactor: minimum, 
      maxPageScaleFactor: maximum) 
  }

  public func setViewportSizeAndScale(viewport: IntSize, scale: Float, surfaceId: LocalSurfaceId) {
    layerTreeHost.setViewportSizeAndScale(viewport: viewport, scale: scale, surfaceId: surfaceId)
  }

  public func queueSwapPromise(swapPromise: SwapPromise) {
    layerTreeHost.queueSwapPromise(swapPromise: swapPromise) 
  }

  public func createLatencyInfoSwapPromiseMonitor(latency: LatencyInfo) -> LatencyInfoSwapPromiseMonitor {
    return LatencyInfoSwapPromiseMonitor(latency: latency, layerTreeHost: layerTreeHost)
  }

  public func setNeedsForcedRedraw() {
    layerTreeHost.setNeedsCommitWithForcedRedraw()
  }

  public func setNeedsDisplayOnAllLayers() {
    layerTreeHost.setNeedsDisplayOnAllLayers()
  }

  public func setRasterizeOnlyVisibleContent() {
    var current = layerTreeHost.debugState
    current.rasterizeOnlyVisibleContent = true
    layerTreeHost.debugState = current
  }

  public func notifyInputThrottledUntilCommit() {
    layerTreeHost.notifyInputThrottledUntilCommit()
  }

  public func scheduleMicroBenchmark() {
    //print("warning: UIHostCompositor.scheduleMicroBenchmark() called. not implemented")
  }

  public func sendMessageToMicroBenchmark(id: Int, value: String) -> Bool {
    //print("warning: UIHostCompositor.sendMessageToMicroBenchmark() called. not implemented")
    return false
  }

  public func setRootLayer(_ layer: Compositor.Layer) {
    layerTreeHost.rootLayer = layer
  }

  public func clearRootLayer() {
    layerTreeHost.rootLayer = nil
  }

  public func setLayerTreeFrameSink(_ layerTreeFrameSink: Compositor.LayerTreeFrameSink?) {
    guard let frameSink = layerTreeFrameSink else {
      //print("UIWebWindowCompositor.setLayerTreeFrameSink: layerTreeFrameSink is null")
      didFailToInitializeLayerTreeFrameSink()
      return
    }
    self.layerTreeFrameSink = frameSink
    layerTreeHost.setLayerTreeFrameSink(surface: frameSink)
  }

  public func startPageScaleAnimation(
    destination: IntPoint,
    useAnchor: Bool,
    newPageScale: Float,
    duration durationSec: Double) {
    //let duration = TimeDelta.from(microseconds: Int64(durationSec) * Time.MicrosecondsPerSecond)
    layerTreeHost.startPageScaleAnimation(
      targetOffset: IntVec2(x: destination.x, y: destination.y), 
      useAnchor: useAnchor, 
      scale: newPageScale,
      duration: durationSec)
  }

  public func didStopFlinging() {
    layerTreeHost.didStopFlinging()
  }

  public func registerViewportLayers(
    overscrollElasticityLayer: Compositor.Layer?,
    pageScaleLayer: Compositor.Layer?,
    innerViewportContainerLayer: Compositor.Layer?,
    outerViewportContainerLayer: Compositor.Layer?,
    innerViewportScrollLayer: Compositor.Layer?,
    outerViewportScrollLayer: Compositor.Layer?) {

    layerTreeHost.registerViewportLayers(
      overscrollElasticityLayer: overscrollElasticityLayer,
      pageScaleLayer: pageScaleLayer,
      innerViewportContainerLayer: innerViewportContainerLayer,
      outerViewportContainerLayer: outerViewportContainerLayer,
      innerViewportScrollLayer: innerViewportScrollLayer,
      outerViewportScrollLayer: outerViewportScrollLayer)
  }

  public func clearViewportLayers() {    
    layerTreeHost.registerViewportLayers(
      overscrollElasticityLayer: nil,
      pageScaleLayer: nil,
      innerViewportContainerLayer: nil,
      outerViewportContainerLayer: nil,
      innerViewportScrollLayer: nil,
      outerViewportScrollLayer: nil) 
  }

  public func registerSelection(selection: LayerSelection) {
    layerTreeHost.registerSelection(selection: selection)
  }

  public func clearSelection() {
    layerTreeHost.registerSelection(selection: LayerSelection()) 
  }

  public func setMutatorClient(_ client: Compositor.LayerTreeMutator) {
    layerTreeHost.setLayerTreeMutator(client)
  }

  public func forceRecalculateRasterScales() {
    layerTreeHost.setNeedsRecalculateRasterScales()
  }

  public func setEventListenerProperties(_ eventClass: EventListenerClass, _ eventProperties: EventListenerProperties) {
    layerTreeHost.setEventListenerProperties(
      eventClass: eventClass,
      eventProperties: eventProperties)
  }

  public func updateEventRectsForSubframeIfNecessary() {
    //print("warning: UIWebWindowCompositor.updateEventRectsForSubframeIfNecessary called. not implemented")
  }

  // public func layoutAndPaintAsync(_ callback: @escaping () -> Void) {
  //   //print("\n\n*** UIWebWindowCompositor.layoutAndPaintAsync -> setting layoutAndPaintAsyncCallback = () -> Void callback ***\n\n")
    
  //   layoutAndPaintAsyncCallback = callback

  //   if compositeIsSynchronous {
  //     // The LayoutAndPaintAsyncCallback is invoked in WillCommit, which is
  //     // dispatched after layout and paint for all compositing modes.
  //     let raster = false
  //     //print("UIWebWindowCompositor.layoutAndPaintAsync: composite is synchronous -> layerTreeHost.synchronouslyCompositeHelper() ...")
  //     layerTreeHost.synchronouslyCompositeHelper(raster: raster, swapPromise: nil)
  //   } else {
  //     //print("UIWebWindowCompositor.layoutAndPaintAsync: composite is not synchronous -> layerTreeHost.synchronouslyCompositeHelper() ...")
  //     layerTreeHost.setNeedsCommit()
  //   }
  // }

  public func layoutAndPaintAsync(callbackState: UnsafeMutableRawPointer?, callback: (@convention(c) (UnsafeMutableRawPointer?) -> Void)?) {
    layoutAndPaintAsyncCallback = callback
    layoutAndPaintAsyncCallbackState = callbackState

    if compositeIsSynchronous {
      // The LayoutAndPaintAsyncCallback is invoked in WillCommit, which is
      // dispatched after layout and paint for all compositing modes.
      let raster = false
      layerTreeHost.synchronouslyCompositeHelper(raster: raster, swapPromise: nil)
    } else {
      layerTreeHost.setNeedsCommit()
    } 
  }

  public func invokeLayoutAndPaintCallback() {
    if let callback = layoutAndPaintAsyncCallback {
      //callback()
      callback(layoutAndPaintAsyncCallbackState)
      layoutAndPaintAsyncCallback = nil
    }
  }

  public func compositeAndReadbackAsync(_ callback: @escaping (_: Bitmap) -> Void) {
    let request = CopyOutputRequest.createBitmapRequest(layerTreeHost: layerTreeHost, callback: callback)
    let swapPromise = delegate.requestCopyOfOutputForLayoutTest(request: request)

    // Force a commit to happen. The temporary copy output request will
    // be installed after layout which will happen as a part of the commit, for
    // widgets that delay the creation of their output surface.
    if compositeIsSynchronous {
      // Since the composite is required for a pixel dump, we need to raster.
      // Note that we defer queuing the SwapPromise until the requested Composite
      // with rasterization is done.
      let raster = true
      layerTreeHost.synchronouslyCompositeHelper(raster: raster, swapPromise: swapPromise)
    } else {
      // Force a redraw to ensure that the copy swap promise isn't cancelled due
      // to no damage.
      setNeedsForcedRedraw()
      layerTreeHost.queueSwapPromise(swapPromise: swapPromise!)
      layerTreeHost.setNeedsCommit()
    }
  }

  public func synchronouslyCompositeNoRasterForTesting() {
    layerTreeHost.synchronouslyCompositeHelper(raster: false, swapPromise: nil)
  }

  public func compositeWithRasterForTesting() {
    layerTreeHost.synchronouslyCompositeHelper(raster: true, swapPromise: nil)
  }

  public func setDeferCommits(deferCommits: Bool) {
    layerTreeHost.setDeferCommits(deferCommits: deferCommits)
  }

  public func requestDecode(image: ImageSkia, callback: @escaping (_: Bool) -> Void) {
    layerTreeHost.queueImageDecode(image: image, callback: callback)

    // If we're compositing synchronously, the SetNeedsCommit call which will be
    // issued by |layer_tree_host_| is not going to cause a commit, due to the
    // fact that this would make layout tests slow and cause flakiness. However,
    // in this case we actually need a commit to transfer the decode requests to
    // the impl side. So, force a commit to happen.
    if compositeIsSynchronous {
      let raster = true;
      layerTreeHost.synchronouslyCompositeHelper(raster: raster, swapPromise: nil)
    }
  }

  public func heuristicsForGpuRasterizationUpdated(heuristics: Bool) {
    layerTreeHost.hasGpuRasterizationTrigger = heuristics
  }

  public func setOverscrollBehavior(behavior: OverscrollBehavior) {
    layerTreeHost.setOverscrollBehavior(behavior: behavior)
  }

  public func willBeginMainFrame() {
    delegate.willBeginCompositorFrame()
  }

  public func didBeginMainFrame() {
    ////print("UIWebWindowCompositor.didBeginMainFrame")
  }
  
  public func beginMainFrame(args: BeginFrameArgs) {
    layerTreeHost.beginMainFrameHelper(args: args)
    delegate.beginMainFrame(frameTime: args.frameTime)
    for observer in observers {
      observer.beginMainFrame(args: args)
    }
  }
  
  public func beginMainFrameNotExpectedSoon() {
    layerTreeHost.beginMainFrameNotExpectedSoonHelper()
  }

  public func beginMainFrameNotExpectedUntil(time: TimeTicks) {
    layerTreeHost.beginMainFrameNotExpectedUntilHelper(time: time)
  }

  public func updateLayerTreeHost(requestedUpdate: VisualStateUpdate) {
    delegate.updateVisualState(requestedUpdate: requestedUpdate)
    for observer in observers {
      observer.updateLayerTreeHost(requestedUpdate: requestedUpdate)
    }
  }

  public func applyViewportDeltas(
    innerDelta: FloatVec2,
    outerDelta: FloatVec2,
    elasticOverscrollDelta: FloatVec2,
    pageScale: Float,
    topControlsDelta: Float) {
    delegate.applyViewportDeltas(innerDelta: innerDelta, 
                                 outerDelta: outerDelta,
                                 elasticOverscrollDelta: elasticOverscrollDelta, 
                                 pageScale: pageScale,
                                 topControlsDelta: topControlsDelta)
  }

  public func recordWheelAndTouchScrollingCount(
      hasScrolledByWheel: Bool,
      hasScrolledByTouch: Bool) {
    delegate.recordWheelAndTouchScrollingCount(hasScrolledByWheel: hasScrolledByWheel,
                                               hasScrolledByTouch: hasScrolledByTouch)
  }

  public func requestNewLayerTreeFrameSink() {
    // If the layerTreeHost is closing, then no more compositing is possible.  This
    // prevents shutdown races between handling the close message and
    // the CreateLayerTreeFrameSink task.
    guard !delegate.isClosing else {
      return
    }
    delegate.requestNewLayerTreeFrameSink(callback: self.setLayerTreeFrameSink)
  }

  public func didInitializeLayerTreeFrameSink() {
    delegate.didInitializeLayerTreeFrameSink() 
  }

  public func didFailToInitializeLayerTreeFrameSink() {
    guard layerTreeHost.isVisible else {
      layerTreeFrameSinkRequestFailedWhileInvisible = true
      return
    }
    layerTreeFrameSinkRequestFailedWhileInvisible = false
    layerTreeHost.requestNewLayerTreeFrameSinkHelper(callback: self.requestNewLayerTreeFrameSink)
  }

  public func willCommit() {
    invokeLayoutAndPaintCallback()
  }

  public func didCommit() {
    delegate.didCommitCompositorFrame()
    layerTreeHost.didCommitFrameToCompositorHelper()
    for observer in observers {
      observer.didCommit()
    }
  }

  public func didCommitAndDrawFrame() {    
    delegate.didCommitAndDrawCompositorFrame()
  }

  public func didReceiveCompositorFrameAck() {
    delegate.didReceiveCompositorFrameAck()
    for observer in observers {
      observer.didReceiveCompositorFrameAck()
    }
  }

  public func didCompletePageScaleAnimation() {
    delegate.didCompletePageScaleAnimation()
  }

  public func requestScheduleComposite() {
    
    ////print("UIWebWindowCompositor.requestScheduleComposite")
  }
  
  public func didSubmitCompositorFrame() {
    ////print("UIWebWindowCompositor.didSubmitCompositorFrame")
    for observer in observers {
      observer.didSubmitCompositorFrame()
    }
  }
  
  public func requestScheduleAnimation() {
    ////print("UIWebWindowCompositor.requestScheduleAnimation")
    delegate.requestScheduleAnimation()
  }
 
  public func didLoseLayerTreeFrameSink() {
    //print("UIWebWindowCompositor.didLoseLayerTreeFrameSink")
  }

  public func setFrameSinkId(_ frameSinkId: FrameSinkId) {
    self.frameSinkId = frameSinkId
  }

  public func setRasterColorSpace(_ colorSpace: ColorSpace) {
    layerTreeHost.setRasterColorSpace(colorSpace)
  }

  public func setContentSourceId(_ id: UInt32) {
    layerTreeHost.setContentSourceId(id)
  }

  public func notifySwapTime(_ callback: @escaping (_: Bool, _: DidNotSwapReason, _: Double) -> Void) {
  }
  //  //print("UIWebWindowCompositor.notifySwapTime")
    //notifySwapTimeSwapPromiseCounter += 1
    //let promiseId = notifySwapTimeSwapPromiseCounter
    //let item = NotifySwapTimeSwapPromise(id: promiseId, callback: callback, promise: ReportTimeSwapPromise(host: layerTreeHost, 
    //  callback: { (swap: Bool, reason: DidNotSwapReason, time: Double) in
    //    //print("notifySwapTime callback. didSwap? \(swap)")
    //    for (index, item) in self.notifySwapTimeList.enumerated() {
    //      if item.id == promiseId {
    //        item.callback(swap, reason, time)
    //        self.notifySwapTimeList.remove(at: index)
    //        break
    //      }
    //    }
    //  })) 
    //self.notifySwapTimeList.append(item)
  //  queueSwapPromise(swapPromise: ReportTimeSwapPromise(host: layerTreeHost, callback: nil))//item.promise)
  //}

  public func requestBeginMainFrameNotExpected(newState: Bool) {
    layerTreeHost.requestBeginMainFrameNotExpected(newState: newState)
  }

  public func setBrowserControlsShownRatio(ratio: Float) {

  }
  
  public func updateBrowserControlsState(constraints: InputTopControlsState, current: InputTopControlsState, animate: Bool) {

  }
  
  public func setBrowserControlsHeight(topHeight: Float, bottomHeight: Float, shrinkViewport: Bool) {

  }

  public func withUnretainedReference(_ callback: (_: UnsafeMutableRawPointer?) -> Void) {
    callback(unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self))
  }

  public func createLayerTreeViewCallbacks() -> WebLayerTreeViewCbs {
    var layerTreeCbs = WebLayerTreeViewCbs()
    memset(&layerTreeCbs, 0, MemoryLayout<WebLayerTreeViewCbs>.stride)
    
    // void (*SetRootLayer)(void* state, LayerRef web_layer)
    layerTreeCbs.SetRootLayer = { (state: UnsafeMutableRawPointer?,
        webLayer: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        let layer = Compositor.Layer(reference: webLayer!, isWeak: true)
        compositor.setRootLayer(layer)
    }
    // void (*ClearRootLayer)(void* state);
    layerTreeCbs.ClearRootLayer = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.clearRootLayer()
    }
    // AnimationHostRef (*CompositorAnimationHost)(void* state);
    layerTreeCbs.CompositorAnimationHost = { (state: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        if let animator = compositor.compositorAnimationHost {
            return animator.reference
        }
        return nil
    }

    // LayerTreeHostRef (*GetLayerTreeHost)(void* state)
    layerTreeCbs.GetLayerTreeHost = { (state: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        if let layerTree = compositor.layerTreeHost {
          return layerTree.reference
        }
        return nil
    }  

    // void (*GetViewportSize)(void* state, int* w, int* h);
    layerTreeCbs.GetViewportSize = { (state: UnsafeMutableRawPointer?,
        w: UnsafeMutablePointer<CInt>?, h: UnsafeMutablePointer<CInt>?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        let size = compositor.viewportSize
        w!.pointee = CInt(size.width)
        h!.pointee = CInt(size.height)
    }
    // void (*SetBackgroundColor)(void* state, uint8_t a, uint8_t r, uint8_t g, uint8_t b);
    layerTreeCbs.SetBackgroundColor = { (state: UnsafeMutableRawPointer?,
        a: UInt8,
        r: UInt8,
        g: UInt8,
        b: UInt8) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        let color = Color(a: a, r: r, g: g, b: b)
        compositor.backgroundColor = color
    }
    // void (*SetVisible)(void* state, int visible);
    layerTreeCbs.SetVisible = { (state: UnsafeMutableRawPointer?, visible: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.isVisible = visible != 0
    }
    // void (*SetPageScaleFactorAndLimits)(void* state, 
    //                                     float page_scale_factor,
    //                                     float minimum,
    //                                     float maximum);
    layerTreeCbs.SetPageScaleFactorAndLimits = { (state: UnsafeMutableRawPointer?,
        pageScaleFactor: Float,
        minimum: Float,
        maximum: Float) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setPageScaleFactorAndLimits(
            scaleFactor: pageScaleFactor, 
            minimum: minimum, 
            maximum: maximum)
    }
    // void (*StartPageScaleAnimation)(void* state,
    //                                 int px,
    //                                 int py,
    //                                 int use_anchor,
    //                                 float new_page_scale,
    //                                 double duration_sec);
    layerTreeCbs.StartPageScaleAnimation = { (state: UnsafeMutableRawPointer?,
        px: CInt,
        py: CInt,
        useAnchor: CInt,
        newPageScale: Float,
        durationSec: Double) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.startPageScaleAnimation(
            destination: IntPoint(x: Int(px), y: Int(py)), 
            useAnchor: useAnchor != 0, 
            newPageScale: newPageScale, 
            duration: durationSec)
    }
    // int (*HasPendingPageScaleAnimation)(void* state);
    layerTreeCbs.HasPendingPageScaleAnimation = { (state: UnsafeMutableRawPointer?) -> CInt in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        return compositor.hasPendingPageScaleAnimation ? 1 : 0
    }
    // void (*HeuristicsForGpuRasterizationUpdated)(void* state, int);
    layerTreeCbs.HeuristicsForGpuRasterizationUpdated = { (state: UnsafeMutableRawPointer?, heuristics: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.heuristicsForGpuRasterizationUpdated(heuristics: heuristics != 0)
    }
    // void (*SetBrowserControlsShownRatio)(void* state, float);
    layerTreeCbs.SetBrowserControlsShownRatio = { (state: UnsafeMutableRawPointer?,
        ratio: Float) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setBrowserControlsShownRatio(ratio: ratio)
    }
    // void (*UpdateBrowserControlsState)(void* state,
    //                                    WebTopControlsStateEnum constraints, 
    //                                    WebTopControlsStateEnum current,
    //                                    int animate);
    layerTreeCbs.UpdateBrowserControlsState = { (state: UnsafeMutableRawPointer?,
        constraints: WebTopControlsStateEnum,
        current: WebTopControlsStateEnum,
        animate: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.updateBrowserControlsState(
            constraints: InputTopControlsState(rawValue: Int32(constraints.rawValue))!, 
            current: InputTopControlsState(rawValue: Int32(current.rawValue))!, 
            animate: animate != 0)
    }
    // void (*SetBrowserControlsHeight)(void* state,
    //                                  float top_height,
    //                                  float bottom_height,
    //                                  int shrink_viewport);
    layerTreeCbs.SetBrowserControlsHeight = { (
        state: UnsafeMutableRawPointer?,
        topHeight: Float,
        bottomHeight: Float,
        shrinkViewport: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setBrowserControlsHeight(
            topHeight: topHeight, 
            bottomHeight: bottomHeight, 
            shrinkViewport: shrinkViewport != 0)
    }
    // void (*SetOverscrollBehavior)(void* state,
    //   WebOverscrollBehaviorTypeEnum x,
    //   WebOverscrollBehaviorTypeEnum y);
    layerTreeCbs.SetOverscrollBehavior = { (state: UnsafeMutableRawPointer?,
        x: WebOverscrollBehaviorTypeEnum,
        y: WebOverscrollBehaviorTypeEnum) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        let xob = OverscrollBehaviorType(rawValue: Int(x.rawValue))!
        let yob = OverscrollBehaviorType(rawValue: Int(y.rawValue))!
        compositor.setOverscrollBehavior(behavior: OverscrollBehavior(x: xob, y: yob))
    }
    // void (*SetNeedsBeginFrame)(void* state);
    layerTreeCbs.SetNeedsBeginFrame = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setNeedsBeginFrame()
    }
    // void (*DidStopFlinging)(void* state);
    layerTreeCbs.DidStopFlinging = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.didStopFlinging()
    }
    // void (*LayoutAndPaintAsync)(void* state, void* cb_state, void(*callback)(void*));
    layerTreeCbs.LayoutAndPaintAsync = { (
        state: UnsafeMutableRawPointer?,
        callbackState: UnsafeMutableRawPointer?, 
        cb: (@convention(c) (UnsafeMutableRawPointer?) -> Void)?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        //compositor.layoutAndPaintAsync{ [cb, callbackState] in
        //  //print("\n\n** layoutAndPaintAsync: calling back the callback on C side **\n\n")
        //  cb!(callbackState)
        //}
        compositor.layoutAndPaintAsync(callbackState: state, callback: cb)
    }
    // void (*CompositeAndReadbackAsync)(
    //       void* state,
    //       void* cb_state,
    //       void(*callback)(void*, BitmapRef));
    layerTreeCbs.CompositeAndReadbackAsync = { (state: UnsafeMutableRawPointer?,
        callbackState: UnsafeMutableRawPointer?, 
        cb: (@convention(c) (UnsafeMutableRawPointer?, _: UnsafeMutableRawPointer?) -> Void)?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.compositeAndReadbackAsync({ [cb, callbackState] in
            cb!(callbackState, $0.reference)  
        })
    }
    // void (*SynchronouslyCompositeNoRasterForTesting)(void* state);
    layerTreeCbs.SynchronouslyCompositeNoRasterForTesting = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.synchronouslyCompositeNoRasterForTesting()
    }
    // void (*CompositeWithRasterForTesting)(void* state);
    layerTreeCbs.CompositeWithRasterForTesting = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.compositeWithRasterForTesting()
    }
    // void (*SetDeferCommits)(void* state, int defer_commits);
    layerTreeCbs.SetDeferCommits = { (state: UnsafeMutableRawPointer?, deferCommits: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setDeferCommits(deferCommits: deferCommits != 0)
    }
    // void (*RegisterViewportLayers)(void* state, 
    //   LayerRef overscroll_elasticity,
    //   LayerRef page_scale,
    //   LayerRef inner_viewport_container,
    //   LayerRef outer_viewport_container,
    //   LayerRef inner_viewport_scroll,
    //   LayerRef outer_viewport_scroll);
    layerTreeCbs.RegisterViewportLayers = { (state: UnsafeMutableRawPointer?,
        overscrollElasticity: UnsafeMutableRawPointer?,
        pageScale: UnsafeMutableRawPointer?,
        innerViewportContainer: UnsafeMutableRawPointer?,
        outerViewportContainer: UnsafeMutableRawPointer?,
        innerViewportScroll: UnsafeMutableRawPointer?,
        outerViewportScroll: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.registerViewportLayers(
            overscrollElasticityLayer: overscrollElasticity != nil ? Compositor.Layer(reference: overscrollElasticity!, isWeak: true) : nil,
            pageScaleLayer: pageScale != nil ? Compositor.Layer(reference: pageScale!, isWeak: true) : nil,
            innerViewportContainerLayer: innerViewportContainer != nil ? Compositor.Layer(reference: innerViewportContainer!, isWeak: true) : nil,
            outerViewportContainerLayer: outerViewportContainer != nil ? Compositor.Layer(reference: outerViewportContainer!, isWeak: true) : nil,
            innerViewportScrollLayer: innerViewportScroll != nil ? Compositor.Layer(reference: innerViewportScroll!, isWeak: true) : nil,
            outerViewportScrollLayer: outerViewportScroll != nil ? Compositor.Layer(reference: outerViewportScroll!, isWeak: true) : nil)
    }
    // void (*ClearViewportLayers)(void* state);
    layerTreeCbs.ClearViewportLayers = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.clearViewportLayers()
    }
    // void (*RegisterSelection)(void* state, 
    //   WebSelectionTypeEnum type,
    //   WebSelectionBoundTypeEnum start_bound_type,
    //   int start_bound_layer_id,
    //   int start_bound_edge_top_in_layer_x,
    //   int start_bound_edge_top_in_layer_y,
    //   int start_bound_edge_bottom_in_layer_x,
    //   int start_bound_edge_bottom_in_layer_y,
    //   int start_bound_is_text_direction_rtl,
    //   int start_bound_hidden,
    //   WebSelectionBoundTypeEnum end_bound_type,
    //   int end_bound_layer_id,
    //   int end_bound_edge_top_in_layer_x,
    //   int end_bound_edge_top_in_layer_y,
    //   int end_bound_edge_bottom_in_layer_x,
    //   int end_bound_edge_bottom_in_layer_y,
    //   int end_bound_is_text_direction_rtl,
    //   int end_bound_hidden);
    layerTreeCbs.RegisterSelection = { (state: UnsafeMutableRawPointer?,
        type: WebSelectionTypeEnum,
        startBoundType: WebSelectionBoundTypeEnum,
        startBoundLayerId: CInt,
        startBoundEdgeTopInLayerX: CInt,
        startBoundEdgeTopInLayerY: CInt,
        startBoundEdgeBottomInLayerX: CInt,
        startBoundEdgeBottomInLayerY: CInt,
        startBoundIsTextDirectionRtl: CInt,
        startBoundHidden: CInt,
        endBoundType: WebSelectionBoundTypeEnum,
        endBoundLayerId: CInt,
        endBoundEdgeTopInLayerX: CInt,
        endBoundEdgeTopInLayerY: CInt,
        endBoundEdgeBottomInLayerX: CInt,
        endBoundEdgeBottomInLayerY: CInt,
        endBoundIsTextDirectionRtl: CInt,
        endBoundHidden: CInt) in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        
    }
    // void (*ClearSelection)(void* state);
    layerTreeCbs.ClearSelection = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.clearSelection()
    }
    // void (*SetMutatorClient)(void* state, LayerTreeMutatorRef mutator);
    layerTreeCbs.SetMutatorClient = { (state: UnsafeMutableRawPointer?,
        mutator: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setMutatorClient(Compositor.LayerTreeMutator(reference: mutator!))
    }
    // void (*ForceRecalculateRasterScales)(void* state);
    layerTreeCbs.ForceRecalculateRasterScales = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.forceRecalculateRasterScales()
    }
    // void (*SetEventListenerProperties)(void* state, 
    //                                    WebEventListenerClassEnum,
    //                                    WebEventListenerPropertiesEnum);
    layerTreeCbs.SetEventListenerProperties = { (state: UnsafeMutableRawPointer?,
        cls: WebEventListenerClassEnum,
        props: WebEventListenerPropertiesEnum) in
        ////print("warning: WebLayerTreeView.SetEventListenerProperties was called but the protocol dont implements it")
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.setEventListenerProperties(EventListenerClass(rawValue: Int(cls.rawValue))!, EventListenerProperties(rawValue: Int(props.rawValue))!)
    }
    // void (*UpdateEventRectsForSubframeIfNecessary)(void* state);
    layerTreeCbs.UpdateEventRectsForSubframeIfNecessary = { (state: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.updateEventRectsForSubframeIfNecessary()
    }
    // void (*SetHaveScrollEventHandlers)(void* state, int);
    layerTreeCbs.SetHaveScrollEventHandlers = { (state: UnsafeMutableRawPointer?, haveScrollEventHandlers: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.haveScrollEventHandlers = haveScrollEventHandlers != 0
    }
    // void (*GetFrameSinkId)(
    //   void* state,
    //   uint32_t* frame_sink_client_id, 
    //   uint32_t* frame_sink_sink_id);
    layerTreeCbs.GetFrameSinkId = { (state: UnsafeMutableRawPointer?,
        frameSinkClientId: UnsafeMutablePointer<UInt32>?,
        frameSinkSinkId: UnsafeMutablePointer<UInt32>?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        if let frameSink = compositor.frameSinkId {
            frameSinkClientId!.pointee = UInt32(frameSink.clientId)
            frameSinkSinkId!.pointee = UInt32(frameSink.sinkId)
            return
        }
    }
    // WebEventListenerPropertiesEnum (*EventListenerProperties)(
    //     void* state,
    //     WebEventListenerClassEnum);
    layerTreeCbs.EventListenerProperties = { (
        state: UnsafeMutableRawPointer?,
        cls: WebEventListenerClassEnum) -> WebEventListenerPropertiesEnum in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        return WebEventListenerPropertiesNothing
    }
    // int (*HaveScrollEventHandlers)(void* state);
    layerTreeCbs.HaveScrollEventHandlers = { (state: UnsafeMutableRawPointer?) -> CInt in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        return compositor.haveScrollEventHandlers ? 1 : 0
    }
    // int (*LayerTreeId)(void* state);
    layerTreeCbs.LayerTreeId = { (state: UnsafeMutableRawPointer?) -> CInt in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        return CInt(compositor.layerTreeId)
    }
    // void (*SetShowFPSCounter)(void* state, int);
    layerTreeCbs.SetShowFPSCounter = { (state: UnsafeMutableRawPointer?, show: CInt) in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
    }
    // void (*SetShowPaintRects)(void* state, int);
    layerTreeCbs.SetShowPaintRects = { (state: UnsafeMutableRawPointer?, show: CInt) in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        
    }
    // void (*SetShowDebugBorders)(void* state, int);
    layerTreeCbs.SetShowDebugBorders = { (state: UnsafeMutableRawPointer?, show: CInt) in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        
    }
    // void (*SetShowScrollBottleneckRects)(void* state, int);
    layerTreeCbs.SetShowScrollBottleneckRects = { (state: UnsafeMutableRawPointer?, show: CInt) in
        //let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        
    }
    // void (*NotifySwapTime)(void* state, void* cb_state, void(*callback)(void*, WebSwapResultEnum, double));
    layerTreeCbs.NotifySwapTime = { (state: UnsafeMutableRawPointer?, callbackState: UnsafeMutableRawPointer?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.queueSwapPromise(swapPromise: ReportTimeSwapPromise(host: compositor.layerTreeHost, callbackState: callbackState!))
        //compositor.notifySwapTime({ [cb, callbackState] in 
        //    //print("calling back NotifySwapTime callback on C side. success!")   
        //    cb!(callbackState, WebSwapResultEnum(rawValue: UInt32($1.rawValue)), $2)
        //})
    }
    // void (*RequestBeginMainFrameNotExpected)(void* state, int new_state);
    layerTreeCbs.RequestBeginMainFrameNotExpected = { (state: UnsafeMutableRawPointer?, newState: CInt) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.requestBeginMainFrameNotExpected(newState: newState != 0)
    }
    // void (*RequestDecode)(void* state,
    //                       void* cb_state,
    //                       PaintImageRef image,
    //                       void(*callback)(void*, int))
    layerTreeCbs.RequestDecode = { (state: UnsafeMutableRawPointer?,
        callbackState: UnsafeMutableRawPointer?,
        image: UnsafeMutableRawPointer?, 
        cb: (@convention(c) (UnsafeMutableRawPointer?, _: CInt) -> Void)?) in
        let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
        compositor.requestDecode(image: ImageSkia(reference: image!), 
        callback: { [cb, callbackState] in
            cb!(callbackState, $0 ? 1 : 0)
        })
    }

    layerTreeCbs.GetLayerTreeSettings = { (
      state: UnsafeMutableRawPointer?,
      single_thread_proxy_scheduler: UnsafeMutablePointer<CInt>?,
      main_frame_before_activation_enabled: UnsafeMutablePointer<CInt>?,
      using_synchronous_renderer_compositor: UnsafeMutablePointer<CInt>?,
      enable_early_damage_check: UnsafeMutablePointer<CInt>?,
      damaged_frame_limit: UnsafeMutablePointer<CInt>?,
      enable_latency_recovery: UnsafeMutablePointer<CInt>?,
      can_use_lcd_text: UnsafeMutablePointer<CInt>?,
      gpu_rasterization_forced: UnsafeMutablePointer<CInt>?,
      gpu_rasterization_msaa_sample_count: UnsafeMutablePointer<CInt>?,
      gpu_rasterization_skewport_target_time_in_seconds: UnsafeMutablePointer<Float>?,
      create_low_res_tiling: UnsafeMutablePointer<CInt>?,
      use_stream_video_draw_quad: UnsafeMutablePointer<CInt>?,
      scrollbar_fade_delay: UnsafeMutablePointer<Int64>?,
      scrollbar_fade_duration: UnsafeMutablePointer<Int64>?,
      scrollbar_thinning_duration: UnsafeMutablePointer<Int64>?,
      scrollbar_flash_after_any_scroll_update: UnsafeMutablePointer<CInt>?,
      scrollbar_flash_when_mouse_enter: UnsafeMutablePointer<CInt>?,
      solid_color_scrollbar_color_a: UnsafeMutablePointer<UInt8>?,
      solid_color_scrollbar_color_r: UnsafeMutablePointer<UInt8>?,
      solid_color_scrollbar_color_g: UnsafeMutablePointer<UInt8>?,
      solid_color_scrollbar_color_b: UnsafeMutablePointer<UInt8>?,
      timeout_and_draw_when_animation_checkerboards: UnsafeMutablePointer<CInt>?,
      layer_transforms_should_scale_layer_contents: UnsafeMutablePointer<CInt>?,
      layers_always_allowed_lcd_text: UnsafeMutablePointer<CInt>?,
      minimum_contents_scale: UnsafeMutablePointer<Float>?,
      low_res_contents_scale_factor: UnsafeMutablePointer<Float>?,
      top_controls_show_threshold: UnsafeMutablePointer<Float>?,
      top_controls_hide_threshold: UnsafeMutablePointer<Float>?,
      background_animation_rate: UnsafeMutablePointer<Double>?,
      default_tile_size_width: UnsafeMutablePointer<CInt>?,
      default_tile_size_height: UnsafeMutablePointer<CInt>?,
      max_untiled_layer_size_width: UnsafeMutablePointer<CInt>?,
      max_untiled_layer_size_height: UnsafeMutablePointer<CInt>?,
      max_gpu_raster_tile_size_width: UnsafeMutablePointer<CInt>?,
      max_gpu_raster_tile_size_height: UnsafeMutablePointer<CInt>?,
      minimum_occlusion_tracking_size_width: UnsafeMutablePointer<CInt>?,
      minimum_occlusion_tracking_size_height: UnsafeMutablePointer<CInt>?,
      tiling_interest_area_padding: UnsafeMutablePointer<CInt>?,
      skewport_target_time_in_seconds: UnsafeMutablePointer<Float>?,
      skewport_extrapolation_limit_in_screen_pixels: UnsafeMutablePointer<CInt>?,
      max_memory_for_prepaint_percentage: UnsafeMutablePointer<CInt>?,
      use_zero_copy: UnsafeMutablePointer<CInt>?,
      use_partial_raster: UnsafeMutablePointer<CInt>?,
      enable_elastic_overscroll: UnsafeMutablePointer<CInt>?,
      ignore_root_layer_flings: UnsafeMutablePointer<CInt>?,
      scheduled_raster_task_limit: UnsafeMutablePointer<CInt>?,
      use_occlusion_for_tile_prioritization: UnsafeMutablePointer<CInt>?,
      use_layer_lists: UnsafeMutablePointer<CInt>?,
      max_staging_buffer_usage_in_bytes: UnsafeMutablePointer<CInt>?,
      memory_policy_bytes_limit_when_visible: UnsafeMutablePointer<CInt>?,
      memory_policy_priority_cutoff_when_visible: UnsafeMutablePointer<CInt>?,
      decoded_image_working_set_budget_bytes: UnsafeMutablePointer<CInt>?,
      max_preraster_distance_in_screen_pixels: UnsafeMutablePointer<CInt>?,
      use_rgba_4444: UnsafeMutablePointer<CInt>?,
      unpremultiply_and_dither_low_bit_depth_tiles: UnsafeMutablePointer<CInt>?,
      enable_mask_tiling: UnsafeMutablePointer<CInt>?,
      enable_checker_imaging: UnsafeMutablePointer<CInt>?,
      min_image_bytes_to_checker: UnsafeMutablePointer<CInt>?,
      only_checker_images_with_gpu_raster: UnsafeMutablePointer<CInt>?,
      enable_surface_synchronization: UnsafeMutablePointer<CInt>?,
      is_layer_tree_for_subframe: UnsafeMutablePointer<CInt>?,
      disallow_non_exact_resource_reuse: UnsafeMutablePointer<CInt>?,
      wait_for_all_pipeline_stages_before_draw: UnsafeMutablePointer<CInt>?,
      commit_to_active_tree: UnsafeMutablePointer<CInt>?,
      enable_oop_rasterization: UnsafeMutablePointer<CInt>?,
      enable_image_animation_resync: UnsafeMutablePointer<CInt>?,
      enable_edge_anti_aliasing: UnsafeMutablePointer<CInt>?,
      always_request_presentation_time: UnsafeMutablePointer<CInt>?,
      use_painted_device_scale_factor: UnsafeMutablePointer<CInt>?) in
      
      let compositor = unsafeBitCast(state, to: UIWebWindowCompositor.self)
      let s = compositor.settings

      single_thread_proxy_scheduler!.pointee = s.singleThreadProxyScheduler ? 1 : 0
      main_frame_before_activation_enabled!.pointee = s.mainFrameBeforeActivationEnabled ? 1 : 0
      using_synchronous_renderer_compositor!.pointee = s.usingSynchronousRendererCompositor ? 1 : 0
      enable_early_damage_check!.pointee = s.enableEarlyDamageCheck ? 1 : 0
      damaged_frame_limit!.pointee = CInt(s.damagedFrameLimit)
      enable_latency_recovery!.pointee = s.enableLatencyRecovery ? 1 : 0
      can_use_lcd_text!.pointee = s.canUseLcdText ? 1 : 0
      gpu_rasterization_forced!.pointee = s.gpuRasterizationForced ? 1 : 0
      gpu_rasterization_msaa_sample_count!.pointee = CInt(s.gpuRasterizationMsaaSampleCount)
      gpu_rasterization_skewport_target_time_in_seconds!.pointee = s.gpuRasterizationSkewportTargetTimeInSeconds
      create_low_res_tiling!.pointee = s.createLowResTiling ? 1 : 0
      use_stream_video_draw_quad!.pointee = s.useStreamVideoDrawQuad ? 1 : 0
      scrollbar_fade_delay!.pointee = s.scrollbarFadeDelay.microseconds
      scrollbar_fade_duration!.pointee = s.scrollbarFadeDuration.microseconds
      scrollbar_thinning_duration!.pointee = s.scrollbarThinningDuration.microseconds
      scrollbar_flash_after_any_scroll_update!.pointee = s.scrollbarFlashAfterAnyScrollUpdate ? 1 : 0
      scrollbar_flash_when_mouse_enter!.pointee = s.scrollbarFlashWhenMouseEnter ? 1 : 0
      solid_color_scrollbar_color_a!.pointee = s.solidColorScrollbarColor == nil ? 0 : s.solidColorScrollbarColor!.a
      solid_color_scrollbar_color_r!.pointee = s.solidColorScrollbarColor == nil ? 0 : s.solidColorScrollbarColor!.r
      solid_color_scrollbar_color_g!.pointee = s.solidColorScrollbarColor == nil ? 0 : s.solidColorScrollbarColor!.g
      solid_color_scrollbar_color_b!.pointee = s.solidColorScrollbarColor == nil ? 0 : s.solidColorScrollbarColor!.b      
      timeout_and_draw_when_animation_checkerboards!.pointee = s.timeoutAndDrawWhenAnimationCheckerboards ? 1 : 0
      layer_transforms_should_scale_layer_contents!.pointee = s.layerTransformsShouldScaleLayerContents ? 1 : 0
      layers_always_allowed_lcd_text!.pointee = s.layersAlwaysAllowedLcdText ? 1 : 0
      minimum_contents_scale!.pointee = s.minimumContentsScale
      low_res_contents_scale_factor!.pointee = s.lowResContentsScaleFactor
      top_controls_show_threshold!.pointee = s.topControlsShowThreshold
      top_controls_hide_threshold!.pointee = s.topControlsHideThreshold
      background_animation_rate!.pointee = s.backgroundAnimationRate
      default_tile_size_width!.pointee = CInt(s.defaultTileSize.width)
      default_tile_size_height!.pointee = CInt(s.defaultTileSize.height)
      max_untiled_layer_size_width!.pointee = CInt(s.maxUntiledLayerSize.width)
      max_untiled_layer_size_height!.pointee = CInt(s.maxUntiledLayerSize.height)
      max_gpu_raster_tile_size_width!.pointee = CInt(s.maxGpuRasterTileSize.width)
      max_gpu_raster_tile_size_height!.pointee = CInt(s.maxGpuRasterTileSize.height)
      minimum_occlusion_tracking_size_width!.pointee = CInt(s.minimumOcclusionTrackingSize.width)
      minimum_occlusion_tracking_size_height!.pointee = CInt(s.minimumOcclusionTrackingSize.height)
      tiling_interest_area_padding!.pointee = CInt(s.tilingInterestAreaPadding)
      skewport_target_time_in_seconds!.pointee = s.skewportTargetTimeInSeconds
      skewport_extrapolation_limit_in_screen_pixels!.pointee = CInt(s.skewportExtrapolationLimitInScreenPixels)
      max_memory_for_prepaint_percentage!.pointee = CInt(s.maxMemoryForPrepaintPercentage)
      use_zero_copy!.pointee = s.useZeroCopy ? 1 : 0
      use_partial_raster!.pointee = s.usePartialRaster ? 1 : 0
      enable_elastic_overscroll!.pointee = s.enableElasticOverscroll ? 1 : 0
      ignore_root_layer_flings!.pointee = s.ignoreRootLayerFlings ? 1 : 0
      scheduled_raster_task_limit!.pointee = CInt(s.scheduledTasterTaskLimit)
      use_occlusion_for_tile_prioritization!.pointee = s.useOcclusionForTilePrioritization ? 1 : 0
      use_layer_lists!.pointee = s.useLayerLists ? 1 : 0
      max_staging_buffer_usage_in_bytes!.pointee = CInt(s.maxStagingBufferUsageInBytes)
      memory_policy_bytes_limit_when_visible!.pointee = CInt(s.memoryPolicy.bytesLimitWhenVisible)
      memory_policy_priority_cutoff_when_visible!.pointee = CInt(s.memoryPolicy.priorityCutoffWhenVisible.rawValue)
      decoded_image_working_set_budget_bytes!.pointee = CInt(s.decodedImageWorkingSetBudgetBytes)
      max_preraster_distance_in_screen_pixels!.pointee = CInt(s.maxPrerasterDistanceInScreenPixels)
      use_rgba_4444!.pointee = s.useRgba4444 ? 1 : 0
      unpremultiply_and_dither_low_bit_depth_tiles!.pointee = s.unpremultiplyAndDitherLowBitDepthTiles ? 1 : 0
      enable_mask_tiling!.pointee = s.enableMaskTiling ? 1 : 0
      enable_checker_imaging!.pointee = s.enableCheckerImaging ? 1 : 0
      min_image_bytes_to_checker!.pointee = CInt(s.minImageBytesToChecker)
      only_checker_images_with_gpu_raster!.pointee = s.onlyCheckerImagesWithGpuRaster ? 1 : 0
      enable_surface_synchronization!.pointee = s.enableSurfaceSynchronization ? 1 : 0
      is_layer_tree_for_subframe!.pointee = s.isLayerTreeForSubframe  ? 1 : 0
      disallow_non_exact_resource_reuse!.pointee = s.disallowNonExactResourceReuse ? 1 : 0
      wait_for_all_pipeline_stages_before_draw!.pointee = s.waitForAllPipelineStagesBeforeDraw ? 1 : 0
      commit_to_active_tree!.pointee = s.commitToActiveTree ? 1 : 0
      enable_oop_rasterization!.pointee = s.enableOopRasterization ? 1 : 0
      enable_image_animation_resync!.pointee = s.enableImageAnimationResync ? 1 : 0
      enable_edge_anti_aliasing!.pointee = s.enableEdgeAntiAliasing ? 1 : 0
      always_request_presentation_time!.pointee = s.alwaysRequestPresentationTime ? 1 : 0
      use_painted_device_scale_factor!.pointee = s.usePaintedDeviceScaleFactor ? 1 : 0
    }

    return layerTreeCbs
  }

}
