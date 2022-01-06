// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor
import Base
import Graphics
import Foundation
import Gpu

public typealias SingleThreadTaskRunner = Int
public typealias CompositorVSyncManager = Int
public typealias BeginFrameSource = Int
public typealias RendererSettings = Int
public typealias CompositorBeginFrameObserver = Int
public typealias GLFrameData = Int
public typealias CompositorAnimationObserver = Int

public typealias WebCompositeAndReadbackAsyncCallback = () -> Void

public struct FrameTimingTracker {
  public typealias CompositeTimingSet = Int
  public typealias MainFrameTimingSet = Int
}

public protocol WebScheduler {
  func willBeginFrame(args: BeginFrameArgs)
  func beginFrameNotExpectedSoon()
  func didCommitFrameToCompositor()
}

public protocol WebLayoutAndPaintAsyncCallback {
  func didLayoutAndPaint()
}

public protocol WebCompositorDependencies {

 var isGpuRasterizationForced: Bool { get }
 var isGpuRasterizationEnabled: Bool { get }
 var gpuRasterizationMSAASampleCount: Int { get }
 var isLcdTextEnabled: Bool { get }
 var isDistanceFieldTextEnabled: Bool { get }
 var isZeroCopyEnabled: Bool { get }
 var isPartialRasterEnabled: Bool { get }
 var isGpuMemoryBufferCompositorResourcesEnabled: Bool { get }
 var isElasticOverscrollEnabled: Bool { get }
 var imageTextureTargets: [UInt] { get }
 var compositorMainThreadTaskRunner: SingleThreadTaskRunner? { get }
 var compositorImplThreadTaskRunner: SingleThreadTaskRunner? { get }
 var sharedBitmapManager: SharedBitmapManager { get }
 //var scheduler: WebScheduler { get }
 var gpuMemoryBufferManager: GpuMemoryBufferManager { get }
 var sharedMainThreadContextProvider: ContextProvider { get }
 var taskGraphRunner: TaskGraphRunner { get }
 var isImageDecodeTasksEnabled: Bool { get }
 var isThreadedAnimationEnabled: Bool { get }

 func createExternalBeginFrameSource(routingId: Int) -> BeginFrameSource
}

public protocol WebCompositorAnimationObserver {
 func onAnimationStep(timestamp: TimeInterval)
 func onCompositingShuttingDown(compositor: WebCompositor)
}

public typealias WebCompositorAnimationPlayerClient = Int

public struct WebCompositorAnimationTimeline {
    
    public var animationTimeline: AnimationTimeline

    public init(animationTimeline: AnimationTimeline) {
      self.animationTimeline = animationTimeline
    }

    public func playerAttached(client: WebCompositorAnimationPlayerClient) {}
    public func playerDestroyed(client: WebCompositorAnimationPlayerClient) {}  
}

public protocol WebCompositorDelegate {

  // Report viewport related properties during a commit from the compositor
  // thread.
  func applyViewportDeltas(
      innerDelta: FloatVec2,
      outerDelta: FloatVec2,
      elasticOverscrollDelta: FloatVec2,
      pageScale: Float,
      topControlsDelta: Float)

  // Notifies that the compositor has issed a BeginMainFrame.
  func beginMainFrame(frameTimeSec: Double)

  // Requests an OutputSurface to render into.
  func createOutputSurface(fallback: Bool) -> OutputSurface?

  // Requests an external BeginFrameSource from the delegate.
  func createExternalBeginFrameSource() -> BeginFrameSource

  // Notifies that the draw commands for a committed frame have been issued.
  func didCommitAndDrawCompositorFrame()

  // Notifies about a compositor frame commit operation having finished.
  func didCommitCompositorFrame()

  // Called by the compositor when page scale animation completed.
  func didCompletePageScaleAnimation()

  // Notifies that the compositor has posted a swapbuffers operation to the GPU
  // process.
  func didCompleteSwapBuffers()

  // Called by the compositor to forward a proto that represents serialized
  // compositor state.
  func forwardCompositorProto(proto: [UInt8])

  // Indicates whether the RenderWidgetCompositor is about to close.
  func isClosing() -> Bool

  // Called by the compositor in single-threaded mode when a swap is aborted.
  func onSwapBuffersAborted()

  // Called by the compositor in single-threaded mode when a swap completes.
  func onSwapBuffersComplete()

  // Called by the compositor in single-threaded mode when a swap is posted.
  func onSwapBuffersPosted()

  // Called by the compositor to request the delegate to record frame timing.
  func recordFrameTimingEvents(compositeEvents: FrameTimingTracker.CompositeTimingSet,
    mainFrameEvents: FrameTimingTracker.MainFrameTimingSet)

  // Requests that the client schedule a composite now, and calculate
  // appropriate delay for potential future frame.
  func scheduleAnimation()

  // Requests a visual frame-based update to the state of the delegate if there
  // an update available.
  func updateVisualState()

  // Indicates that the compositor is about to begin a frame. This is primarily
  // to signal to flow control mechanisms that a frame is beginning, not to
  // perform actual painting work.
  func willBeginCompositorFrame()
}

public class WebCompositor {

  static let outputSurfaceRetriesBeforeFallback = 4
  static let maxOutputSurfaceRetries = 5

  public var delegate: WebCompositorDelegate

  public var neverVisible: Bool {
    get {
      return _neverVisible
    }
    set {
      guard !host.visible else {
        return
      }
      _neverVisible = newValue
    }
  }

  public var inputHandler: InputHandler? {
    get {
      return host.inputHandler
    }
  }

  var compositeIsSynchronous: Bool {
    return compositorDeps.compositorImplThreadTaskRunner == nil && host.settings.singleThreadProxyScheduler
  }
  
  var numFailedRecreateAttempts: Int = 0
  var compositorDeps: WebCompositorDependencies
  var host: LayerTreeHost
  var layoutAndPaintAsyncCallback: WebLayoutAndPaintAsyncCallback? = nil
  var temporaryCopyOutputRequest: CopyOutputRequest! = nil
  var rendererScheduler: WebCompositorScheduler
  var _neverVisible: Bool

  init(delegate: WebCompositorDelegate, deps: WebCompositorDependencies) throws {
    self.delegate = delegate
    compositorDeps = deps
//     let settings = CCLayerTreeSettings()

//     settings.layerTransformsShouldScaleLayerContents = true


//     settings.mainFrameBeforeActivationEnabled = true
//     settings.acceleratedAnimationEnabled = deps.isThreadedAnimationEnabled
//     settings.useCompositorAnimationTimelines = true

//     // TODO: We need to enable this on the Shims somehow

//     //blink::WebRuntimeFeatures::enableCompositorAnimationTimelines(
//     //    settings.use_compositor_animation_timelines)

//     settings.defaultTileSize = calculateDefaultTileSize(_view)

//     let max_untiled_layer_width = settings.max_untiled_layer_size.width()
//     let max_untiled_layer_height = settings.max_untiled_layer_size.height()

//     settings.max_untiled_layer_size = IntSize(max_untiled_layer_width,
//                                          max_untiled_layer_height)

//     settings.gpu_rasterization_msaa_sample_count =
//       _deps.GetGpuRasterizationMSAASampleCount()
//     settings.gpu_rasterization_forced =
//       _deps.IsGpuRasterizationForced()
//     settings.gpu_rasterization_enabled =
//       _deps.IsGpuRasterizationEnabled()

//     settings.can_use_lcd_text = _deps.IsLcdTextEnabled()
//     settings.use_distance_field_text =
//       _deps.IsDistanceFieldTextEnabled()
//     settings.use_zero_copy = _deps.IsZeroCopyEnabled()
//     settings.use_partial_raster = _deps.IsPartialRasterEnabled()
//     settings.enable_elastic_overscroll =
//       _deps.IsElasticOverscrollEnabled()
//     settings.renderer_settings.use_gpu_memory_buffer_resources =
//       _deps.IsGpuMemoryBufferCompositorResourcesEnabled()
//     settings.use_image_texture_targets =
//       _deps.GetImageTextureTargets()
//     settings.image_decode_tasks_enabled =
//       _deps.AreImageDecodeTasksEnabled()


//     settings.verify_property_trees = false
//     settings.use_property_trees = true
//     settings.renderer_settings.allow_antialiasing = true
//   // The means the renderer compositor has 2 possible modes:
//   // - Threaded compositing with a scheduler.
//   // - Single threaded compositing without a scheduler (for layout tests only).
//   // Using the scheduler in layout tests introduces additional composite steps
//   // that create flakiness.
//   settings.single_thread_proxy_scheduler = false

//   // These flags should be mirrored by  versions in ui/compositor/.
//   settings.initial_debug_state.show_debug_borders =
//       cmd->HasSwitch(cc::switches::kShowCompositedLayerBorders)
//   settings.initial_debug_state.show_layer_animation_bounds_rects =
//       cmd->HasSwitch(cc::switches::kShowLayerAnimationBounds)
//   settings.initial_debug_state.show_paint_rects =
//       cmd->HasSwitch(switches::kShowPaintRects)
//   settings.initial_debug_state.show_property_changed_rects =
//       cmd->HasSwitch(cc::switches::kShowPropertyChangedRects)
//   settings.initial_debug_state.show_surface_damage_rects =
//       cmd->HasSwitch(cc::switches::kShowSurfaceDamageRects)
//   settings.initial_debug_state.show_screen_space_rects =
//       cmd->HasSwitch(cc::switches::kShowScreenSpaceRects)
//   settings.initial_debug_state.show_replica_screen_space_rects =
//       cmd->HasSwitch(cc::switches::kShowReplicaScreenSpaceRects)

//   settings.initial_debug_state.SetRecordRenderingStats(
//       cmd->HasSwitch(cc::switches::kEnableGpuBenchmarking))

//   if (cmd->HasSwitch(cc::switches::kSlowDownRasterScaleFactor)) {
//     const int kMinSlowDownScaleFactor = 0
//     const int kMaxSlowDownScaleFactor = INT_MAX
//     GetSwitchValueAsInt(
//         *cmd,
//         cc::switches::kSlowDownRasterScaleFactor,
//         kMinSlowDownScaleFactor,
//         kMaxSlowDownScaleFactor,
//         &settings.initial_debug_state.slow_down_raster_scale_factor)
//   }

//   settings.strict_layer_property_change_checking =
//       cmd->HasSwitch(cc::switches::kStrictLayerPropertyChangeChecking)

// #if defined(OS_ANDROID)
//   DCHECK(!SynchronousCompositorFactory::GetInstance() ||
//          !cmd->HasSwitch(switches::kIPCSyncCompositing))
//   bool using_synchronous_compositor =
//       SynchronousCompositorFactory::GetInstance() ||
//       cmd->HasSwitch(switches::kIPCSyncCompositing)

//   // We can't use GPU rasterization on low-end devices, because the Ganesh
//   // cache would consume too much memory.
//   if (base::SysInfo::IsLowEndDevice())
//     settings.gpu_rasterization_enabled = false
//   settings.using_synchronous_renderer_compositor = using_synchronous_compositor
//   if (using_synchronous_compositor) {
//     // Android WebView uses system scrollbars, so make ours invisible.
//     settings.scrollbar_animator = cc::LayerTreeSettings::NO_ANIMATOR
//     settings.solid_color_scrollbar_color = SK_olorTRANSPARENT
//   } else {
//     settings.scrollbar_animator = CCLayerTreeSettings.LINEAR_FADE
//     settings.scrollbar_fade_delay_ms = 300
//     settings.scrollbar_fade_resize_delay_ms = 2000
//     settings.scrollbar_fade_duration_ms = 300
//     settings.solid_color_scrollbar_color = SkColorSetARGB(128, 128, 128, 128)
//   }
//   settings.renderer_settings.highp_threshold_min = 2048
//   // Android WebView handles root layer flings itself.
//   settings.ignore_root_layer_flings = using_synchronous_compositor
//   // Memory policy on Android WebView does not depend on whether device is
//   // low end, so always use default policy.
//   bool use_low_memory_policy =
//       base::SysInfo::IsLowEndDevice() && !using_synchronous_compositor
//   // RGBA_4444 textures are only enabled by default for low end devices
//   // and are disabled for Android WebView as it doesn't support the format.
//   settings.renderer_settings.use_rgba_4444_textures = use_low_memory_policy
//   if (use_low_memory_policy) {
//     // On low-end we want to be very carefull about killing other
//     // apps. So initially we use 50% more memory to avoid flickering
//     // or raster-on-demand.
//     settings.max_memory_for_prepaint_percentage = 67
//   } else {
//     // On other devices we have increased memory excessively to avoid
//     // raster-on-demand already, so now we reserve 50% _only_ to avoid
//     // raster-on-demand, and use 50% of the memory otherwise.
//     settings.max_memory_for_prepaint_percentage = 50
//   }
//   // Webview does not own the surface so should not clear it.
//   settings.renderer_settings.should_clear_root_render_pass =
//       !using_synchronous_compositor

//   // TODO(danakj): Only do this on low end devices.
//   settings.create_low_res_tiling = true

//   settings.use_external_begin_frame_source = true

//   if ui.IsOverlayScrollbarEnabled() {
//     settings.scrollbar_animator = cc::LayerTreeSettings::THINNING
//     settings.solid_color_scrollbar_color = SkColorSetARGB(128, 128, 128, 128)
//   } else {
//     settings.scrollbar_animator = cc::LayerTreeSettings::LINEAR_FADE
//     settings.solid_color_scrollbar_color = SkColorSetARGB(128, 128, 128, 128)
//   }
//   settings.scrollbar_fade_delay_ms = 500
//   settings.scrollbar_fade_resize_delay_ms = 500
//   settings.scrollbar_fade_duration_ms = 300

//   settings.renderer_settings.use_rgba_4444_textures = true

//   settings.max_staging_buffer_usage_in_bytes = 32 * 1024 * 1024  // 32MB
//   // Use 1/4th of staging buffers on low-end devices.
//   if (base::SysInfo::IsLowEndDevice())
//     settings.max_staging_buffer_usage_in_bytes /= 4

//   cc::ManagedMemoryPolicy current = settings.memory_policy_
//   settings.memory_policy_ = GetGpuMemoryPolicy(current)

//   scoped_refptr<base::SingleThreadTaskRunner> compositor_thread_task_runner =
//       _deps.GetCompositorImplThreadTaskRunner()
//   scoped_refptr<base::SingleThreadTaskRunner>
//       main_thread_compositor_task_runner =
//           _deps.GetCompositorMainThreadTaskRunner()
//   cc::SharedBitmapManager* shared_bitmap_manager =
//       _deps.GetSharedBitmapManager()
//   gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager =
//       _deps.GetGpuMemoryBufferManager()
//   cc::TaskGraphRunner* task_graph_runner =
//       _deps.GetTaskGraphRunner()

//   //bool use_remote_compositing = cmd->HasSwitch(switches::kUseRemoteCompositing)

//   //if (use_remote_compositing)
//   settings.useExternalBeginFrameSource = true

//   let externalBeginFrameSource: BeginFrameSource
//   if settings.useExternalBeginFrameSource {
//     externalBeginFrameSource =
//         deps.createExternalBeginFrameSource(_widget.routingId)
//   }

//   let params: LayerTreeInitParams
//   params.client = this
//   params.sharedBitmapManager = sharedBitmapManager
//   params.gpuMemoryBufferManager = gpuMemoryBufferManager
//   params.settings = settings
//   params.taskGraphRunner = task_graph_runner
//   params.mainTaskRunner = main_thread_compositor_task_runner
//   params.externalBeginFrameSource = externalBeginFrameSource

//   if use_remote_compositing {
//     _layerTreeHost = LayerTree.CreateSingleThreaded(this, params)
//   } else if (compositor_thread_task_runner.get()) {
//     _layerTreeHost = LayerTree.CreateThreaded(
//         compositor_thread_task_runner, params)
//   } else {
//     _layerTreeHost = LayerTree.CreateSingleThreaded(this, params)
//   }
    _neverVisible = false

    var settings = LayerTreeSettings()

    settings.layersAlwaysAllowedLcdText = true

    var params = LayerTreeHost.InitParams()
    
    params.settings = settings
    //params.sharedBitmapManager = sharedBitmapManager
    //params.gpuMemoryBufferManager = gpuMemoryBufferManager
    //params.taskGraphRunner = taskGraphRunner
    //params.client = self

    host = try LayerTreeHost(params: params)
    //host.setSurfaceIdNamespace(surfaceIdAllocator.idNamespace)
    //host.rootLayer = rootWebLayer
    //host.visible = true
    rendererScheduler = WebCompositorScheduler()
  }

  deinit {
  
  }

  public func beginMainFrameRequested() -> Bool {
    return host.beginMainFrameRequested()
  }

  public func setNeedsDisplayOnAllLayers() {
    host.setNeedsDisplayOnAllLayers()
  }

  public func setRasterizeOnlyVisibleContent() {
    var current = host.debugState
    current.rasterizeOnlyVisibleContent = true
    host.debugState = current
  }

  public func setNeedsRedrawRect(damageRect: IntRect) {
    host.setNeedsRedrawRect(damaged: damageRect)
  }

  public func setNeedsForcedRedraw() {
    host.setNextCommitForcesRedraw()
    setNeedsAnimate()
  }

  public func createLatencyInfoSwapPromiseMonitor(latency: LatencyInfo) -> SwapPromiseMonitor? {
    return LatencyInfoSwapPromiseMonitor(layerTreeHost: host, latency: latency)
  }

  public func queueSwapPromise(swapPromise: SwapPromise) {
    host.queueSwapPromise(swapPromise: swapPromise)
  }

  public func getSourceFrameNumber() -> Int {
    return host.sourceFrameNumber()
  }

  public func setNeedsUpdateLayers() {
    host.setNeedsUpdateLayers()
  }

  public func setNeedsCommit() {
    host.setNeedsCommit()
  }

  public func notifyInputThrottledUntilCommit() {
    host.notifyInputThrottledUntilCommit()
  }

  public func setSurfaceIdNamespace(surfaceIdNamespace: UInt) {
    host.setSurfaceIdNamespace(idNamespace: surfaceIdNamespace)
  }

  public func onHandleCompositorProto(proto: [UInt8] ) { assert(false) }

  public func setPaintedDeviceScaleFactor(deviceScale: Float) {
    host.setPaintedDeviceScaleFactor(paintedDeviceScaleFactor: deviceScale)
  }

  public func scheduleAnimation() {
    delegate.scheduleAnimation()
  }

  func layoutAndUpdateLayers() {
    guard compositeIsSynchronous else {
      return
    }
    host.layoutAndUpdateLayers()
    invokeLayoutAndPaintCallback()
  }

  func invokeLayoutAndPaintCallback() {
    guard let callback = layoutAndPaintAsyncCallback else {
      return
    }
    callback.didLayoutAndPaint()
    layoutAndPaintAsyncCallback = nil
  }

  func synchronouslyComposite() {

    guard compositeIsSynchronous else {
      return
    }

    let date = Date()
    host.composite(frameBeginTime: date.timeIntervalSinceReferenceDate)
  }
  
}

extension WebCompositor : LayerTreeHostClient {

  public func willBeginMainFrame() {
    delegate.willBeginCompositorFrame()
  }

  public func didBeginMainFrame() {}

  public func sendBeginFramesToChildren(args: BeginFrameArgs) {}
  
  public func scheduleComposite() {}

  public func beginMainFrame(args: BeginFrameArgs) {
    
    rendererScheduler.willBeginFrame(args: args)
    
    let date = Date()
    let frameTimeSec = (args.frameTime - date.timeIntervalSinceReferenceDate)
    
    delegate.beginMainFrame(frameTimeSec: frameTimeSec)
  }

  public func beginMainFrameNotExpectedSoon() {
    rendererScheduler.beginFrameNotExpectedSoon()
  }

  public func updateLayerTreeHost() {
    delegate.updateVisualState()
    
    if let copyOutputRequest = temporaryCopyOutputRequest {
      if let rootLayer = host.rootLayer {
        rootLayer.requestCopyOfOutput(request: copyOutputRequest)
      } else {
        copyOutputRequest.sendEmptyResult()
        temporaryCopyOutputRequest = nil
      }
    }
  
  }

  public func applyViewportDeltas(innerDelta: FloatVec2,
    outerDelta: FloatVec2,
    elasticOverscrollDelta: FloatVec2,
    pageScale: Float,
    topControlsDelta: Float) {
    
    delegate.applyViewportDeltas(
      innerDelta: innerDelta,
      outerDelta: outerDelta,
      elasticOverscrollDelta: elasticOverscrollDelta,
      pageScale: pageScale,
      topControlsDelta: topControlsDelta)
  }

  public func requestNewOutputSurface() {

    if delegate.isClosing() {
      return
    }

    let fallback = (numFailedRecreateAttempts >= WebCompositor.outputSurfaceRetriesBeforeFallback)
    
    guard let surface = delegate.createOutputSurface(fallback: fallback) else {
      didFailToInitializeOutputSurface()
      return
    }

    host.setOutputSurface(outputSurface: surface)
  }

  public func didInitializeOutputSurface() {
    numFailedRecreateAttempts = 0
  }

  public func didFailToInitializeOutputSurface() {
    numFailedRecreateAttempts =  numFailedRecreateAttempts + 1
   // Tolerate a certain number of recreation failures to work around races
   // in the output-surface-lost machinery.
   //LOG_IF(FATAL, (num_failed_recreate_attempts_ >= MAX_OUTPUT_SURFACE_RETRIES))
   //    << "Failed to create a fallback OutputSurface."

  // TODO: How to use this?

  //base::ThreadTaskRunnerHandle::Get()->PostTask(
  //    FROM_HERE, base::Bind(&RenderWidgetCompositor::RequestNewOutputSurface,
  //                          weak_factory_.GetWeakPtr()))
    
     // TODO: implement async version!
    //ThreadTaskRunnerHandle.instance().postTask(self, callback: WebCompositor.requestNewOutputSurface)
    assert(false)
    requestNewOutputSurface()
  }

  public func willCommit() {
    invokeLayoutAndPaintCallback()
  }

  public func didCommit() {
    delegate.didCommitCompositorFrame()
    rendererScheduler.didCommitFrameToCompositor()
  }

  public func didCommitAndDrawFrame() {
    delegate.didCommitAndDrawCompositorFrame()
  }

  public func didCompleteSwapBuffers() {
    delegate.didCompleteSwapBuffers()
    
    let threaded: Bool = compositorDeps.compositorImplThreadTaskRunner != nil ? true: false
    
    if !threaded {
      delegate.onSwapBuffersComplete()
    }
  }

  public func didCompletePageScaleAnimation() {
    delegate.didCompletePageScaleAnimation()
  }

  public func didPostSwapBuffers() {
    delegate.onSwapBuffersPosted()
  }

  public func didAbortSwapBuffers() {
    delegate.onSwapBuffersAborted()
  }

}

extension WebCompositor : WebLayerTreeView {
  
  public var viewport: IntSize {

    get {
      return host.viewportSize
    }

    set {
      host.viewportSize = newValue
    }

  }

  public var deviceScaleFactor: Float {
    
    get {
      return host.deviceScaleFactor
    }
    
    set {
      host.deviceScaleFactor = newValue
    }

  }

  public var backgroundColor: Color {
    
    get {
      return host.backgroundColor
    }

    set {
      host.backgroundColor = newValue
    }

  }

  public var hasTransparentBackground: Bool {
    
    get {
      return host.hasTransparentBackground
    }

    set {
      host.hasTransparentBackground = newValue
    }

  }

  public var rootLayer: WebLayer? {
    
    get {
      if let layer = host.rootLayer {
        return WebLayer(layer: layer)
      }
      return nil
    }

    set {
      if let layer = newValue {
        host.rootLayer = layer.cclayer
      } else {
        host.rootLayer = nil
      }
    }

  }

  public var layerTreeId: Int {
    return host.id
  }

  public var visible: Bool {
    
    get {
      return host.visible
    }

    set {
      guard !_neverVisible else {
        return
      }
      host.visible = newValue
    }

  }

  public var showFPSCounter: Bool {
    
    get {
      return host.debugState.showFPSCounter
    }

    set {
      var debugState = host.debugState
      debugState.showFPSCounter = newValue
      host.debugState = debugState
    }

  }

  public var showPaintRects: Bool {
    
    get {
      return host.debugState.showPaintRects
    }
    
    set {
      var debugState = host.debugState
      debugState.showPaintRects = newValue
      host.debugState = debugState
    }

  }

  public var showDebugBorders: Bool {
    
    get {
      return host.debugState.showDebugBorders
    }
    
    set {
      var debugState = host.debugState
      debugState.showDebugBorders = newValue
      host.debugState = debugState
    }

  }

  public var showScrollBottleneckRects: Bool {
    
    get {
      let state = host.debugState
      return state.showTouchEventHandlerRects && 
        state.showWheelEventHandlerRects && 
        state.showNonFastScrollableRects
    }

    set {
      var debugState = host.debugState
      debugState.showTouchEventHandlerRects = newValue
      debugState.showWheelEventHandlerRects = newValue
      debugState.showNonFastScrollableRects = newValue
      host.debugState = debugState
    }
  }

  public func clearRootLayer() {
    host.rootLayer = nil
  }

  public func attachCompositorAnimationTimeline(timeline: WebCompositorAnimationTimeline) {
    if let animationHost = host.animationHost {
      animationHost.addAnimationTimeline(timeline: timeline.animationTimeline)
    }
  }

  public func detachCompositorAnimationTimeline(timeline: WebCompositorAnimationTimeline) {
    if let animationHost = host.animationHost {
      animationHost.removeAnimationTimeline(timeline: timeline.animationTimeline)
    }
  }

  public func setPageScaleFactorAndLimits(scale: Float, minimum: Float, maximum: Float) {
    host.setPageScaleFactorAndLimits(pageScaleFactor: scale, minPageScaleFactor: minimum, maxPageScaleFactor: maximum)
  }

  public func startPageScaleAnimation(destination: IntPoint, useAnchor: Bool, newPageScale: Float, durationSec: Double) {
    let duration = TimeDelta.fromMicroseconds(ms: durationSec * Double(Time.MicrosecondsPerSecond))
  
    host.startPageScaleAnimation(
      targetOffset: IntVec2(x: destination.x, y: destination.y),
      useAnchor: useAnchor,
      scale: newPageScale,
      duration: TimeInterval(duration.seconds))
  }

  public func heuristicsForGpuRasterizationUpdated(heuristics: Bool) {
    host.hasGpuRasterizationTrigger = heuristics
  }

  public func setTopControlsShownRatio(ratio: Float) {
    host.setTopControlsShownRatio(ratio: ratio)
  }

  public func updateTopControlsState(
      constraints: InputTopControlsState, 
      current: InputTopControlsState, 
      animate: Bool) {
    
    host.updateTopControlsState(constraints: constraints,
                                current: current,
                                animate: animate)
  }

  public func setTopControlsHeight(height: Float, shrinkViewport: Bool) {
    host.setTopControlsHeight(height: height, shrink: shrinkViewport)
  }

  public func setNeedsAnimate() {
    host.setNeedsAnimate()
    host.setNeedsUpdateLayers()
  }

  public func setNeedsBeginFrame() {
    host.setNeedsAnimate()
  }

  public func setNeedsCompositorUpdate() {
    host.setNeedsUpdateLayers()
  }

  public func didStopFlinging() {
    host.didStopFlinging()
  }

  public func layoutAndPaintAsync(callback: WebLayoutAndPaintAsyncCallback) {
    
    guard temporaryCopyOutputRequest == nil && layoutAndPaintAsyncCallback == nil else {
      return
    }
    
    layoutAndPaintAsyncCallback = callback

    if compositeIsSynchronous {
      assert(false)
      // TODO: implement async version
      //ThreadTaskRunnerHandle.instance().postTask(self, callback: WebCompositor.layoutAndUpdateLayers)
      layoutAndUpdateLayers()
    } else {
      host.setNeedsCommit()
    }
  }

  public func compositeAndReadbackAsync(callback: WebCompositeAndReadbackAsyncCallback) {
    
    guard temporaryCopyOutputRequest == nil && layoutAndPaintAsyncCallback == nil else {
      return
    }

    //temporaryCopyOutputRequest = CopyOutputRequest.createBitmapRequest(compositeAndReadbackAsyncCallback, callback)
    temporaryCopyOutputRequest = CopyOutputRequest.createBitmapRequest(callback: callback)

  // Force a commit to happen. The temporary copy output request will
  // be installed after layout which will happen as a part of the commit, for
  // widgets that delay the creation of their output surface.
    if compositeIsSynchronous {
      // TODO: implement async version
      assert(false)
      //ThreadTaskRunnerHandle.instance().postTask(self, callback: WebCompositor.synchronouslyComposite)
      synchronouslyComposite()
    } else {
      host.setNeedsCommit()
    }

  }

  public func setDeferCommits(deferCommits: Bool) {
    host.setDeferCommits(deferCommits: deferCommits)
  }

  public func registerForAnimations(layer: WebLayer) {
    if let registrar = host.animationRegistrar {
      layer.cclayer.registerForAnimations(registrar: registrar)
    }
  }

  public func registerViewportLayers(
    overscrollElasticityLayer: WebLayer,
    pageScaleLayer: WebLayer,
    innerViewportScrollLayer: WebLayer,
    outerViewportScrollLayer: WebLayer) {

    host.registerViewportLayers(
      overscrollElasticityLayer: overscrollElasticityLayer.cclayer,
      pageScaleLayer: pageScaleLayer.cclayer,
      innerViewportScrollLayer: innerViewportScrollLayer.cclayer,
      outerViewportScrollLayer: outerViewportScrollLayer.cclayer)
  }

  public func clearViewportLayers() {
    host.registerViewportLayers(overscrollElasticityLayer: nil, pageScaleLayer: nil, innerViewportScrollLayer: nil, outerViewportScrollLayer: nil)
  }

  public func registerSelection(selection: LayerSelection) {
    host.registerSelection(selection: selection)
  }

  public func clearSelection() {
    let emptySelection = LayerSelection()
    host.registerSelection(selection: emptySelection)
  }

}
