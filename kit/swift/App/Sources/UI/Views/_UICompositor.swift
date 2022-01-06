// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Compositor
import Graphics
import Gpu
import Platform
import Foundation

public let compositorLockTimeoutMs: Int = 67

public typealias PresentationTimeCallback = (_: TimeTicks, _: TimeDelta, _: UInt32) -> Void

public protocol UICompositorAnimationObserver : class {
  func onAnimationStep(timestamp: TimeTicks)
  func onCompositingShuttingDown(compositor: UICompositor)
}

public protocol UICompositorBeginFrameObserver : class {
  func onSendBeginFrame(args: BeginFrameArgs)
}

public protocol UICompositorObserver : class {
  func onCompositingDidCommit(compositor: UICompositor)
  func onCompositingStarted(compositor: UICompositor, startTime: TimeTicks)
  func onCompositingEnded(compositor: UICompositor)
  func onCompositingAborted(compositor: UICompositor)
  func onCompositingLockStateChanged(compositor: UICompositor)
  func onCompositingShuttingDown(compositor: UICompositor)
  func onCompositingChildResizing(compositor: UICompositor)
}

public class UICompositor : HostFrameSinkClient {
  
  public private(set) var contextFactory: UIContextFactory

  //public private(set) var contextFactoryPrivate: UIContextFactoryPrivate

  public internal(set) var rootLayer: Layer? {
    get {
      return _rootLayer
    }
    set {
      guard _rootLayer !== newValue else {
        return
      }
      if let layer = _rootLayer {
        layer.resetCompositor()
      }
      _rootLayer = newValue
      rootWebLayer!.removeAllChildren()
      if let layer = _rootLayer {
        layer.setCompositor(compositor: self, rootLayer: rootWebLayer!)
      }
    }
  }

  public private(set) var animationTimeline: AnimationTimeline
  // The scale factor of the device that this compositor is
  // compositing layers on.
  public private(set) var deviceScaleFactor: Float = 1.0

  // The color space of the device that this compositor is being displayed on.
  public private(set) var outputColorSpace: ColorSpace = ColorSpace()

  public var displayColorMatrix: Mat4 {
    didSet {
//      if let context = contextFactoryPrivate {
      contextFactory.setDisplayColorMatrix(compositor: self, matrix: displayColorMatrix)
  //    }
    }
  }

  // Returns the size of the widget that is being drawn to in pixel coordinates.
  public private(set) var size: IntSize = IntSize()

  public var isVisible: Bool {
    get {
      return host.isVisible
    }
    set {
      host.isVisible = newValue
      // Visibility is reset when the output surface is lost, so this must also be
      // updated then.
      // TODO(fsamuel): Eliminate this call.
      //if let context = contextFactory {
      contextFactory.setDisplayVisible(compositor: self, visible: newValue)
     // }
    }
  }

  public var backgroundColor: Color {
    get {
      return host.backgroundColor
    }
    set {
      host.backgroundColor = newValue
      scheduleDraw()
    }
  }
  
  public var widget: AcceleratedWidget?
  //{
  //   didSet {
  //     assert(!widgetValid)
  //     widgetValid = true
  //     if outputSurfaceRequested {
  //       contextFactory.createOutputSurface(compositor: self)
  //     }
  //   }
  // }

  // Returns the vsync manager for this compositor.
  public private(set) var vsyncManager: UICompositorVSyncManager

  public private(set) var externalBeginFramesEnabled: Bool = false

  // This flag is used to force a compositor into software compositing even tho
  // in general chrome is using gpu compositing. This allows the compositor to
  // be created without a gpu context, and does not go through the gpu path at
  // all. This flag can not be used with a compositor that embeds any external
  // content via a SurfaceLayer, as they would not agree on what compositing
  // mode to use for resources, but may be used eg for tooltip windows.
  public private(set) var forceSoftwareCompositor: Bool = false

  // Returns the main thread task runner this compositor uses. Users of the
  // compositor generally shouldn't use this.
  public private(set) var taskRunner: SingleThreadTaskRunner?

  public var isLocked: Bool { 
    return lockManager.isLocked
  }

  // public var layerTreeDebugState: LayerTreeDebugState {
  //   get {
  //     return host.debugState
  //   }
  //   set {
  //     host.debugState = newValue      
  //   }
  // }

  public private(set) var layerAnimatorCollection: LayerAnimatorCollection!

  public private(set) var frameSinkId: FrameSinkId = FrameSinkId()

    // A sequence number of a current compositor frame for use with metrics.
  public private(set) var activatedFrameCount: Int = 0

  // Current vsync refresh rate per second.
  public private(set) var refreshRate: Float = 0.0

  // If true, all paint commands are recorded at pixel size instead of DIP.
  public private(set) var isPixelCanvas: Bool = false

  public private(set) var scrollInputHandler: ScrollInputHandler?

  public var hasTransparentBackground: Bool = false

  // -- // 

 // public var deviceScaleFactor : Float

  // public var rootLayer: Layer? {
  //   willSet(newRootLayer) {
  //     if rootLayer === newRootLayer {
  //       return
  //     }
  //     if rootLayer != nil {
  //       rootLayer!.resetCompositor()
  //     }
  //   }
  //   didSet {
  //     rootWebLayer!.removeAllChildren()
  //     if rootLayer != nil {
  //      rootLayer!.setCompositor(compositor: self, rootLayer: rootWebLayer!)
  //     }
  //   }
  // }

  // public var nativeWidget: AcceleratedWidget {
  //   didSet {
  //     assert(!widgetValid)
  //     widgetValid = true
  //     if outputSurfaceRequested {
  //       contextFactory.createOutputSurface(compositor: self)
  //     }
  //   }
  // }

  // public var visible: Bool {
  //   get {
  //     return host.visible
  //   }
  //   set {
  //     host.visible = newValue
  //   }
  // }

  // public var hasTransparentBackground: Bool {
  //   get {
  //     return host.hasTransparentBackground
  //   }
  //   set {
  //     host.hasTransparentBackground = newValue
  //   }
  // }

 
  // fileprivate(set) public var animatorCollection: LayerAnimatorCollection

  // fileprivate(set) public var surfaceIdAllocator: SurfaceIdAllocator

  // fileprivate(set) public var vsyncManager: UICompositorVSyncManager

  // fileprivate var host: LayerTreeHost!
  // fileprivate var outputSurfaceRequested: Bool
  // fileprivate var lastStartedFrame: Int
  // fileprivate var lastEndedFrame: Int
  // fileprivate var widgetValid: Bool
  // fileprivate var missedBeginFrameArgs: BeginFrameArgs?
  // fileprivate var beginFrameObservers: [UICompositorBeginFrameObserver]
  // // ---- //

  private var observerList: [UICompositorObserver] = []
  private var animationObserverList: [UICompositorAnimationObserver] = []
  // If nonzero, this is the refresh rate forced from the command-line.
  private var forcedRefreshRate: Double = 0.0

  // A map from child id to parent id.
  //private var childFrameSinks: [FrameSinkId: FrameSinkIdHash]
  private var childFrameSinks: [FrameSinkId: FrameSinkId] = [:]
  private var widgetValid: Bool = false
  private var layerTreeFrameSinkRequested: Bool = false
  private var animationHost: AnimationHost
  private var host: LayerTreeHost!
  private var _rootLayer: UI.Layer? 
  private var rootWebLayer: Compositor.Layer!

 // private var externalBeginFramesEnabled: Bool
  private var externalBeginFrameClient: ExternalBeginFrameClient?
  private var needsExternalBeginFrames: Bool = false

  //private let forceSoftwareCompositor: Bool

  //private var slowAnimations: ScopedAnimationDurationScaleMode?

  //private var outputColorSpace: ColorSpace
  private var blendingColorSpace: ColorSpace = ColorSpace()

  private var lockManager: UICompositorLockManager!

  // public init(factory contextFactory: UIContextFactory) throws {
  //   deviceScaleFactor = 0
  //   self.contextFactory = contextFactory
  //   nativeWidget = NullAcceleratedWidget
  //   vsyncManager = UICompositorVSyncManager()
  //   size = IntSize()
  //   animatorCollection = LayerAnimatorCollection()
  //   surfaceIdAllocator = contextFactory.createSurfaceIdAllocator()
  //   animationObservers = [UICompositorAnimationObserver]()
  //   widgetValid = false
  //   outputSurfaceRequested = false
  //   lastStartedFrame = 0
  //   lastEndedFrame = 0
  //   beginFrameObservers = [UICompositorBeginFrameObserver]()
  //   observers = [UICompositorObserver]()

  //   var sets = Compositor.LayerSettings(type: .ContentLayer)
  //   sets.isDefault = true
  //   rootWebLayer = try Compositor.Layer(settings: sets, client: nil)

  //   var params = LayerTreeHost.InitParams()
  //   var settings = LayerTreeSettings()

  //   settings.layersAlwaysAllowedLcdText = true

  //   params.settings = settings
  //   params.sharedBitmapManager = contextFactory.sharedBitmapManager
  //   params.gpuMemoryBufferManager = contextFactory.gpuMemoryBufferManager
  //   params.taskGraphRunner = contextFactory.taskGraphRunner
  //   params.client = self

  //   host = try LayerTreeHost(params: params)
  //   host.setSurfaceIdNamespace(idNamespace: surfaceIdAllocator.idNamespace)
  //   host.rootLayer = rootWebLayer
  //   host.visible = true

  //   animatorCollection.compositor = self
  // }

  public init(frameSinkId: FrameSinkId,
              contextFactory: UIContextFactory,
              // contextFactoryPrivate: UIContextFactoryPrivate,
              taskRunner: SingleThreadTaskRunner?,
              enableSurfaceSynchronization: Bool,
              enablePixelCanvas: Bool,
              singleThreaded: Bool = false,
              externalBeginFramesEnabled: Bool = false,
              forceSoftwareCompositor: Bool = false) {

    self.contextFactory = contextFactory
    // self.contextFactoryPrivate = contextFactoryPrivate
    self.frameSinkId = frameSinkId
    // TODO: this is a illusion.. we are using the task runner from
    //       the C++ side impl.. figure it out if we can share
    //       this from the swift thread to the c++ thread 
    //       (maybe tricky because of TLS cookies)
    displayColorMatrix = Mat4()
    animationTimeline = AnimationTimeline.create(id: AnimationIdProvider.nextTimelineId)
    isPixelCanvas = enablePixelCanvas
    animationHost = AnimationHost.createMainInstance()
    
    self.taskRunner = taskRunner
    vsyncManager = UICompositorVSyncManager()
    self.externalBeginFramesEnabled = externalBeginFramesEnabled
    self.forceSoftwareCompositor = forceSoftwareCompositor
    super.init() 
    
    layerAnimatorCollection = LayerAnimatorCollection(compositor: self)
    lockManager = UICompositorLockManager(taskRunner: taskRunner, client: self)
    
    let hostFrameSinkManager = contextFactory.hostFrameSinkManager
    hostFrameSinkManager.registerFrameSinkId(id: frameSinkId, client: self)
    hostFrameSinkManager.setFrameSinkDebugLabel(id: frameSinkId, label: "Compositor")
    
    self.rootWebLayer = Compositor.Layer.create()


    //let commandLine = CommandLine.forCurrentProcess()

    var settings = LayerTreeSettings()

    // This will ensure PictureLayers always can have LCD text, to match the
    // previous behaviour with ContentLayers, where LCD-not-allowed notifications
    // were ignored.
    settings.layersAlwaysAllowedLcdText = true
    // Use occlusion to allow more overlapping windows to take less memory.
    settings.useOcclusionForTilePrioritization = true
    refreshRate = Float(self.contextFactory.refreshRate)
    settings.mainFrameBeforeActivationEnabled = false

    // Disable edge anti-aliasing in order to increase support for HW overlays.
    settings.enableEdgeAntiAliasing = false

    //settings.initial_debug_state.show_fps_counter =
        //command_line->HasSwitch(cc::switches::kUIShowFPSCounter);
    //settings.initial_debug_state.show_layer_animation_bounds_rects =
        //command_line->HasSwitch(cc::switches::kUIShowLayerAnimationBounds);
    //settings.initial_debug_state.show_paint_rects =
        //command_line->HasSwitch(switches::kUIShowPaintRects);
    //settings.initial_debug_state.show_property_changed_rects =
        //command_line->HasSwitch(cc::switches::kUIShowPropertyChangedRects);
    //settings.initial_debug_state.show_surface_damage_rects =
       // command_line->HasSwitch(cc::switches::kUIShowSurfaceDamageRects);
    //settings.initial_debug_state.show_screen_space_rects =
        //command_line->HasSwitch(cc::switches::kUIShowScreenSpaceRects);

    //settings.initial_debug_state.SetRecordRenderingStats()
        //command_line->HasSwitch(cc::switches::kEnableGpuBenchmarking));
    settings.enableSurfaceSynchronization = enableSurfaceSynchronization

    settings.useZeroCopy = false//true//isUIZeroCopyEnabled

    settings.useLayerLists = false
        //command_line->HasSwitch(cc::switches::kUIEnableLayerLists);

    // UI compositor always uses partial raster if not using zero-copy. Zero copy
    // doesn't currently support partial raster.
    settings.usePartialRaster = !settings.useZeroCopy

    settings.useRgba4444 = false//true
        //command_line->HasSwitch(switches::kUIEnableRGBA4444Textures);

  #if os(macOS)
    // Using CoreAnimation to composite requires using GpuMemoryBuffers, which
    // require zero copy.
    settings.resource_settings.useGpuMemoryBufferResources =
        settings.useZeroCopy
    settings.enableElasticOverscroll = true
  #endif

    settings.memoryPolicy.bytesLimitWhenVisible = 512 * 1024 * 1024
    settings.memoryPolicy.priorityCutoffWhenVisible = Gpu.PriorityCutoff.allowNiceToHave

    settings.disallowNonExactResourceReuse = false //commandLine.hasSwitch(switches.DisallowNonExactResourceReuse)

    //if commandLine.hasSwitch(switches.runAllCompositorStagesBeforeDraw) {
    //  settings.waitForAllPipelineStagesBeforeDraw = true
    //  settings.enableLatencyRecovery = false
    //}

    settings.alwaysRequestPresentationTime = false
       // command_line->HasSwitch(cc::switches::kAlwaysRequestPresentationTime);

    // WARNING: check if we will want this in all cases or just when 
    //          we arwe using in-process compositor
    //if UI.compositorIsSingleThreaded {
    //  settings.singleThreadProxyScheduler = true
    //}

    //let beforeCreate = TimeTicks.now
    
    var params = LayerTreeHost.InitParams()
    params.client = self
    //params.taskGraphRunner = contextFactory.taskGraphRunner
    params.settings = settings
    //params.mainTaskRunner = taskRunner
    //params.mutatorHost = animationHost
    params.animationHost = animationHost
    params.isSingleThreaded = singleThreaded//UI.compositorIsSingleThreaded
    //host = LayerTreeHost.createSingleThreaded(self, params)
    
    host = LayerTreeHost(params: params)
    //if FeatureList.isEnabled(features.UiCompositorScrollWithLayers) {
    scrollInputHandler = ScrollInputHandler(inputHandler: host.inputHandler)
    //}

    animationHost.addAnimationTimeline(timeline: animationTimeline)

    host.rootLayer = self.rootWebLayer!
    host.isVisible = true

    // if commandLine.hasSwitch(switches.UISlowAnimations) {
    //   slowAnimations = ScopedAnimationDurationScaleMode(ScopedAnimationDurationScaleMode.SlowDuration)
    // }
  }

  deinit {
    // for observer in observers {
    //   observer.onCompositingShuttingDown(compositor: self)
    // }

    // for observer in animationObservers {
    //   observer.onCompositingShuttingDown(compositor: self)
    // }

    // if let layer = rootLayer {
    //   layer.resetCompositor()
    // }

    // contextFactory.removeCompositor(compositor: self)
    for observer in observerList {
      observer.onCompositingShuttingDown(compositor: self)
    }

    for observer in animationObserverList {
      observer.onCompositingShuttingDown(compositor: self)
    }

    if let layer = rootLayer {
      layer.resetCompositor()
    }

    //if animationTimeline != nil {
      animationHost.removeAnimationTimeline(timeline: animationTimeline)
    //}

    // Stop all outstanding draws before telling the ContextFactory to tear
    // down any contexts that the |host_| may rely upon.
    
    //host = nil

    contextFactory.removeCompositor(compositor: self)
    let hostFrameSinkManager = contextFactory.hostFrameSinkManager 
    for client in childFrameSinks.keys {
      hostFrameSinkManager.unregisterFrameSinkHierarchy(parent: frameSinkId, child: client)
    }
    hostFrameSinkManager.invalidateFrameSinkId(frameSinkId)
  }

  public func addFrameSink(id: FrameSinkId) {
    //guard let context = contextFactory else {
    //  return
    //}
    let _ = contextFactory.hostFrameSinkManager.registerFrameSinkHierarchy(parent: frameSinkId, child: id)
    childFrameSinks[id] = frameSinkId
  }
  
  public func removeFrameSink(id: FrameSinkId) {
    if childFrameSinks.removeValue(forKey: id) != nil {
      contextFactory.hostFrameSinkManager.unregisterFrameSinkHierarchy(parent: frameSinkId, child: id)
    }
  }

  public func onChildResizing() {
    for observer in observerList {
      observer.onCompositingChildResizing(compositor: self)
    }
  }

  public func scheduleDraw() {
    host.setNeedsCommit()
  }

  public func scheduleFullRedraw() {
    host.setNeedsRedrawRect(damaged: IntRect(size: host.deviceViewportSize))
    host.setNeedsCommit()
  }

  public func scheduleRedrawRect(damaged: IntRect) {
    host.setNeedsRedrawRect(damaged: damaged)
    host.setNeedsCommit()
  }

  public func disableSwapUntilResize() {
    //if let context = contextFactory {
    contextFactory.resizeDisplay(compositor: self, size: IntSize())
    //}
  }
  
  public func reenableSwap() {
    //if let context = contextFactory {    
    contextFactory.resizeDisplay(compositor: self, size: size)
    //}
  }
  
  // Sets the compositor's device scale factor and size.
  public func setScaleAndSize(scale: Float,
    sizeInPixel: IntSize,
    localSurfaceId: LocalSurfaceId) {
    
    // //print("UICompositor.setScaleAndSize: scale: \(scale) size: width = \(sizeInPixel.width) height = \(sizeInPixel.height), surface: valid? \(localSurfaceId.isValid)")

    let deviceScaleFactorChanged = deviceScaleFactor != scale
    deviceScaleFactor = scale

    // if size_ != size_in_pixel && local_surface_id.is_valid() {
    //   // A new LocalSurfaceId must be set when the compositor size changes.
    //   DCHECK_NE(local_surface_id, host_->local_surface_id())
    // }

    if !sizeInPixel.isEmpty {
      size = sizeInPixel
      host.setViewportSizeAndScale(viewport: sizeInPixel, scale: scale, surfaceId: localSurfaceId)
      rootWebLayer!.bounds = sizeInPixel
      // TODO(fsamuel): Get rid of ContextFactoryPrivate.
      //if let context = contextFactory {
      contextFactory.resizeDisplay(compositor: self, size: sizeInPixel)
      //}
    }
    if deviceScaleFactorChanged {
      if isPixelCanvas {
        host.recordingScaleFactor = scale
      }
      if let layer = rootLayer {
        layer.onDeviceScaleFactorChanged(deviceScaleFactor: scale)
      }
    }
  }
  
  public func getScrollOffsetForLayer(layerId: Int) -> ScrollOffset? {
    return host.inputHandler!.getScrollOffsetForLayer(layerId: layerId)
  }
  
  public func scrollLayerTo(layerId: Int, offset: ScrollOffset) -> Bool {
    return host.inputHandler!.scrollLayerTo(layerId: layerId, offset: offset)
  }

  public func setAuthoritativeVSyncInterval(interval: TimeDelta) {
    refreshRate = Float(Time.MillisecondsPerSecond / interval.milliseconds)
    //if let context = contextFactory {
    contextFactory.setAuthoritativeVSyncInterval(compositor: self, interval: interval)
    //}
    vsyncManager.setAuthoritativeVSyncInterval(interval: interval)
  }

  public func setDisplayVSyncParameters(timebase: TimeTicks, interval: TimeDelta) {
    var intervalMut = interval
    var timebaseMut = timebase
    if forcedRefreshRate > 0.0 {
      timebaseMut = TimeTicks()
      intervalMut = TimeDelta(delta: TimeDelta.from(seconds: 1).microseconds / Int64(forcedRefreshRate))
    }
    if interval.isZero {
      // TODO(brianderson): We should not be receiving 0 intervals.
      intervalMut = BeginFrameArgs.defaultInterval
    }
    refreshRate = Float(Time.MillisecondsPerSecond / intervalMut.milliseconds)

    //if let context = contextFactory {
    contextFactory.setDisplayVSyncParameters(compositor: self, timebase: timebaseMut, interval: intervalMut)
    //}
    vsyncManager.updateVSyncParameters(timebase: timebaseMut, interval: intervalMut)
  }

  public func setLocalSurfaceId(localSurfaceId: LocalSurfaceId) {
    host.localSurfaceId = localSurfaceId
  }

  public func setLayerTreeFrameSink(surface: LayerTreeFrameSink) {
    layerTreeFrameSinkRequested = false
    host.setLayerTreeFrameSink(surface: surface)//layerTreeFrameSink
    // Display properties are reset when the output surface is lost, so update it
    // to match the Compositor's.
    //if let context = contextFactory {
      contextFactory.setDisplayVisible(compositor: self, visible: host.isVisible)
      contextFactory.setDisplayColorSpace( compositor: self, blendingColorSpace: blendingColorSpace, outputColorSpace: outputColorSpace)
      contextFactory.setDisplayColorMatrix(compositor: self, matrix: displayColorMatrix)
    //}
  }

  public func setLatencyInfo(latencyInfo: LatencyInfo) {
    let swapPromise: SwapPromise = LatencyInfoSwapPromise(latency: latencyInfo, host: host)
    host.queueSwapPromise(swapPromise: swapPromise)
  }

  // Set the output color profile into which this compositor should render.
  public func setDisplayColorSpace(colorSpace: ColorSpace) {
    if outputColorSpace == colorSpace {
      return
    }
    outputColorSpace = colorSpace
    blendingColorSpace = outputColorSpace.blendingColorSpace
    // Do all ui::Compositor rasterization to sRGB because UI resources will not
    // have their color conversion results cached, and will suffer repeated
    // image color conversions.
    // https://crbug.com/769677
    host.setRasterColorSpace(ColorSpace.createSRGB())
    // Always force the ui::Compositor to re-draw all layers, because damage
    // tracking bugs result in black flashes.
    // https://crbug.com/804430
    // TODO(ccameron): Remove this when the above bug is fixed.
    host.setNeedsDisplayOnAllLayers()

    // Color space is reset when the output surface is lost, so this must also be
    // updated then.
    // TODO(fsamuel): Get rid of this.
    //if let context = contextFactory {
      contextFactory.setDisplayColorSpace(
        compositor: self, 
        blendingColorSpace: blendingColorSpace, 
        outputColorSpace: outputColorSpace)
    //}
  }

  public func setAcceleratedWidget(widget: AcceleratedWidget) {
    self.widget = widget
    widgetValid = true
    if layerTreeFrameSinkRequested {
      contextFactory.createLayerTreeFrameSink(compositor: self)
    }
  }
 
  public func releaseAcceleratedWidget() -> AcceleratedWidget {
    host.releaseLayerTreeFrameSink()
    contextFactory.removeCompositor(compositor: self)
    widgetValid = false
    let localWidget = widget
    widget = nil//Graphics.NullAcceleratedWidget
    return localWidget!
  }
  
  public func setExternalBeginFrameClient(client: ExternalBeginFrameClient?) {
    externalBeginFrameClient = client
    if let beginFrameClient = externalBeginFrameClient, needsExternalBeginFrames {
      beginFrameClient.onNeedsExternalBeginFrames(needsBeginFrames: true)
    }
  }

  public func issueExternalBeginFrame(args: BeginFrameArgs) {
    //if let context = contextFactory {
    contextFactory.issueExternalBeginFrame(compositor: self, args: args)
    //}
  }

  public func onDisplayDidFinishFrame(ack: BeginFrameAck) {
    if let client = externalBeginFrameClient {
      client.onDisplayDidFinishFrame(ack: ack)
    }
  }

  public func onNeedsExternalBeginFrames(needsBeginFrames: Bool) {
    if let client = externalBeginFrameClient {
      client.onNeedsExternalBeginFrames(needsBeginFrames: needsBeginFrames)
    }
    needsExternalBeginFrames = needsBeginFrames
  }

  public func addObserver(observer: UICompositorObserver) {
    observerList.append(observer) 
  }
  
  public func removeObserver(observer: UICompositorObserver) {
    for (i, elem) in observerList.enumerated() {
      if observer === elem {
        observerList.remove(at: i)
        break
      }
    }
  }

  public func hasObserver(observer: UICompositorObserver) -> Bool {
    for elem in observerList {
      if observer === elem {
        return true
      }
    }
    return false
  }

  public func addAnimationObserver(observer: UICompositorAnimationObserver) {
    //print("UICompositor.addAnimationObserver: calling host.setNeedsAnimate()")
    animationObserverList.append(observer)
    host.setNeedsAnimate()
  }

  public func removeAnimationObserver(observer: UICompositorAnimationObserver) {
    for (i, elem) in animationObserverList.enumerated() {
      if observer === elem {
        animationObserverList.remove(at: i)
        break
      }
    }
  }
  
  public func hasAnimationObserver(observer: UICompositorAnimationObserver) -> Bool {
    for elem in animationObserverList {
      if observer === elem {
        return true
      }
    }
    return false
  }

  public func getCompositorLock(
      client: UICompositorLockClient, 
      timeout: TimeDelta =
          TimeDelta.from(milliseconds: Int64(compositorLockTimeoutMs))) -> UICompositorLock? {
    return lockManager.getCompositorLock(client: client, timeout: timeout)
  } 

  public func requestPresentationTimeForNextFrame(callback: @escaping PresentationTimeCallback) {
    host.requestPresentationTimeForNextFrame(callback)
  }

  public func setOutputIsSecure(outputIsSecure: Bool) {
    //if let context = contextFactory {
    contextFactory.setOutputIsSecure(compositor: self, secure: outputIsSecure)
    //}
  }

  public func setAllowLocksToExtendTimeout(allowed: Bool) {
    lockManager.allowLocksToExtendTimeout = allowed
  }

  // // cc::LayerTreeHostSingleThreadClient implementation.
  // void DidSubmitCompositorFrame() override;
  // void DidLoseLayerTreeFrameSink() override {}

  // // viz::HostFrameSinkClient implementation.
  // void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
  // void OnFrameTokenChanged(uint32_t frame_token) override;

  public override func onFirstSurfaceActivation(surfaceInfo: SurfaceInfo) {
    
  }
 
  public override func onFrameTokenChanged(frameToken: UInt32) {
    
  }

  // // CompositorLockManagerClient implementation.
  // void OnCompositorLockStateChanged(bool locked) override;
  

  // NOTE: took the comment away..check if is still there
  //public func setOutputSurface(surface: OutputSurface) {
     //outputSurfaceRequested = false
     //host.outputSurface = surface
  //}

  // public func finishAllRendering() {
  //   host.finishAllRendering()
  // }

  // public func disableSwapUntilResize() {
  //   host.finishAllRendering()
  //   contextFactory.resizeDisplay(compositor: self, size: IntSize())
  // }

  // public func setLatencyInfo(latencyInfo: LatencyInfo) {
  //   let swapPromise = LatencyInfoSwapPromise(latency: latencyInfo)
  //   host.queueSwapPromise(swapPromise: swapPromise)
  // }

  // public func setScaleAndSize(scale inscale: Float, size: IntSize) {
  //   assert(inscale > 0)
  //   if !size.empty {
  //     self.size = size
  //     host.viewportSize = size
  //     rootWebLayer!.bounds = size
  //     contextFactory.resizeDisplay(compositor: self, size: size)
  //   }
  //   if deviceScaleFactor != inscale {
  //     deviceScaleFactor = inscale
  //     host.deviceScaleFactor = inscale
  //     if let layer = rootLayer {
  //       layer.onDeviceScaleFactorChanged(deviceScaleFactor: inscale)
  //     }
  //   }
  // }

  // public func setAuthoritativeVSyncInterval(interval: TimeDelta) {
  //   vsyncManager.setAuthoritativeVSyncInterval(interval: interval)
  // }

  // public func addObserver(observer: UICompositorObserver) {
  //   observers.append(observer)
  // }

  // public func removeObserver(observer: UICompositorObserver) {
  //   for (index, other) in observers.enumerated() {
  //     if observer === other {
  //       observers.remove(at: index)
  //     }
  //   }
  // }

  // public func hasObserver(observer: UICompositorObserver) -> Bool {
  //   for other in observers {
  //     if observer === other {
  //       return true
  //     }
  //   }
  //   return false
  // }

  // public func addAnimationObserver(observer: UICompositorAnimationObserver) {
  //   animationObservers.append(observer)
  //   host.setNeedsAnimate()
  // }

  // public func removeAnimationObserver(observer: UICompositorAnimationObserver) {
  //   for (index, other) in animationObservers.enumerated() {
  //     if observer === other {
  //       animationObservers.remove(at: index)
  //     }
  //   }
  // }

  // public func hasAnimationObserver(observer: UICompositorAnimationObserver) -> Bool {
  //   for other in animationObservers {
  //     if observer === other {
  //       return true
  //     }
  //   }
  //   return false
  // }

  // public func addBeginFrameObserver(observer: UICompositorBeginFrameObserver) {
  //   if beginFrameObservers.count > 0 {
  //     host.setChildrenNeedBeginFrames(childrenNeedBeginFrames: true)
  //   }

  //   beginFrameObservers.append(observer)

  //   if let missed = missedBeginFrameArgs {
  //     if missed.isValid {
  //       observer.onSendBeginFrame(args: missed)
  //     }
  //   }
  // }

  // public func removeBeginFrameObserver(observer: UICompositorBeginFrameObserver) {
  //   for (index, other) in animationObservers.enumerated() {
  //     if observer === other {
  //       beginFrameObservers.remove(at: index)
  //     }
  //   }
  // }


  // public func onWidgetDestroyed() {
  //   widgetValid = false
  // }

  // public func releaseAcceleratedWidget() -> AcceleratedWidget {
  //   assert(!visible)
  //   if !host.outputSurfaceLost() {
  //     let _ = host.releaseOutputSurface()
  //   }
  //   contextFactory.removeCompositor(compositor: self)
  //   widgetValid = false
  //   let w = nativeWidget
  //   nativeWidget = NullAcceleratedWidget
  //   return w
  // }

  // func sendDamagedRectsRecursive(layer: Layer) {
  //   layer.sendDamagedRects()
  //   for child in layer.children {
  //     sendDamagedRectsRecursive(layer: child)
  //   }
  // }

}


extension UICompositor : LayerTreeHostClient {

  // public func willBeginMainFrame() {}

  // public func didBeginMainFrame() {}

  // public func beginMainFrame(args: BeginFrameArgs) {
  //   for observer in animationObservers {
  //     observer.onAnimationStep(timestamp: args.frameTime)
  //   }
  //   if animationObservers.count > 0 {
  //     host.setNeedsAnimate()
  //   }
  // }

  // public func beginMainFrameNotExpectedSoon() {

  // }

  // public func updateLayerTreeHost() {
  //   if let layer = rootLayer {
  //     sendDamagedRectsRecursive(layer: layer)
  //   }
  // }

  // public func applyViewportDeltas(innerDelta: FloatVec2,
  //   outerDelta: FloatVec2,
  //   elasticOverscrollDelta: FloatVec2,
  //   pageScale: Float,
  //   topControlsDelta: Float) {

  // }

  // public func requestNewOutputSurface() {
  //   assert(!outputSurfaceRequested)
  //   outputSurfaceRequested = true
  //   if widgetValid {
  //     contextFactory.createOutputSurface(compositor: self)
  //   }
  // }

  // public func didInitializeOutputSurface() {

  // }

  // public func didFailToInitializeOutputSurface() {

  // }

  // public func willCommit() {

  // }

  // public func didCommit() {
  //   for observer in observers {
  //     observer.onCompositingDidCommit(compositor: self)
  //   }
  // }

  // public func didCommitAndDrawFrame() {

  // }

  // public func didCompleteSwapBuffers() {
  //   for observer in observers {
  //     observer.onCompositingEnded(compositor: self)
  //   }
  // }

  // public func didCompletePageScaleAnimation() {

  // }

  // public func sendBeginFramesToChildren(args: BeginFrameArgs) {
  //   for observer in beginFrameObservers {
  //     observer.onSendBeginFrame(args: args)
  //   }

  //   if beginFrameObservers.count == 0 {
  //     host.setChildrenNeedBeginFrames(childrenNeedBeginFrames: false)
  //     // Unsubscription should reset |missed_begin_frame_args_|, avoiding stale
  //     // BeginFrame dispatch when the next BeginFrame observer is added.
  //     missedBeginFrameArgs = BeginFrameArgs()
  //     return
  //   }

  //   missedBeginFrameArgs = args
  //   missedBeginFrameArgs!.type = .Missed
  // }


  // NEW VER

  public var isForSubframe: Bool {
    return false
  }

  public func willBeginMainFrame() {}
  
  public func beginMainFrame(args: BeginFrameArgs) {
    //print("UICompositor.beginMainFrame")
    for observer in animationObserverList {
      observer.onAnimationStep(timestamp: args.frameTime)
    }
    if animationObserverList.count > 0 {
      //print("UICompositor.beginMainFrame: calling host.setNeedsAnimate()")
      host.setNeedsAnimate()
    }
  }
  
  public func beginMainFrameNotExpectedSoon() {}
  
  public func beginMainFrameNotExpectedUntil(time: TimeTicks) {}
  
  public func didBeginMainFrame() {}
  
  public func updateLayerTreeHost(requestedUpdate: VisualStateUpdate) {
      
    //guard let layer = rootLayer, requestedUpdate != VisualStateUpdate.PrePaint else {
    guard let layer = rootLayer else {
      return
    }
    sendDamagedRectsRecursive(layer: layer)    
  }
  
  public func applyViewportDeltas(
    innerDelta: FloatVec2,
    outerDelta: FloatVec2,
    elasticOverscrollDelta: FloatVec2,
    pageScale: Float,
    topControlsDelta: Float) {
  }
  
  public func recordWheelAndTouchScrollingCount(
      hasScrolledByWheel: Bool,
      hasScrolledByTouch: Bool) {}
  
  public func requestNewLayerTreeFrameSink() {
    layerTreeFrameSinkRequested = true
    if widgetValid {
      contextFactory.createLayerTreeFrameSink(compositor: self)
    }
  }
  
  public func didInitializeLayerTreeFrameSink() {}
  public func didFailToInitializeLayerTreeFrameSink() {}
  
  public func willCommit() {}
  
  public func didCommit() {
    for observer in observerList {
      observer.onCompositingDidCommit(compositor: self)
    }
  }
  
  public func didCommitAndDrawFrame() {}
   
  public func didReceiveCompositorFrameAck() {
    activatedFrameCount += 1
    for observer in observerList {
      observer.onCompositingEnded(compositor: self)
    }
  }
  
  public func didCompletePageScaleAnimation() {}
}

extension UICompositor : LayerTreeHostSingleThreadClient {
  
  public func requestScheduleComposite() {}
  
  public func requestScheduleAnimation() {}
  
  public func didSubmitCompositorFrame() {
    let startTime = TimeTicks.now
    for observer in observerList {
      observer.onCompositingStarted(compositor: self, startTime: startTime)
    }
  }
  
  public func didLoseLayerTreeFrameSink() {}
}

extension UICompositor : UICompositorLockManagerClient {
  
  public func onCompositorLockStateChanged(locked: Bool) {
    host.setDeferCommits(deferCommits: locked)
    for observer in observerList {
      observer.onCompositingLockStateChanged(compositor: self)
    }
  }

}

//extension UICompositor : HostFrameSinkClient {
  //public func onFirstSurfaceActivation(surfaceInfo: SurfaceInfo) {}
  //public func onFrameTokenChanged(frameToken: UInt32) {}
//}

extension UICompositor : Hashable {
  
  // public var hashValue: Int {
  //   let hash = Unmanaged.passUnretained(self).toOpaque().hashValue
  //   return hash
  // }

  public func hash(into hasher: inout Hasher) {
    let hash = Unmanaged.passUnretained(self).toOpaque().hashValue
    hasher.combine(hash)
  }

  public static func ==(lhs: UICompositor, rhs: UICompositor) -> Bool {
    return lhs === rhs
  }

}

fileprivate func sendDamagedRectsRecursive(layer: Layer) {
  layer.sendDamagedRects()
  for child in layer.children {
    sendDamagedRectsRecursive(layer: child)
  }
}