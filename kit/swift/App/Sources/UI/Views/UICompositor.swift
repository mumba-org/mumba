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

public class UICompositor {
  
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
      //rootWebLayer!.removeAllChildren()
      if let layer = _rootLayer {
        layer.setCompositor(compositor: self, rootLayer: rootWebLayer!)
      }
    }
  }

  public private(set) var animationTimeline: AnimationTimeline
  public private(set) var deviceScaleFactor: Float = 1.0
  public private(set) var outputColorSpace: ColorSpace = ColorSpace()
  public private(set) var size: IntSize = IntSize()

  public var isVisible: Bool {
    get {
      return compositor.isVisible
    }
    set {
      compositor.isVisible = newValue
    }
  }

  public var backgroundColor: Color {
    get {
      return compositor.backgroundColor
    }
    set {
      compositor.backgroundColor = newValue
      scheduleDraw()
    }
  }
  
  public var widget: AcceleratedWidget?

  // Returns the vsync manager for this compositor.
  public private(set) var vsyncManager: UICompositorVSyncManager

  public var isLocked: Bool { 
    return false//return lockManager.isLocked
  }

  public var animationHost: AnimationHost {
    return compositor.animationHost!
  }

  public private(set) var layerAnimatorCollection: LayerAnimatorCollection!
  public private(set) var activatedFrameCount: Int = 0
  public private(set) var refreshRate: Float = 0.0
  public private(set) var isPixelCanvas: Bool = false
  public private(set) var scrollInputHandler: ScrollInputHandler?
  public var hasTransparentBackground: Bool = false
  private var observerList: [UICompositorObserver] = []
  private var animationObserverList: [UICompositorAnimationObserver] = []
  private var forcedRefreshRate: Double = 0.0
  private var widgetValid: Bool = false
  //private var animationHost: AnimationHost
  //private var host: LayerTreeHost!
  //private var _rootLayer: UI.Layer? 
  //private var rootWebLayer: Compositor.Layer!
  //private var externalBeginFrameClient: ExternalBeginFrameClient?
  //private var needsExternalBeginFrames: Bool = false
  private var blendingColorSpace: ColorSpace = ColorSpace()
 // private var lockManager: UICompositorLockManager!
  public let compositor: UIWebWindowCompositor
  private var _rootLayer: UI.Layer? 
  private var rootWebLayer: Compositor.Layer?

  public init(compositor: UIWebWindowCompositor) {
    self.compositor = compositor
    animationTimeline = AnimationTimeline.create(id: AnimationIdProvider.nextTimelineId)
    vsyncManager = UICompositorVSyncManager() 
    layerAnimatorCollection = LayerAnimatorCollection(compositor: self)
   // lockManager = UICompositorLockManager(taskRunner: taskRunner, client: self)
    scrollInputHandler = ScrollInputHandler(inputHandler: compositor.layerTreeHost.inputHandler)
    rootWebLayer = compositor.rootLayer
    compositor.addObserver(self)
    animationHost.addAnimationTimeline(timeline: animationTimeline)
  }

  deinit {
    for observer in observerList {
      observer.onCompositingShuttingDown(compositor: self)
    }

    for observer in animationObserverList {
      observer.onCompositingShuttingDown(compositor: self)
    }

    animationHost.removeAnimationTimeline(timeline: animationTimeline)
    compositor.removeObserver(self)
  }

  public func onChildResizing() {
    for observer in observerList {
      observer.onCompositingChildResizing(compositor: self)
    }
  }

  public func scheduleDraw() {
    compositor.layerTreeHost.setNeedsCommit()
  }

  public func scheduleFullRedraw() {
    compositor.layerTreeHost.setNeedsRedrawRect(damaged: IntRect(size: compositor.layerTreeHost.deviceViewportSize))
    compositor.layerTreeHost.setNeedsCommit()
  }

  public func scheduleRedrawRect(damaged: IntRect) {
    compositor.layerTreeHost.setNeedsRedrawRect(damaged: damaged)
    compositor.layerTreeHost.setNeedsCommit()
  }

  public func disableSwapUntilResize() {
    //if let context = contextFactory {
    //contextFactory.resizeDisplay(compositor: self, size: IntSize())
    //}
  }
  
  public func reenableSwap() {
    //if let context = contextFactory {    
    //contextFactory.resizeDisplay(compositor: self, size: size)
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
      //compositor.layerTreeHost.setViewportSizeAndScale(viewport: sizeInPixel, scale: scale, surfaceId: localSurfaceId)
      //rootWebLayer!.bounds = sizeInPixel
      //compositor.rootLayer!.bounds = sizeInPixel
      // TODO(fsamuel): Get rid of ContextFactoryPrivate.
      //if let context = contextFactory {
      //contextFactory.resizeDisplay(compositor: self, size: sizeInPixel)
      //}
    }
    if deviceScaleFactorChanged {
      if isPixelCanvas {
        compositor.layerTreeHost.recordingScaleFactor = scale
      }
      if let layer = rootLayer {
        layer.onDeviceScaleFactorChanged(deviceScaleFactor: scale)
      }
    }
  }
  
  public func getScrollOffsetForLayer(layerId: Int) -> ScrollOffset? {
    return compositor.layerTreeHost.inputHandler!.getScrollOffsetForLayer(layerId: layerId)
  }
  
  public func scrollLayerTo(layerId: Int, offset: ScrollOffset) -> Bool {
    return compositor.layerTreeHost.inputHandler!.scrollLayerTo(layerId: layerId, offset: offset)
  }

  public func setAuthoritativeVSyncInterval(interval: TimeDelta) {
    refreshRate = Float(Time.MillisecondsPerSecond / interval.milliseconds)
    //if let context = contextFactory {
    //contextFactory.setAuthoritativeVSyncInterval(compositor: self, interval: interval)
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
    //contextFactory.setDisplayVSyncParameters(compositor: self, timebase: timebaseMut, interval: intervalMut)
    //}
    vsyncManager.updateVSyncParameters(timebase: timebaseMut, interval: intervalMut)
  }

  //public func setLocalSurfaceId(localSurfaceId: LocalSurfaceId) {
    //host.localSurfaceId = localSurfaceId
  //}

  //public func setLayerTreeFrameSink(surface: LayerTreeFrameSink) {
    //layerTreeFrameSinkRequested = false
    //host.setLayerTreeFrameSink(surface: surface)//layerTreeFrameSink
    // Display properties are reset when the output surface is lost, so update it
    // to match the Compositor's.
    //if let context = contextFactory {
    //  contextFactory.setDisplayVisible(compositor: self, visible: host.isVisible)
    //  contextFactory.setDisplayColorSpace( compositor: self, blendingColorSpace: blendingColorSpace, outputColorSpace: outputColorSpace)
    //  contextFactory.setDisplayColorMatrix(compositor: self, matrix: displayColorMatrix)
    //}
  //}

  //public func setLatencyInfo(latencyInfo: LatencyInfo) {
  //  let swapPromise: SwapPromise = LatencyInfoSwapPromise(latency: latencyInfo, host: host)
  //  host.queueSwapPromise(swapPromise: swapPromise)
  //}

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
    compositor.layerTreeHost.setRasterColorSpace(ColorSpace.createSRGB())
    // Always force the ui::Compositor to re-draw all layers, because damage
    // tracking bugs result in black flashes.
    // https://crbug.com/804430
    // TODO(ccameron): Remove this when the above bug is fixed.
    compositor.layerTreeHost.setNeedsDisplayOnAllLayers()

    // Color space is reset when the output surface is lost, so this must also be
    // updated then.
    // TODO(fsamuel): Get rid of this.
    //if let context = contextFactory {
    //  contextFactory.setDisplayColorSpace(
    //    compositor: self, 
    //    blendingColorSpace: blendingColorSpace, 
    //    outputColorSpace: outputColorSpace)
    //}
  }

  public func setAcceleratedWidget(widget: AcceleratedWidget) {
    self.widget = widget
    widgetValid = true
    //if layerTreeFrameSinkRequested {
    //  contextFactory.createLayerTreeFrameSink(compositor: self)
    //}
  }
 
  public func releaseAcceleratedWidget() -> AcceleratedWidget {
    //host.releaseLayerTreeFrameSink()
    //contextFactory.removeCompositor(compositor: self)
    //widgetValid = false
    //let localWidget = widget
    //widget = nil//Graphics.NullAcceleratedWidget
    //return localWidget!
    return Graphics.NullAcceleratedWidget
  }
  
  //public func setExternalBeginFrameClient(client: ExternalBeginFrameClient?) {
  //  externalBeginFrameClient = client
  //  if let beginFrameClient = externalBeginFrameClient, needsExternalBeginFrames {
  //    beginFrameClient.onNeedsExternalBeginFrames(needsBeginFrames: true)
  //  }
  //}

  //public func issueExternalBeginFrame(args: BeginFrameArgs) {
    //if let context = contextFactory {
  //  contextFactory.issueExternalBeginFrame(compositor: self, args: args)
    //}
  //}

  //public func onDisplayDidFinishFrame(ack: BeginFrameAck) {
  //  if let client = externalBeginFrameClient {
  //    client.onDisplayDidFinishFrame(ack: ack)
  //  }
  //}

  //public func onNeedsExternalBeginFrames(needsBeginFrames: Bool) {
  //  if let client = externalBeginFrameClient {
  //    client.onNeedsExternalBeginFrames(needsBeginFrames: needsBeginFrames)
  //  }
  //  needsExternalBeginFrames = needsBeginFrames
  //}

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
    animationObserverList.append(observer)
    compositor.layerTreeHost.setNeedsAnimate()
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
    //return lockManager.getCompositorLock(client: client, timeout: timeout)
    return nil
  } 

  public func requestPresentationTimeForNextFrame(callback: @escaping PresentationTimeCallback) {
    compositor.layerTreeHost.requestPresentationTimeForNextFrame(callback)
  }

  //public func setOutputIsSecure(outputIsSecure: Bool) {
    //if let context = contextFactory {
    //contextFactory.setOutputIsSecure(compositor: self, secure: outputIsSecure)
    //}
  //}

  public func setAllowLocksToExtendTimeout(allowed: Bool) {
    //lockManager.allowLocksToExtendTimeout = allowed
  }

  // // cc::LayerTreeHostSingleThreadClient implementation.
  // void DidSubmitCompositorFrame() override;
  // void DidLoseLayerTreeFrameSink() override {}

  // // viz::HostFrameSinkClient implementation.
  // void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
  // void OnFrameTokenChanged(uint32_t frame_token) override;

  //public override func onFirstSurfaceActivation(surfaceInfo: SurfaceInfo) {
    
  //}
 
  //public override func onFrameTokenChanged(frameToken: UInt32) {
    
  //}

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


extension UICompositor : UIWebWindowCompositorObserver {

  public func beginMainFrame(args: BeginFrameArgs) {
    for observer in animationObserverList {
      observer.onAnimationStep(timestamp: args.frameTime)
    }
    if animationObserverList.count > 0 {
      compositor.layerTreeHost.setNeedsAnimate()
    }
  }
  
  public func updateLayerTreeHost(requestedUpdate: VisualStateUpdate) {    
    guard let layer = rootLayer else {
      return
    }
    sendDamagedRectsRecursive(layer: layer)    
  }
  
  public func didCommit() {
    for observer in observerList {
      observer.onCompositingDidCommit(compositor: self)
    }
  }
     
  public func didReceiveCompositorFrameAck() {
    activatedFrameCount += 1
    for observer in observerList {
      observer.onCompositingEnded(compositor: self)
    }
  }

  public func didSubmitCompositorFrame() {
    let startTime = TimeTicks.now
    for observer in observerList {
      observer.onCompositingStarted(compositor: self, startTime: startTime)
    }
  }
}

extension UICompositor : UICompositorLockManagerClient {
  
  public func onCompositorLockStateChanged(locked: Bool) {
    compositor.layerTreeHost.setDeferCommits(deferCommits: locked)
    for observer in observerList {
      observer.onCompositingLockStateChanged(compositor: self)
    }
  }

}

extension UICompositor : Hashable {
  
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