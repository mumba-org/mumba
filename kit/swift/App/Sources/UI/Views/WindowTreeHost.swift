// Copyright (c) 2015-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

public protocol WindowTreeHostObserver: class {
  func onHostResized(host: WindowTreeHost)
  func onHostWorkspaceChanged(host: WindowTreeHost)
  func onHostMovedInPixels(host: WindowTreeHost, newOrigin: IntPoint)
  func onHostCloseRequested(host: WindowTreeHost)
}

public class WindowTreeHost : EventSource,
                              InputMethodDelegate,
                              DisplayObserver, 
                              UICompositorObserver {

  public override var eventSink: EventSink? {
    return dispatcher as? EventSink
  }

  public var rootTransform: Transform {
    get {
      var transform = Transform()
      transform.scale(x: deviceScaleFactor, y: deviceScaleFactor)
      transform = transform * window.layer!.transform
      return transform
    }
    set {
      window.setTransform(transform: newValue)
      updateRootWindowSizeInPixels()
    }
  }

  public var inverseRootTransform: Transform {
    var invert = Transform()
    let transform = rootTransform
    if !transform.getInverse(invert: &invert) {
      return transform
    }
    return invert
  }

  public var rootTransformForLocalEventCoordinates: Transform {
    return rootTransform
  }

  public var inverseTransformForLocalEventCoordinates: Transform {
    var invert = Transform()
    let transform = rootTransformForLocalEventCoordinates
    if !transform.getInverse(invert: &invert) {
      return transform
    }
    return invert
  }

  public var hasInputMethod: Bool {
    return _inputMethod != nil
  }

  public var displayId: Int64 {
    return Screen.getDisplayNearestWindow(windowId: window.id)!.id
  }

  public var eventSource: EventSource? {
    return nil
  }

  public var shouldAllocateLocalSurfaceId: Bool {
    return true
  }
  
  public var acceleratedWidget: AcceleratedWidget? {
    return nil
  }

  public var inputMethod: InputMethod {
    if _inputMethod == nil {
      _inputMethod = UI.createInputMethod(delegate: self, window: acceleratedWidget)
    }
    return _inputMethod!
  }

  public var boundsInPixels: IntRect {
    assert(false)
    return IntRect()
  }

  internal var locationOnScreenInPixels: IntPoint {
    assert(false)
    return IntPoint()
  }

  public private(set) var window: Window
  public private(set) var dispatcher: WindowEventDispatcher?
  public private(set) var compositor: UICompositor?
  public private(set) var deviceScaleFactor: Float = 1.0
  private var observers: [WindowTreeHostObserver] = []
  public private(set) var lastCursor: PlatformCursor?
  private var lastCursorRequestPositionInHost: IntPoint = IntPoint()
  private var holdingPointerMoves: Bool = false
  private var ownedInputMethod: Bool = true
  private var synchronizationStartTime: TimeTicks = TimeTicks()
  private var _inputMethod: InputMethod?

  // should be a temporary hack (should not retain a ref-count)
  internal static weak var tempInstance: WindowTreeHost?
  
  public class func create(compositor: UIWebWindowCompositor, bounds: IntRect) -> WindowTreeHost {
    return WindowTreeHostPlatform(compositor: compositor, bounds: bounds)
  }

  public static func getForAcceleratedWidget(window: AcceleratedWidget) -> WindowTreeHost? {
    return WindowTreeHost.tempInstance
  }

  public func initHost() {
    let display = Screen.getDisplayNearestWindow(windowId: window.id)
    self.deviceScaleFactor = display!.deviceScaleFactor
    
    updateRootWindowSizeInPixels()
    initCompositor()
    UI.notifyHostInitialized(host: self)
    //window.show()
  }

  public func addObserver(observer: WindowTreeHostObserver) {
    observers.append(observer)
  }

  public func removeObserver(observer: WindowTreeHostObserver) {
    if let index = observers.firstIndex(where: { $0 === observer }) {
      observers.remove(at: index)
    }
  }

  public func updateRootWindowSizeInPixels() {
    // Validate that the LocalSurfaceId does not change.
    //let compositorInitialized = compositor!.rootLayer != nil
    //lsiValidator = ScopedLocalSurfaceIdValidator(compositorInitialized ? self.window : nil)
    let transformedBoundsInPixels =
        getTransformedRootWindowBoundsInPixels(sizeInPixels: boundsInPixels.size)
    window.bounds = transformedBoundsInPixels
  }

  public func convertDIPToScreenInPixels(point: inout IntPoint) {
    convertDIPToPixels(point: &point)
    let location = locationOnScreenInPixels
    point.offset(x: location.x, y: location.y)
  }

  public func convertScreenInPixelsToDIP(point: inout IntPoint) {
    let location = locationOnScreenInPixels
    point.offset(x: -location.x, y: -location.y)
    convertPixelsToDIP(point: &point)
  }

  public func convertDIPToPixels(point: inout IntPoint) {
    var point3f = FloatPoint3(FloatPoint(point))
    rootTransform.transformPoint(point: &point3f)
    point = IntPoint.toFloored(point: FloatPoint(point3f))
  }

  public func convertPixelsToDIP(point: inout IntPoint) {
    var point3f = FloatPoint3(FloatPoint(point))
    inverseRootTransform.transformPoint(point: &point3f)
    point = IntPoint.toFloored(point: FloatPoint(point3f))
  }

  public func setCursor(_ platformCursor: PlatformCursor) {
    lastCursor = platformCursor
    setCursorNative(cursor: platformCursor)
  }

  public func onCursorVisibilityChanged(visible show: Bool) {
    if !show {
      let details: EventDispatchDetails =
          dispatcher!.dispatchMouseExitAtPoint(target: nil, point: dispatcher!.lastMouseLocationInRoot)
      if details.dispatcherDestroyed {
        return
      }
    }

    onCursorVisibilityChangedNative(show: show)  
  }

  public func moveCursorToLocationInDIP(location locationInDIP: IntPoint) {
    var hostLocation = locationInDIP
    convertDIPToPixels(point: &hostLocation)
    moveCursorToInternal(rootLocation: locationInDIP, hostLocation: hostLocation)
  }

  public func moveCursorToLocationInPixels(location locationInPixels: IntPoint) {
    var rootLocation = locationInPixels
    convertPixelsToDIP(point: &rootLocation)
    moveCursorToInternal(rootLocation: rootLocation, hostLocation: locationInPixels) 
  }

  public func setSharedInputMethod(inputMethod: InputMethod?) {
    _inputMethod = inputMethod
    ownedInputMethod = false
  }

  public func dispatchKeyEventPostIME(event: KeyEvent) -> EventDispatchDetails {
    dispatcher!.skipIme = true
    // We should bypass event rewriters here as they've been tried before.
    let dispatchDetails: EventDispatchDetails = eventSink!.onEventFromSource(event: event)
    if !dispatchDetails.dispatcherDestroyed {
      dispatcher!.skipIme = false
    }
    return dispatchDetails
  }

  public func show() {
    compositor!.isVisible = true
    showImpl()
    window.show()
  }

  public func hide() {
    hideImpl()
    if let c = compositor {
      c.isVisible = false
    }
  }

  public func setBoundsInPixels(bounds: IntRect, localSurfaceId: LocalSurfaceId = LocalSurfaceId()) {
    assert(false)
  }

  public func setCapture() {}
  public func releaseCapture() {}

  internal func destroyCompositor() {
    if compositor != nil {
      compositor!.removeObserver(observer: self)
      compositor = nil
    }
  }

  internal func destroyDispatcher() {
    //window = nil
    dispatcher = nil
  }

  // internal func createCompositor(
  //   frameSinkId: FrameSinkId = FrameSinkId(),
  //   forceSoftwareCompositor: Bool = false,
  //   externalBeginFramesEnabled: Bool = false) throws {

  //   compositor = UICompositor(
  //     frameSinkId: frameSinkId.isValid
  //         ? frameSinkId
  //         : UI.contextFactory!.allocateFrameSinkId(),
  //     contextFactory: UI.contextFactory!,
  //     //contextFactoryPrivate: UI.contextFactory!,
  //     taskRunner: nil,//ThreadTaskRunnerHandle.get(),
  //     enableSurfaceSynchronization: true,
  //     enablePixelCanvas: false,//true,
  //     externalBeginFramesEnabled: externalBeginFramesEnabled,
  //     forceSoftwareCompositor: forceSoftwareCompositor)

  //   compositor!.addObserver(observer: self)
  //   if dispatcher == nil {  
  //     try window.initialize(type: LayerType.None)
  //     window.host = self
  //     window.name = "RootWindow"
  //     window.eventTargeter = WindowTargeter()
  //     dispatcher = WindowEventDispatcher(self)
  //   }
  // }

  internal func createCompositor(compositor webCompositor: UIWebWindowCompositor) throws {
    compositor = UICompositor(compositor: webCompositor)
    compositor!.addObserver(observer: self)
    if dispatcher == nil {  
      try window.initialize(type: LayerType.None)
      window.host = self
      window.name = "RootWindow"
      window.eventTargeter = WindowTargeter()
      dispatcher = WindowEventDispatcher(self)
    }
  }

  internal func initCompositor() {
    compositor!.setScaleAndSize(
      scale: deviceScaleFactor, 
      sizeInPixel: boundsInPixels.size,
      localSurfaceId: window.localSurfaceId)
    compositor!.rootLayer = window.layer!
    let display = Screen.getDisplayNearestWindow(windowId: window.id)//Screen.instance.getDisplayNearestWindow(window)
    compositor!.setDisplayColorSpace(colorSpace: display!.colorspace)
  }

  internal func onAcceleratedWidgetAvailable() {
    // TODO: FIX
    WindowTreeHost.tempInstance = self
    compositor!.setAcceleratedWidget(widget: acceleratedWidget!)
  }

  internal func onHostMovedInPixels(newLocation: IntPoint) {
    for observer in observers {
      observer.onHostMovedInPixels(host: self, newOrigin: newLocation)
    }
  }

  public func onHostResizedInPixels(_ newSize: IntSize, localSurfaceId newLocalSurfaceId: LocalSurfaceId = LocalSurfaceId()) {
    let display = Screen.getDisplayNearestWindow(windowId: window.id)//instance.getDisplayNearestWindow(window: window)
    
    self.deviceScaleFactor = display!.deviceScaleFactor
    updateRootWindowSizeInPixels()

    // Allocate a new LocalSurfaceId for the new state.
    var localSurfaceId = newLocalSurfaceId
    if shouldAllocateLocalSurfaceId && !newLocalSurfaceId.isValid {
      //self.window.allocateLocalSurfaceId()
      self.window.allocateSurfaceId()
      localSurfaceId = window.localSurfaceId
    }
    //let lsiValidator = ScopedLocalSurfaceIdValidator(self.window)

    compositor!.setScaleAndSize(scale: self.deviceScaleFactor,
                                sizeInPixel: newSize,
                                localSurfaceId: localSurfaceId)

    for observer in observers {
      observer.onHostResized(host: self)
    }
  }

  internal func onHostWorkspaceChanged() {
    for observer in observers {
      observer.onHostWorkspaceChanged(host: self)
    }
  }
  
  internal func onHostDisplayChanged() {
    guard let c = compositor else {
      return
    }
    let display = Screen.getDisplayNearestWindow(windowId: window.id)//Screen.instance.getDisplayNearestWindow(window)
    c.setDisplayColorSpace(colorSpace: display!.colorspace)
  }
  
  public func onHostCloseRequested() {
    for observer in observers {
      observer.onHostCloseRequested(host: self)
    }
  }
  
  public func onHostActivated() {
    UI.notifyHostActivated(host: self)
  }
  
  public func onHostLostWindowCapture() {
    //guard let w = window else {
    //  return
    //}
    if let captureWindow = UI.getCaptureClient(window: window)?.captureWindow {
      if captureWindow.rootWindow === window {
        captureWindow.releaseCapture()
      }
    }
  }

  internal func setCursorNative(cursor: PlatformCursor) {
    //assert(false)
  }

  internal func moveCursorToScreenLocationInPixels(location locationInPixels: IntPoint) {
    //assert(false)
  }

  internal func onCursorVisibilityChangedNative(show: Bool) {
    //assert(false)
  }

  internal func showImpl() {
    //assert(false)
  }

  internal func hideImpl() {
    //assert(false)
  }

  // not implemented
  public func onDisplayAdded(display newDisplay: Display) {}
  public func onDisplayRemoved(display oldDisplay: Display) {}
  public func onDisplayMetricsChanged(display: Display,
                                        metrics: UInt32)  {}

  internal func captureSystemKeyEventsImpl(nativeKeyCodes: [Int]?) -> Bool {
    //assert(false)
    return false
  }

  
  internal func releaseSystemKeyEventCapture() {
    //assert(false)
  }

  internal func isKeyLocked(nativeKeyCode: Int) -> Bool {
    //assert(false)
    return false
  }

  internal func getTransformedRootWindowBoundsInPixels(sizeInPixels: IntSize) -> IntRect {
    let bounds = IntRect(size: sizeInPixels)
    var newBounds = FloatRect.scale(rect: FloatRect(bounds), factor: 1.0 / self.deviceScaleFactor)
    window.layer!.transform.transformRect(rect: &newBounds)
    return IntRect.toEnclosingRect(rect: newBounds)//Graphics.toEnclosingRect(newBounds)
  }

  private func moveCursorToInternal(rootLocation: IntPoint,
                                    hostLocation: IntPoint) {
    lastCursorRequestPositionInHost = hostLocation
    moveCursorToScreenLocationInPixels(location: hostLocation)
    if let cursorClient = window.cursorClient {
      let display = Screen.getDisplayNearestWindow(windowId: window.id)
      cursorClient.setDisplay(display: display!)
    }
    dispatcher!.onCursorMovedToRootLocation(rootLocation: rootLocation)
  }

  
  public func onCompositingDidCommit(compositor: UICompositor) {
    if !self.holdingPointerMoves  {
      return
    }

    dispatcher!.releasePointerMoves()
    self.holdingPointerMoves = false  
  }

  public func onCompositingStarted(compositor: UICompositor,
                                    startTime: TimeTicks) {}
  public func onCompositingEnded(compositor: UICompositor) {}
  public func onCompositingLockStateChanged(compositor: UICompositor) {}
  public func onCompositingAborted(compositor: UICompositor) {}
  public func onCompositingChildResizing(compositor: UICompositor) {
    if !UI.throttleInputOnResize || self.holdingPointerMoves {
      return
    }
    self.synchronizationStartTime = TimeTicks.now
    dispatcher!.holdPointerMoves()
    self.holdingPointerMoves = true
  }

  public func onCompositingShuttingDown(compositor: UICompositor) {
    compositor.removeObserver(observer: self)
  }

  internal override init() {
    window = Window()  
    ownedInputMethod = false
    super.init()
    Screen.instance.addObserver(self)
  }

  deinit {
    Screen.instance.removeObserver(self)
    WindowTreeHost.tempInstance = nil
  }

}

