// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Platform
import Compositor

public protocol WindowTreeHostObserver: class {
  func onHostResized(host: WindowTreeHost)
  func onHostMoved(host: WindowTreeHost, newOrigin: IntPoint)
  func onHostCloseRequested(host: WindowTreeHost)
}

// WindowTreeHost + WindowTreeHostPlatform all-in-one
public class WindowTreeHost : EventSource {

  private(set) public var window: Window

  private(set) public var dispatcher: WindowEventDispatcher?

  private(set) public var compositor: UICompositor?

  private(set) public var platformWindow: PlatformWindow?

  private(set) public var cursor: PlatformCursor?

  public var inputMethod: InputMethod? {
    if _inputMethod == nil {
      _inputMethod = UI.createInputMethod(delegate: self, window: nativeWidget)
    }
    return _inputMethod
  }

  private(set) public var eventSource: EventSource?

  // from EventSource
  public override var eventProcessor: EventProcessor? {
    return dispatcher
  }

  public var locationOnNativeScreen: IntPoint {
    return platformWindow!.bounds.origin
  }

  // public var bounds: IntRect {
  //   get {
  //     if let win = platformWindow {
  //       return win.bounds
  //     }
  //     return IntRect()
  //   }
  //   set {
  //     if let win = platformWindow {
  //       win.bounds = newValue
  //     }
  //   }
  // }

  public var boundsInPixels: IntRect {
    assert(false)
  }

  public var rootTransform: Transform {
    get {
      var transform = Transform()
      if let layer = window.layer {
        let scale = UI.getDeviceScaleFactor(layer: layer)
        transform.scale(x: scale, y: scale)
        transform = transform * layer.transform
      }
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

  public var nativeWidget: AcceleratedWidget?

  //public var outputSurfacePadding: IntInsets {
  //  didSet {
  //     onHostResized(newSize: bounds.size)
  //  }
  //}

  private var observers: [WindowTreeHostObserver]
  private var hasCapture: Bool
  private var lastCursorRequestPositionInHost: IntPoint
  private var _inputMethod: InputMethod?
  private var holdingPointerMoves: Bool = false
  private var synchronizationStartTime: TimeTicks = TimeTicks()

  static var properties: [AcceleratedWidget: WindowTreeHost?] = [AcceleratedWidget: WindowTreeHost?]()

  public static func getForAcceleratedWidget(window: AcceleratedWidget) -> WindowTreeHost? {
    if let host = WindowTreeHost.properties[window] {
      return host
    }
    return nil
  }

  public override init() {
    observers = [WindowTreeHostObserver]()
    //dispatcher = WindowEventDispatcher(self)
    window = Window()
    hasCapture = false
    lastCursorRequestPositionInHost = IntPoint()
    outputSurfacePadding = IntInsets()
    super.init()
  }

  public func initHost() throws {
    // TODO: change to UI.createPlatformWindow()
    //platformWindow = try UI.platform.createWindow(self, bounds: window.bounds)
    initCompositor()
    updateRootWindowSizeInPixels()//(hostSize: bounds.size)
    UI.notifyHostInitialized(host: self)
    window.show()
  }

  public func initCompositor() {
    compositor!.setScaleAndSize(
      scale: getDeviceScaleFactor(window: window), 
      sizeInPixel: bounds.size,
      localSurfaceId: window.localSurfaceId)
    compositor!.rootLayer = window.layer!
  }

  public func addObserver(observer: WindowTreeHostObserver) {
    observers.append(observer)
  }

  public func removeObserver(observer: WindowTreeHostObserver) {
    for (index, item) in observers.enumerated() {
      if observer === item {
        observers.remove(at: index)
      }
    }
  }

  // public func updateRootWindowSize(hostSize: IntSize) {
  //   if let layer = window.layer {
  //     let localBounds = IntRect(x: outputSurfacePadding.left,
  //                  y: outputSurfacePadding.top, width: hostSize.width,
  //                  height: hostSize.height)
  //     var newBounds = FloatRect(UI.convertRectToDIP(layer: layer, localBounds))
      
  //     layer.transform.transformRect(rect: &newBounds)
  //     let finalBounds = IntRect(size: IntSize.toFloored(newBounds.size))
  //     window.bounds = finalBounds
  //   }
  // }

  public func updateRootWindowSizeInPixels() {
    // Validate that the LocalSurfaceId does not change.
    let compositorInitialized = compositor.rootLayer != nil
    lsiValidator = ScopedLocalSurfaceIdValidator(compositorInitialized ? self.window : nil)
    let transformedBoundsInPixels =
        getTransformedRootWindowBoundsInPixels(boundsInPixels.size)
    window.bounds = transformedBoundsInPixels
  }


  public func convertPointToNativeScreen(point: inout IntPoint) {
    convertPointToHost(point: &point)
    let location = locationOnNativeScreen
    point.offset(x: location.x, y: location.y)
  }

  public func convertPointFromNativeScreen(point: inout IntPoint) {
    let location = locationOnNativeScreen
    point.offset(x: -location.x, y: -location.y)
    convertPointFromHost(point: &point)
  }

  public func convertPointToHost(point: inout IntPoint) {
    var point3f = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    rootTransform.transformPoint(point: &point3f)
    point = IntPoint.toFloored(point: FloatPoint(point3f))
  }

  public func convertPointFromHost(point: inout IntPoint) {
    var point3f = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    inverseRootTransform.transformPoint(point: &point3f)
    point = IntPoint.toFloored(point: FloatPoint(point3f))
  }

  public func setCursor(platformCursor: PlatformCursor) {
    if cursor! == platformCursor {
      return
    }
    cursor = platformCursor

  //#if os(Windows)
  //  let cursorLoader = CursorLoaderWin()
  //  cursorLoader.setPlatformCursor(cursor)
  //#endif

    //platformWindow.setCursor(cursor.platform)
   platformWindow!.setCursor(cursor: cursor!)
  }

  public func onCursorVisibilityChanged(show: Bool) {
    if !show {
      let details: EventDispatchDetails =
          dispatcher!.dispatchMouseExitAtPoint(target: nil, point: dispatcher!.lastMouseLocationInRoot)
      if details.dispatcherDestroyed {
        return
      }
    }

    onCursorVisibilityChangedNative(show: show)
  }

  public func moveCursorTo(location: IntPoint) {
    var hostLocation = IntPoint(location)
    convertPointToHost(point: &hostLocation)
    moveCursorToInternal(rootLocation: location, hostLocation)
  }

  public func moveCursorToHostLocation(hostLocation: IntPoint) {
    var rootLocation = IntPoint(hostLocation)
    convertPointFromHost(point: &rootLocation)
    moveCursorToInternal(rootLocation: rootLocation, hostLocation)
  }

  public func setBoundsInPixels(bounds: IntRect, localSurfaceId: LocalSurfaceId){
    assert(false)
  }

  public func show() {
    if let c = compositor {
      c.isVisible = true
    }

    // TODO: usar a showImpl
    //platformWindow!.show()
    showImpl()
  }

  public func hide() {
    hideImpl()
    if let c = compositor {
      c.isVisible = false
    }
    // TODO: usar a hideImpl
    //platformWindow!.hide()
  }

  public func showImpl() {}
  public func hideImpl() {}

  // virtual
  public func setCapture() {
    //if !hasCapture {
    //  hasCapture = true
    //  platformWindow!.setCapture()
    //}
  }

  public func releaseCapture() {
    //if hasCapture {
    //  platformWindow!.releaseCapture()
    //  hasCapture = false
    //}
  }

  public override func sendEventToProcessor(event: Graphics.Event) -> EventDispatchDetails {
    return dispatcher!.sendEventToProcessor(event: event)
  }

  public func dispatchEvent(event: Graphics.Event) {
    let details: EventDispatchDetails = self.sendEventToProcessor(event: event)
    if details.dispatcherDestroyed {
      event.handled = true
    }
  }

  public func onHostResizedInPixels(_ newSize: IntSize, localSurfaceId newLocalSurfaceId: LocalSurfaceId = LocalSurfaceId()) {
    //var adjustedSize = newSize
    //adjustedSize.enlarge(width: outputSurfacePadding.width,
     //                    height: outputSurfacePadding.height)
    // The compositor should have the same size as the native root window host.
    // Get the latest scale from display because it might have been changed.
    //compositor!.setScaleAndSize(scale: getDeviceScaleFactor(window: window),
    //                            sizeInPixel: adjustedSize,
    //                            localSurfaceId: window.localSurfaceId)

    //let layerSize = bounds.size
    // The layer, and the observers should be notified of the
    // transformed size of the root window.
    //updateRootWindowSize(hostSize: layerSize)
    ////print("onHostResized: host.window.bounds.size: \(self.window.bounds.size)")
    

    let display = Screen.instance.getDisplayNearestWindow(window: window)
    
    self.deviceScaleFactor = display.deviceScaleFactor
    updateRootWindowSizeInPixels()

    // Allocate a new LocalSurfaceId for the new state.
    var localSurfaceId = newLocalSurfaceId
    if shouldAllocateLocalSurfaceId && !newLocalSurfaceId.isValid {
      self.window.allocateLocalSurfaceId()
      localSurfaceId = window.localSurfaceId
    }
    let lsiValidator = ScopedLocalSurfaceIdValidator(self.window)

    compositor!.setScaleAndSize(scale: self.deviceScaleFactor,
                                sizeInPixel: newSize,
                                localSurfaceId: localSurfaceId)

    for observer in observers {
      observer.onHostResized(host: self)
    }
  }

  // TODO: verificar se é mesmo necessário
  func destroyCompositor() {
    compositor = nil
  }

  // TODO: verificar se é mesmo necessário
  func destroyDispatcher() {

  }

  func createCompositor(frameSinkId: FrameSinkId) throws {
    compositor = UICompositor(
      frameSinkId: frameSinkId.isValid
          ? frameSinkId
          : UI.contextFactory!.allocateFrameSinkId(),
      contextFactory: UI.contextFactory!,
      //contextFactoryPrivate: UI.contextFactory!,
      taskRunner: nil,//ThreadTaskRunnerHandle.get(),
      enableSurfaceSynchronization: true,
      enablePixelCanvas: true)
    compositor!.addObserver(observer: self)
    if dispatcher == nil {  
      try window.initialize(type: LayerType.NotDrawn)
      window.host = self
      window.name = "RootWindow"
      window.eventTargeter = WindowTargeter()
      dispatcher = WindowEventDispatcher(self)
    }
  }

  func moveCursorToNative(location: IntPoint) {
    platformWindow!.moveCursorTo(location: location)
  }

  func onCursorVisibilityChangedNative(show: Bool)  {

  }

  func moveCursorToInternal(rootLocation: IntPoint,
                            _ hostLocation: IntPoint) {
    lastCursorRequestPositionInHost = hostLocation
    moveCursorToNative(location: hostLocation)
    if let cursorClient = window.cursorClient {
      let display = Screen.getDisplayNearestWindow(windowId: window.id)
      cursorClient.setDisplay(display: display!)
    }
    dispatcher!.onCursorMovedToRootLocation(rootLocation: rootLocation)
  }

  func getDeviceScaleFactor(window: Window) -> Float {
    let display = Screen.getDisplayNearestWindow(windowId: window.id)
    return display!.deviceScaleFactor
  }

  func getTransformedRootWindowBoundsInPixels(_ sizeInPixels: IntSize) -> IntRect {
    let bounds = IntRect(size: sizeInPixels)
    var newBounds: FloatRect = Graphics.scaleRect(FloatRect(bounds), 1.0 / self.deviceScaleFactor)
    window.layer!.transform.transformRect(rect: &newBounds)
    return Graphics.toEnclosingRect(newBounds)
  }

}

extension WindowTreeHost : PlatformWindowDelegate {

  public var deviceScaleFactor: Float {
    if let c = compositor {
      return c.deviceScaleFactor
    }
    return 0
  }

  public func onBoundsChanged(newBounds: IntRect) {
    let currentScale = compositor!.deviceScaleFactor
    let newScale = Screen.getDisplayNearestWindow(windowId: window.id)!.deviceScaleFactor
    let oldBounds = bounds
    bounds = newBounds

    if (bounds.origin != oldBounds.origin) {
      onHostMoved(newLocation: bounds.origin)
    }

    if (bounds.size != oldBounds.size || currentScale != newScale) {
      onHostResized(newSize: bounds.size)
    }
  }

  public func onDamageRect(damagedRegion: IntRect) {
    compositor!.scheduleRedrawRect(damaged: damagedRegion)
  }

  public func onCloseRequest() {
    onHostCloseRequested()
  }

  public func onClosed() {
    destroyCompositor()
    destroyDispatcher()
  }

  public func onWindowStateChanged(newState: PlatformWindowState) {

  }

  public func onLostCapture() {
    if self.hasCapture {
      hasCapture = false
      onHostLostWindowCapture()
    }
  }

  public func onAcceleratedWidgetAvailable(newWidget: AcceleratedWidget,
                                           devicePixelRatio: Float) {
    //try createCompositor()
    nativeWidget = newWidget

    //compositor!.nativeWidget = newWidget
    //compositor!.widget = newWidget
    compositor!.setAcceleratedWidget(widget: newWidget)
    WindowTreeHost.properties[newWidget] = self
    // why again ? is this right?
    nativeWidget = newWidget
  }

  //public func onAcceleratedWidgetDestroyed() {
    //let compositorWidget = compositor!.nativeWidget
    //assert(nativeWidget == compositorWidget)
  //  compositor!.onWidgetDestroyed()
  //  nativeWidget = nil
  //}

  public func onAcceleratedWidgetDestroyed() {
  }

  public func onActivationChanged(active: Bool) {
    if active {
      onHostActivated()
    }
  }

  public func onHostMovedInPixels(newLocation: IntPoint) {
    for observer in observers {
      observer.onHostMoved(host: self, newOrigin: newLocation)
    }
  }


  public func onHostActivated() {
    UI.notifyHostActivated(host: self)
  }

  public func onHostLostWindowCapture() {
    if let captureWindow = UI.getCaptureClient(window: window)?.captureWindow {
      if captureWindow.rootWindow === window {
        captureWindow.releaseCapture()
      }
    }
  }

  public func onHostEnterWindow() {
    if let cursorClient = window.cursorClient {
      if let display = Screen.getDisplayNearestWindow(windowId: window.id) {
        cursorClient.setDisplay(display: display)
      }
    }
  }

  public func onHostCloseRequested() {
    for observer in observers {
      observer.onHostCloseRequested(host: self)
    }
  }

  public func translateAndDispatchLocatedEvent(event: LocatedEvent) {

  }

  public func schedulePaint() {
    window.schedulePaintInRect(rect: window.bounds)
  }

}

extension WindowTreeHost : InputMethodDelegate {

  public func dispatchKeyEventPostIME(event: KeyEvent) -> EventDispatchDetails {
    return sendEventToProcessor(event: event)
  }

}

extension WindowTreeHost : UICompositorObserver {
  
  public func onCompositingDidCommit(compositor: UICompositor) {
    if !self.holdingPointerMoves  {
      return
    }

    dispatcher!.releasePointerMoves()
    self.holdingPointerMoves = false
  }

  public func onCompositingStarted(compositor: UICompositor, startTime: TimeTicks) {}
  public func onCompositingEnded(compositor: UICompositor) {}
  public func onCompositingAborted(compositor: UICompositor) {}
  public func onCompositingLockStateChanged(compositor: UICompositor) {}
  
  public func onCompositingShuttingDown(compositor: UICompositor) {
    compositor.removeObserver(observer: self)
  }

  public func onCompositingChildResizing(compositor: UICompositor) {
    if !UI.throttleInputOnResize || self.holdingPointerMoves {
      return
    }
    self.synchronizationStartTime = TimeTicks.now
    dispatcher!.holdPointerMoves()
    self.holdingPointerMoves = true
  }

}

extension WindowTreeHost : DisplayObserver {
}