// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Platform
#if os(Linux)
import X11
#endif

public enum LayerMode {
  case LayerNotDrawn
}

public protocol UIObserver : class {
  func onWindowInitialized(window: Window)
  func onHostInitialized(host: WindowTreeHost)
  func onHostActivated(host: WindowTreeHost)
  func onBeforeDestroy()
}

public func initialize(contextFactory: UIContextFactory) {
  //UIGlobal.initialize(contextFactory: contextFactory)
}

public func initialize() {
  //UIGlobal.initialize()
}

public var UI: UIGlobal {
  if UIGlobal.instance == nil {
      let instance = UIGlobal(contextFactory: nil)
      UIGlobal.instance = instance
  }

  return UIGlobal.instance! // and it will fail right here
}

public class UIGlobal : EventTarget {

  public var contextFactory: UIContextFactory? {
    get {
      //  return _contextFactory!
      return _factory
    }
    set {
      _factory = newValue
    }
  }

  //public var contextFactoryPrivate: UIContextFactoryPrivate? {
    //get {
   //     return _contextFactoryPrivate!
    //}
    //set {
    //  _contextFactory = newValue
    //}
  //  return _factory
  //}

  public let showStateKey = "ShowState"
  public let windowVisibilityAnimationTransitionKey = "WindowVisibilityAnimationTransition"
  public let windowVisibilityAnimationDurationKey = "WindowVisibilityAnimationDuration"
  public let childWindowVisibilityChangesAnimatedKey = "ChildWindowVisibilityChangesAnimated"
  public let windowVisibilityChangesAnimatedKey = "WindowVisibilityChangesAnimated"
  public let windowVisibilityAnimationTypeKey = "WindowVisibilityAnimationType"
  public let windowVisibilityAnimationVerticalPositionKey = "WindowVisibilityAnimationVerticalPosition"
  public let shadowElevationKey = "ShadowElevation"
 
  public var platform: Platform
  public var compositorIsSingleThreaded: Bool = true
  public var throttleInputOnResize: Bool = true
  static var instance: UIGlobal?
  private var observers: [UIObserver]
  //private var _contextFactory: UIContextFactory?
  //private var _contextFactoryPrivate: UIContextFactoryPrivate?
  private var _factory: UIContextFactory?
  private var _nextViewId: Int = 0

  public var isMouseButtonDown: Bool {
    return false
  }

  public var nextViewId: Int {
    _nextViewId += 1
    return _nextViewId
  }

  public static func initialize(contextFactory: UIContextFactory) {
    UIGlobal.instance = UIGlobal(contextFactory: contextFactory)
    try! UIGlobal.instance!.initializePlatform()
  }

  public static func initialize() {
    UIGlobal.instance = UIGlobal(contextFactory: nil)
    //try! UIGlobal.instance!.initializePlatform()
  }

  init(contextFactory: UIContextFactory?) {
#if os(Linux)
   self.platform = X11Platform()
#endif
   // singlethreaded = true for InProcessContextFactory .. we need to make this more custom
   //                  for when we change the current factory
  // TODO: this should be provided to us.. not to be "fixed" like this
   _factory = contextFactory
   //_contextFactory = factory 
   //_contextFactoryPrivate = factory
   observers = []

   super.init()

   //Compositor.initialize(singleThreaded: self.compositorIsSingleThreaded)
  }

  deinit {
    for observer in observers {
      observer.onBeforeDestroy()
    }
  }

  public func initializePlatform() throws {
    try platform.initialize()
  }

  public func notifyHostInitialized(host: WindowTreeHost) {
    for observer in observers {
      observer.onHostInitialized(host: host)
    }
  }

  public func notifyHostActivated(host: WindowTreeHost) {
    for observer in observers {
      observer.onHostActivated(host: host)
    }
  }

  public func notifyWindowInitialized(window: Window) {
    for observer in observers {
      observer.onWindowInitialized(window: window)
    }
  }

  public func addObserver(observer: UIObserver) {
    observers.append(observer)
  }

  public func removeObserver(observer: UIObserver) {
    for (index, item) in observers.enumerated() {
      if observer === item {
        observers.remove(at: index)
      }
    }
  }

  public func getDeviceScaleFactor(layer: Layer) -> Float {
    return 1
  }

  public func getScaleFactorForWindow(window: Window) -> Float {
    //if Screen.instance == nil {
    //  return 1.0
    //}
    if let display = Screen.getDisplayNearestWindow(windowId: window.id) {
      return display.deviceScaleFactor
    }
    return 1.0
  }

  public func convertRectToDIP(layer: Layer, _ bounds: IntRect) -> IntRect {
    let scaleFactor = getDeviceScaleFactor(layer: layer)
    return IntRect.toFloored(r: FloatRect.scale(rect: bounds, factor: 1.0 / scaleFactor))
  }

  public func convertRectToPixel(layer: Layer, _ bounds: IntRect) ->IntRect {
    let scaleFactor = getDeviceScaleFactor(layer: layer)
    if scaleFactor == 1.0 {
      return bounds
    }
    return IntRect.toEnclosingRect(rect:
      FloatRect(origin: FloatPoint.scale(p: FloatPoint(bounds.origin), scaleFactor),
                size: FloatSize.scale(FloatSize(bounds.size), scaleFactor))
    )
  }

  public func snapLayerToPhysicalPixelBoundary(snappedLayer: Layer, toSnap: Layer) {

  }

  public func parentWindowWithContext(window: Window,
                                      context: Window,
                                      screenBounds: IntRect) throws {
    let client = UI.getWindowTreeClient(window: context)
    if let defaultParent = try client!.getDefaultParent(context: context, window: window, bounds: screenBounds) {
      try defaultParent.addChild(child: window)
    }
  }

  public func setFocusClient(window: Window, client: FocusClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.focusClient = client
    }
  }

  public func setCursorClient(window: Window, client: CursorClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.cursorClient = client
    }
  }

  public func setEventClient(window: Window, client: EventClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.eventClient = client
    }
  }

  public func setCaptureClient(window: Window, client: CaptureClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.captureClient = client
    }
  }

  public func setScreenPositionClient(window: Window, client: ScreenPositionClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.screenPositionClient = client
    }
  }

  public func setWindowTreeClient(window: Window,
                                  treeClient: WindowTreeClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.windowTreeClient = treeClient
    }
  }

  public func setWindowStackingClient(window: Window, client: WindowStackingClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.windowStackingClient = client
    }
  }

  public func setWindowMoveClient(window: Window, client: WindowMoveClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.windowMoveClient = client
    }
  }

  public func setTransientWindowClient(window: Window, client: TransientWindowClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.transientWindowClient = client
    }
  }

  public func setVisibilityClient(window: Window, client: VisibilityClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.visibilityClient = client
    }
  }

  public func setFocusChangeObserver(window: Window, observer: FocusChangeObserver) {
    if let rootWindow = window.rootWindow {
      rootWindow.focusChangeObserver = observer
    }
  }

  public func setActivationChangeObserver(window: Window, observer: ActivationChangeObserver) {
    if let rootWindow = window.rootWindow {
      rootWindow.activationChangeObserver = observer
    }
  }

  public func setActivationClient(window: Window, client: ActivationClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.activationClient = client
    }
  }

  public func setActivationDelegate(window: Window, delegate: ActivationDelegate?) {
    if let rootWindow = window.rootWindow {
      rootWindow.activationDelegate = delegate
    }
  }

  public func setDispatcherClient(window: Window, client: DispatcherClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.dispatcherClient = client
    }
  }

  public func setDragDropClient(window: Window, client: DragDropClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.dragDropClient = client
    }
  }

  public func setDragDropDelegate(window: Window, delegate: DragDropDelegate?) {
    if let rootWindow = window.rootWindow {
      rootWindow.dragDropDelegate = delegate
    }
  }

  public func setTooltipClient(window: Window, client: TooltipController?) {
    if let rootWindow = window.rootWindow {
      rootWindow.tooltipController = client
    }
  }

  public func setWindowParentingClient(window: Window, client: WindowParentingClient?) {
    if let rootWindow = window.rootWindow {
      rootWindow.parentingClient = client
    }
  }

  public func setAnimationHost(window: Window, host: WindowAnimationHost) {
    if let rootWindow = window.rootWindow {
      rootWindow.animationHost = host
    }
  }

  public func getAnimationHost(window: Window?) -> WindowAnimationHost? {
    if let rootWindow = window?.rootWindow {
      return rootWindow.animationHost
    }
    return nil
  }

  public func getEventClient(window: Window?) -> EventClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.eventClient
    }
    return nil
  }

  public func getFocusClient(window: Window?) -> FocusClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.focusClient
    }
    return nil
  }

  public func getCaptureClient(window: Window?) -> CaptureClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.captureClient
    }
    return nil
  }

  public func getCursorClient(window: Window?) -> CursorClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.cursorClient
    }
    return nil
  }

  public func getScreenPositionClient(window: Window?) -> ScreenPositionClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.screenPositionClient
    }
    return nil
  }

  public func getWindowTreeClient(window: Window?) -> WindowTreeClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.windowTreeClient
    }
    return nil
  }

  public func getWindowStackingClient(window: Window?) -> WindowStackingClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.windowStackingClient
    }
    return nil
  }

  public func getWindowMoveClient(window: Window?) -> WindowMoveClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.windowMoveClient
    }
    return nil
  }

  public func getTransientWindowClient(window: Window?) -> TransientWindowClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.transientWindowClient
    }
    return nil
  }

  public func getVisibilityClient(window: Window?) -> VisibilityClient? {
    if let client = window?.rootWindow?.visibilityClient {
      return client
    }
    return nil
  }

  public func getFocusChangeObserver(window: Window?) -> FocusChangeObserver? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.focusChangeObserver
    }
    return nil
  }

  public func getActivationChangeObserver(window: Window?) -> ActivationChangeObserver? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.activationChangeObserver
    }
    return nil
  }

  public func getActivationClient(window: Window?) -> ActivationClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.activationClient
    }
    return nil
  }

  public func getActivationDelegate(window: Window?) -> ActivationDelegate? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.activationDelegate
    }
    return nil
  }

  public func getDispatcherClient(window: Window?) -> DispatcherClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.dispatcherClient
    }
    return nil
  }

  public func getDragDropClient(window: Window?) -> DragDropClient? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.dragDropClient
    }
    return nil
  }

  public func getDragDropDelegate(window: Window?) -> DragDropDelegate? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.dragDropDelegate
    }
    return nil
  }

  public func getTooltipClient(window: Window?) -> TooltipController? {
    if let w = window, let rootWindow = w.rootWindow {
      return rootWindow.tooltipController
    }
    return nil
  }

  public func getTransientChildren(window: Window) -> [Window] {
    return []
  }

  public func getToplevelWindow(window: Window) -> Window? {
    if let client = getActivationClient(window: window.rootWindow) {
      return client.getToplevelWindow(window: window)
    }
    return nil
  }


  public func getModalTransientChild(toplevel: Window, window: Window) -> Window? {
    return nil
  }

  public func getModalTransient(window: Window?) -> Window? {
    if window == nil {
      return nil
    }

    // We always want to check the for the transient child of the toplevel window.
    let toplevel = getToplevelWindow(window: window!)
    if toplevel == nil {
      return nil
    }

    return getModalTransientChild(toplevel: toplevel!, window: window!)
  }

  public func setWindowVisibilityAnimationTransition(
    window: Window,
    transition: Window.VisibilityAnimationTransition) {
    window.property[windowVisibilityAnimationTransitionKey] = transition
  }

  public func setWindowVisibilityAnimationDuration(
    window: Window,
    duration: TimeDelta) {
    window.property[windowVisibilityAnimationDurationKey] = duration
  }

  public func setChildWindowVisibilityChangesAnimated(window: Window) {
    window.property[childWindowVisibilityChangesAnimatedKey] = true
  }

  public func setShadowElevation(window: Window, elevation: Int) {
    window.property[shadowElevationKey] = elevation
  }

  public func runShellDrag(view window: Window,
                           data: OSExchangeData,
                           location: IntPoint,
                           operation: DragOperation,
                           source: DragEventSource) {
    assert(false)
    //gfx::IntPoint screen_location(location)
    //wm::ConvertPointToScreen(view, &screen_location)
    //aura::Window* root_window = view->GetRootWindow()
    //if (aura::client::GetDragDropClient(root_window)) {
    //  aura::client::GetDragDropClient(root_window)->StartDragAndDrop(
    //        data, root_window, view, screen_location, operation, source)
    //}
  }

  public func createInputMethod(delegate: InputMethodDelegate, window: AcceleratedWidget?) -> InputMethod {
#if os(Linux)
    return InputMethodLinux(delegate: delegate)
#endif
  }

}

public enum WindowShowState : Int {
  case Default    = 0
  case Normal     = 1
  case Minimized  = 2
  case Maximized  = 3
  case Inactive   = 4
  case Fullscreen = 5
  case Docked     = 6
  case End        = 7
}

// Specifies the type of modality applied to a window. Different modal
// treatments may be handled differently by the window manager.
public enum ModalType : Int {
  case None   = 0
  case Window = 1
  case Child  = 2
  case System = 3
}

public enum MenuSourceType : Int {
  case Mouse           = 0
  case Keyboard        = 1
  case Touch           = 2
  case TouchEditMenu   = 3
}

public enum WindowType {
  case Unknown
  case Normal
  case Popup
  case Bubble
  case Control
  case Panel
  case Menu
  case Tooltip
  case Frameless
  case Drag
}

public enum ScaleFactor : Int {
  
  case none = 0
  case scale100
  case scale125
  case scale133
  case scale140
  case scale150
  case scale180
  case scale200
  case scale250
  case scale300

  static let scaleFactorScales: [Float] = 
              [1.0, 1.0, 1.25, 
              1.33, 1.4, 1.5, 
              1.8, 2.0, 2.5, 3.0]

  public func getScale(_ factor: ScaleFactor) -> Float {
    return ScaleFactor.scaleFactorScales[factor.rawValue]
  }

}