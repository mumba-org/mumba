// Copyright (c) 2016-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Compositor
import Platform
import X11
#if os(Linux)
import Glibc
#endif

fileprivate let atomCacheList: [String] = [
  "UTF8_STRING",
  "WM_DELETE_WINDOW",
  "WM_PROTOCOLS",
  "_NET_FRAME_EXTENTS",
  "_NET_WM_M_S0",
  "_NET_WM_DESKTOP",
  "_NET_WM_ICON",
  "_NET_WM_NAME",
  "_NET_WM_PID",
  "_NET_WM_PING",
  "_NET_WM_STATE",
  "_NET_WM_STATE_ABOVE",
  "_NET_WM_STATE_FULLSCREEN",
  "_NET_WM_STATE_HIDDEN",
  "_NET_WM_STATE_MAXIMIZED_HORZ",
  "_NET_WM_STATE_MAXIMIZED_VERT",
  "_NET_WM_STATE_SKIP_TASKBAR",
  "_NET_WM_STATE_STICKY",
  "_NET_WM_USER_TIME",
  "_NET_WM_WINDOW_OPACITY",
  "_NET_WM_WINDOW_TYPE",
  "_NET_WM_WINDOW_TYPE_DND",
  "_NET_WM_WINDOW_TYPE_MENU",
  "_NET_WM_WINDOW_TYPE_NORMAL",
  "_NET_WM_WINDOW_TYPE_NOTIFICATION",
  "_NET_WM_WINDOW_TYPE_TOOLTIP",
  // recently added - check
  "_NET_ACTIVE_WINDOW",
  "XdndActionAsk",
  "XdndActionCopy",
  "XdndActionLink",
  "XdndActionList",
  "XdndActionMove",
  "XdndActionPrivate",
  "XdndAware",
  "XdndDrop",
  "XdndEnter",
  "XdndFinished",
  "XdndLeave",
  "XdndPosition",
  "XdndProxy",  // Proxy windows?
  "XdndSelection",
  "XdndStatus",
  "XdndTypeList"
  ]

fileprivate let allDesktops: Int = 0xFFFFFFFF

fileprivate let x11WindowRolePopup = "popup"
fileprivate let x11WindowRoleBubble = "bubble"

fileprivate enum TitlebarVisibility: Int32 {
  case ShowTitlebarWhenMaximized = 0
  case HideTitlebarWhenMaximized = 1
}

// X11 defines

fileprivate let XA_ATOM: Atom = 4
fileprivate let XA_ARDINAL: Atom = 6
fileprivate let XA_STRING: Atom = 31
fileprivate let CurrentTime: UInt =	0

fileprivate let NetWMStateAdd = 1
fileprivate let NetWMStateRemove = 0

//
fileprivate let X11ShapeSet: Int32         = 0
fileprivate let X11ShapeUnion: Int32       = 1
fileprivate let X11ShapeIntersect: Int32   = 2
fileprivate let X11ShapeSubtract: Int32    = 3
fileprivate let X11ShapeInvert: Int32      = 4

fileprivate let X11ShapeBounding: Int32    = 0
fileprivate let X11ShapeClip: Int32        = 1
fileprivate let X11ShapeInput: Int32       = 2

fileprivate let X11ShapeNotifyMask: Int32  = (1 << 0)
fileprivate let X11ShapeNotify: Int32      = 0

fileprivate let X11ShapeNumberEvents: Int32 = X11ShapeNotify + 1

fileprivate enum WindowManagerName {
  case Unknown
  case Awesome
  case Blackbox
  case Compiz
  case Enlightenment
  case Fluxbox
  case I3
  case Icewm
  case Ion3
  case Kwin
  case Matchbox
  case Metacity
  case Muffin
  case Mutter
  case Notion
  case Openbox
  case Qtile
  case Ratpoison
  case Stumpwm
  case WMII
  case XFWM4
};

public protocol DesktopWindowTreeHostObserverX11 : class {
 func onWindowMapped(xid: CUnsignedLong)
 func onWindowUnmapped(xid: CUnsignedLong)
}

// Returns the whole path from |window| to the root.
fileprivate func getParentsList(xdisplay: XDisplayHandle, window: CUnsignedLong) -> [CUnsignedLong] {
  var parentWin: CUnsignedLong = 0, rootWin: CUnsignedLong = 0
  //var childWindows = UnsafeMutableRawPointer<UInt>()
  var childWindows: UnsafeMutablePointer<UInt>? = nil
  var numChildWindows: UInt32 = 0
  var result = [CUnsignedLong]()

  var curWindow = window
  while curWindow != 0 {
    result.append(curWindow)
    if XQueryTree(xdisplay, curWindow, &rootWin, &parentWin, &childWindows, &numChildWindows) == 0 {
      return result
    }
    if childWindows != nil {
      XFree(childWindows)
    }
    curWindow = parentWin
  }
  return result
}


public class DesktopWindowTreeHostX11 : WindowTreeHost,
                                        DesktopWindowTreeHost,
                                        PlatformEventDispatcher {

  public var isVisible: Bool {
    get {
      return windowMappedInClient
    }
    set {
      if let c = compositor {
        c.isVisible = newValue
      }
      if isVisible != newValue {
        nativeWidgetDelegate.onNativeWidgetVisibilityChanged(visible: newValue)
      }
    }
  }

  public var size: IntSize { 
   get {
     return _boundsInPixels.size
   }
   set (requestedSize) {
     var sizeInPixels = toPixelRect(IntRect(size: requestedSize)).size
     sizeInPixels = adjustSize(requestedSize: sizeInPixels)
     let sizeChanged = _boundsInPixels.size != sizeInPixels
     XResizeWindow(xdisplay, xwindow, UInt32(sizeInPixels.width), UInt32(sizeInPixels.height))
     _boundsInPixels.size = sizeInPixels
     if sizeChanged {
       onHostResizedInPixels(sizeInPixels)
       resetWindowRegion()
     }
   }
  }

  public var windowBoundsInScreen: IntRect {
    return toDIPRect(_boundsInPixels)
  }

  public var clientAreaBoundsInScreen: IntRect {
    return windowBoundsInScreen
  }

  public var restoredBounds: IntRect {
    if !restoredBoundsInPixels.isEmpty {
      return toDIPRect(restoredBoundsInPixels)
    }
    return windowBoundsInScreen
  }
  
  public var workspace: String {
    if _workspace.isEmpty {
      let _ = updateWorkspace()
    }
    return _workspace
  }
  
  public var workAreaBoundsInScreen: IntRect {
    return toDIPRect(workAreaBoundsInPixels)
  }
  
  public var isActive: Bool {
    return (hasWindowFocus || hasPointerFocus) && !ignoreKeyboardInput
  }
  
  public var isMaximized: Bool {
    return hasWMSpecProperty(property: "_NET_WM_STATE_MAXIMIZED_VERT") &&
         hasWMSpecProperty(property: "_NET_WM_STATE_MAXIMIZED_HORZ")
  }
  
  public var isMinimized: Bool {
    return hasWMSpecProperty(property: "_NET_WM_STATE_HIDDEN")
  }
  
  public var hasCapture: Bool {
    return DesktopWindowTreeHostX11.currentCapture === self
  }

  public var isAlwaysOnTop: Bool {
    get {
      return _alwaysOnTop
    }
    set {
      _alwaysOnTop = newValue
      setWMSpecState(
        enabled: _alwaysOnTop, 
        state1: atomCache.getAtom(name: "_NET_WM_STATE_ABOVE")!, 
        state2: UInt(None))
    }
  }
  
  public var isVisibleOnAllWorkspaces: Bool { 
    get {
      return workspace == String(allDesktops)
    } 
    set {
      setWMSpecState(enabled: newValue,
                   state1: atomCache.getAtom(name: "_NET_WM_STATE_STICKY")!,
                   state2: UInt(None))

      var newDesktop = 0
      if newValue {
        newDesktop = allDesktops
      } else {
        if !getCurrentDesktop(desktop: &newDesktop) {
          return
        }
      }

      var xevent = XEvent()
      memset(&xevent, 0, MemoryLayout<XEvent>.stride)
      xevent.type = ClientMessage
      xevent.xclient.window = xwindow
      xevent.xclient.message_type = atomCache.getAtom(name: "_NET_WM_DESKTOP")!
      xevent.xclient.format = 32

      // Create a sized buffer pointer from .xclient.data.l[0] 
      // to .xclient.data.l[4] where data.l is a C's long[5]
      
      xevent.xclient.data.l = (newDesktop, 0, 0, 0, 0)
      
      //var dataBuffer = UnsafeMutableBufferPointer<Int64>(start: &xevent.xclient.data, count: 5)
      //dataBuffer[0] = newDesktop
      //dataBuffer[1] = 0
      //dataBuffer[2] = 0
      //dataBuffer[3] = 0
      //dataBuffer[4] = 0
      XSendEvent(xdisplay, xrootWindow, False,
              SubstructureRedirectMask | SubstructureNotifyMask,
              &xevent)
    }
  }
  
  public var shouldUseNativeFrame: Bool {
    return useNativeFrame
  }
  
  public var shouldWindowContentsBeTransparent: Bool {
    // TODO: fix
    return false//useARGBVisual
  }
  
  public var isFullscreen: Bool {
    get {
      return _fullscreen
    }
    set {
      _fullscreen = newValue
      onFullscreenStateChanged()

      let unmaximizeAndRemaximize = !self._fullscreen && isMaximized &&
                              guessWindowManager() == .Metacity

      if unmaximizeAndRemaximize {
        restore()
      }

      setWMSpecState(enabled: self._fullscreen,
                     state1: atomCache.getAtom(name: "_NET_WM_STATE_FULLSCREEN")!,
                     state2: UInt(None))

       if unmaximizeAndRemaximize {
         maximize()
       }

       // Try to guess the size we will have after the switch to/from fullscreen:
       // - (may) avoid transient states
       // - works around Flash content which expects to have the size updated
       //   synchronously.
       // See https://crbug.com/361408
       if self._fullscreen {
         restoredBoundsInPixels = _boundsInPixels
         //let display = Screen.getScreenFor(nil).getDisplayNearestWindow(window)
         let display = Screen.getDisplayNearestWindow(windowId: window.id)!
         _boundsInPixels = toPixelRect(display.bounds)
       } else {
         _boundsInPixels = restoredBoundsInPixels
       }

       onHostMovedInPixels(newLocation: _boundsInPixels.origin)
       onHostResizedInPixels(_boundsInPixels.size)

       if hasWMSpecProperty(property: "_NET_WM_STATE_FULLSCREEN") == self._fullscreen {
         relayout()
         resetWindowRegion()
       }
    }
  }

  public var isAnimatingClosed: Bool {
    return false
  }
  
  public var translucentWindowOpacitySupported: Bool {
    //return XVisualManager.instance.argbVisualAvailable
    // TODO: FIX
    return true
  }

  public var shouldUpdateWindowTransparency: Bool {
    return true
  }

  public var shouldUseDesktopNativeCursorManager: Bool {
    return true
  }

  public var shouldCreateVisibilityController: Bool {
    return true
  }
  
  // WindowTreeHost

  public override var rootTransform: Transform {
    get {
      // TODO: fix Screen, Display, etc... we still didnt implement them properly
      var display = Graphics.Screen.nativeScreen.primaryDisplay
      if isVisible {
        display = Graphics.Screen.nativeScreen._getDisplayNearestWindow(windowId: window.id)!
      }

      let scale = display.deviceScaleFactor
      var transform = Transform()
      transform.scale(x: scale, y: scale)
      return transform
    }
    set {
      // just pass (interested only in overriding 'get')
      super.rootTransform = newValue
    }
  }

  public override var eventSource: EventSource? {
    return self
  }

  public override var acceleratedWidget: AcceleratedWidget? {
    return xwindow
  }

  public override var boundsInPixels: IntRect {
    return _boundsInPixels
  }

  internal override var locationOnScreenInPixels: IntPoint {
    return _boundsInPixels.origin
  }
  
  public var X11RootWindowBounds: IntRect {
    return _boundsInPixels
  }

  public var X11RootWindowOuterBounds: IntRect {
    var outerBounds = _boundsInPixels
    outerBounds.inset(insets: -nativeWindowFrameBordersInPixels)
    return outerBounds
  }

  public private(set) var windowShape: MumbaShims.Region?

  private static var openWindows: [XID] {
    if DesktopWindowTreeHostX11._openWindows == nil {
      DesktopWindowTreeHostX11._openWindows = []
    }
    return DesktopWindowTreeHostX11._openWindows!
  }

  private var workAreaBoundsInPixels: IntRect {
    var value = [Int]()

    if getIntArrayProperty(window: xrootWindow, propertyName: "_NET_WORKAREA", value: &value) && value.count >= 4 {
      return IntRect(x: value[0], y: value[1], width: value[2], height: value[3])
    }

    // Fetch the geometry of the root window.
    var root = MumbaShims.Window()
    var x: Int32 = 0, y: Int32 = 0
    var width: UInt32 = 0, height: UInt32 = 0
    var borderWidth: UInt32 = 0, depth: UInt32 = 0
    if XGetGeometry(xdisplay, xrootWindow, &root, &x, &y, &width, &height,
                    &borderWidth, &depth) == 0 { // error case
     //NOTIMPLEMENTED();
     return IntRect(x: 0, y: 0, width: 10, height: 10)
    }

    return IntRect(x: Int(x), y: Int(y), width: Int(width), height: Int(height))
  }

  private var contentWindow: Window? {
    return desktopNativeWidget.contentWindow
  }

  private weak var parent: DesktopWindowTreeHostX11?
  private var xdisplay: XDisplayHandle
  private var xwindow: CUnsignedLong = 0
  private var xrootWindow: CUnsignedLong
  private var atomCache: AtomCache
  private var previousBoundsInPixels: IntRect = IntRect()
  private var restoredBoundsInPixels: IntRect = IntRect()
  private var minSizeInPixels: IntSize = IntSize()
  private var maxSizeInPixels: IntSize = IntSize()
  private var windowProperties: [Atom] = []
  private var dragDropClient: DesktopDragDropClientX11?
  private var x11NonClientEventFilter: EventHandler?
  private var x11WindowMoveClient: DesktopWindowMoveClientX11?
  private var children: [DesktopWindowTreeHostX11] = []
  private var observers: [DesktopWindowTreeHostObserverX11] = []
  private var nativeWindowFrameBordersInPixels: IntInsets = IntInsets()
  private var windowTitle: String = String()
  private var grabWindow: XID
  // The "owner events" parameter used to grab the pointer.
  private var grabOwnerEvents: Bool = false
  private var nativeWidgetDelegate: NativeWidgetDelegate
  private var desktopNativeWidget: DesktopNativeWidget
  private var _boundsInPixels: IntRect = IntRect()
  private var windowMappedInServer: Bool = false
  private var windowMappedInClient: Bool = false
  private var useNativeFrame: Bool = true
  private var shouldMaximizeAfterMap: Bool = false
  private var useARGBVisual: Bool = false
  private var urgencyHintSet: Bool = false
  private var activatable: Bool = false
  private var customWindowShape: Bool = false
  private var hasPointer: Bool = false
  private var hasPointerGrab: Bool = false
  private var hasWindowFocus: Bool = false
  private var hasPointerFocus: Bool = false
  private var wasActive: Bool = false
  private var hadPointer: Bool = false
  private var hadPointerGrab: Bool = false
  private var hadWindowFocus: Bool = false
  private var ignoreKeyboardInput: Bool = true
  private var _alwaysOnTop: Bool = false
  private var _fullscreen: Bool = false
  private var _workspace: String = String()

  private static var _openWindows: [XID]?
  private static var currentCapture: DesktopWindowTreeHostX11?

  public static func create(
      nativeWidgetDelegate: NativeWidgetDelegate,
      desktopNativeWidget: DesktopNativeWidget) -> DesktopWindowTreeHost {
    return DesktopWindowTreeHostX11(nativeWidgetDelegate: nativeWidgetDelegate,
                                    desktopNativeWidget: desktopNativeWidget)
  }

  public static func getContentWindowForXID(xid: XID) -> Window? {
    return WindowTreeHost.getForAcceleratedWidget(window: xid)?.window.rootWindow?.viewsWindow ?? nil
  }

  public static func getHostForXID(xid: XID) -> DesktopWindowTreeHostX11? {
    return WindowTreeHost.getForAcceleratedWidget(window: xid)?.window.rootWindow?.host as? DesktopWindowTreeHostX11 ?? nil
  }

  public static func getAllOpenWindows() -> Array<Window> {
    guard let openWindowsList = DesktopWindowTreeHostX11._openWindows else {
      // should always works
      // but we could use a exception here anyway
      assert(false)
      return Array<Window>()
    }
    var windows = Array<Window>()
    for xid in openWindowsList {
      if let window = DesktopWindowTreeHostX11.getContentWindowForXID(xid: xid) {
        windows.append(window)
      }
    }
    return windows
  }

  public static func cleanupWindowList(_ mapFunc: (_: Window?) -> Void) {
    if DesktopWindowTreeHostX11._openWindows == nil {
      return
    }
    while !DesktopWindowTreeHostX11._openWindows!.isEmpty {
      if let xid = DesktopWindowTreeHostX11._openWindows!.first {
        mapFunc(DesktopWindowTreeHostX11.getContentWindowForXID(xid: xid))
        if !DesktopWindowTreeHostX11._openWindows!.isEmpty && DesktopWindowTreeHostX11._openWindows!.first! == xid {
          DesktopWindowTreeHostX11._openWindows!.remove(at: DesktopWindowTreeHostX11._openWindows!.startIndex)
        }
      }
    }
    DesktopWindowTreeHostX11._openWindows = nil
  }

  public init(nativeWidgetDelegate: NativeWidgetDelegate,
              desktopNativeWidget: DesktopNativeWidget) {
    xdisplay = X11Environment.XDisplay
    xrootWindow = XDefaultRootWindow(xdisplay)
    self.nativeWidgetDelegate = nativeWidgetDelegate
    self.desktopNativeWidget = desktopNativeWidget
    atomCache = AtomCache(xdisplay, atomCacheList)
    grabWindow = UInt(None)
    super.init()
    if DesktopWindowTreeHostX11._openWindows == nil {
      DesktopWindowTreeHostX11._openWindows = []
    }
  }

  deinit {
    window.rootWindow!.host = nil
    UI.setWindowMoveClient(window: window, client: nil)
    desktopNativeWidget.onDesktopWindowTreeHostDestroyed(host: self)
    destroyDispatcher()
  }

  //public func initialize(params: UIWidget.InitParams) throws {
  //  self.activatable = params.activatable == UIWidget.Activatable.Yes
    
    //if params.type == .Window {
    //  contentWindow.setProperty(client.animationsDisabledKey, true)
    //}

  //  var sanitizedParams = params

  //  if sanitizedParams.bounds.width == 0 {
  //    sanitizedParams.bounds.width = 100
  //  }
  //  if sanitizedParams.bounds.height == 0 {
  //    sanitizedParams.bounds.height = 100
  //  }

  //  try initX11Window(params: sanitizedParams)
  //  initHost()
  //  window.show()
  //}

  public func initialize(compositor: UIWebWindowCompositor, params: UIWidget.InitParams) throws {
    self.activatable = params.activatable == UIWidget.Activatable.Yes
    
    //if params.type == .Window {
    //  contentWindow.setProperty(client.animationsDisabledKey, true)
    //}

    var sanitizedParams = params

    if sanitizedParams.bounds.width == 0 {
      sanitizedParams.bounds.width = 100
    }
    if sanitizedParams.bounds.height == 0 {
      sanitizedParams.bounds.height = 100
    }

    try initX11Window(compositor: compositor, params: sanitizedParams)
    initHost()
    window.show()
  }
  
  public func onNativeWidgetCreated(params: UIWidget.InitParams) {
    //window.setProperty(viewsWindowForRootWindow, contentWindow)
    //window.setProperty(hostForRootWindow, self)
    window.rootWindow!.viewsWindow = contentWindow
    window.rootWindow!.host = self

//    let _ = DesktopHandlerX11.instance

    swapNonClientEventHandler(handler: WindowEventFilterX11(host: self))
    setUseNativeFrame(params.type == .Normal && !params.removeStandardFrame)

    x11WindowMoveClient = DesktopWindowMoveClientX11()
    UI.setWindowMoveClient(window: window, client: x11WindowMoveClient)

    setWindowTransparency()
    nativeWidgetDelegate.onNativeWidgetCreated(visible: true)
  }
  
  public func onWidgetInitDone() {}
  public func onActiveWindowChanged(active: Bool)  {}
  
  public func createTooltip() -> Tooltip {
    return Tooltip() 
  }
  
  public func createDragDropClient(cursorManager: DesktopNativeCursorManager) -> DragDropClient? {
    dragDropClient = DesktopDragDropClientX11(
      rootWindow: window,
      cursorManager: cursorManager,
      xdisplay: xdisplay,
      xwindow: xwindow)

    dragDropClient!.initialize()

    return dragDropClient
  }
  
  public func close() {
    closeNow()
  }
  
  public func closeNow() {
    guard xwindow == UInt(None) else {
      return
    }

    releaseCapture()
    nativeWidgetDelegate.onNativeWidgetDestroying()

    for child in children {
      child.close()
    }

    children.removeAll()

    // If we have a parent, remove ourselves from its children list.
    if let p = parent {
      if let index = p.children.firstIndex(where: { $0 === self }) {
        p.children.remove(at: index)
      }
      parent = nil
    }

    if let eventFilter = desktopNativeWidget.rootWindowEventFilter {
      eventFilter.removeHandler(filter: x11NonClientEventFilter!)
    }

    x11NonClientEventFilter = nil

    destroyCompositor()

    if let index = DesktopWindowTreeHostX11.openWindows.firstIndex(where: { $0 == xwindow }) {
      DesktopWindowTreeHostX11._openWindows!.remove(at: index)
    }   

    //if let eventSource = PlatformEventSource.instance() {
      let eventSource = X11EventSource.instance
      eventSource.removePlatformEventDispatcher(dispatcher: self)
    //}

    XDestroyWindow(xdisplay, xwindow)
    xwindow = UInt(None)

    desktopNativeWidget.onHostClosed()
  }
  
  public func asWindowTreeHost() -> WindowTreeHost {
    return self 
  }
  
  public func showWindowWithState(showState: WindowShowState) {
    if compositor != nil {
      isVisible = true
    }

    if !isVisible || !windowMappedInServer {
      mapWindow(showState: showState)
    }

    switch showState {
      case .Maximized:
        maximize()
      case .Minimized:
        minimize()
      case .Fullscreen:
        isFullscreen = true
      default:
        break
    }

    let _ = nativeWidgetDelegate.asWidget().setInitialFocus(showState: showState)
  }
  
  public func showMaximizedWithBounds(restoredBounds: IntRect) {
    showWindowWithState(showState: .Maximized)
    restoredBoundsInPixels = toPixelRect(restoredBounds)
  }
  
  public func stackAbove(window: Window) {
    if window.rootWindow != nil {
      let windowBelow = window.host!.acceleratedWidget!
      // Find all parent windows up to the root.
      let windowBelowParents = getParentsList(xdisplay: xdisplay, window: windowBelow)
      let windowAboveParents = getParentsList(xdisplay: xdisplay, window: xwindow)

      var below: UInt = 0, above: UInt = 0
      var found = false
      // Find their common ancestor.
      // TODO: this is probably wrong and doesnt do what the original algorithm did
      // CHECK!!!
      for b in windowBelowParents {
        for a in windowAboveParents {
          if b != a {
            below = b
            above = a
            found = true
            break
          }
        }
      }

      if found {
        var windows: [UInt] = [below, above]
        windows.withUnsafeMutableBufferPointer({ (arr: inout UnsafeMutableBufferPointer<UInt>) in
          if XRestackWindows(xdisplay, &arr[0], 2) == 0 {
            // Now stack them properly.
            // lets hope this swaps the **contents**
            // of the 'mutable buffer pointer'
            let tmp = arr[0]
            arr[0] = arr[1]
            arr[1] = tmp
            XRestackWindows(xdisplay, &arr[0], 2)
          }
        })
      }
    }
  }
  
  public func stackAtTop() {
    XRaiseWindow(xdisplay, xwindow)
  }
  
  public func centerWindow(size: IntSize) {
    let sizeInPixels = toPixelRect(IntRect(size: size)).size
    var parentBoundsInPixels = workAreaBoundsInPixels

    // If |window_|'s transient parent bounds are big enough to contain |size|,
    // use them instead.
    if let manager = TransientWindowManager.get(window: contentWindow!),
        let transientParent = manager.transientParent {
      let transientParentRect = transientParent.boundsInScreen
      if transientParentRect.height >= size.height && transientParentRect.width >= size.width {
        parentBoundsInPixels = toPixelRect(transientParentRect)
      }
    }

    var windowBoundsInPixels = IntRect(
      x: parentBoundsInPixels.x + (parentBoundsInPixels.width - sizeInPixels.width) / 2,
      y: parentBoundsInPixels.y + (parentBoundsInPixels.height - sizeInPixels.height) / 2,
      width: sizeInPixels.width,
      height: sizeInPixels.height)

    windowBoundsInPixels.adjustToFit(rect: parentBoundsInPixels)
    _boundsInPixels = windowBoundsInPixels
  }
  
  public func getWindowPlacement(bounds: inout IntRect,
                                 showState: inout WindowShowState) {
    bounds = restoredBounds

    if isFullscreen {
      showState = .Fullscreen
    } else if isMinimized {
      showState = .Minimized
    } else if isMaximized {
      showState = .Maximized
    } else if !isActive {
      showState = .Inactive
    } else {
      showState = .Normal
    }
  }
  
  public func setShape(nativeShape: UIWidget.ShapeRects?) {
    customWindowShape = false
    windowShape = nil
    if let shape = nativeShape {
      let nativeRegion = Graphics.Region()
      for rect in shape {
        let _ = nativeRegion.union(rect: rect)
      }
      let transform = rootTransform
      if !transform.isIdentity && !nativeRegion.isEmpty {
        var pathInDip = Path()
        if nativeRegion.getBoundaryPath(path: &pathInDip) {
          var pathInPixels = Path()
          pathInDip.transform(matrix: transform.matrix, dst: &pathInPixels)
          self.windowShape = createRegionFromGfxPath(path: pathInPixels)
        } else {
          self.windowShape = XCreateRegion()
        }
      } else {
        windowShape = createRegionFromGfxRegion(region: nativeRegion)
      }
      customWindowShape = true
    }
    resetWindowRegion()
  }
  
  public func activate() {
    if !isVisible || !activatable {
      return
    }

    beforeActivationStateChanged()

    ignoreKeyboardInput = false
    
    let wmSupportsActiveWindow = wmSupportsHint(atom: atomCache.getAtom(name: "_NET_ACTIVE_WINDOW")!)
    let timestamp: Time = X11EventSource.instance.timestamp

    if wmSupportsActiveWindow {
      var xclient = XEvent()
      memset(&xclient, 0, MemoryLayout<XEvent>.stride)
      xclient.type = ClientMessage
      xclient.xclient.window = xwindow
      xclient.xclient.message_type = atomCache.getAtom(name: "_NET_ACTIVE_WINDOW")!
      xclient.xclient.format = 32

      // Create a sized buffer pointer from .xclient.data.l[0] 
      // to .xclient.data.l[4] where data.l is a C's long[5]
      //var dataBuffer = UnsafeMutableBufferPointer<Int64>(start: &xclient.xclient.data.l, count: 5)
      //dataBuffer[0] = 1
      //dataBuffer[1] = timestamp
      //dataBuffer[2] = None
      //dataBuffer[3] = 0
      //dataBuffer[4] = 0

      //xclient.xclient.data.l[0] = 1
      //xclient.xclient.data.l[1] = timestamp//Int(wmUserTimeMS)
      //xclient.xclient.data.l[2] = None
      //xclient.xclient.data.l[3] = 0
      //xclient.xclient.data.l[4] = 0

      xclient.xclient.data.l = (1, Int(timestamp), None, 0, 0)
    
      XSendEvent(xdisplay, xrootWindow, False,
            SubstructureRedirectMask | SubstructureNotifyMask,
            &xclient)
        
    } else {
        XRaiseWindow(xdisplay, xwindow)
        // Directly ask the X server to give focus to the window. Note
        // that the call will raise an X error if the window is not
        // mapped.
        let oldErrorHandler = XSetErrorHandler(ignoreX11Errors)

        XSetInputFocus(xdisplay, xwindow, RevertToParent, CurrentTime)

        hasPointerFocus = false
        hasWindowFocus = true
        // window_mapped_in_client_ == true based on the IsVisible() check above.
        windowMappedInServer = true
        XSetErrorHandler(oldErrorHandler)
    }
    afterActivationStateChanged()
  }
  
  public func deactivate() {
    beforeActivationStateChanged()
    ignoreKeyboardInput = true
    releaseCapture()
    XLowerWindow(xdisplay, xwindow)
    afterActivationStateChanged()
  }
  
  public func maximize() {
    if hasWMSpecProperty(property: "_NET_WM_STATE_FULLSCREEN") {

      setWMSpecState(enabled: false,
                     state1: atomCache.getAtom(name: "_NET_WM_STATE_FULLSCREEN")!,
                     state2: UInt(None))

      let adjustedBoundsInPixels = IntRect(origin: _boundsInPixels.origin,
                                        size: adjustSize(requestedSize: _boundsInPixels.size))
      if adjustedBoundsInPixels != _boundsInPixels {
        self._boundsInPixels = adjustedBoundsInPixels
      }
    }

    shouldMaximizeAfterMap = !isVisible

    restoredBoundsInPixels = _boundsInPixels

    setWMSpecState(enabled: true,
                   state1: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_VERT")!,
                   state2: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_HORZ")!)

    if isMinimized {
      showWindowWithState(showState: .Normal)
    } 
  }
  
  public func minimize() {
    releaseCapture()
    XIconifyWindow(xdisplay, xwindow, 0)  
  }
  
  public func restore() {
    shouldMaximizeAfterMap = false
    setWMSpecState(enabled: false,
                   state1: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_VERT")!,
                   state2: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_HORZ")!)
    if isMinimized {
      showWindowWithState(showState: .Normal)
    }
  }
  
  public func setWindowTitle(title: String) -> Bool {
    guard windowTitle != title else {
      return false
    }

    windowTitle = title

    XChangeProperty(xdisplay,
                    xwindow,
                    atomCache.getAtom(name: "_NET_WM_NAME")!,
                    atomCache.getAtom(name: "UTF8_STRING")!,
                    8,
                    PropModeReplace,
                    windowTitle,
                    Int32(windowTitle.count))

    var xtp = XTextProperty()

    //char *c_utf8_str = const_cast<char *>(utf8str.c_str());
    windowTitle.withCString({ (string: UnsafePointer<Int8>?) in
      var mutView = UnsafeMutablePointer<Int8>(mutating: string)
      if Xutf8TextListToTextProperty(xdisplay, &mutView, 1,
                                     XUTF8StringStyle, &xtp) == Success {
        XSetWMName(xdisplay, xwindow, &xtp)
        XFree(xtp.value)
      }
    })
    return true
  }
  
  public func clearNativeFocus() {
    if let window = contentWindow, let focusClient = UI.getFocusClient(window: window) {
      if window.contains(other: focusClient.focusedWindow!) {
        focusClient.focusWindow(window: window)
      }
    }  
  }
  
  public func runMoveLoop(
      dragOffset: IntVec2,
      source: UIWidget.MoveLoopSource,
      escapeBehavior: UIWidget.MoveLoopEscapeBehavior) -> UIWidget.MoveLoopResult {
    
    let windowMoveSource: WindowMoveSource =
      source == .Mouse ? WindowMoveSource.Mouse : WindowMoveSource.Touch

    if x11WindowMoveClient!.runMoveLoop(window: contentWindow!, dragOffset: dragOffset,
        source: windowMoveSource) == .MoveSuccessful {
      return UIWidget.MoveLoopResult.Successful
    }

    return UIWidget.MoveLoopResult.Canceled
  }
  
  public func endMoveLoop() {
    x11WindowMoveClient!.endMoveLoop()
  }
  
  public func setVisibilityChangedAnimationsEnabled(value: Bool) {}
  
  public func createNonClientFrameView() -> NonClientFrameView? {
    return shouldUseNativeFrame
             ? NativeFrameView(frame: nativeWidgetDelegate.asWidget())
             : nil  
  }
  
  public func frameTypeChanged() {
    let newType = nativeWidgetDelegate.asWidget().frameType

    if newType == .Default {
      // The default is determined by UIWidget::InitParams::remove_standard_frame
      // and does not change.
      return
    }
    // TODO: this is actually scheduled on the current thread
    // via ThreadTaskRunnerHandle.get. As we need a UI main thread
    // on C++ side, we dont control it on the Swift side
    // We need some kind of wrapper so threads on c++ and c++ compositor
    // can 'live' and be reached on the Swift side.. 
    // The best we can do is to assign UI main via Swift, so we can
    // save it on TLS, pass it over so C++ create it, and then we can
    // safely reference it on Swift, even if we are using a wrapper
    delayedChangeFrameType(type: newType)
  }
 
  public func setOpacity(opacity: Float) {
    let opacity8bit = UInt(opacity * 255.0) & 0xff
    let result = UInt(opacity8bit * 0x1010101)
    var cardinality = UInt8(result)

    if result == 0xffffffff {
      XDeleteProperty(xdisplay, xwindow,
                    atomCache.getAtom(name: "_NET_WM_WINDOW_OPACITY")!)
    } else {
      XChangeProperty(xdisplay, xwindow,
                      atomCache.getAtom(name: "_NET_WM_WINDOW_OPACITY")!,
                      XA_ARDINAL, 32,
                      PropModeReplace,
                      &cardinality, 1)
    }
  }
  
  public func setWindowIcons(windowIcon: ImageSkia?,
                             appIcon: ImageSkia?) {
    var data = ContiguousArray<UInt>()
    if let wbitmap = windowIcon?.getBitmapFor(scale: 1.0) {
      serializeImageRepresentation(bitmap: wbitmap, data: &data)
    }

    if let abitmap = appIcon?.getBitmapFor(scale: 1.0) {
      serializeImageRepresentation(bitmap: abitmap, data: &data)
    }

    if data.count > 0 {
      let _ = setAtomArrayProperty(window: xwindow, name: "_NET_WM_ICON", type: "CARDINAL", value: &data)
    }
  }
  
  public func initModalType(modalType: ModalType) {}
  
  public func flashFrame(_ flashFrame: Bool) {
    guard urgencyHintSet != flashFrame else {
      return
    }

    // TODO: we are not manualy managing this memory
    // so this is probably leaking
    //gfx::XScopedPtr<XWMHints> hints(XGetWMHints(xdisplay_, xwindow_))
    var hints = XGetWMHints(xdisplay, xwindow)
    if hints == nil {
      // The window hasn't had its hints set yet.
      //hints.reset(XAllocWMHints());
      hints = XAllocWMHints()
    }

    if flashFrame {
      hints!.pointee.flags = hints!.pointee.flags | XUrgencyHint
    } else {
      hints!.pointee.flags = hints!.pointee.flags & ~XUrgencyHint
    }
    XSetWMHints(xdisplay, xwindow, hints)
    urgencyHintSet = flashFrame
//#if os(Linux)
    free(hints)
//#endif
  }
  
  public func sizeConstraintsChanged() {
    updateMinAndMaxSize()
  }

  public func addObserver(observer: DesktopWindowTreeHostObserverX11) {
    observers.append(observer)
  }

  public func removeObserver(observer: DesktopWindowTreeHostObserverX11) {
    if let index = observers.firstIndex(where: { $0 === observer }) {
      observers.remove(at: index)
    }
  }

  public func swapNonClientEventHandler(handler: EventHandler) {
    if let compoundEventFilter = desktopNativeWidget.rootWindowEventFilter {
      if let eventFilter = x11NonClientEventFilter {
        compoundEventFilter.removeHandler(filter: eventFilter)
      }
      compoundEventFilter.addHandler(filter: handler)
    }
    x11NonClientEventFilter = handler
  }

  public override func setBoundsInPixels(bounds requestedBoundsInPixels: IntRect, localSurfaceId: LocalSurfaceId = LocalSurfaceId()) {
    var boundsPx = IntRect(origin: requestedBoundsInPixels.origin, size: adjustSize(requestedSize: requestedBoundsInPixels.size))
    let originChanged = _boundsInPixels.origin != boundsPx.origin
    let sizeChanged = _boundsInPixels.size != boundsPx.size
    var changes = XWindowChanges()
    var valueMask: Int32 = 0

    if sizeChanged {
      // Update the minimum and maximum sizes in case they have changed.
      updateMinAndMaxSize()

      if boundsPx.width < minSizeInPixels.width ||
        boundsPx.height < minSizeInPixels.height ||
        (!minSizeInPixels.isEmpty &&
      (boundsPx.width > minSizeInPixels.width ||
        boundsPx.height > minSizeInPixels.height)) {
          var sizeInPixels = boundsPx.size
          if !maxSizeInPixels.isEmpty {
            sizeInPixels.setToMin(other: maxSizeInPixels)
          }
          sizeInPixels.setToMax(other: minSizeInPixels)
          boundsPx.size = sizeInPixels
      }

      changes.width = Int32(boundsPx.width)
      changes.height = Int32(boundsPx.height)
      valueMask = valueMask | CWHeight | CWWidth
    }

    if originChanged {
      changes.x = Int32(boundsPx.x)
      changes.y = Int32(boundsPx.y)
      valueMask = valueMask | CWX | CWY
    }
    if valueMask != 0 {
      XConfigureWindow(xdisplay, xwindow, UInt32(valueMask), &changes)
    }

    // Assume that the resize will go through as requested, which should be the
    // case if we're running without a window manager.  If there's a window
    // manager, it can modify or ignore the request, but (per ICCCM) we'll get a
    // (possibly synthetic) ConfigureNotify about the actual size and correct
    // |bounds_in_pixels_| later.
    self._boundsInPixels = boundsPx

    if originChanged {
      nativeWidgetDelegate.asWidget().onNativeWidgetMove()
    }

    if sizeChanged {
      onHostResizedInPixels(_boundsInPixels.size, localSurfaceId: localSurfaceId)
      resetWindowRegion()
    }
  }

  public override func setCapture() {
    guard !hasCapture else {
      return
    }

    let oldCapturer = DesktopWindowTreeHostX11.currentCapture

    // Update |g_current_capture| prior to calling OnHostLostWindowCapture() to
    // avoid releasing pointer grab.
    DesktopWindowTreeHostX11.currentCapture = self

    if let capturer = oldCapturer {
      capturer.onHostLostWindowCapture()
    }

    hasPointerGrab = hasPointerGrab || grabPointer(window: xwindow, ownerEvents: true, cursor: UInt(None)) != 0
  }
  
  public override func releaseCapture() {
    if DesktopWindowTreeHostX11.currentCapture === self {
      DesktopWindowTreeHostX11.currentCapture = nil
      ungrabPointer()
      hasPointerGrab = false
      onHostLostWindowCapture()
    }
  }

  internal override func showImpl() {
    showWindowWithState(showState: .Normal)
  }

  internal override func hideImpl() {
    if isVisible {
      XWithdrawWindow(xdisplay, xwindow, 0)
      windowMappedInClient = false
      nativeWidgetDelegate.onNativeWidgetVisibilityChanged(visible: false)
    }
  }

  internal override func captureSystemKeyEventsImpl(nativeKeyCodes: [Int]?) -> Bool {
    // not implemented by now
    //assert(false)
    return false
  }

  internal override func releaseSystemKeyEventCapture() {
    // not implemented by now
    assert(false)
  }

  internal override func isKeyLocked(nativeKeyCode: Int) -> Bool {
    // not implemented by now
    return false
  }

  internal override func setCursorNative(cursor: PlatformCursor) {
     XDefineCursor(xdisplay, xwindow, cursor)
  }

  internal override func moveCursorToScreenLocationInPixels(location locationInPixels: IntPoint) {
     XWarpPointer(xdisplay, UInt(None), xrootWindow, 0, 0, 0, 0,
              Int32(boundsInPixels.x) + Int32(locationInPixels.x),
              Int32(boundsInPixels.y) + Int32(locationInPixels.y))
  }

  internal override func onCursorVisibilityChangedNative(show: Bool) {}

  public override func onDisplayMetricsChanged(display: Display,
                                        metrics: UInt32)  {}

  internal func beforeActivationStateChanged() {
    self.wasActive = isActive
    self.hadPointer = self.hasPointer
    self.hadPointerGrab = self.hasPointerGrab
    self.hadWindowFocus = self.hasWindowFocus
  }

  internal func afterActivationStateChanged() {

    if hadPointerGrab && !hasPointerGrab {
      dispatcher!.onHostLostMouseGrab()
    }

    let hadPointerCapture = hadPointer || hadPointerGrab
    let hasPointerCapture = hasPointer || hasPointerGrab
    
    if hadPointerCapture && !hasPointerCapture {
      onHostLostWindowCapture()
    }

    if !wasActive && isActive {
      flashFrame(false)
      onHostActivated()
      var openWindowsList = DesktopWindowTreeHostX11._openWindows!
      if let removeIndex = openWindowsList.firstIndex(where: { $0 == xwindow }) {
        openWindowsList.remove(at: removeIndex)
      }
      openWindowsList.insert(xwindow, at: openWindowsList.startIndex)
    }

    if wasActive != isActive {
      desktopNativeWidget.handleActivationChanged(active: isActive)
      nativeWidgetDelegate.asWidget().rootView!.schedulePaint()
    }
  }

  internal func onMaximizedStateChanged() {}
  internal func onFullscreenStateChanged() {}

  private func onCrossingEvent(enter: Bool,
                               focusInWindowOrAncestor: Bool,
                               mode: Int,
                               detail: Int) {
    if detail == NotifyInferior {
      return
    }

    beforeActivationStateChanged()

    if mode == NotifyGrab {
      hasPointerGrab = enter
    } else if mode == NotifyUngrab {
      hasPointerGrab = false
    }

    hasPointer = enter
    if focusInWindowOrAncestor && !hasWindowFocus {
      hasPointerFocus = hasPointer
    }

    afterActivationStateChanged()
  }

  private func onFocusEvent(focusIn: Bool, mode: Int32, detail: Int32) {
    
    if detail == NotifyInferior {
      return
    }

    let notifyGrab = mode == NotifyGrab || mode == NotifyUngrab

    beforeActivationStateChanged()

    if !notifyGrab && detail != NotifyPointer {
      hasWindowFocus = focusIn
    }

    if !notifyGrab && hasPointer {
      switch detail {
        case NotifyAncestor:
          fallthrough
        case NotifyVirtual:
          hasPointerFocus = !focusIn
        case NotifyPointer:
          hasPointerFocus = focusIn
        case NotifyNonlinear:
          fallthrough
        case NotifyNonlinearVirtual:
          hasPointerFocus = false
        default:
          break
      }
    }

    ignoreKeyboardInput = false

    afterActivationStateChanged()
  }

  //private func initDispatcher(params: UIWidget.InitParams) -> WindowEventDispatcher? {
  //}

  private func adjustSize(requestedSize: IntSize) -> IntSize {
    let displays = Graphics.Screen.getScreenByType(type: ScreenType.Native).getAllDisplays()
    // Compare against all monitor sizes. The window manager can move the window
    // to whichever monitor it wants.
    for display in displays {
      if requestedSize == display.sizeInPixel {
        return IntSize(width: requestedSize.width - 1,
                    height: requestedSize.height - 1)
      }
    }

    // Do not request a 0x0 window size. It causes an XError.
    var sizeInPixels = requestedSize
    sizeInPixels.setToMax(other: IntSize(width: 1, height: 1))
    return sizeInPixels
  }

  private func onWMStateUpdated() {
    var atomList = [Atom]()
    // Ignore the return value of ui::GetAtomArrayProperty(). Fluxbox removes the
    // _NET_WM_STATE property when no _NET_WM_STATE atoms are set.
    let _ = getAtomArrayProperty(window: xwindow, propertyName: "_NET_WM_STATE", value: &atomList)

    let wasMinimized = isMinimized

    windowProperties.removeAll()

    //     std::copy(atom_list.begin(), atom_list.end(),
    //            inserter(window_properties_, window_properties_.begin()))

    windowProperties.append(contentsOf: atomList)

    // Propagate the window minimization information to the content window, so
    // the render side can update its visibility properly. OnWMStateUpdated() is
    // called by PropertyNofify event from DispatchEvent() when the browser is
    // minimized or shown from minimized state. On Windows, this is realized by
    // calling OnHostResized() with an empty size. In particular,
    // HWNDMessageHandler::GetClientAreaBounds() returns an empty size when the
    // window is minimized. On Linux, returning empty size in GetBounds() or
    // SetBounds() does not work.
    // We also propagate the minimization to the compositor, to makes sure that we
    // don't draw any 'blank' frames that could be noticed in applications such as
    // window manager previews, which show content even when a window is
    // minimized.
    if isMinimized != wasMinimized {
      if isMinimized {
        isVisible = false
        contentWindow!.hide()
      } else {
        contentWindow!.show()
        isVisible = true
      }
    }

    if restoredBoundsInPixels.isEmpty {
      assert(!isFullscreen)
      if isMaximized {
        // The request that we become maximized originated from a different
        // process. |bounds_in_pixels_| already contains our maximized bounds. Do
        // a best effort attempt to get restored bounds by setting it to our
        // previously set bounds (and if we get this wrong, we aren't any worse
        // off since we'd otherwise be returning our maximized bounds).
        ////print("\(previousBoundsInPixels)")
        restoredBoundsInPixels = previousBoundsInPixels
      }
    } else if !isMaximized && !isFullscreen {
      // If we have restored bounds, but WM_STATE no longer claims to be
      // maximized or fullscreen, we should clear our restored bounds.
      restoredBoundsInPixels = IntRect()
    }

    // Ignore requests by the window manager to enter or exit fullscreen (e.g. as
    // a result of pressing a window manager accelerator key). Chrome does not
    // reference window manager initiated fullscreen. In particular, Chrome needs to
    // do preprocessing before the x window's fullscreen state is toggled.

    isAlwaysOnTop = hasWMSpecProperty(property: "_NET_WM_STATE_ABOVE")

    // Now that we have different window properties, we may need to relayout the
    // window. (The windows code doesn't need this because their window change is
    // synchronous.)
    relayout()
    resetWindowRegion()
  }

  private func onFrameExtentsUpdated() {
    var insets = [Int]()
    if getIntArrayProperty(window: xwindow, propertyName: "_NET_FRAME_EXTENTS", value: &insets) && insets.count == 4 {
      // |insets| are returned in the order: [left, right, top, bottom].
      nativeWindowFrameBordersInPixels = IntInsets(top: insets[2], left: insets[0], bottom: insets[3], right: insets[1])
    } else {
      nativeWindowFrameBordersInPixels = IntInsets()
    }
  }

  private func updateWorkspace() -> Bool {
    return false
  }

  private func updateMinAndMaxSize() {
    let minimumInPixels = toPixelRect(IntRect(size: nativeWidgetDelegate.minimumSize)).size
    let maximumInPixels = toPixelRect(IntRect(size: nativeWidgetDelegate.maximumSize)).size

    if minSizeInPixels == minimumInPixels && maxSizeInPixels == maximumInPixels {
        return
    }

    minSizeInPixels = minimumInPixels
    maxSizeInPixels = maximumInPixels

    var hints = XSizeHints()
    var suppliedReturn = 0
    XGetWMNormalHints(xdisplay, xwindow, &hints, &suppliedReturn)

    if minimumInPixels.isEmpty {
      hints.flags &= ~PMinSize
    } else {
      hints.flags |= PMinSize
      hints.min_width = Int32(minSizeInPixels.width)
      hints.min_height = Int32(minSizeInPixels.height)
    }

    if maximumInPixels.isEmpty {
      hints.flags &= ~PMaxSize
    } else {
      hints.flags |= PMaxSize
      hints.max_width = Int32(maxSizeInPixels.width)
      hints.max_height = Int32(maxSizeInPixels.height)
    }

    XSetWMNormalHints(xdisplay, xwindow, &hints)
  }

  private func updateWMUserTime(event: PlatformEvent) {
    guard isActive else {
      return
    }

    let type: EventType = eventTypeFromNative(nativeEvent: event)

    if type == .MousePressed || type == .KeyPressed || type == .TouchPressed {

      let wmUserTimeMS: UInt = UInt(eventTimeFromNative(nativeEvent: event).milliseconds)
      var arr = [UInt]()
      arr.append(wmUserTimeMS)

      let _ = arr.withUnsafeBufferPointer({ (ptr: UnsafeBufferPointer<UInt>) in
        XChangeProperty(xdisplay,
                        xwindow,
                        atomCache.getAtom(name: "_NET_WM_USER_TIME")!,
                        XA_ARDINAL,
                        32,
                        PropModeReplace,
                        unsafeBitCast(ptr.baseAddress, to: UnsafePointer<UInt8>.self),
                        1)
      })

      //DesktopHandlerX11.instance.wmUserTimeMS = wmUserTimeMS
    }
  }

  private func setUseNativeFrame(_ useNativeFrame: Bool) {
    self.useNativeFrame = useNativeFrame
    setUseOSWindowFrame(window: xwindow, useOSWindowFrame: useNativeFrame)
    resetWindowRegion()
  }

  private func dispatchMouseEvent(event: inout MouseEvent) {
    // In Windows, the native events sent to chrome are separated into client
    // and non-client versions of events, which we record on our LocatedEvent
    // structures. On X11, we emulate the concept of non-client. Before we pass
    // this event to the cross platform event handling framework, we need to
    // make sure it is appropriately marked as non-client if it's in the non
    // client area, or otherwise, we can get into a state where the a window is
    // set as the |mouse_pressed_handler_| in window_event_dispatcher.cc
    // despite the mouse button being released.
    //
    // We can't do this later in the dispatch process because we share that
    // with ash, and ash gets confused about event IS_NON_LIENT-ness on
    // events, since ash doesn't expect this bit to be set, because it's never
    // been set before. (This works on ash on Windows because none of the mouse
    // events on the ash desktop are clicking in what Windows considers to be a
    // non client area.) Likewise, we won't want to do the following in any
    // WindowTreeHost that hosts ash.
    if let win = contentWindow, let delegate = win.delegate {
      var flags = event.flags.rawValue

      let hitTestCode = delegate.getNonClientComponent(point: event.location)
      if hitTestCode != .HTCLIENT && hitTestCode != .HTNOWHERE {
        flags |= EventFlags.IsNonClient.rawValue
      }
      event.flags = EventFlags(rawValue: flags)
    }

    // While we unset the urgency hint when we gain focus, we also must remove it
    // on mouse clicks because we can call FlashFrame() on an active window.
    if event.isAnyButton || event.isMouseWheelEvent {
      flashFrame(false)
    }

    if DesktopWindowTreeHostX11.currentCapture == nil || DesktopWindowTreeHostX11.currentCapture === self {
      let _ = sendEventToSink(event: event)
    } else {
      // Another DesktopWindowTreeHostX11 has installed itself as
      // capture. Translate the event's location and dispatch to the other.
      var locatedEvent = event as LocatedEvent
      //convertEventToDifferentHost(locatedEvent: &locatedEvent, host: DesktopWindowTreeHostX11.currentCapture!)
      convertEventLocationToTargetWindowLocation(
        DesktopWindowTreeHostX11.currentCapture!.locationOnScreenInPixels,
        locationOnScreenInPixels, 
        &locatedEvent)
      let _ = DesktopWindowTreeHostX11.currentCapture!.sendEventToSink(event: locatedEvent as! MouseEvent)
    }
  }

  private func dispatchTouchEvent(event: inout TouchEvent) {
    if DesktopWindowTreeHostX11.currentCapture != nil &&
        DesktopWindowTreeHostX11.currentCapture !== self && event.type == .TouchPressed {
        var locatedEvent = event as LocatedEvent
        convertEventLocationToTargetWindowLocation(
          DesktopWindowTreeHostX11.currentCapture!.locationOnScreenInPixels,
          locationOnScreenInPixels, 
          &locatedEvent)
        //convertEventToDifferentHost(locatedEvent: &locatedEvent, host: DesktopWindowTreeHostX11.currentCapture!)
        let _ = DesktopWindowTreeHostX11.currentCapture!.sendEventToSink(event: event)
    } else {
        let _ = sendEventToSink(event: event)
    }
  }

  private func dispatchKeyEvent(event: inout KeyEvent) {
    if nativeWidgetDelegate.asWidget().isActive {
      sendEventToSink(event: event)
    }
  }

  private func resetWindowRegion() {
    if customWindowShape {
      XShapeCombineRegion(xdisplay, xwindow, X11ShapeBounding, 0, 0,
                         windowShape, False)
      return
    }

    windowShape = nil

    if !isMaximized && !isFullscreen {
      var windowMask = Path()
      let widget = nativeWidgetDelegate.asWidget()
      if let view = widget.nonClientView {
        // Some frame views define a custom (non-rectangular) window mask. If
        // so, use it to define the window shape. If not, fall through.
        view.getWindowMask(size: _boundsInPixels.size, windowMask: &windowMask)
        if windowMask.pointCount > 0 {
          var x11Points = ContiguousArray<XPoint>(repeating: XPoint(), count: windowMask.pointCount)
          windowShape = createRegionFromPath(path: windowMask, points: &x11Points)
          XShapeCombineRegion(xdisplay, xwindow, X11ShapeBounding, 0, 0,
                              windowShape, False)
          return
        }
      }
    }

    // If we didn't set the shape for any reason, reset the shaping information.
    // How this is done depends on the border style, due to quirks and bugs in
    // various window managers.
    if shouldUseNativeFrame {
      // If the window has system borders, the mask must be set to null (not a
      // rectangle), because several window managers (eg, KDE, XFCE, XMonad) will
      // not put borders on a window with a custom shape.
      XShapeCombineMask(xdisplay, xwindow, X11ShapeBounding, 0, 0, UInt(None), X11ShapeSet)
    } else {
      // Conversely, if the window does not have system borders, the mask must be
      // manually set to a rectangle that covers the whole window (not null). This
      // is due to a bug in KWin <= 4.11.5 (KDE bug #330573) where setting a null
      // shape causes the hint to disable system borders to be ignored (resulting
      // in a double border).
      var r = XRectangle(x: 0, y: 0, width: UInt16(_boundsInPixels.width), height: UInt16(_boundsInPixels.height))
      XShapeCombineRectangles(
        xdisplay, xwindow, X11ShapeBounding, 0, 0, &r, 1, X11ShapeSet, YXBanded)
    }
  }

  private func serializeImageRepresentation(bitmap: Bitmap?,//rep: ImageSkia,//ImageRep,
                                            data: inout ContiguousArray<UInt>) {
    if let bmp = bitmap {
      let width = Int(bmp.width)
      data.append(UInt(width))

      let height = Int(bmp.height)
      data.append(UInt(height))

      //SkAutoLockPixels locker(bm)

      //bmp.lockPixels()

      for y in 0..<height {
        for x in 0..<width {
          let color = bmp.getColorAt(x: Float(x), y: Float(y))
          data.append(UInt(color.value))
        }
      }
      
      //bmp.unlockPixels()
    }
  }

  private func mapWindow(showState: WindowShowState) {
    if showState != .Default && showState != .Normal &&
       showState != .Inactive && showState != .Maximized {
     // It will behave like SHOW_STATE_NORMAL.
     //NOTIMPLEMENTED();
     // TODO: throw a exception here
     assert(false)
   }

   var sizeHints = XSizeHints()
   sizeHints.flags = 0
   var suppliedReturn: Int = 0
   XGetWMNormalHints(xdisplay, xwindow, &sizeHints, &suppliedReturn)
   sizeHints.flags = PPosition
   sizeHints.x = Int32(_boundsInPixels.x)
   sizeHints.y = Int32(_boundsInPixels.y)
   XSetWMNormalHints(xdisplay, xwindow, &sizeHints)

   ignoreKeyboardInput = showState == .Inactive

   let wmUserTimeMS = showState == .Inactive ? 0 : X11EventSource.instance.timestamp//DesktopHandlerX11.instance.wmUserTimeMS
   let arr = [UInt](repeating: wmUserTimeMS, count: 1)

   if showState == .Inactive || wmUserTimeMS != 0 {

     let _ = arr.withUnsafeBufferPointer({ (ptr: UnsafeBufferPointer<UInt>) in
       XChangeProperty(xdisplay,
                       xwindow,
                       atomCache.getAtom(name: "_NET_WM_USER_TIME")!,
                       XA_ARDINAL,
                       32,
                       PropModeReplace,
                       //UnsafePointer<UInt8>(ptr.baseAddress),
                       unsafeBitCast(ptr.baseAddress, to: UnsafePointer<UInt8>.self),
                       1)
     })
    }

    //if let eventSource = X11EventSource.instance() as! X11EventSource? {
    //  eventSource.blockUntilWindowMapped(window: xwindow)
    //}
    let _ = X11EventSource.instance
    //assert(eventSource != nil)
    
    updateMinAndMaxSize()
    
    XMapWindow(xdisplay, xwindow)

    windowMappedInClient = true
  }

  private func setWindowTransparency() {
    let isTransparent = false//useARGBVisual
    compositor!.backgroundColor = Color.White//isTransparent ? Color.Transparent
                                             //              : Color.White
    window.transparent = isTransparent
    contentWindow!.transparent = isTransparent
  }

  private func relayout() {
    let widget = nativeWidgetDelegate.asWidget()
    if let nonClientView = widget.nonClientView {
      nonClientView.clientView!.invalidateLayout()
      nonClientView.invalidateLayout()
    }
    widget.rootView!.layout()
  }

  // PlatformEventDispatcher:
  public func canDispatchEvent(event: inout PlatformEvent) -> Bool {
    let xidev = unsafeBitCast(event.xcookie.data, to: UnsafeMutablePointer<XIDeviceEvent>.self)//.load(as: UnsafeMutablePointer<XIDeviceEvent>.self)
    return event.xany.window == xwindow || (event.type == GenericEvent && xidev.pointee.event == xwindow)
  }
  
  public func dispatchEvent(event: inout PlatformEvent) -> PostDispatchAction {
      //var xev = UnsafeMutablePointer<XEvent>(&event)
   let xev = event
   //TRACE_EVENT1("views", "DesktopWindowTreeHostX11::Dispatch",
   //             "event->type", event->type);

   updateWMUserTime(event: event)

  // May want to factor CheckXEventForConsistency(xev); into a common location
  // since it is called here.
  switch xev.type {
    case EnterNotify, LeaveNotify:
      // Ignore EventNotify and LeaveNotify events from children of |xwindow_|.
      // NativeViewGLSurfaceGLX adds a child to |xwindow_|.
      // TODO(pkotwicz|tdanderson): Figure out whether the suppression is
      // necessary. crbug.com/385716
      if xev.xcrossing.detail == NotifyInferior {
        break
      }

      var mouseEvent = MouseEvent(xev)
      dispatchMouseEvent(event: &mouseEvent)

    case Expose:
      let damageRectInPixels = IntRect(x: Int(xev.xexpose.x), y: Int(xev.xexpose.y),
                                    width: Int(xev.xexpose.width), height: Int(xev.xexpose.height))
      compositor!.scheduleRedrawRect(damaged: damageRectInPixels)
    case KeyPress:
      var keydownEvent = KeyEvent(xev)
      dispatchKeyEvent(event: &keydownEvent)
    case KeyRelease:
      // There is no way to deactivate a window in X11 so ignore input if
      // window is supposed to be 'inactive'. See comments in
      // DesktopHandlerX11.deactivateWindow() for more details.
      if !isActive && !hasCapture {
        break
      }
      var keyEvent = KeyEvent(xev)
      dispatchKeyEvent(event: &keyEvent)
    case ButtonPress, ButtonRelease:
      let eventType: EventType = eventTypeFromNative(nativeEvent: xev)
      switch eventType {
        case .MouseWheel:
          let mousewev = MouseWheelEvent(xev)
          var mouseev = mousewev as MouseEvent
          dispatchMouseEvent(event: &mouseev)
        case .MousePressed, .MouseReleased:
          var mouseev = MouseEvent(xev)
          dispatchMouseEvent(event: &mouseev)
        case .Unknown:
          // No event is created for X11-release events for mouse-wheel buttons.
          break
        default:
          break
          //NOTREACHED() << event_type
      }
    case FocusIn, FocusOut:
      onFocusEvent(focusIn: xev.type == FocusIn, 
                   mode: xev.xfocus.mode,
                   detail: xev.xfocus.detail)
    //case FocusOut:
    //  if xev.xfocus.mode != NotifyGrab {
    //    releaseCapture()
    //    onHostLostWindowCapture()
    //    DesktopHandlerX11.instance.processXEvent(event: &event)
    //  } else {
    //    dispatcher!.onHostLostMouseGrab()
    //  }
    //case FocusIn:
    //  DesktopHandlerX11.instance.processXEvent(event: &event)
    case ConfigureNotify:
      assert(xwindow == xev.xconfigure.window)
      assert(xwindow == xev.xconfigure.event)
      // It's possible that the X window may be resized by some other means than
      // from within aura (e.g. the X window manager can change the size). Make
      // sure the root window size is maintained properly.
      var translatedXInPixels: Int32 = xev.xconfigure.x
      var translatedYInPixels: Int32 = xev.xconfigure.y
      if xev.xconfigure.send_event == 0 && xev.xconfigure.override_redirect == 0 {
        var unused = MumbaShims.Window()
        XTranslateCoordinates(xdisplay, xwindow, xrootWindow, 0, 0,
                              &translatedXInPixels, &translatedYInPixels,
                              &unused)
      }
      let boundsPx = IntRect(x: Int(translatedXInPixels), y: Int(translatedYInPixels),
                             width: Int(xev.xconfigure.width), height: Int(xev.xconfigure.height))

      let sizeChanged = self._boundsInPixels.size != boundsPx.size

      let originChanged = self._boundsInPixels.origin != boundsPx.origin
      self.previousBoundsInPixels = self._boundsInPixels
      self._boundsInPixels = boundsPx

      if originChanged {
        onHostMovedInPixels(newLocation: _boundsInPixels.origin)
      }

      if sizeChanged {
        //delayed_resize_task_.Reset(base::Bind(
        //    &DesktopWindowTreeHostX11::DelayedResize,
        //    close_widget_factory_.GetWeakPtr(), bounds_in_pixels.size()));
        //base::MessageLoop::current()->PostTask(
        //    FROM_HERE, delayed_resize_task_.callback());

        // TODO: o original é assincrono, refazer assim que
        // mecanismo de tasks estiver pronto
        ////print("boundsInPixels: \(boundsInPixels.size)")
        delayedResize(sizeInPixels: boundsInPixels.size)
        //restartDelayedResizeTask()
      }
    case GenericEvent:
      if let factory = X11TouchFactory.instance() {
        if !factory.shouldProcessXI2Event(xev: xev) {
          break
        }
      }

      let enterEvent = xev.xcookie.data.bindMemory(to: XIEnterEvent.self, capacity: 1)
      let xiEvent = xev.xcookie.data.bindMemory(to: XIEvent.self, capacity: 1)
      switch xiEvent.pointee.evtype {//static_cast<XIEvent*>(xev->xcookie.data)->evtype {
        case XI_Enter:
          fallthrough
        case XI_Leave:
          onCrossingEvent(enter: enterEvent.pointee.evtype == XI_Enter, 
                          focusInWindowOrAncestor: enterEvent.pointee.focus != 0,
                          mode: XI2ModeToXMode(enterEvent.pointee.mode),
                          detail: Int(enterEvent.pointee.detail))
          return PostDispatchAction.StopPropagation
        case XI_FocusIn:
          fallthrough
        case XI_FocusOut:
          onFocusEvent(focusIn: enterEvent.pointee.evtype == XI_FocusIn,
                       mode: Int32(XI2ModeToXMode(enterEvent.pointee.mode)), 
                       detail: enterEvent.pointee.detail)
          return PostDispatchAction.StopPropagation
        default:
          break
      }

      let type: EventType = eventTypeFromNative(nativeEvent: xev)
      var lastEvent = XEvent()
      var numCoalesced = 0

      switch type {
        case .TouchMoved:
          numCoalesced = coalescePendingMotionEvents(xev: &event, lastEvent: &lastEvent)
          if numCoalesced > 0 {
            event = lastEvent
          }
          fallthrough
        case .TouchPressed, .TouchReleased:
          var touchev = TouchEvent(xev)
          dispatchTouchEvent(event: &touchev)
        case .MouseMoved, .MouseDragged, .MousePressed,
             .MouseReleased, .MouseEntered, .MouseExited:
          if type == .MouseMoved || type == .MouseDragged {
            // If this is a motion event, we want to coalesce all pending motion
            // events that are at the top of the queue.
            numCoalesced = coalescePendingMotionEvents(xev: &event, lastEvent: &lastEvent)
            if numCoalesced > 0 {
              event = lastEvent
            }
          }
          var mouseev = MouseEvent(xev)
          dispatchMouseEvent(event: &mouseev)
        case .MouseWheel:
          let mousewev = MouseWheelEvent(xev)
          var mouseev = mousewev as MouseEvent
          dispatchMouseEvent(event: &mouseev)
        case .ScrollFlingStart, .ScrollFlingCancel, .Scroll:
          let scrollev = ScrollEvent(xev)
          let _ = sendEventToSink(event: scrollev)
        case .KeyPressed, .KeyReleased:
          var keyEvent = KeyEvent(xev)
          dispatchKeyEvent(event: &keyEvent)
        case .Unknown:
          break
        default:
          break
          //NOTREACHED();
      }

      // If we coalesced an event we need to free its cookie.
      if numCoalesced > 0 {
        XFreeEventData(xev.xgeneric.display, &lastEvent.xcookie)
      }

    case MapNotify:
      windowMappedInServer = true
      for observer in observers {
        observer.onWindowMapped(xid: xwindow)
      }
      if shouldMaximizeAfterMap {
        maximize()
        shouldMaximizeAfterMap = false
      }
    case UnmapNotify:
      windowMappedInServer = false
      hasPointer = false
      hasPointerGrab = false
      hasPointerFocus = false
      hasWindowFocus = false
      for observer in observers {
        observer.onWindowUnmapped(xid: xwindow)
      }
    case ClientMessage:
      let messageType: Atom = xev.xclient.message_type
      if messageType == atomCache.getAtom(name: "WM_PROTOCOLS")! {
        let (l0, _, _, _, _) = xev.xclient.data.l
        let proto: Atom = Atom(l0)
        if proto == atomCache.getAtom(name: "WM_DELETE_WINDOW")! {
          // We have received a close message from the window manager.
          onHostCloseRequested()
        } else if proto == atomCache.getAtom(name: "_NET_WM_PING")! {
          var replyEvent = event
          replyEvent.xclient.window = xrootWindow

          XSendEvent(xdisplay,
                     replyEvent.xclient.window,
                     False,
                     SubstructureRedirectMask | SubstructureNotifyMask,
                     &replyEvent)
        }
      } else if messageType == atomCache.getAtom(name: "XdndEnter")! {
        dragDropClient!.onXdndEnter(event: xev.xclient)
      } else if messageType == atomCache.getAtom(name: "XdndLeave")! {
        dragDropClient!.onXdndLeave(event: xev.xclient)
      } else if messageType == atomCache.getAtom(name: "XdndPosition")! {
        dragDropClient!.onXdndPosition(event: xev.xclient)
      } else if messageType == atomCache.getAtom(name: "XdndStatus")! {
        dragDropClient!.onXdndStatus(event: xev.xclient)
      } else if messageType == atomCache.getAtom(name: "XdndFinished")! {
        dragDropClient!.onXdndFinished(event: xev.xclient)
      } else if messageType == atomCache.getAtom(name: "XdndDrop")! {
        dragDropClient!.onXdndDrop(event: xev.xclient)
      }
    case MappingNotify:
      switch xev.xmapping.request {
        case MappingModifier, MappingKeyboard:
          XRefreshKeyboardMapping(&event.xmapping)
        case MappingPointer:
          X11DeviceDataManager.instance()!.updateButtonMap()
        default: // TODO: throw exception here
          break
          //NOTIMPLEMENTED() << " Unknown request: " << xev.xmapping.request
      }
    case MotionNotify:
      // Discard all but the most recent motion event that targets the same
      // window with unchanged state.
      var lastEvent = XEvent()
      while XPending(xev.xany.display) != 0 {
        var nextEvent = XEvent()
        XPeekEvent(xev.xany.display, &nextEvent)
        if nextEvent.type == MotionNotify &&
           nextEvent.xmotion.window == xev.xmotion.window &&
           nextEvent.xmotion.subwindow == xev.xmotion.subwindow &&
          nextEvent.xmotion.state == xev.xmotion.state {
          XNextEvent(xev.xany.display, &lastEvent)
          event = lastEvent
        } else {
          break
        }
      }

      var mouseev = MouseEvent(xev)
      dispatchMouseEvent(event: &mouseev)

      case PropertyNotify:
        let changedAtom: Atom = xev.xproperty.atom
        if changedAtom == atomCache.getAtom(name: "_NET_WM_STATE") {
          onWMStateUpdated()
        }
        else if changedAtom == atomCache.getAtom(name: "_NET_FRAME_EXTENTS") {
          onFrameExtentsUpdated()
        } else if changedAtom == atomCache.getAtom(name: "_NET_WM_DESKTOP") {
          if updateWorkspace() {
            onHostWorkspaceChanged()
          }
        }
      case SelectionNotify:
        dragDropClient!.onSelectionNotify(xselection: xev.xselection)
      default:
        break
    }

    return PostDispatchAction.StopPropagation
  }

  private func delayedResize(sizeInPixels: IntSize) {
    onHostResizedInPixels(sizeInPixels)
    resetWindowRegion()
    //delayedResizeTask.cancel()
  }
  
  private func delayedChangeFrameType(type newType: UIWidget.FrameType) {
    setUseNativeFrame(newType == .ForceNative)
    // Replace the frame and layout the contents. Even though we don't have a
    // swapable glass frame like on Windows, we still replace the frame because
    // the button assets don't update otherwise.
    nativeWidgetDelegate.asWidget().nonClientView!.updateFrame()
  }

  private func toDIPRect(_ rectInPixels: IntRect) -> IntRect {
    var rectInDip = FloatRect(rectInPixels)
    let _ = rootTransform.transformRectReverse(rect: &rectInDip)
    return IntRect.toEnclosingRect(rect: rectInDip)
  }
  
  private func toPixelRect(_ rectInDip: IntRect) -> IntRect {
    var rectInPixels = FloatRect(rectInDip)
    rootTransform.transformRect(rect: &rectInPixels)
    return IntRect.toEnclosingRect(rect: rectInPixels)
  }

  //private func enableEventListening() {}

  private func restartDelayedResizeTask() {
    delayedResize(sizeInPixels: _boundsInPixels.size)
  }

  private func grabPointer(window: XID, ownerEvents: Bool, cursor: MumbaShims.Cursor) -> Int {

    var result = GrabInvalidTime

    if X11Environment.isXInput2Available {
      // Do an XInput2 pointer grab. If there is an active XInput2 pointer grab
      // as a result of normal button press, XGrabPointer() will fail.
      //unsigned char mask[XIMaskLen(XI_LASTEVENT)]
      var mask: [UInt8] = [UInt8](repeating: 0, count: (Int(XI_LASTEVENT) >> 3) + 1)
      _XISetMask(mask: &mask, XI_ButtonPress)
      _XISetMask(mask: &mask, XI_ButtonRelease)
      _XISetMask(mask: &mask, XI_Motion)
      _XISetMask(mask: &mask, XI_TouchBegin)
      _XISetMask(mask: &mask, XI_TouchUpdate)
      _XISetMask(mask: &mask, XI_TouchEnd)
      var evmask = XIEventMask()
      evmask.mask_len = Int32(mask.count)

      mask.withUnsafeMutableBufferPointer({ (arr: inout UnsafeMutableBufferPointer<UInt8>) in
        evmask.mask = arr.baseAddress
      })

      let masterPointers =
        X11DeviceDataManager.instance()!.masterPointers
        for masterPointer in masterPointers {
          evmask.deviceid = Int32(masterPointer)
          result = XIGrabDevice(
            X11Environment.XDisplay, Int32(masterPointer), window, CurrentTime, cursor,
            GrabModeAsync, GrabModeAsync, ownerEvents == true ? 1 : 0, &evmask)
          // Assume that the grab will succeed on either all or none of the master
          // pointers.
          if result != GrabSuccess {
            // Try core pointer grab.
            break
          }
        }
    }

    if result != GrabSuccess {
      let eventMask: Int = PointerMotionMask | ButtonReleaseMask | ButtonPressMask
      result =
        XGrabPointer(X11Environment.XDisplay, window, ownerEvents == true ? 1 : 0, UInt32(eventMask),
                     GrabModeAsync, GrabModeAsync, UInt(None), cursor, CurrentTime)
    }

    if result == GrabSuccess {
      grabWindow = window
      grabOwnerEvents = ownerEvents
    }

    return Int(result)
  }

  private func ungrabPointer() {
    grabWindow = UInt(None)

    if X11Environment.isXInput2Available {
      let masterPointers = X11DeviceDataManager.instance()!.masterPointers
      for masterPointer in masterPointers {
        XIUngrabDevice(X11Environment.XDisplay, Int32(masterPointer), CurrentTime)
      }
    }
    // Try core pointer ungrab in case the XInput2 pointer ungrab failed.
    XUngrabPointer(X11Environment.XDisplay, CurrentTime)
  }

  private func setWMSpecState(enabled: Bool, state1: Atom, state2: Atom) {
    var xclient = XEvent()
    memset(&xclient, 0, MemoryLayout<XEvent>.stride)
    xclient.type = ClientMessage
    xclient.xclient.window = xwindow
    xclient.xclient.message_type = atomCache.getAtom(name: "_NET_WM_STATE")!
    xclient.xclient.format = 32

    //var dataBuffer = UnsafeMutableBufferPointer<Int64>(start: &xclient.xclient.data, count: 5)

    //dataBuffer[0] = enabled ? NetWMStateAdd : NetWMStateRemove
    //dataBuffer[1] = Int64(state1)
    //dataBuffer[2] = Int64(state2)
    //dataBuffer[3] = 1
    //dataBuffer[4] = 0

    xclient.xclient.data.l = (enabled ? NetWMStateAdd : NetWMStateRemove, Int(state1), Int(state2), 1, 0)
    XSendEvent(xdisplay, xrootWindow, False,
             SubstructureRedirectMask | SubstructureNotifyMask,
             &xclient)
  }

  private func hasWMSpecProperty(property: String) -> Bool {

    if let atom = atomCache.getAtom(name: property) {
        for p in windowProperties {
          if p == atom {
            return true
          }
        }
    }
    return false
  }
  
  // private func convertEventToDifferentHost(locatedEvent: inout LocatedEvent, host: DesktopWindowTreeHostX11) {
  //   assert(self !== host)

  //   let displaySrc = Screen.nativeScreen._getDisplayNearestWindow(windowId: window.id)
  //   let displayDest = Screen.nativeScreen._getDisplayNearestWindow(windowId: host.window.id)

  //   assert(displaySrc!.deviceScaleFactor == displayDest!.deviceScaleFactor)

  //   let offset: IntVec2 = self.locationOnNativeScreen - host.locationOnNativeScreen

  //   let locationInPixelInHost: FloatPoint = locatedEvent.location + FloatVec2(offset)
  //   locatedEvent.locationf = locationInPixelInHost
  // }

  private func initX11Window(compositor: UIWebWindowCompositor, params: UIWidget.InitParams) throws {
    var attributeMask: Int = CWBackPixmap

    var swa = XSetWindowAttributes()
    memset(&swa, 0, MemoryLayout<XSetWindowAttributes>.stride)
    swa.background_pixmap = UInt(None)
    swa.bit_gravity = NorthWestGravity

    var windowType: Atom = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_NORMAL") ?? 0

    switch params.type {
      case .Menu:
        swa.override_redirect = True
        windowType = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_MENU")!
      case .Tooltip:
        swa.override_redirect = True
        windowType = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_TOOLTIP")!
      case .Popup:
        swa.override_redirect = True
        windowType = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_NOTIFICATION")!
      case .Drag:
        swa.override_redirect = True
        windowType = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_DND")!
      default:
        windowType = atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE_NORMAL")!
    }

    if !activatable {
     swa.override_redirect = True
    }

    if swa.override_redirect != 0 {
      attributeMask |= CWOverrideRedirect
    }

    var enableTransparentVisuals: Bool
    switch params.opacity {
      case UIWidget.WindowOpacity.Opaque:
        enableTransparentVisuals = false
      case UIWidget.WindowOpacity.Translucent:
        enableTransparentVisuals = true
      case UIWidget.WindowOpacity.InferOpacity:
        fallthrough
      default:
        enableTransparentVisuals = params.type == WindowType.Drag
    }
    let usingSoftwareRendering = false
    // Detect whether we're running inside a compositing manager. If so, try to
    // use the ARGB visual. Otherwise, just use our parent's visual.
    var visual: UnsafeMutablePointer<Visual>? = nil // TODO: como encaixar "CopyFromParent" aqui?
    var depth = CopyFromParent
    swa.colormap = Colormap(CopyFromParent)
    // TODO: we should use XVisualManager::ChooseVisualForWindow instead now
   
    let usingCompositingWm = XGetSelectionOwner(xdisplay, atomCache.getAtom(name: "_NET_WM_M_S0")!) != UInt(None)
    var haveGpuArgbVisual = false
    let rgbaVisual = getARGBVisual()
    if rgbaVisual != nil {
      haveGpuArgbVisual = true
    }

    if haveGpuArgbVisual {
       visual = rgbaVisual!
       depth = 32
       attributeMask |= CWColormap
       swa.colormap = XCreateColormap(xdisplay, xrootWindow, visual, AllocNone)
        //useARGBVisual = true
     }

     if enableTransparentVisuals && usingCompositingWm && (haveGpuArgbVisual || usingSoftwareRendering) {
       useARGBVisual = true
     }
    
    // x.org will BadMatch if we don't set a border when the depth isn't the
    // same as the parent depth.
    attributeMask |= CWBorderPixel
    swa.border_pixel = 0

    _boundsInPixels = toPixelRect(params.bounds)
    _boundsInPixels.size = adjustSize(requestedSize: _boundsInPixels.size)
    xwindow = XCreateWindow(xdisplay, xrootWindow, Int32(_boundsInPixels.x),
                           Int32(_boundsInPixels.y), UInt32(_boundsInPixels.width),
                           UInt32(_boundsInPixels.height),
                           0,  // border width
                           Int32(depth), UInt32(InputOutput), visual, UInt(attributeMask), &swa)

    if isX11Error(code: xwindow) {
     throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }
   
    //if let eventSource = PlatformEventSource.instance() {
     let eventSource = X11EventSource.instance
     eventSource.addPlatformEventDispatcher(dispatcher: self)
    //}

    DesktopWindowTreeHostX11._openWindows!.append(xwindow)

    // TODO(erg): Maybe need to set a ViewProp here like in RWHL::RWHL().
    let eventMask: Int =  ButtonPressMask | ButtonReleaseMask | FocusChangeMask |
                          KeyPressMask | KeyReleaseMask |
                          EnterWindowMask | LeaveWindowMask |
                          ExposureMask | VisibilityChangeMask |
                          StructureNotifyMask | PropertyChangeMask |
                          PointerMotionMask

    XSelectInput(xdisplay, xwindow, eventMask)
    XFlush(xdisplay)

    if X11Environment.isXInput2Available {
      X11TouchFactory.instance()!.setupXI2ForXWindow(window: xwindow)
    }

    // TODO(erg): We currently only request window deletion events. We also
    // should listen for activation events and anything else that GTK+ listens
    // for, and do something useful.
    var protocols = ContiguousArray<Atom>(repeating: 0, count: 2)
    protocols[0] = atomCache.getAtom(name: "WM_DELETE_WINDOW")!
    protocols[1] = atomCache.getAtom(name: "_NET_WM_PING")!
    let res = XSetWMProtocols(xdisplay, xwindow, &protocols[0], 2)
    if isX11Error(code: res) {
      throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }

    // We need a WM_LIENT_MACHINE and WM_LOCALE_NAME value so we integrate with
    // the desktop environment.
    XSetWMProperties(xdisplay, xwindow, nil, nil, nil, 0, nil, nil, nil)

    // Likewise, the X server needs to know this window's pid so it knows which
    // program to kill if the window hangs.
    // XChangeProperty() expects "pid" to be long.
    //static_assert(sizeof(long) >= sizeof(pid_t),
    //              "pid_t should not be larger than long")

    var pid: Int32 = getpid()

    let _ = withUnsafePointer(to: &pid, { (ptr: UnsafePointer<Int32>) in

      //let voidPtr: UnsafePointer<UInt8> = unsafeBitCast(ptr, to: UnsafePointer<UInt8>.self)
      let voidPtr = ptr.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
        XChangeProperty(xdisplay,
                        xwindow,
                        atomCache.getAtom(name: "_NET_WM_PID")!,
                        XA_ARDINAL,
                        32,
                        PropModeReplace,
                        voidPtr,
                        1)
    })


    //var typePtr: UnsafeMutableRawPointer<UInt8> = nil
    //_X11_getint_ptr(Int32(windowType!), &typePtr)
    
    let _ = withUnsafePointer(to: &windowType, { (ptr: UnsafePointer<Atom>) in

      let voidPtr = ptr.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
      XChangeProperty(xdisplay,
                      xwindow,
                      atomCache.getAtom(name: "_NET_WM_WINDOW_TYPE")!,
                      XA_ATOM,
                      32,
                      PropModeReplace,
                      voidPtr,
                      1)
    })



    // List of window state properties (_NET_WM_STATE) to set, if any.
    var stateAtomList = ContiguousArray<Atom>()

    // Remove popup windows from taskbar unless overridden.
    if (params.type == .Popup ||
        params.type == .Bubble) &&
        !params.forceShowInTaskbar {
      stateAtomList.append(
        atomCache.getAtom(name: "_NET_WM_STATE_SKIP_TASKBAR")!)
    }

    // If the window should stay on top of other windows, add the
    // _NET_WM_STATE_ABOVE property.
    isAlwaysOnTop = params.onTop
    if isAlwaysOnTop {
      stateAtomList.append(atomCache.getAtom(name: "_NET_WM_STATE_ABOVE")!)
    }

    if params.visibleOnAllWorkspaces {
      stateAtomList.append(atomCache.getAtom(name: "_NET_WM_STATE_STICKY")!)
      let _ = setIntProperty(window: xwindow, name: "_NET_WM_DESKTOP", type: "CARDINAL", value: allDesktops)
    }

    // Setting _NET_WM_STATE by sending a message to the root_window (with
    // SetWMSpecState) has no effect here since the window has not yet been
    // mapped. So we manually change the state.
    if stateAtomList.count > 0 {
      let _ = setAtomArrayProperty(window: xwindow,
                                   name: "_NET_WM_STATE",
                                   type: "ATOM",
                                   value: &stateAtomList)
    }

    if !params.wmClassName.isEmpty || !params.wmClassClass.isEmpty {
      setWindowClassHint(
          display: xdisplay, window: xwindow, resName: params.wmClassName, resClass: params.wmClassClass)
    }

    var wmRoleName: String? = nil
    // If the widget isn't overriding the role, provide a default value for popup
    // and bubble types.
    if !params.wmRoleName.isEmpty {
      wmRoleName = params.wmRoleName
    } else {
      switch params.type {
        case .Popup:
          wmRoleName = x11WindowRolePopup
        case .Bubble:
          wmRoleName = x11WindowRoleBubble
        default:
          break
      }
    }
    if let roleName = wmRoleName {
      setWindowRole(display: xdisplay,  window: xwindow, role: roleName)
    }

    if params.removeStandardFrame {
      // Setting _GTK_HIDE_TITLEBAR_WHEN_MAXIMIZED tells gnome-shell to not force
      // fullscreen on the window when it matches the desktop size.
      setHideTitlebarWhenMaximizedProperty(window: xwindow,
                                           property: .HideTitlebarWhenMaximized)
    }

     //if let linuxUI = LinuxUI.instance, linuxUI.preferDarkTheme {
     // let darkGtkThemeVariant = "dark"
     // darkGtkThemeVariant.withCString { cbuf in
     //   XChangeProperty(xdisplay, xwindow, atomCache.getAtom(name: "_GTK_THEME_VARIANT"),
     //                   atomCache.getAtom(name: "UTF8_STRING"), 8, PropModeReplace,
     //                   cbuf, darkGtkThemeVariant.count)
     // }
     //}

    // Always composite Chromium windows if a compositing WM is used.  Sometimes,
    // WMs will not composite fullscreen windows as an optimization, but this can
    // lead to tearing of fullscreen videos.
    //ui::SetIntProperty(xwindow, "_NET_WM_BYPASS_OMPOSITOR", "CARDINAL", 2)
    let _ = setIntProperty(window: xwindow, name: "_NET_WM_BYPASS_OMPOSITOR", type: "CARDINAL", value: 2)

    // If we have a parent, record the parent/child relationship. We use this
    // data during destruction to make sure that when we try to close a parent
    // window, we also destroy all child windows.
    if let p = params.parent, let phost = p.host {
      let parentXid: XID = phost.acceleratedWidget!
      self.parent = DesktopWindowTreeHostX11.getHostForXID(xid: parentXid)
      assert(self.parent != nil)
      self.parent!.children.append(self)
    }

    if let icon = ViewsDelegate.instance.getDefaultWindowIcon() {
      setWindowIcons(windowIcon: ImageSkia(), appIcon: icon as? ImageSkia)
    }
    
    //try createCompositor(frameSinkId: FrameSinkId(),
    //                     forceSoftwareCompositor: params.type == WindowType.Tooltip)
    try createCompositor(compositor: compositor)
    //onAcceleratedWidgetAvailable(newWidget: xwindow, devicePixelRatio: 0)
    onAcceleratedWidgetAvailable()
  }

  private func getARGBVisual() -> UnsafeMutablePointer<Visual>? {
    var visualTemplate = XVisualInfo()
    visualTemplate.screen = 0

    var visualsLen: Int32 = 0
    var visualList = [XVisualInfo]()

    let offset = XGetVisualInfo(xdisplay, Int(VisualScreenMask), &visualTemplate, &visualsLen)
    for i in 0...Int(visualsLen) {
      visualList.append(offset![i])
    }

    //visualList.withUnsafeMutableBufferPointer({ (ptr: inout UnsafeMutableBufferPointer<XVisualInfo>) in

      //XFree(offset)
    //})

    for elem in visualList {
      // Why support only 8888 ARGB? Because it's all that GTK+ supports. In
      // gdkvisual-x11.cc, they look for this specific visual and use it for all
      // their alpha channel using needs.
      //
      // TODO(erg): While the following does find a valid visual, some GL drivers
      // don't believe that this has an alpha channel. According to marcheu@,
      // this should work on open source driver though. (It doesn't work with
      // NVidia's binaries currently.) http://crbug.com/369209
      let info = elem//XVisualInfo(visualList[i])
      if info.visual != nil {
        //let visual = unsafeBitCast(info.visual, to: Visual.self)
        if info.depth == 32 && info.visual.pointee.red_mask == 0xff0000 &&
          info.visual.pointee.green_mask == 0x00ff00 &&
          info.visual.pointee.blue_mask == 0x0000ff {
            return info.visual
        }
      }
     }

     // TODO: check if this is right
    // XFree(visualList)
    return nil
  }

}

fileprivate func convertEventLocationToTargetWindowLocation(
    _ targetWindowOrigin: IntPoint,
    _ currentWindowOrigin: IntPoint,
    _ locatedEvent: inout LocatedEvent) {
  guard currentWindowOrigin != targetWindowOrigin else {
    return
  }

  let offset: IntVec2 = currentWindowOrigin - targetWindowOrigin
  let locationInPixelInHost: FloatPoint = locatedEvent.location + offset
  locatedEvent.location = IntPoint(locationInPixelInHost)
  locatedEvent.rootLocation = locationInPixelInHost
}

fileprivate func XI2ModeToXMode(_ xi2Mode: Int32) -> Int {
  switch xi2Mode {
    case XINotifyNormal:
      return Int(NotifyNormal)
    case XINotifyGrab, XINotifyPassiveGrab:
      return Int(NotifyGrab)
    case XINotifyUngrab, XINotifyPassiveUngrab:
      return Int(NotifyUngrab)
    case XINotifyWhileGrabbed:
      return Int(NotifyWhileGrabbed)
    default:
      return Int(NotifyNormal)
  }
}

fileprivate func ignoreX11Errors(_ display: OpaquePointer?, _ error: UnsafeMutablePointer<XErrorEvent>?) -> CInt {
  //print("X11Error callback called")
  return 0
}