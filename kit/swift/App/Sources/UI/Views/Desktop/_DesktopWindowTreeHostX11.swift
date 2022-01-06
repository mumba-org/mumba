// Copyright (c) 2016 Mumba. All rights reserved.
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

let atomCacheList: [String] = [
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

let allDesktops: Int = 0xFFFFFFFF

let x11WindowRolePopup = "popup"
let x11WindowRoleBubble = "bubble"

enum TitlebarVisibility: Int32 {
  case ShowTitlebarWhenMaximized = 0
  case HideTitlebarWhenMaximized = 1
}

// X11 defines

let XA_ATOM: Atom = 4
let XA_ARDINAL: Atom = 6
let XA_STRING: Atom = 31
let CurrentTime: UInt =	0

let NetWMStateAdd = 1
let NetWMStateRemove = 0

//
let X11ShapeSet: Int32         = 0
let X11ShapeUnion: Int32       = 1
let X11ShapeIntersect: Int32   = 2
let X11ShapeSubtract: Int32    = 3
let X11ShapeInvert: Int32      = 4

let X11ShapeBounding: Int32    = 0
let X11ShapeClip: Int32        = 1
let X11ShapeInput: Int32       = 2

let X11ShapeNotifyMask: Int32  = (1 << 0)
let X11ShapeNotify: Int32      = 0

let X11ShapeNumberEvents: Int32 = X11ShapeNotify + 1


enum WindowManagerName {
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
func getParentsList(xdisplay: XDisplayHandle, window: CUnsignedLong) -> [CUnsignedLong] {
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


public class DesktopWindowTreeHostX11 : WindowTreeHost {

  public override var rootTransform: Transform {

    get {
      var display = Graphics.Screen.nativeScreen.primaryDisplay
      if windowMapped {
        display = Graphics.Screen.nativeScreen._getDisplayNearestWindow(windowId: window.id)!
      }

      let scale = display.deviceScaleFactor
      var transform = Transform()
      transform.scale(x: scale, y: scale)
      return transform
    }

    set {

    }

  }

  public override var eventSource: EventSource? {

    get {
      return self
    }

    set {

    }

  }
    // TODO: change to AcceleratedWindow or NativeWindow

  public override var nativeWidget: AcceleratedWidget? {

    get {
      return NullAcceleratedWidget
    }

    set {

    }

  }

  public override var locationOnNativeScreen: IntPoint {
    return boundsInPixels.origin
  }

  public override var boundsInPixels: IntRect {

    //get {
      return _boundsInPixels
    //}

    set (requestedBoundsInPixel) {
      var boundsPx = IntRect(origin: requestedBoundsInPixel.origin, size: adjustSize(requestedSize: requestedBoundsInPixel.size))
      let originChanged = boundsPx.origin != boundsPx.origin
      let sizeChanged = boundsPx.size != boundsPx.size
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
        widget!.onMove()
      }
      if sizeChanged {
        onHostResizedInPixels(newSize: _boundsInPixels.size, localSurfaceId: localSurfaceId)
        resetWindowRegion()
      }

      ////print("x11 set: \(requestedBoundsInPixel.size) \(boundsInPixels.size)")
    }
  }

  // Returns the current bounds in terms of the X11 Root Window.
  public var X11RootWindowBounds: IntRect {
    return boundsInPixels
  }

  public var X11RootWindowOuterBounds: IntRect {
    var outerBounds = IntRect(boundsInPixels)
    outerBounds.inset(insets: -desktopWindowFrameBordersInPixels)
    return outerBounds
  }

  public var windowShape: MumbaShims.Region? {
    return _windowShape
  }

  var workAreaBoundsInPixels: IntRect {

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

  var xdisplay: XDisplayHandle
  var xwindow: CUnsignedLong
  var xrootWindow: CUnsignedLong
  var atomCache: AtomCache
  var windowMapped: Bool
  var _boundsInPixels: IntRect
  var previousBoundsInPixels: IntRect
  var restoredBoundsInPixels: IntRect
  var minSizeInPixels: IntSize
  var maxSizeInPixels: IntSize
  var windowProperties: [Atom]
  var useNativeFrame: Bool
  var shouldMaximizeAfterMap: Bool
  var useARGBVisual: Bool
  var dragDropClient: DesktopDragDropClientX11?
  var nonClientEventFilter: EventHandler?
  var windowMoveClient: DesktopWindowMoveClientX11?
  weak var widget: UIWidget?
  var contentWindow: Window?
  weak var parent: DesktopWindowTreeHostX11?
  var children: [DesktopWindowTreeHostX11]
  var observers: [DesktopWindowTreeHostObserverX11]
  var urgencyHintSet: Bool
  var activatable: Bool
  var customWindowShape: Bool
  var desktopWindowFrameBordersInPixels: IntInsets
  var windowTitle: String
  var grabWindow: XID
  // The "owner events" parameter used to grab the pointer.
  var grabOwnerEvents: Bool
  var _windowShape: MumbaShims.Region?
  var _alwaysOnTop: Bool
  var _fullscreen: Bool
  var windowShape: _XRegion


  static var openWindows: [CUnsignedLong] = [CUnsignedLong]()
  static var currentCapture: DesktopWindowTreeHostX11?

  public init(widget: UIWidget) {
    xdisplay = X11Environment.XDisplay
    xrootWindow = XDefaultRootWindow(xdisplay)
    self.widget = widget
    atomCache = AtomCache(xdisplay, atomCacheList)
    xwindow = 0
    urgencyHintSet = false
    activatable = true
    customWindowShape = false
    desktopWindowFrameBordersInPixels = IntInsets()
    windowTitle = ""
    windowMapped = false
    _boundsInPixels = IntRect()
    previousBoundsInPixels = IntRect()
    restoredBoundsInPixels = IntRect()
    minSizeInPixels = IntSize()
    maxSizeInPixels = IntSize()
    windowProperties = [Atom]()
    _fullscreen = false
    _alwaysOnTop = false
    useNativeFrame = true
    shouldMaximizeAfterMap = false
    useARGBVisual = false
    grabWindow = UInt(None)
    grabOwnerEvents = false
    children = [DesktopWindowTreeHostX11]()
    observers = [DesktopWindowTreeHostObserverX11]()
    _windowShape = nil
    super.init()
  }

  deinit {
    //window.clearProperty(kHostForRootWindow)
    window.rootWindow!.host = nil
    UI.setWindowMoveClient(window: window, client: nil)
    widget!.onWindowTreeHostDestroyed(host: self)
    destroyDispatcher()
  }

  static public func getContentWindowForXID(xid: XID) -> Window? {
    if let host = WindowTreeHost.getForAcceleratedWidget(window: xid) {
      return host.window.rootWindow!.viewsWindow
    }
    return nil
  }

  static public func getHostForXID(xid: XID) -> DesktopWindowTreeHostX11? {
    if let host = WindowTreeHost.getForAcceleratedWidget(window: xid) {
      return host.window.rootWindow!.host as? DesktopWindowTreeHostX11
    }
    return nil
  }

  static public func getOpenWindows() -> [Window] {
    var windows = [Window]()
    for xid in DesktopWindowTreeHostX11.openWindows {
      if let w = DesktopWindowTreeHostX11.getContentWindowForXID(xid: xid) {
        windows.append(w)
      }
    }
    return windows
  }

  static public func cleanUpWindowList(closure: (_: Window?) -> Void ) {
    for (index, xid) in DesktopWindowTreeHostX11.openWindows.enumerated() {
      closure(DesktopWindowTreeHostX11.getContentWindowForXID(xid: xid))
      DesktopWindowTreeHostX11.openWindows.remove(at: index)
    }
  }

  public func handleDesktopWidgetActivationChanged(active: Bool) {
    if active {
      flashFrame(flashFrame: false)
      onHostActivated()
      for (index, item) in DesktopWindowTreeHostX11.openWindows.enumerated() {
        if item == xwindow {
          DesktopWindowTreeHostX11.openWindows.remove(at: index)
        }
      }
      DesktopWindowTreeHostX11.openWindows.insert(xwindow, at: 0)
    } else {
      releaseCapture()
    }
    widget!.handleActivationChanged(active: active)
    widget!.rootView.schedulePaint()
  }

  public func addObserver(observer: DesktopWindowTreeHostObserverX11) {
    observers.append(observer)
  }

  public func removeObserver(observer: DesktopWindowTreeHostObserverX11) {
    for (index, item) in observers.enumerated() {
      if item === observer {
        observers.remove(at: index)
      }
    }
  }

  public func swapNonClientEventHandler(handler: EventHandler) {
    if let compoundEventFilter = widget!.rootWindowEventFilter {
      if let eventFilter = nonClientEventFilter {
        compoundEventFilter.removeHandler(filter: eventFilter)
      }
      compoundEventFilter.addHandler(filter: handler)
    }
    nonClientEventFilter = handler
  }

  public override func showImpl() {
    showWindowWithState(showState: .Normal)
    widget!.onVisibilityChanged(visible: true)
  }

  public override func hideImpl() {
    if windowMapped {
      XWithdrawWindow(xdisplay, xwindow, 0)
      windowMapped = false
    }
    widget!.onVisibilityChanged(visible: false)
  }

  public override func setBoundsInPixels(bounds requestedBoundsInPixel: IntRect, localSurfaceId: LocalSurfaceId){
    
    var boundsPx = IntRect(origin: requestedBoundsInPixel.origin, size: adjustSize(requestedSize: requestedBoundsInPixel.size))
    let originChanged = _boundsPixels.origin != boundsPx.origin
    let sizeChanged = _boundsPixels.size != boundsPx.size
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
      widget!.onMove()
    }

    if sizeChanged {
      onHostResizedInPixels(newSize: _boundsInPixels.size, localSurfaceId: localSurfaceId)
      resetWindowRegion()
    }

    ////print("x11 set: \(requestedBoundsInPixel.size) \(boundsInPixels.size)")
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

    let _ = grabPointer(window: xwindow, ownerEvents: true, cursor: UInt(None))
  }

  public override func releaseCapture() {

    if DesktopWindowTreeHostX11.currentCapture === self {
      DesktopWindowTreeHostX11.currentCapture = nil
      ungrabPointer()
      onHostLostWindowCapture()
    }

  }

  public override func setCursor(platformCursor: PlatformCursor) {
    XDefineCursor(xdisplay, xwindow, cursor!)
  }

  public override func moveCursorTo(location: IntPoint) {
    XWarpPointer(xdisplay, UInt(None), xrootWindow, 0, 0, 0, 0,
              Int32(boundsInPixels.x) + Int32(location.x),
              Int32(boundsInPixels.y) + Int32(location.y))
  }

  public override func onCursorVisibilityChanged(show: Bool) {}

  func initX11Window(params: UIWidget.InitParams) throws {
    //print("DesktopWindowTreeHostX11.initX11Window")
    var attributeMask: Int = CWBackPixmap
    var swa = XSetWindowAttributes()
    //memset(&swa, 0, sizeof(swa));
    swa.background_pixmap = UInt(None)

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

    if swa.override_redirect != 0 {
      attributeMask |= CWOverrideRedirect
    }

    // Detect whether we're running inside a compositing manager. If so, try to
    // use the ARGB visual. Otherwise, just use our parent's visual.
    var visual: UnsafeMutablePointer<Visual>? = nil // TODO: como encaixar "CopyFromParent" aqui?
    var depth = CopyFromParent

    if XGetSelectionOwner(xdisplay, atomCache.getAtom(name: "_NET_WM_M_S0")!) != UInt(None) {
      let rgbaVisual = getARGBVisual()
      if  rgbaVisual != nil {
        visual = rgbaVisual
        depth = 32

        attributeMask |= CWColormap
        swa.colormap = XCreateColormap(xdisplay, xrootWindow, visual, AllocNone)

        // x.org will BadMatch if we don't set a border when the depth isn't the
        // same as the parent depth.
        attributeMask |= CWBorderPixel
        swa.border_pixel = 0

        useARGBVisual = true
      }
    }

    _boundsInPixels = toPixelRect(rectInDip: params.bounds)
    _boundsInPixels.size = adjustSize(requestedSize: _boundsInPixels.size)
    //print(" --- XCreateWindow: bounds: x: \(boundsInPixels.x) y: \(boundsInPixels.y), width: \(boundsInPixels.width) height: \(boundsInPixels.height) ---")
    xwindow = XCreateWindow(xdisplay, xrootWindow, Int32(_boundsInPixels.x),
                           Int32(_boundsInPixels.y), UInt32(_boundsInPixels.width),
                           UInt32(_boundsInPixels.height),
                           0,  // border width
                           Int32(depth), UInt32(InputOutput), visual, UInt(attributeMask), &swa)

    if isX11Error(code: xwindow) {
     throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }
    if let eventSource = PlatformEventSource.instance() {
      eventSource.addPlatformEventDispatcher(dispatcher: self)
    }

    DesktopWindowTreeHostX11.openWindows.append(xwindow)

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
    alwaysOnTop = params.onTop
    if alwaysOnTop {
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

    // If we have a parent, record the parent/child relationship. We use this
    // data during destruction to make sure that when we try to close a parent
    // window, we also destroy all child windows.
    if let p = params.parent, let phost = p.host {
      let parentXid: XID = phost.nativeWidget!
      self.parent = DesktopWindowTreeHostX11.getHostForXID(xid: parentXid)
      assert(self.parent != nil)
      self.parent!.children.append(self)
    }
    // If we have a delegate which is providing a default window icon, use that
    // icon.

    if let icon = ViewsDelegate.instance.getDefaultWindowIcon() {
      setWindowIcons(windowIcon: ImageSkia(), appIcon: icon)
    }
    
    //print("DesktopWindowTreeHostX11.initX11Window: creating compositor")
    try createCompositor(frameSinkId: FrameSinkId())
    onAcceleratedWidgetAvailable(newWidget: xwindow, devicePixelRatio: 0)
  }

  func initDispatcher(params: UIWidget.InitParams) -> WindowEventDispatcher? {
    return nil
  }

  func adjustSize(requestedSize: IntSize) -> IntSize {
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

  func onWMStateUpdated() {

    var atomList = [Atom]()
    // Ignore the return value of ui::GetAtomArrayProperty(). Fluxbox removes the
    // _NET_WM_STATE property when no _NET_WM_STATE atoms are set.
    let _ = getAtomArrayProperty(window: xwindow, propertyName: "_NET_WM_STATE", value: &atomList)

    let wasMinimized = minimized

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
    if minimized != wasMinimized {
      if minimized {
        compositor!.isVisible = false
        contentWindow!.hide()
      } else {
        contentWindow!.show()
        compositor!.isVisible = true
      }
    }

    if restoredBoundsInPixels.isEmpty {
      assert(!fullscreen)
      if maximized {
        // The request that we become maximized originated from a different
        // process. |bounds_in_pixels_| already contains our maximized bounds. Do
        // a best effort attempt to get restored bounds by setting it to our
        // previously set bounds (and if we get this wrong, we aren't any worse
        // off since we'd otherwise be returning our maximized bounds).
        ////print("\(previousBoundsInPixels)")
        restoredBoundsInPixels = previousBoundsInPixels
      }
    } else if !maximized && !fullscreen {
      // If we have restored bounds, but WM_STATE no longer claims to be
      // maximized or fullscreen, we should clear our restored bounds.
      restoredBoundsInPixels = IntRect()
    }

    // Ignore requests by the window manager to enter or exit fullscreen (e.g. as
    // a result of pressing a window manager accelerator key). Chrome does not
    // reference window manager initiated fullscreen. In particular, Chrome needs to
    // do preprocessing before the x window's fullscreen state is toggled.

    alwaysOnTop = hasWMSpecProperty(property: "_NET_WM_STATE_ABOVE")

    // Now that we have different window properties, we may need to relayout the
    // window. (The windows code doesn't need this because their window change is
    // synchronous.)
    relayout()
    resetWindowRegion()
  }

  func onFrameExtentsUpdated() {
    var insets = [Int]()
    if getIntArrayProperty(window: xwindow, propertyName: "_NET_FRAME_EXTENTS", value: &insets) && insets.count == 4 {
      // |insets| are returned in the order: [left, right, top, bottom].
      desktopWindowFrameBordersInPixels = IntInsets(top: insets[2], left: insets[0], bottom: insets[3], right: insets[1])
    } else {
      desktopWindowFrameBordersInPixels = IntInsets()
    }
  }

  func updateMinAndMaxSize() {

    guard windowMapped else {
      return
    }

    let minimumInPixels = toPixelRect(rectInDip: IntRect(size: widget!.minimumSize)).size
    let maximumInPixels = toPixelRect(rectInDip: IntRect(size: widget!.maximumSize)).size

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

  func updateWMUserTime(event: PlatformEvent) {

    guard active else {
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

      DesktopHandlerX11.instance.wmUserTimeMS = wmUserTimeMS
    }
  }

  func setWMSpecState(enabled: Bool, state1: Atom, state2: Atom) {
    var xclient = XEvent()
    xclient.type = ClientMessage
    xclient.xclient.window = xwindow
    xclient.xclient.message_type = atomCache.getAtom(name: "_NET_WM_STATE")!
    xclient.xclient.format = 32
    xclient.xclient.data.l = (enabled ? NetWMStateAdd : NetWMStateRemove, Int(state1), Int(state2), 1, 0)
    XSendEvent(xdisplay, xrootWindow, False,
             SubstructureRedirectMask | SubstructureNotifyMask,
             &xclient)
  }

  func hasWMSpecProperty(property: String) -> Bool {

    if let atom = atomCache.getAtom(name: property) {
        for p in windowProperties {
          if p == atom {
            return true
          }
        }
    }
    return false
  }

  // TODO: passar para property
  func setUseNativeFrame(useNativeFrame: Bool) {
    self.useNativeFrame = useNativeFrame
    setUseOSWindowFrame(window: xwindow, useOSWindowFrame: useNativeFrame)
    resetWindowRegion()
  }

  func dispatchMouseWheelEvent(event: inout MouseWheelEvent) {
    var mev = event as MouseEvent
    dispatchMouseEvent(event: &mev)
  }

  func dispatchMouseEvent(event: inout MouseEvent) {
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
      flashFrame(flashFrame: false)
    }

    if DesktopWindowTreeHostX11.currentCapture == nil || DesktopWindowTreeHostX11.currentCapture === self {
      let _ = sendEventToProcessor(event: event)
    } else {
      // Another DesktopWindowTreeHostX11 has installed itself as
      // capture. Translate the event's location and dispatch to the other.
      var locatedEvent = event as LocatedEvent
      convertEventToDifferentHost(locatedEvent: &locatedEvent, host: DesktopWindowTreeHostX11.currentCapture!)
      let _ = DesktopWindowTreeHostX11.currentCapture!.sendEventToProcessor(event: event)
    }
  }

  func dispatchTouchEvent(event: inout TouchEvent) {
    if DesktopWindowTreeHostX11.currentCapture != nil &&
        DesktopWindowTreeHostX11.currentCapture !== self && event.type == .TouchPressed {
        var locatedEvent = event as LocatedEvent
        convertEventToDifferentHost(locatedEvent: &locatedEvent, host: DesktopWindowTreeHostX11.currentCapture!)
        let _ = DesktopWindowTreeHostX11.currentCapture!.sendEventToProcessor(event: event)
    } else {
        let _ = sendEventToProcessor(event: event)
    }
  }

  func dispatchKeyEvent(event: inout KeyEvent) {
    // TODO: inputMethod nao existe!! corrigir
    inputMethod!.dispatchKeyEvent(event: event)
  }

  func convertEventToDifferentHost(locatedEvent: inout LocatedEvent, host: DesktopWindowTreeHostX11) {
    assert(self !== host)

    let displaySrc = Screen.nativeScreen._getDisplayNearestWindow(windowId: window.id)
    let displayDest = Screen.nativeScreen._getDisplayNearestWindow(windowId: host.window.id)

    assert(displaySrc!.deviceScaleFactor == displayDest!.deviceScaleFactor)

    let offset: IntVec2 = locationOnNativeScreen - host.locationOnNativeScreen

    let locationInPixelInHost: FloatPoint = locatedEvent.location + FloatVec2(offset)
    locatedEvent.locationf = locationInPixelInHost
  }

  func resetWindowRegion() {
    // If a custom window shape was supplied then apply it.
    if customWindowShape {
      XShapeCombineRegion(xdisplay, xwindow, X11ShapeBounding, 0, 0,
                         _windowShape, False)
      return
    }

    _windowShape = nil

    if !maximized && !fullscreen {
      var windowMask = Path()
      if let win = widget, let view = win.nonClientView {
        // Some frame views define a custom (non-rectangular) window mask. If
        // so, use it to define the window shape. If not, fall through.
        view.getWindowMask(size: _boundsInPixels.size, windowMask: &windowMask)
        if windowMask.pointCount > 0 {
          var x11Points = ContiguousArray<XPoint>(repeating: XPoint(), count: windowMask.pointCount)
          _windowShape = createRegionFromPath(path: windowMask, points: &x11Points)
          XShapeCombineRegion(xdisplay, xwindow, X11ShapeBounding, 0, 0,
                              _windowShape, False)
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

  func serializeImage(bitmap: Bitmap?,
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

  func getARGBVisual() -> UnsafeMutablePointer<Visual>? {
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

  func mapWindow(showState: WindowShowState) {
    if showState != .Default && showState != .Normal &&
       showState != .Inactive && showState != .Maximized {
     // It will behave like SHOW_STATE_NORMAL.
     //NOTIMPLEMENTED();
     // TODO: throw a exception here
     assert(false)
   }

   // Before we map the window, set size hints. Otherwise, some window managers
   // will ignore toplevel XMoveWindow commands.
   var sizeHints = XSizeHints()
   sizeHints.flags = PPosition
   sizeHints.x = Int32(_boundsInPixels.x)
   sizeHints.y = Int32(_boundsInPixels.y)
   XSetWMNormalHints(xdisplay, xwindow, &sizeHints)

   // If SHOW_STATE_INACTIVE, tell the window manager not to focus the window
   // when mapping. This is done by setting the _NET_WM_USER_TIME to 0. See e.g.
   // http://standards.freedesktop.org/wm-spec/latest/ar01s05.html
   let wmUserTimeMS = showState == .Inactive ? 0 : DesktopHandlerX11.instance.wmUserTimeMS
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

    XMapWindow(xdisplay, xwindow)

    // We now block until our window is mapped. Some X11 APIs will crash and
    // burn if passed |xwindow_| before the window is mapped, and XMapWindow is
    // asynchronous.
    if let eventSource = X11EventSource.instance() as! X11EventSource? {
      eventSource.blockUntilWindowMapped(window: xwindow)
    }

    windowMapped = true

    updateMinAndMaxSize()

    // Some WMs only respect maximize hints after the window has been mapped.
    // Check whether we need to re-do a maximization.
    if shouldMaximizeAfterMap {
      maximize()
      shouldMaximizeAfterMap = false
    }
  }

  func setWindowTransparency() {
    compositor!.hasTransparentBackground = useARGBVisual
    window.transparent = useARGBVisual
    contentWindow!.transparent = useARGBVisual
  }

  func relayout() {
    guard let win = widget else {
      return
    }
    // non_client_view may be NULL, especially during creation.
    if let view = win.nonClientView {
      if let clientView = view.clientView {
        clientView.invalidateLayout()
      }
      view.invalidateLayout()
    }
    win.rootView.layout()
  }

  func delayedResize(sizeInPixels: IntSize) {
    onHostResizedInPixels(newSize: sizeInPixels)
    resetWindowRegion()
    //delayedResizeTask.cancel()
  }

  func toDIPRect(rectInPixels: IntRect) -> IntRect {
    var rectInDip = FloatRect(rectInPixels)
    let _ = rootTransform.transformRectReverse(rect: &rectInDip)
    return IntRect.toEnclosingRect(rect: rectInDip)
  }

  func toPixelRect(rectInDip: IntRect) -> IntRect {
    var rectInPixels = FloatRect(rectInDip)
    rootTransform.transformRect(rect: &rectInPixels)
   return IntRect.toEnclosingRect(rect: rectInPixels)
  }

  func grabPointer(window: XID, ownerEvents: Bool, cursor: MumbaShims.Cursor) -> Int {

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

  func ungrabPointer() {
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

}

extension DesktopWindowTreeHostX11 : DesktopWindowTreeHost {

  public var shouldUseNativeFrame: Bool {
    return useNativeFrame
  }

  public var visible: Bool {
    return windowMapped
  }

  public var windowBoundsInScreen: IntRect {
    return toDIPRect(rectInPixels: _boundsInPixels)
  }

  public var clientAreaBoundsInScreen: IntRect {
    return windowBoundsInScreen
  }

  public var restoredBounds: IntRect {
    if !restoredBoundsInPixels.isEmpty {
      return toDIPRect(rectInPixels: restoredBoundsInPixels)
    }
    return windowBoundsInScreen
  }

  public var workAreaBoundsInScreen: IntRect {
    return toDIPRect(rectInPixels: workAreaBoundsInPixels)
  }

  public var active: Bool {
    return DesktopHandlerX11.instance.isActiveWindow(window: xwindow)
  }

  public var maximized: Bool {
    return hasWMSpecProperty(property: "_NET_WM_STATE_MAXIMIZED_VERT") &&
         hasWMSpecProperty(property: "_NET_WM_STATE_MAXIMIZED_HORZ")
  }

  public var minimized: Bool {
    return hasWMSpecProperty(property: "_NET_WM_STATE_HIDDEN")
  }

  public var hasCapture: Bool {
    return DesktopWindowTreeHostX11.currentCapture === self
  }

  public var alwaysOnTop: Bool {
    get {
      return _alwaysOnTop
    }
    set {
      _alwaysOnTop = newValue
      setWMSpecState(enabled: _alwaysOnTop,
                     state1: atomCache.getAtom(name: "_NET_WM_STATE_ABOVE")!,
                     state2: UInt(None))
    }
  }

  public var size: IntSize {

    get {
      return IntSize()
    }
    set {

    }
  }

  public var shouldWindowContentsBeTransparent: Bool {
    return false
  }

  public var fullscreen: Bool {

    get {
      return _fullscreen
    }

    set {
      guard _fullscreen != newValue else {
        return
      }

      _fullscreen = newValue

      //if _fullscreen {
      //  delayedResizeTask.cancel()
      //}

      // Work around a bug where if we try to unfullscreen, metacity immediately
      // fullscreens us again. This is a little flickery and not necessary if
      // there's a gnome-panel, but it's not easy to detect whether there's a
      // panel or not.
      let unmaximizeAndRemaximize = !_fullscreen && maximized &&
                                  guessWindowManager() == .Metacity

      if unmaximizeAndRemaximize {
        restore()
      }

      setWMSpecState(enabled: fullscreen,
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
       if _fullscreen {
         restoredBoundsInPixels = _boundsInPixels
         //let display = Screen.getScreenFor(nil).getDisplayNearestWindow(window)
         let display = Screen.getDisplayNearestWindow(windowId: window.id)!
         _boundsInPixels = toPixelRect(rectInDip: display.bounds)
       } else {
         _boundsInPixels = restoredBoundsInPixels
       }

       onHostMovedInPixels(newLocation: _boundsInPixels.origin)
       onHostResizedInPixels(newSize: _boundsInPixels.size)

       if hasWMSpecProperty(property: "_NET_WM_STATE_FULLSCREEN") == fullscreen {
         relayout()
         resetWindowRegion()
       }
       // Else: the widget will be relaid out either when the window bounds change or
       // when |xwindow_|'s fullscreen state changes.
    }
  }

  public var translucentWindowOpacitySupported: Bool {
    return false
  }

  public var tree: WindowTreeHost {
    return self
  }

  public var isAnimatingClosed: Bool {
    return false
  }

  public func initialize(window w: Window, params: UIWidget.InitParams) throws {
    contentWindow = w
    activatable = params.activatable == UIWidget.Activatable.Yes

    var sanitizedParams = params

    if sanitizedParams.bounds.width == 0 {
      sanitizedParams.bounds.width = 100
    }
    if sanitizedParams.bounds.height == 0 {
      sanitizedParams.bounds.height = 100
    }

    try initX11Window(params: sanitizedParams)
  }

  public func onWindowCreated(params: UIWidget.InitParams) {
    window.rootWindow!.viewsWindow = contentWindow
    window.rootWindow!.host = self

    let _ = DesktopHandlerX11.instance

    swapNonClientEventHandler(handler: WindowEventFilterX11(host: self))
    setUseNativeFrame(useNativeFrame: params.type == .Normal && !params.removeStandardFrame)

    windowMoveClient = DesktopWindowMoveClientX11()
    UI.setWindowMoveClient(window: window, client: windowMoveClient)

    setWindowTransparency()
    widget!.onCreated(widget: true)
  }
  public func createTooltip() -> Tooltip {
    return Tooltip()
  }

  public func createDragDropClient(cursorManager: DesktopCursorManager) -> DragDropClient?  {

    dragDropClient = DesktopDragDropClientX11(rootWindow: window,
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
    widget!.onDestroying()

    for child in children {
      child.close()
    }

    assert(children.count == 0)

    // If we have a parent, remove ourselves from its children list.
    if let p = parent {
      for (index, child) in p.children.enumerated() {
        if child === self {
          p.children.remove(at: index)
        }
      }
      parent = nil
    }

    if let eventFilter = widget!.rootWindowEventFilter {
      eventFilter.removeHandler(filter: nonClientEventFilter!)
    }

    nonClientEventFilter = nil

    destroyCompositor()

    for (index, xid) in DesktopWindowTreeHostX11.openWindows.enumerated() {
      if xid == xwindow {
        DesktopWindowTreeHostX11.openWindows.remove(at: index)
      }
    }

    if let eventSource = PlatformEventSource.instance() {
      eventSource.removePlatformEventDispatcher(dispatcher: self)
    }

    XDestroyWindow(xdisplay, xwindow)
    xwindow = UInt(None)

    widget!.onHostClosed()
  }

  public func showWindowWithState(showState: WindowShowState) {

    if let c = compositor {
      c.isVisible = true
    }

    if !windowMapped {
      mapWindow(showState: showState)
    }

    switch showState {
      case .Maximized:
        maximize()
      case .Minimized:
        minimize()
      case .Fullscreen:
        fullscreen = true
      default:
        break
    }

    if showState != .Inactive && showState != .Minimized && activatable {
      activate()
    }

    let _ = widget!.setInitialFocus(showState: showState)
  }

  public func showMaximizedWithBounds(restoredBounds: IntRect) {
    showWindowWithState(showState: .Maximized)
    restoredBoundsInPixels = toPixelRect(rectInDip: restoredBounds)
  }

  public func setSize(requestedSize: IntSize) {
    var sizeInPixels = toPixelRect(rectInDip: IntRect(size: requestedSize)).size
    sizeInPixels = adjustSize(requestedSize: sizeInPixels)
    let sizeChanged = _boundsInPixels.size != sizeInPixels
    XResizeWindow(xdisplay, xwindow, UInt32(sizeInPixels.width), UInt32(sizeInPixels.height))
    _boundsInPixels.size = sizeInPixels
    if sizeChanged {
      onHostResizedInPixels(newSize: sizeInPixels)
      resetWindowRegion()
    }
  }

  public func stackAbove(window: Window) {

    if window.rootWindow != nil {
      let windowBelow = window.host!.nativeWidget
      // Find all parent windows up to the root.
      let windowBelowParents = getParentsList(xdisplay: xdisplay, window: windowBelow!)
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

      // Find their common ancestor.
      // auto it_below_window = window_below_parents.rbegin();
      // auto it_above_window = window_above_parents.rbegin();
      //
      // for (; it_below_window != window_below_parents.rend() &&
      //      it_above_window != window_above_parents.rend() &&
      //      *it_below_window == *it_above_window;
      //    ++it_below_window, ++it_above_window) {
      // }
      //
      // if (it_below_window != window_below_parents.rend() &&
      //   it_above_window != window_above_parents.rend()) {
      //   // First stack |xwindow_| below so Z-order of |window| stays the same.
      //   ::Window windows[] = {*it_below_window, *it_above_window};
      //   if (XRestackWindows(xdisplay_, windows, 2) == 0) {
      //     // Now stack them properly.
      //     std::swap(windows[0], windows[1]);
      //     XRestackWindows(xdisplay, windows, 2)
      //   }
      // }
    }
  }

  public func stackAtTop() {
    XRaiseWindow(xdisplay, xwindow)
  }

  public func centerWindow(size: IntSize) {
    let sizeInPixels = toPixelRect(rectInDip: IntRect(size: size)).size
    var parentBoundsInPixels = workAreaBoundsInPixels

    // If |window_|'s transient parent bounds are big enough to contain |size|,
    // use them instead.
    if let manager = TransientWindowManager.get(window: contentWindow!),
        let transientParent = manager.transientParent {
      let transientParentRect = transientParent.boundsInScreen
      if transientParentRect.height >= size.height && transientParentRect.width >= size.width {
        parentBoundsInPixels = toPixelRect(rectInDip: transientParentRect)
      }
    }

    var windowBoundsInPixels = IntRect(
      x: parentBoundsInPixels.x + (parentBoundsInPixels.width - sizeInPixels.width) / 2,
      y: parentBoundsInPixels.y + (parentBoundsInPixels.height - sizeInPixels.height) / 2,
      width: sizeInPixels.width,
      height: sizeInPixels.height)

    windowBoundsInPixels.adjustToFit(rect: parentBoundsInPixels)
    bounds = windowBoundsInPixels
  }

  public func getWindowPlacement(bounds: inout IntRect,
                                 showState: inout WindowShowState) {
    bounds = restoredBounds

    if fullscreen {
      showState = .Fullscreen
    } else if minimized {
      showState = .Minimized
    } else if maximized {
      showState = .Maximized
    } else if !active {
      showState = .Inactive
    } else {
      showState = .Normal
    }
  }

  public func setShape(nativeRegion: Graphics.Region?) {
    customWindowShape = false
    // reset
    _windowShape = nil//MumbaShims.Region()

    if let region = nativeRegion {
      let transform = rootTransform
      if !transform.isIdentity && !region.isEmpty {
        var pathInDip = Path()
        if region.getBoundaryPath(path: &pathInDip) {
          var pathInPixels = Path()
          pathInDip.transform(matrix: transform.matrix, dst: &pathInPixels)
          _windowShape = createRegionFromGfxPath(path: pathInPixels)
        } else {
          _windowShape = XCreateRegion()
        }
      } else {
        _windowShape = createRegionFromGfxRegion(region: region)
      }

      customWindowShape = true
    }
    resetWindowRegion()
  }

  public func activate() {
    guard windowMapped else {
      return
    }
    DesktopHandlerX11.instance.activateWindow(window: xwindow)
  }

  public func deactivate() {
    guard active else {
      return
    }
    releaseCapture()
    DesktopHandlerX11.instance.deactivateWindow(window: xwindow)
  }

  public func maximize() {
    if hasWMSpecProperty(property: "_NET_WM_STATE_FULLSCREEN") {

      setWMSpecState(enabled: false,
                     state1: atomCache.getAtom(name: "_NET_WM_STATE_FULLSCREEN")!,
                     state2: UInt(None))

      let adjustedBoundsInPixels = IntRect(origin: _boundsInPixels.origin,
                                        size: adjustSize(requestedSize: _boundsInPixels.size))
      if adjustedBoundsInPixels != _boundsInPixels {
        bounds = adjustedBoundsInPixels
      }
    }

    shouldMaximizeAfterMap = !windowMapped

    restoredBoundsInPixels = _boundsInPixels

    setWMSpecState(enabled: true,
                   state1: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_VERT")!,
                   state2: atomCache.getAtom(name: "_NET_WM_STATE_MAXIMIZED_HORZ")!)

    if minimized {
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
    if minimized {
      showWindowWithState(showState: .Normal)
    }
  }

  public func setVisibleOnAllWorkspaces(alwaysVisible: Bool) {

    setWMSpecState(enabled: alwaysVisible,
                   state1: atomCache.getAtom(name: "_NET_WM_STATE_STICKY")!,
                   state2: UInt(None))

    var newDesktop = 0
    if alwaysVisible {
      newDesktop = allDesktops
    } else {
      if !getCurrentDesktop(desktop: &newDesktop) {
        return
      }
    }

    var xevent = XEvent()
    xevent.type = ClientMessage
    xevent.xclient.window = xwindow
    xevent.xclient.message_type = atomCache.getAtom(name: "_NET_WM_DESKTOP")!
    xevent.xclient.format = 32
    xevent.xclient.data.l = (newDesktop, 0, 0, 0, 0)
    XSendEvent(xdisplay, xrootWindow, False,
             SubstructureRedirectMask | SubstructureNotifyMask,
             &xevent)
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

      if windowMoveClient!.runMoveLoop(window: contentWindow!, dragOffset: dragOffset,
          source: windowMoveSource) == .MoveSuccessful {
        return UIWidget.MoveLoopResult.Successful
      }

      return UIWidget.MoveLoopResult.Canceled
  }

  public func endMoveLoop() {
    windowMoveClient!.endMoveLoop()
  }

  public func frameTypeChanged() {

    let newType = widget!.frameType

    if newType == .Default {
      // The default is determined by UIWidget::InitParams::remove_standard_frame
      // and does not change.
      return
    }

    setUseNativeFrame(useNativeFrame: newType == .ForceNative)
    // Replace the frame and layout the contents. Even though we don't have a
    // swapable glass frame like on Windows, we still replace the frame because
    // the button assets don't update otherwise.
    widget!.nonClientView!.updateFrame()
  }

  public func setOpacity(opacity: UInt8) {

    let result: UInt = UInt(opacity) * 0x1010101
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

  public func setWindowIcons(windowIcon: Image?,
                             appIcon: Image?) {
    // TODO(erg): The way we reference icons across different versions of chrome
    // could be substantially improved. The Windows version does its own thing
    // and only sometimes comes down this code path. The icon stuff in
    // ChromeViewsDelegate is hard coded to use HICONs. Likewise, we're hard
    // coded to be given two images instead of an arbitrary collection of images
    // so that we can pass to the WM.
    //
    // All of this could be made much, much better.
    var data = ContiguousArray<UInt>()
    if let wbitmap = windowIcon?.getBitmapFor(scale: 1.0) {
      serializeImage(bitmap: wbitmap, data: &data)
    }

    if let abitmap = appIcon?.getBitmapFor(scale: 1.0) {
      serializeImage(bitmap: abitmap, data: &data)
    }

    if data.count > 0 {
      let _ = setAtomArrayProperty(window: xwindow, name: "_NET_WM_ICON", type: "CARDINAL", value: &data)
    }
  }

  public func initModalType(modalType: ModalType) {}

  public func flashFrame(flashFrame: Bool) {

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
#if os(Linux)
    free(hints)
#endif
  }

  public func onRootViewLayout() {
    updateMinAndMaxSize()
  }

  public func onWindowFocus() {}
  public func onWindowBlur() {}
  public func setVisibilityChangedAnimationsEnabled(value: Bool) {}

  public func sizeConstraintsChanged() {
    updateMinAndMaxSize()
  }

}

extension DesktopWindowTreeHostX11 : PlatformEventDispatcher {

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
      if !active && !hasCapture {
        break
      }
      var keyEvent = KeyEvent(xev)
      dispatchKeyEvent(event: &keyEvent)
    case ButtonPress, ButtonRelease:
      let eventType: EventType = eventTypeFromNative(nativeEvent: xev)
      switch eventType {
        case .MouseWheel:
          var mouseev = MouseWheelEvent(xev)
          dispatchMouseWheelEvent(event: &mouseev)
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
    case FocusOut:
      if xev.xfocus.mode != NotifyGrab {
        releaseCapture()
        onHostLostWindowCapture()
        DesktopHandlerX11.instance.processXEvent(event: &event)
      } else {
        dispatcher!.onHostLostMouseGrab()
      }
    case FocusIn:
      DesktopHandlerX11.instance.processXEvent(event: &event)
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
        //delayedResize(sizeInPixels: boundsInPixels.size)
        restartDelayedResizeTask()
      }
    case GenericEvent:
      if let factory = X11TouchFactory.instance() {
        if !factory.shouldProcessXI2Event(xev: xev) {
          break
        }
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
          var mousewev = MouseWheelEvent(xev)
          dispatchMouseWheelEvent(event: &mousewev)
        case .ScrollFlingStart, .ScrollFlingCancel, .Scroll:
          let scrollev = ScrollEvent(xev)
          let _ = sendEventToProcessor(event: scrollev)
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
      for observer in observers {
        observer.onWindowMapped(xid: xwindow)
      }
    case UnmapNotify:
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
        }
      case SelectionNotify:
        dragDropClient!.onSelectionNotify(xselection: xev.xselection)
      default:
        break
    }

    return PostDispatchAction.StopPropagation
  }

}

public class DesktopWindowTreeHostFactoryX11: DesktopWindowTreeHostFactory {

  public override func make(widget: UIWidget) -> DesktopWindowTreeHost? {
    return DesktopWindowTreeHostX11(widget: widget)
  }

  public override init() {

  }

}
