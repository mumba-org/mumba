// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform
import MumbaShims
#if os(Linux)
import Glibc
#endif

let atomCache: [String] = ["WM_DELETE_WINDOW", "_NET_WM_PING", "_NET_WM_PID"]

public class X11Window: PlatformWindow {

  public var bounds: IntRect {
    get {
      return _bounds
    }

    set {
      let bounds = newValue
      let currentScale: Float  = _delegate.deviceScaleFactor
      // this "Screen.getDisplayNearestWindow(0)" will fail. Fixit
      let newScale: Float = Screen.getDisplayNearestWindow(windowId: 0)!.deviceScaleFactor
      let originChanged: Bool = _bounds.origin != bounds.origin
      let sizeChanged: Bool = _bounds.size != bounds.size
      var valueMask: Int32 = 0
      var changes: XWindowChanges = XWindowChanges()

      if sizeChanged {
        changes.width = Int32(bounds.width)
        changes.height = Int32(bounds.height)
        valueMask = (CWHeight | CWWidth)
      }

      if originChanged {
        changes.x = Int32(bounds.x)
        changes.y = Int32(bounds.y)
        valueMask |= CWX | CWY
      }

      if valueMask != 0 {
        XConfigureWindow(_xdisplay, _xwindow, UInt32(valueMask), &changes)
      }
      // Assume that the resize will go through as requested, which should be the
      // case if we're running without a window manager.  If there's a window
      // manager, it can modify or ignore the request, but (per ICCCM) we'll get a
      // (possibly synthetic) ConfigureNotify about the actual size and correct
      // |bounds_| later.
      _bounds = bounds
      if originChanged {
        _delegate.onHostMoved(newLocation: bounds.origin)
      }
      if sizeChanged || currentScale != newScale {
        _delegate.onHostResized(newSize: bounds.size)
      } else {
        _delegate.schedulePaint()
      }
    }
  }

  public var delegate: PlatformWindowDelegate {
    get {
      return _delegate
    }
  }

  public var nativeImeController: PlatformImeController {
    get {
      return 0
    }

  }

  public var acceleratedWidget: AcceleratedWidget {
    return _xwindow
  }

  public var cursor: PlatformCursor = PlatformCursorNil

  public init(_ delegate: PlatformWindowDelegate, bounds: IntRect, display: XDisplayHandle) throws {
    _delegate = delegate
    _bounds = bounds
    _xdisplay = display
    _xrootWindow = XDefaultRootWindow(display)
    _mapped = false
    _requestedBounds = IntRect()
    _confirmedBounds = IntRect()
    _currentCursor = 0
    _atomCache = AtomCache(display, atomCache)
    _touchCalibrate = TouchEventCalibrate()

    var swa: XSetWindowAttributes = XSetWindowAttributes()
    swa.background_pixmap = UInt(None)
    swa.override_redirect = 0
    _xwindow = XCreateWindow(
        _xdisplay, _xrootWindow,
        Int32(bounds.x), Int32(bounds.y), UInt32(bounds.width), UInt32(bounds.height),
        0,               // border width
        Int32(CopyFromParent),  // depth
        UInt32(InputOutput),
        //CopyFromParent,  // visual
        nil,
        UInt(CWBackPixmap) | UInt(CWOverrideRedirect),
        &swa)
    if isX11Error(code: _xwindow)  {
         throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }

    let eventMask: Int = ButtonPressMask | ButtonReleaseMask | FocusChangeMask |
                      KeyPressMask | KeyReleaseMask |
                      EnterWindowMask | LeaveWindowMask |
                      ExposureMask | VisibilityChangeMask |
                      StructureNotifyMask | PropertyChangeMask |
                      PointerMotionMask
    var res = XSelectInput(_xdisplay, _xwindow, eventMask)
    if isX11Error(code: res) {
      throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }
    XFlush(_xdisplay)

    if X11Environment.isXInput2Available {
      if let touchFactory = X11TouchFactory.instance() {
        touchFactory.setupXI2ForXWindow(window: _xwindow)
      }
      selectXInput2EventsForRootWindow(display: _xdisplay, _xrootWindow)
    }

    // TODO(erg): We currently only request window deletion events. We also
    // should listen for activation events and anything else that GTK+ listens
    // for, and do something useful.
    var protocols: [Atom] = [Atom](repeating: 0, count: 2)
    protocols[0] = _atomCache.getAtom(name: "WM_DELETE_WINDOW")!
    protocols[1] = _atomCache.getAtom(name: "_NET_WM_PING")!
    res = XSetWMProtocols(_xdisplay, _xwindow, &protocols, 2)
    if isX11Error(code: res) {
      throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }
    // We need a WM_LIENT_MACHINE and WM_LOCALE_NAME value so we integrate with
    // the desktop environment.
    XSetWMProperties(_xdisplay, _xwindow, nil, nil, nil, 0, nil, nil, nil)
    // Likewise, the X server needs to know this window's pid so it knows which
    // program to kill if the window hangs.
    // XChangeProperty() expects "pid" to be long.
    let pid = getpid()
    var ptr: UnsafeMutablePointer<UInt8>? = nil
    // we need to use this C helper
    _X11_getint_ptr(pid, &ptr)
    // cause this doenst work
    //var ptr : UnsafeMutablePointer<UInt8>(&pid)
    // XA_ARDINAL is defined as a macro, so we need to redefine it here
    let XACardinal: Atom = Atom(6)

    res = XChangeProperty(_xdisplay,
                          _xwindow,
                          _atomCache.getAtom(name: "_NET_WM_PID")!,
                          XACardinal,
                          32,
                          PropModeReplace,
                          ptr,
                          1)
    if isX11Error(code: res) {
      throw PlatformError.OnInit(exception: X11Exception.WindowCreateException)
    }
    // Allow subclasses to create and cache additional atoms.
    _atomCache.allowUncachedAtoms()

    XRRSelectInput(_xdisplay, _xrootWindow,
                   (Int32(RRScreenChangeNotifyMask) | Int32(RROutputChangeNotifyMask)))
    try _delegate.onAcceleratedWidgetAvailable(newWidget: _xwindow, devicePixelRatio: 0)

    let eventSource = X11EventSource.instance //{ //PlatformEventSource.instance() {
      eventSource.addPlatformEventDispatcher(dispatcher: self)
    //}
  }

  deinit {
    if _xwindow == 0 {
      return
    }

    // Stop processing events.
    let eventSource = X11EventSource.instance //{//PlatformEventSource.instance() {
     eventSource.removePlatformEventDispatcher(dispatcher: self)
    //}
    let xwindow: XID = _xwindow
    let xdisplay: XDisplayHandle = _xdisplay
    _xwindow = 0
    _delegate.onClosed()
    // |this| might be deleted because of the above call.

    XDestroyWindow(xdisplay, xwindow)
  }

  public func show() {
    if !_mapped {
      // Before we map the window, set size hints. Otherwise, some window managers
      // will ignore toplevel XMoveWindow commands.
      var sizeHints: XSizeHints = XSizeHints()
      sizeHints.flags = PPosition | PWinGravity
      sizeHints.x = Int32(_bounds.x)
      sizeHints.y = Int32(_bounds.y)
      // Set StaticGravity so that the window position is not affected by the
      // frame width when running with window manager.
      sizeHints.win_gravity = StaticGravity
      XSetWMNormalHints(_xdisplay, _xwindow, &sizeHints)

      XMapWindow(_xdisplay, _xwindow)

      // We now block until our window is mapped. Some X11 APIs will crash and
      // burn if passed |xwindow_| before the window is mapped, and XMapWindow is
      // asynchronous.
       let eventSource = X11EventSource.instance  //PlatformEventSource.instance() as? X11EventSource {
          eventSource.blockUntilWindowMapped(window: _xwindow)
      
      _mapped = true
    }
  }

  public func hide() {
    if _mapped {
      XWithdrawWindow(_xdisplay, _xwindow, 0)
      _mapped = false
    }
  }

  public func close() {

  }

  public func setTitle(title: String) {

  }

  public func setCapture() {

  }

  public func releaseCapture() {

  }

  public func toggleFullscreen() {

  }

  public func maximize() {

  }

  public func minimize() {

  }

  public func restore() {

  }

  public func setCursor(cursor: PlatformCursor) {
    if cursor == _currentCursor {
      return
    }

    _currentCursor = cursor
    setCursorInternal(cursor: cursor)
  }

  public func moveCursorTo(location: IntPoint) {
    XWarpPointer(_xdisplay, UInt(None), _xrootWindow, 0, 0, 0, 0,
                 Int32(_bounds.x + location.x),
                 Int32(_bounds.y + location.y))
  }

  public func confineCursorToBounds(bounds: IntRect) {

  }

  public func canDispatchEvent(event: inout PlatformEvent) -> Bool {
    let target = _X11_FindEventTarget(&event)
    return target == _xwindow || target == _xrootWindow
  }

  public func dispatchEvent(event: inout PlatformEvent) -> PostDispatchAction {
    var xev = event
    if _X11_FindEventTarget(&xev) == _xrootWindow {
      if xev.type == GenericEvent {
        dispatchXI2Event(event: event)
      }
      return .None
    }

    if xev.type == MotionNotify {
      // Discard all but the most recent motion event that targets the same
      // window with unchanged state.
      var lastEvent: XEvent = XEvent()
      while XPending(xev.xany.display) != 0 {
        
        var nextEvent: XEvent = XEvent()
        XPeekEvent(xev.xany.display, &nextEvent)
        if nextEvent.type == MotionNotify &&
            nextEvent.xmotion.window == xev.xmotion.window &&
            nextEvent.xmotion.subwindow == xev.xmotion.subwindow &&
            nextEvent.xmotion.state == xev.xmotion.state {
          XNextEvent(xev.xany.display, &lastEvent)
          xev = lastEvent
        } else {
          break
        }
      }
    }

    if xev.type == EnterNotify || xev.type == LeaveNotify &&
        xev.xcrossing.detail == NotifyInferior {
      // Ignore EventNotify and LeaveNotify  events from children of |xwindow_|.
      // NativeViewGLSurfaceGLX adds a child to |xwindow_|.
      // TODO(pkotwicz|tdanderson): Figure out whether the suppression is
      // necessary. crbug.com/385716
      return .StopPropagation
    }

    if xev.type == EnterNotify ||
       xev.type == LeaveNotify ||
       xev.type == KeyPress ||
       xev.type == KeyRelease ||
       xev.type == ButtonPress ||
       xev.type == ButtonRelease ||
       xev.type == MotionNotify {

      let eventType: EventType = eventTypeFromNative(event: event)
      switch eventType {
        case .KeyPressed, .KeyReleased:
          let keydownEvent = KeyEvent(event)
          let _ = _delegate.sendEventToProcessor(event: keydownEvent)
        case .MouseDragged, .MouseReleased, .MouseMoved,
        .MouseEntered, .MouseExited, .MousePressed:
          let mouseEvent = MouseEvent(event)
          if xev.type == EnterNotify {
            _delegate.onHostEnterWindow()
            // EnterNotify creates ET_MOUSE_MOVE. Mark as synthesized as this is
            // not a real mouse move event.
            mouseEvent.flags = EventFlags(rawValue: mouseEvent.flags.rawValue | EventFlags.IsSynthesized.rawValue)
          }

          _delegate.translateAndDispatchLocatedEvent(event: mouseEvent)
        case .MouseWheel:
          let mouseEvent = MouseWheelEvent(event)
          _delegate.translateAndDispatchLocatedEvent(event: mouseEvent)
        case .Unknown:
          // No event is created for X11-release events for mouse-wheel buttons.
          break
        default:
          break
      }
      return .StopPropagation
    }

    switch xev.type {
      case Expose:
        let damagedRect = IntRect(x: Int(xev.xexpose.x), y: Int(xev.xexpose.y),
                               width: Int(xev.xexpose.width), height: Int(xev.xexpose.height))
        _delegate.onDamageRect(damagedRegion: damagedRect)
      case FocusOut:
        if xev.xfocus.mode != NotifyGrab {
          _delegate.onHostLostWindowCapture()
        }
      case ConfigureNotify:
        assert(_xwindow == xev.xconfigure.event)
        assert(_xwindow == xev.xconfigure.window)
        // It's possible that the X window may be resized by some other means
        // than from within aura (e.g. the X window manager can change the
        // size). Make sure the root window size is maintained properly.
        let bounds = IntRect(x: Int(xev.xconfigure.x),
                          y: Int(xev.xconfigure.y),
                          width: Int(xev.xconfigure.width),
                          height: Int(xev.xconfigure.height))
        let sizeChanged = _bounds.size != bounds.size
        let originChanged = _bounds.origin != bounds.origin
        _bounds = bounds
        onConfigureNotify()
        if sizeChanged {
          _delegate.onHostResized(newSize: bounds.size)
        }
        if originChanged {
          _delegate.onHostMoved(newLocation: _bounds.origin)
        }
      case GenericEvent:
        dispatchXI2Event(event: event)
      case ClientMessage:
        let messageType: Atom = Atom(xev.xclient.data.l.0)
        if messageType == _atomCache.getAtom(name: "WM_DELETE_WINDOW") {
          // We have received a close message from the window manager.
          _delegate.onHostCloseRequested()
        } else if messageType == _atomCache.getAtom(name: "_NET_WM_PING") {
          var replyEvent: XEvent = xev
          replyEvent.xclient.window = _xrootWindow
          XSendEvent(_xdisplay,
                     replyEvent.xclient.window,
                     False,
                     SubstructureRedirectMask | SubstructureNotifyMask,
                     &replyEvent)
          XFlush(_xdisplay)
        }
      case MappingNotify:
        switch xev.xmapping.request {
          case MappingModifier:
            break
          case MappingKeyboard:
            XRefreshKeyboardMapping(&xev.xmapping)
          case MappingPointer:
            if let devManager = X11DeviceDataManager.instance() {
              devManager.updateButtonMap()
            }
          default:
            //NOTIMPLEMENTED() << " Unknown request: " << xev->xmapping.request;
            break
        }
      default:
        break
    }
    return .StopPropagation
  }

  private func onConfigureNotify() {}

  private func setCursorInternal(cursor: PlatformCursor) {
    //XDefineCursor(_xdisplay, _xwindow, cursor.platform)
    XDefineCursor(_xdisplay, _xwindow, cursor)
  }

  private func dispatchXI2Event(event: PlatformEvent) {
    var xev = event
    let xiev = unsafeBitCast(event.xcookie.data, to: UnsafeMutablePointer<XIDeviceEvent>.self)

    if let factory = X11TouchFactory.instance() {
      if !factory.shouldProcessXI2Event(xev: xev) {
        return
      }
    }

    //TRACE_EVENT1("input", "WindowTreeHostX11::DispatchXI2Event",
    //             "event_latency_us",
    //             (ui::EventTimeForNow() - ui::EventTimeFromNative(event)).
    //               InMicroseconds())

    var numCoalesced = 0
    var lastEvent: PlatformEvent = PlatformEvent()
    if xev.xgeneric.evtype == XI_Motion {
      // If this is a motion event, we want to coalesce all pending motion
      // events that are at the top of the queue. Note, we don't coalesce
      // touch update events here.
      numCoalesced = coalescePendingMotionEvents(event: event, lastEvent: &lastEvent) // lastEvent = inout!
      if numCoalesced > 0 {
        xev = lastEvent
      }
    }

    let type: EventType = eventTypeFromNative(event: event)

    switch type {
      case .TouchMoved, .TouchReleased, .TouchPressed, .TouchCancelled:
        let touchev = TouchEvent(event)
        if let devMananager = X11DeviceDataManager.instance() {
          if devMananager.touchEventNeedsCalibrate(id: xiev.pointee.deviceid) {
            _touchCalibrate.calibrate(event: touchev, _bounds)
          }
        }
        _delegate.translateAndDispatchLocatedEvent(event: touchev)
      case .MousePressed, .MouseDragged, .MouseReleased,
      .MouseMoved, .MouseEntered, .MouseExited:
        let mouseev = MouseEvent(event)
        _delegate.translateAndDispatchLocatedEvent(event: mouseev)
      case .MouseWheel:
        let mouseev = MouseWheelEvent(event)
        _delegate.translateAndDispatchLocatedEvent(event: mouseev)
      case .Scroll, .ScrollFlingStart, .ScrollFlingCancel:
        let scrollev = ScrollEvent(event)
        let _ = _delegate.sendEventToProcessor(event: scrollev) // inout
      case .KeyPressed, .KeyReleased:
        let keyEvent = KeyEvent(event)
        let _ = _delegate.sendEventToProcessor(event: keyEvent) // inout
      case .UMAData:
        break
      case .Unknown:
        break
      default:
        break
    }

    // If we coalesced an event we need to free its cookie.
    if numCoalesced > 0 {
      var reference = lastEvent
      XFreeEventData(xev.xgeneric.display, &reference.xcookie)
    }
  }

  private func eventTypeFromNative(event: PlatformEvent) -> EventType {
    return .Unknown
  }

  private func coalescePendingMotionEvents(event: PlatformEvent, lastEvent: inout PlatformEvent) -> Int {
    return 0
  }

  private func selectXInput2EventsForRootWindow(display: XDisplayHandle, _ rootWindow: Window) {
    let len = Int((XI_LASTEVENT >> 3) + 1)
    var mask: [UInt8] = [UInt8](repeating: 0, count: len)

    _XISetMask(mask: &mask, XI_HierarchyChanged)

    var evmask: XIEventMask = XIEventMask()
    evmask.deviceid = XIAllDevices
    evmask.mask_len = Int32(MemoryLayout.size(ofValue: mask))
    evmask.mask = UnsafeMutablePointer(mutating: mask)
    XISelectEvents(display, rootWindow, &evmask, 1)

  //#if defined(OS_HROMEOS)
  //  if (base::SysInfo::IsRunningOnChromeOS()) {
      // It is necessary to listen for touch events on the root window for proper
      // touch event calibration on Chrome OS, but this is not currently necessary
      // on the desktop. This seems to fail in some cases (e.g. when logging
      // in incognito). So select for non-touch events first, and then select for
      // touch-events (but keep the other events in the mask, i.e. do not memset
      // |mask| back to 0).
      // TODO(sad): Figure out why this happens. http://crbug.com/153976
  //    XISetMask(mask, XI_TouchBegin);
  //    XISetMask(mask, XI_TouchUpdate);
  //    XISetMask(mask, XI_TouchEnd);
  //    XISelectEvents(display, root_window, &evmask, 1);
  //  }
  //#endif
  }

  private func _XISetMask(mask: inout [UInt8], _ event: Int32) {
    let index = Int(event >> 3)
    mask[index] = mask[index] | (1 << (UInt8(event) & 7))
  }

  var _delegate: PlatformWindowDelegate
  var _bounds: IntRect
  var _mapped: Bool
  var _xdisplay: XDisplayHandle
  var _xwindow: CUnsignedLong
  var _xrootWindow: CUnsignedLong
  var _requestedBounds: IntRect
  var _confirmedBounds: IntRect
  var _currentCursor: XCursor
  var _atomCache: AtomCache
  var _touchCalibrate: TouchEventCalibrate
}
