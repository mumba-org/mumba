// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Platform
import Graphics
import MumbaShims

public class X11HotplugEventHandler {
  init() {}
  public func onHotplugEvent() {}
}

public class X11EventSource : PlatformEventSource {

  
  public static var instance: X11EventSource {
    return createDefault()
  }

  //public override class func createDefault() -> PlatformEventSource? {
  public class func createDefault() -> X11EventSource {
    if X11EventSource._instance == nil {
      X11EventSource._instance = X11EventSource(display: X11Environment.XDisplay)
    }
    return X11EventSource._instance!
  }

  private var _display: XDisplayHandle
  private var _xsource: GLibX11SourceHandle?
  private var _hotplugEventHandler: X11HotplugEventHandler
  private var _continueStream: Bool
  private static var _instance: X11EventSource?

  public init(display: XDisplayHandle) {
    _display = display
    _hotplugEventHandler = X11HotplugEventHandler()
    _continueStream = true
    _xsource = nil
    super.init()
    X11DeviceDataManager.createInstance()
    initializeXInput2(display: _display)
    initializeXkb(display: _display)
    initXSource(fd: _X11_onnectionNumber(display))
  }

  deinit {
    _X11_DestroyXSource(_xsource)
  }

  public var timestamp: MumbaShims.Time {
    //print("warning: X11EventSource.timestamp getter: returning default 0 timestamp. Fix to calculate the real value")
    return 0
  }

  public func dispatchXEvents() {
    //assert(_display != nil)
    _continueStream = true
    while XPending(_display) != 0 && _continueStream {
      var xevent: XEvent = XEvent()
      XNextEvent(_display, &xevent)
      let _ = extractCookieDataDispatchEvent(xevent: &xevent)
    }
  }

  public func blockUntilWindowMapped(window: XID) {
    var event = XEvent()
    repeat {
      // Block until there's a message of |event_mask| type on |w|. Then remove
      // it from the queue and stuff it in |event|.
      XWindowEvent(_display, window, StructureNotifyMask, &event)
      let _ = extractCookieDataDispatchEvent(xevent: &event)
    } while event.type != MapNotify

  }

  private func extractCookieDataDispatchEvent(xevent: inout XEvent) -> UInt32 {
    var haveCookie = false
    if xevent.type == GenericEvent && XGetEventData(xevent.xgeneric.display, &xevent.xcookie) != 0 {
      haveCookie = true
    }
    let action = dispatchEvent(platformEvent: &xevent)
    if haveCookie {
      XFreeEventData(xevent.xgeneric.display, &xevent.xcookie)
    }
    return action
  }

  private func dispatchXEvent(xevent: inout XEvent) -> UInt32 {
    let action = dispatchEvent(platformEvent: &xevent)
    if xevent.type == GenericEvent && xevent.xgeneric.evtype == XI_HierarchyChanged {
      X11Environment.updateDeviceList()
      _hotplugEventHandler.onHotplugEvent()
    }
    return action
  }

  private func initXSource(fd: Int32) {
    let temp = unsafeBitCast(self, to: UnsafeMutableRawPointer.self)
    // using a c wrapper cause linking directly into glib can be nasty
    _xsource = _X11_InitXSource(fd, _display,  { (ptr: UnsafeMutableRawPointer?) -> Void in
      let us: X11EventSource = unsafeBitCast(ptr, to: X11EventSource.self)//UnsafeRawPointer(ptr).memory
      us.dispatchXEvents()
    }, temp)
  }

}

func initializeXInput2(display: XDisplayHandle) {

}

func initializeXkb(display: XDisplayHandle) {

}
