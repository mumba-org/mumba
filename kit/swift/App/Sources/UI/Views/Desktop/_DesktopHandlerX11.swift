// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform
import MumbaShims
import X11

let atomList: [String] = [
    "_NET_ACTIVE_WINDOW"
]

public class DesktopHandlerX11 {

  public enum ActiveState {
    case Active
    case NotActive
  }  

  public static let instance: DesktopHandlerX11 = DesktopHandlerX11()

  public var wmUserTimeMS: UInt
  
  var xdisplay: XDisplayHandle
  
  var xrootWindow: CUnsignedLong

  // The last known active X window
  var xActiveWindow: CUnsignedLong
 
  // The active window according to X11 server.
  var currentWindow: CUnsignedLong

  // Whether we should treat |current_window_| as active. In particular, we
  // pretend that a window is deactivated after a call to DeactivateWindow().
  var currentWindowActiveState: ActiveState

  var atomCache: AtomCache

  var wmSupportsActiveWindow: Bool

  public init() {
    xdisplay = X11Environment.XDisplay
    xrootWindow = XDefaultRootWindow(xdisplay)
    xActiveWindow = UInt(None)
    wmUserTimeMS = 0
    currentWindow = UInt(None)
    currentWindowActiveState = .NotActive
    atomCache = AtomCache(xdisplay, atomList)
    wmSupportsActiveWindow = false
    
    if let eventSource = PlatformEventSource.instance() {
     eventSource.addPlatformEventDispatcher(dispatcher: self)
    }
    
    UI.addObserver(observer: self)

    var attr = XWindowAttributes() 
    XGetWindowAttributes(xdisplay, xrootWindow, &attr)
    
    
    let eventMask: Int = attr.your_event_mask | PropertyChangeMask | StructureNotifyMask | SubstructureNotifyMask
    XSelectInput(xdisplay, xrootWindow, eventMask)

    // TODO: this is failing without a apparent reason
    // figure it out and activate when possible
    
    if guessWindowManager() == .WMII {
        // wmii says that it supports _NET_ACTIVE_WINDOW but does not.
        // https://code.google.com/p/wmii/issues/detail?id=266
        wmSupportsActiveWindow = false
    } else {
      wmSupportsActiveWindow = wmSupportsHint(atom: atomCache.getAtom(name: "_NET_ACTIVE_WINDOW")!)
    }
    
    //wmSupportsActiveWindow = true
  }
  
  deinit {
    UI.removeObserver(observer: self)
    if let eventSource = PlatformEventSource.instance() {
        eventSource.removePlatformEventDispatcher(dispatcher: self)
    }
  }

  public func activateWindow(window: CUnsignedLong) {
    if (currentWindow == UInt(None) || currentWindow == window) &&
        currentWindowActiveState == .NotActive {
        // |window| is most likely still active wrt to the X server. Undo the
        // changes made in DeactivateWindow().
        onActiveWindowChanged(window: window, activeState: .Active)

        // Go through the regular activation path such that calling
        // DeactivateWindow() and ActivateWindow() immediately afterwards results
        // in an active X window.
     }

    if wmSupportsActiveWindow {
        //DCHECK_EQ(gfx::GetXDisplay(), xdisplay_);

        // If the window is not already active, send a hint to activate it
        if xActiveWindow != window {
            var xclient = XEvent()
            //memset(&xclient, 0, sizeof(xclient));
            xclient.type = ClientMessage
            xclient.xclient.window = window
            xclient.xclient.message_type = atomCache.getAtom(name: "_NET_ACTIVE_WINDOW")!
            xclient.xclient.format = 32
            xclient.xclient.data.l = (1, Int(wmUserTimeMS), None, 0, 0)   // Specified we are an app.
         
            XSendEvent(xdisplay, xrootWindow, False,
                 SubstructureRedirectMask | SubstructureNotifyMask,
                 &xclient)
        } else {
            onActiveWindowChanged(window: window, activeState: .Active)
        }
    } else {
        XRaiseWindow(xdisplay, window)
        // Directly ask the X server to give focus to the window. Note
        // that the call will raise an X error if the window is not
        // mapped.
        XSetInputFocus(xdisplay, window, RevertToParent, Time(CurrentTime))

        onActiveWindowChanged(window: window, activeState: .Active)
    }
  }

  public func deactivateWindow(window: CUnsignedLong) {
    if !isActiveWindow(window: window) {
        return
    }

    XLowerWindow(xdisplay, window)

    // Per ICCCM: http://tronche.com/gui/x/icccm/sec-4.html#s-4.1.7
    // "Clients should not give up the input focus of their own volition.
    // They should ignore input that they receive instead."
    //
    // There is nothing else that we can do. Pretend that we have been
    // deactivated and ignore keyboard input in DesktopWindowTreeHostX11.
    onActiveWindowChanged(window: window, activeState: .NotActive)
  }

  public func isActiveWindow(window: CUnsignedLong) -> Bool {
    return window == currentWindow && currentWindowActiveState == .Active
  }

  public func processXEvent(event: XEventHandle) {
    // Ignore focus events that are being sent only because the pointer is over
    // our window, even if the input focus is in a different window.
    if event.pointee.xfocus.detail == NotifyPointer {
        return
    }

    switch event.pointee.type {
        
        case FocusIn:
            if currentWindow != event.pointee.xfocus.window {
                onActiveWindowChanged(window: event.pointee.xfocus.window, activeState: .Active)
            }
        case FocusOut:
            if currentWindow == event.pointee.xfocus.window {
                onActiveWindowChanged(window: UInt(None), activeState: .NotActive)
            }
        default:
           break
        //NOTREACHED()
    }
  }
  
  func onActiveWindowChanged(window: CUnsignedLong, activeState: ActiveState) {
      
    if currentWindow == window && currentWindowActiveState == activeState {
        return
    }

    if currentWindowActiveState == .Active {
        if let oldHost = DesktopWindowTreeHostX11.getHostForXID(xid: currentWindow) {
            oldHost.handleActivationChanged(active: false)//handleDesktopWidgetActivationChanged(active: false)
        }
    }

    // Update the current window ID to effectively change the active widget.
    currentWindow = window
    currentWindowActiveState = activeState

    if activeState == .Active {
        if let newHost = DesktopWindowTreeHostX11.getHostForXID(xid: window) {
            newHost.handleActivationChanged(active: true)//.handleDesktopWidgetActivationChanged(active: true)
        }
    }
  }

  func onWindowCreatedOrDestroyed(eventType: Int32, window: CUnsignedLong) {
    if eventType == CreateNotify {
        // The window might be destroyed if the message pump did not get a chance to
        // run but we can safely ignore the X error.
        //gfx::X11ErrorTracker error_tracker
        XMenuList.instance.maybeRegisterMenu(menu: window)
    } else {
        XMenuList.instance.maybeUnregisterMenu(menu: window)
    }

    if eventType == DestroyNotify {
        // Notify the XForeignWindowManager that |window| has been destroyed.
        X11ForeignWindowManager.instance.onWindowDestroyed(xid: window)
    }
  }
}

extension DesktopHandlerX11 : PlatformEventDispatcher {

  public func canDispatchEvent(event: inout PlatformEvent) -> Bool {
    return event.type == CreateNotify || event.type == DestroyNotify ||
         (event.type == PropertyNotify &&
          event.xproperty.window == xrootWindow)
  }

  public func dispatchEvent(event: inout PlatformEvent) -> PostDispatchAction {
    switch event.type {
        case PropertyNotify:
            // Check for a change to the active window.
            assert(xrootWindow == event.xproperty.window)
            let activeWindowAtom = atomCache.getAtom(name: "_NET_ACTIVE_WINDOW")
            if event.xproperty.atom == activeWindowAtom {
                var window = XID()
                if getXIDProperty(window: xrootWindow, propertyName: "_NET_ACTIVE_WINDOW", value: &window) &&
                    window != UInt(None) {
                    xActiveWindow = window
                    onActiveWindowChanged(window: window, activeState: .Active)
                } else {
                    xActiveWindow = UInt(None)
                }
            }
        case CreateNotify:
            onWindowCreatedOrDestroyed(eventType: event.type, window: event.xcreatewindow.window)
        case DestroyNotify:
            onWindowCreatedOrDestroyed(eventType: event.type, window: event.xdestroywindow.window)
            // If the current active window is being destroyed, reset our tracker.
            if xActiveWindow == event.xdestroywindow.window {
                xActiveWindow = UInt(None)
            }
        default:
            break
            //NOTREACHED();
    }

    return PostDispatchAction.None
  }
}


extension DesktopHandlerX11 : UIObserver {

  public func onWindowInitialized(window: Window) {}

  public func onHostInitialized(host: WindowTreeHost) {}

  public func onHostActivated(host: WindowTreeHost) {}

  public func onBeforeDestroy() {}

}
