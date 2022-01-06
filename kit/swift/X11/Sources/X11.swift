// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Platform
import Graphics

public class X11Environment {
  public static var isXInput2Available: Bool {
    if let devManager = X11DeviceDataManager.instance() {
        return devManager.isXInput2Available
    }
    return false
  }

  public static var XDisplay: XDisplayHandle {
    if _display == nil {
     _display = _X11_GetXDisplay()
    }
    return _display!
  }

  public static func updateDeviceList(display: XDisplayHandle) {

  }

  public static func updateDeviceList() {
    updateDeviceList(display: XDisplay)
  }

  private static var _display: XDisplayHandle? = nil
}

//internal class AtomCache {
//  let _display: XDisplayHandle
//  var _cache: [String: Atom]
//  var _uncachedAtomsAllowed: Bool
//
//  init(_ display: XDisplayHandle, _ cache: [String]) {
//    _display = display
//    _cache = [String: Atom]()
//
//    for name in cache {
//       let atom: Atom = XInternAtom(_display, name, 0)
//      _cache[name] = atom
//    }
//    _uncachedAtomsAllowed = false
//  }
//
//  func getAtom(name: String) -> Atom? {
//    let found: Atom? = _cache[name]
//
//    if _uncachedAtomsAllowed && found == nil {
//      let atom: Atom = XInternAtom(_display, name, 0)
//      _cache[name] = atom
//      return atom
//    }
//
//    return found
//  }
//
//  func allowUncachedAtoms() {
//    _uncachedAtomsAllowed = true
// }
//
//}

public final class X11Platform : Platform {
  private var eventSource: X11EventSource?
  public init() {}

  public func initialize() throws {
    eventSource = X11EventSource.createDefault()
  }

  public func createWindow(delegate: PlatformWindowDelegate, bounds: IntRect) throws -> PlatformWindow {
    let display = X11Environment.XDisplay
    return try X11Window(delegate, bounds: bounds, display: display)
  }
}

public func isX11Error(code: Int32) -> Bool {
  return code == X11Error.BadAlloc.rawValue  || code == X11Error.BadColor.rawValue || code == X11Error.BadCursor.rawValue ||
     code == X11Error.BadMatch.rawValue || code == X11Error.BadPixmap.rawValue || code == X11Error.BadValue.rawValue ||
     code == X11Error.BadWindow.rawValue
}

public func isX11Error(code: UInt) -> Bool {
  return isX11Error(code: Int32(code))
}
