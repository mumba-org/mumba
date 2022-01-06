// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
#if os(Linux)
import Glibc
#endif

let XA_ATOM: Atom = 4
let XA_ARDINAL: Atom = 6
let XA_STRING: Atom = 31

public enum TitlebarVisibility: Int32 {
  case ShowTitlebarWhenMaximized = 0
  case HideTitlebarWhenMaximized = 1
}

public enum WindowManagerName {
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

public func getWindowManagerName() -> String? {

  var wmName = String()

  if !supportsEWMH() {
    return nil
  }

  var wmWindow: Int = 0

  let display = X11Environment.XDisplay
  if !getIntProperty(window: XDefaultRootWindow(display),
                     propertyName: "_NET_SUPPORTING_WM_HECK",
                     value: &wmWindow) {
    return nil
  }

  let result = getStringProperty(
      window: UInt(wmWindow), propertyName: "_NET_WM_NAME", value: &wmName)

  if result {
    return wmName
  }

  return nil
}

public func guessWindowManager() -> WindowManagerName {

  if let name = getWindowManagerName() {
    // These names are taken from the WMs' source code.
    if name == "awesome" {
      return .Awesome
    }
    if name == "Blackbox" {
      return .Blackbox
    }
    if name == "Compiz" || name == "compiz" {
      return .Compiz
    }
    if name == "e16" || name == "Enlightenment" {
      return .Enlightenment
    }
    if name == "Fluxbox" {
      return .Fluxbox
    }
    if name == "i3" {
      return .I3
    }
    if name.hasPrefix("IceWM") {
      return .Icewm
    }
    if name == "ion3" {
      return .Ion3
    }
    if name == "KWin" {
      return .Kwin
    }
    if name == "matchbox" {
      return .Matchbox
    }
    if name == "Metacity" {
      return .Metacity
    }
    if name == "Mutter (Muffin)" {
      return .Muffin
    }
    if name == "GNOME Shell" {
      return .Mutter  // GNOME Shell uses Mutter
    }
    if name == "Mutter" {
      return .Mutter
    }
    if name == "notion" {
      return .Notion
    }
    if name == "Openbox" {
      return .Openbox
    }
    if name == "qtile" {
      return .Qtile
    }
    if name == "ratpoison" {
      return .Ratpoison
    }
    if name == "stumpwm" {
      return .Stumpwm
    }
    if name == "wmii" {
      return .WMII
    }
    if name == "Xfwm4" {
      return .XFWM4
    }
  }
  return .Unknown
}

public func wmSupportsHint(atom: Atom) -> Bool {

  if !supportsEWMH() {
    return false
  }

  var supportedAtoms = [Atom]()

  let display = X11Environment.XDisplay
  if !getAtomArrayProperty(window: XDefaultRootWindow(display),
                           propertyName: "_NET_SUPPORTED",
                           value: &supportedAtoms) {
    return false
  }

  for item in supportedAtoms {
    if item == atom {
      return true
    }
  }

  return false
}

public func createRegionFromGfxPath(path: Graphics.Path) -> MumbaShims.Region {
  var result: MumbaShims.Region? = nil
  let pointCount = path.pointCount
  var points = [FloatPoint](repeating: FloatPoint(), count: pointCount)
  let _ = path.getPoints(points: &points, max: pointCount)
  var x11Points = [XPoint](repeating: XPoint(), count: pointCount)
  for i in 0...pointCount {
    x11Points[i].x = Int16(points[i].x)
    x11Points[i].y = Int16(points[i].y)
  }
  x11Points.withUnsafeMutableBufferPointer( { (arr: inout UnsafeMutableBufferPointer<XPoint>) in
    result = XPolygonRegion(arr.baseAddress, Int32(pointCount), EvenOddRule)
  })
  return result!
}

public func createRegionFromGfxRegion(region: Graphics.Region) -> MumbaShims.Region {
  let result = XCreateRegion()
  let iterator = RegionIterator(region: region)
  while !iterator.isDone {
    var rect = XRectangle()
    rect.x = Int16(iterator.rect.x)
    rect.y = Int16(iterator.rect.y)
    rect.width = UInt16(iterator.rect.width)
    rect.height = UInt16(iterator.rect.height)
    XUnionRectWithRegion(&rect, result, result)
    iterator.next()
  }
  return result!
}


public func createRegionFromPath(path: Path, points x11Points: inout ContiguousArray<XPoint>) -> MumbaShims.Region? {
  let pointCount = path.pointCount
  var points = Array<FloatPoint>()

  let _ = path.getPoints(points: &points, max: pointCount)

//  var x11Points = ContiguousArray<XPoint>(repeating: XPoint(), count: pointCount)

  for i in 0..<pointCount {
    x11Points[i].x = Int16(points[i].x)
    x11Points[i].y = Int16(points[i].y)
  }

  // TODO: verificar se nao tem problema que o array x11Points
  // fique invalido depois de retornar da funcao que o declara

  return x11Points.withUnsafeMutableBufferPointer({ (arr: inout UnsafeMutableBufferPointer<XPoint>) in
    return XPolygonRegion(arr.baseAddress, Int32(pointCount), EvenOddRule)
  })

  //return nil
}

public func getAtom(name: String) -> XAtom {
  let display = X11Environment.XDisplay
  return XInternAtom(display, name, False)
}

// TODO: essas propriedades devem ser gerenciadas manualmente
// pois estao vazando

public func getProperty(window: XID, propertyName: String, maxLength: Int,
                 type: inout XAtom, format: inout Int32, numItems: inout UInt,
                 property: inout UnsafeMutablePointer<UInt8>?) -> Int32 {

  let display = X11Environment.XDisplay
  let propertyAtom: XAtom = getAtom(name: propertyName)
  var remainingBytes: UInt = 0
  return XGetWindowProperty(display,
                            window,
                            propertyAtom,
                            0,          // offset into property data to read
                            maxLength, // max length to get
                            False,      // deleted
                            UInt(AnyPropertyType),
                            &type,
                            &format,
                            &numItems,
                            &remainingBytes,
                            &property)
}

public func getStringProperty(window: XID, propertyName: String, value: inout String) -> Bool{
  var type: XAtom = UInt(None)
  var format: Int32 = 0  // size in bits of each item in 'property'
  var numItems: CUnsignedLong = 0
  var property: UnsafeMutablePointer<UInt8>? = nil

  let result = getProperty(window: window, propertyName: propertyName, maxLength: 1024,
                           type: &type, format: &format, numItems: &numItems,
                           property: &property)


  //gfx::XScopedPtr<unsigned char> scoped_property(property);
  if result != Success {
    return false
  }

  if format != 8 {
    return false
  }

  //value->assign(reinterpret_cast<char*>(property), num_items)
  //value = String.fromCString(UnsafePointer<CChar>(property))!
  value = String(describing: property)

  return true
}


public func setHideTitlebarWhenMaximizedProperty(window: XID,
                                                 property: TitlebarVisibility) {
  // XChangeProperty() expects "hide" to be long.
  var hide = property.rawValue
  let display = X11Environment.XDisplay

  withUnsafePointer(to: &hide, { (ptr: UnsafePointer<Int32>) in
    let voidPtr = ptr.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
    XChangeProperty(display,
       window,
       getAtom(name: "_GTK_HIDE_TITLEBAR_WHEN_MAXIMIZED"),
       XA_ARDINAL,
       32,  // size in bits
       PropModeReplace,
       voidPtr,
       1)
  })
}

public func getIntProperty(window: XID, propertyName: String, value: inout Int) -> Bool {
  var type: XAtom = UInt(None)
  var format: Int32 = 0  // size in bits of each item in 'property'
  var numItems: CUnsignedLong = 0
  var property: UnsafeMutablePointer<UInt8>? = nil

  let result = getProperty(window: window, propertyName: propertyName, maxLength: 1,
                           type: &type, format: &format, numItems: &numItems,
                           property: &property)

  //gfx::XScopedPtr<unsigned char> scoped_property(property)

  if result != Success {
    return false
  }

  if format != 32 || numItems != 1 {
    return false
  }

  guard let prop = property else {
    return false
  }

  let intPtr = UnsafeRawPointer(prop).bindMemory(to: CInt.self, capacity: 1)

  value = Int(intPtr.pointee)

  return true
}

public func getXIDProperty(window: XID, propertyName: String, value: inout XID) -> Bool {
  var type: XAtom = UInt(None)
  var format: Int32 = 0
  var numItems: CUnsignedLong = 0
  var property: UnsafeMutablePointer<UInt8>? = nil

  let result = getProperty(window: window, propertyName: propertyName, maxLength: 1,
                           type: &type, format: &format, numItems: &numItems,
                           property: &property)

  //gfx::XScopedPtr<unsigned char> scoped_property(property);
  if result != Success {
    return false
  }

  if format != 32 || numItems != 1 {
    return false
  }

  guard let prop = property else {
    return false
  }

  let xidPtr = UnsafeRawPointer(prop).bindMemory(to: XID.self, capacity: 1)

  value = xidPtr.pointee
  return true
}

public func getIntArrayProperty(window: XID,
                         propertyName: String,
                         value: inout [Int]) -> Bool {

  var type: XAtom = UInt(None)
  var format: Int32 = 0  // size in bits of each item in 'property'
  var numItems: UInt = 0
  var properties: UnsafeMutablePointer<UInt8>? = nil

  let result = getProperty(window: window,
                           propertyName: propertyName,
                           maxLength: (~0), // (all of them)
                           type: &type, format: &format, numItems: &numItems, property: &properties)

  //gfx::XScopedPtr<unsigned char> scoped_properties(properties)

  if result != Success {
    return false
  }

  if format != 32 {
    XFree(properties)
    return false
  }

  guard let props = properties else {
    return false
  }
  
  let cIntArray = UnsafeRawPointer(props).bindMemory(to: UInt.self, capacity: Int(numItems))
  //long* intProperties = reinterpret_cast<long*>(properties)
  value.removeAll()
  var offset = cIntArray
  for _ in 0..<Int(numItems) {
    let x = offset.pointee
    value.append(Int(x))
    offset += 1
  }
  XFree(properties)
  return true
}

public func getAtomArrayProperty(window: XID,
                          propertyName: String,
                          value: inout [XAtom]) -> Bool {

  var type: XAtom = UInt(None)
  var format: Int32 = 0  // size in bits of each item in 'property'
  var numItems: UInt = 0
  var properties: UnsafeMutablePointer<UInt8>? = nil

  let result = getProperty(window: window, propertyName: propertyName,
                           maxLength: (~0), // (all of them)
                           type: &type,
                           format: &format,
                           numItems: &numItems,
                           property: &properties)

  //gfx::XScopedPtr<unsigned char> scoped_properties(properties);

  if result != Success {
    return false
  }

  if type != XA_ATOM {
    XFree(properties)
    return false
  }

  guard let props = properties else {
    return false
  }
  
  //XAtom* atom_properties = reinterpret_cast<XAtom*>(properties)
  let cIntArray = UnsafeRawPointer(props).bindMemory(to: UInt.self, capacity: Int(numItems))
  //long* intProperties = reinterpret_cast<long*>(properties)
  value.removeAll()
  var offset = cIntArray
  for _ in 0..<Int(numItems) {
    let x = offset.pointee
    value.append(UInt(x))
    offset += 1
  }
   //value.append(value->begin(), atomProperties, atomProperties + numItems)
  XFree(properties)
  return true
}

public func setIntProperty(window: XID,
                    name: String,
                    type: String,
                    value: Int) -> Bool {

  var values = [Int](repeating: value, count: 1)
  return setIntArrayProperty(window: window, name: name, type: type, value: &values)
}

public func setAtomArrayProperty(window: XID,
                                 name: String,
                                 type: String,
                                 value: inout ContiguousArray<Atom> ) -> Bool {

  let nameAtom = getAtom(name: name)
  let typeAtom = getAtom(name: type)

  let display = X11Environment.XDisplay
  let count = value.count

  value.withUnsafeMutableBufferPointer({ (array: inout UnsafeMutableBufferPointer<Atom>) in
    //let ptr = unsafeBitCast(array[0], to: UnsafeMutablePointer<UInt8>.self)
    let ptr = array.baseAddress!.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
    XChangeProperty(display,
                    window,
                    nameAtom,
                    typeAtom,
                    32,  // size in bits of items in 'value'
                    PropModeReplace,
                    ptr,
                    CInt(count))  // num items
  })

  //return !err_tracker.FoundNewError()
  return true
}

public func setIntArrayProperty(window: XID,
                         name: String,
                         type: String,
                         value: inout [Int] ) -> Bool {

  let nameAtom = getAtom(name: name)
  let typeAtom = getAtom(name: type)

  let display = X11Environment.XDisplay
  let count = value.count

  value.withUnsafeMutableBufferPointer({ (array: inout UnsafeMutableBufferPointer<Int>) in
    //let ptr = unsafeBitCast(array[0], to: UnsafeMutablePointer<UInt8>.self)
    let ptr = array.baseAddress!.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
    XChangeProperty(display,
                    window,
                    nameAtom,
                    typeAtom,
                    32,  // size in bits of items in 'value'
                    PropModeReplace,
                    ptr,
                    Int32(count))  // num items
  })

  return true
}

 public func setWindowClassHint(display: XDisplayHandle,
                         window: XID,
                         resName: String,
                         resClass: String) {
  var classHints = XClassHint()
  // const_cast is safe because XSetClassHint does not modify the strings.
  // Just to be safe, the res_name and res_class parameters are local copies,
  // not const references.
  //  TODO: check if swift string will auto convert to a C string
  resName.withCString({ (ptr: UnsafePointer<Int8>) in
    classHints.res_name = UnsafeMutablePointer<Int8>(mutating: ptr)
  })
  resClass.withCString({ (ptr: UnsafePointer<Int8>) in
    classHints.res_class = UnsafeMutablePointer<Int8>(mutating: ptr)
  })
  XSetClassHint(display, window, &classHints)
 }


 public func setWindowRole(display: XDisplayHandle, window: XID, role: String) {
   if role.isEmpty {
     XDeleteProperty(display, window, getAtom(name: "WM_WINDOW_ROLE"))
   } else {
     role.withCString({  (cstring: UnsafePointer<Int8>) in
       let ptr = cstring.withMemoryRebound(to: UInt8.self, capacity: 1, { return $0 })
       XChangeProperty(display, window, getAtom(name: "WM_WINDOW_ROLE"), XA_STRING, 8,
                       PropModeReplace,
                       ptr,
                       Int32(role.count))
     })
   }
 }

public func coalescePendingMotionEvents(xev: inout XEvent, lastEvent: inout XEvent) -> Int {

  let xievent = unsafeBitCast(xev.xcookie.data, to: UnsafeMutablePointer<XIDeviceEvent>.self)
  var numCoalesced = 0
  let display = xev.xany.display
  let eventType = xev.xgeneric.evtype

  assert(eventType == XI_Motion || eventType == XI_TouchUpdate)


  while XPending(display) != 0 {
    var nextEvent = PlatformEvent()
    XPeekEvent(display, &nextEvent)

    //let ev = nextEvent
    // If we can't get the cookie, abort the check.
    if XGetEventData(nextEvent.xgeneric.display, &nextEvent.xcookie) == 0 {
      return numCoalesced
    }

    // If this isn't from a valid device, throw the event away, as
    // that's what the message pump would do. Device events come in pairs
    // with one from the master and one from the slave so there will
    // always be at least one pending.
    if let touchFactory = X11TouchFactory.instance() { 
      if touchFactory.shouldProcessXI2Event(xev: nextEvent) {
        XFreeEventData(display, &nextEvent.xcookie)
        XNextEvent(display, &nextEvent)
        continue
      }
    }

    if nextEvent.type == GenericEvent &&
        nextEvent.xgeneric.evtype == eventType &&
        !X11DeviceDataManager.instance()!.isCMTGestureEvent(
            event: nextEvent) {

      let nextXievent = unsafeBitCast(nextEvent.xcookie.data, to: UnsafeMutablePointer<XIDeviceEvent>.self)
      // Confirm that the motion event is targeted at the same window
      // and that no buttons or modifiers have changed.
      if xievent.pointee.event == nextXievent.pointee.event &&
          xievent.pointee.child == nextXievent.pointee.child &&
          xievent.pointee.detail == nextXievent.pointee.detail &&
          xievent.pointee.buttons.mask_len == nextXievent.pointee.buttons.mask_len &&
          (memcmp(xievent.pointee.buttons.mask,
                  nextXievent.pointee.buttons.mask,
                  Int(xievent.pointee.buttons.mask_len)) == 0) &&
          xievent.pointee.mods.base == nextXievent.pointee.mods.base &&
          xievent.pointee.mods.latched == nextXievent.pointee.mods.latched &&
          xievent.pointee.mods.locked == nextXievent.pointee.mods.locked &&
          xievent.pointee.mods.effective == nextXievent.pointee.mods.effective {
        XFreeEventData(display, &nextEvent.xcookie)
        // Free the previous cookie.
        if numCoalesced > 0 {
          XFreeEventData(display, &lastEvent.xcookie)
        }
        // Get the event and its cookie data.
        XNextEvent(display, &lastEvent)
        XGetEventData(display, &lastEvent.xcookie)
        numCoalesced = numCoalesced + 1
        continue
      }
    }
    // This isn't an event we want so free its cookie data.
    XFreeEventData(display, &nextEvent.xcookie)
    break
  }

  if eventType == XI_Motion && numCoalesced > 0 {
    //base::TimeDelta delta = ui::EventTimeFromNative(last_event) -
    //    ui::EventTimeFromNative(const_cast<XEvent*>(xev));
    //UMA_HISTOGRAM_OUNTS_10000("Event.CoalescedCount.Mouse", num_coalesced);
    //UMA_HISTOGRAM_TIMES("Event.CoalescedLatency.Mouse", delta);
  }
  return numCoalesced
}

public func getCurrentDesktop(desktop: inout Int) -> Bool {
  let display = X11Environment.XDisplay
  return getIntProperty(window: XDefaultRootWindow(display), propertyName: "_NET_URRENT_DESKTOP", value: &desktop)
}

// This data structure represents additional hints that we send to the window
// manager and has a direct lineage back to Motif, which defined this de facto
// standard. This struct doesn't seem 64-bit safe though, but it's what GDK
// does.
//  class MotifWmHints {
//     var flags: UInt64 // was unsigned long
//     var functions: UInt64 // was unsigned long
//     var decorations: UInt64 // was unsigned long
//     var input_mode: Int64 // was long
//     var status: UInt64 // was unsigned long
//
//     init(windowFrame: Bool) {
//       flags = (1 << 1)
//       functions = 0
//       decorations = windowFrame ? 1 : 0
//       input_mode = 0
//       status = 0
//     }
// }

public func setUseOSWindowFrame(window: XID, useOSWindowFrame: Bool) {

  // let motifHints = MotifWmHints(windowFrame: useOSWindowFrame)
  //
  // //print("decorations: \(motifHints.decorations)")
  //
  // let hintAtom = getAtom("_MOTIF_WM_HINTS")
  // let display = X11Environment.XDisplay
  // XChangeProperty(display,
  //                 window,
  //                 hintAtom,
  //                 hintAtom,
  //                 32,
  //                 PropModeReplace,
  //                 UnsafePointer<UInt8>(unsafeAddress(of: motifHints)),
  //                 //unsafeAddress(of: motifHints),
  //                 //&motifHints,
  //                 //Int32(sizeof(MotifWmHints)/sizeof(Int)
  //                 Int32(sizeof(MotifWmHints)/sizeof(Int64)))

  // unfortunately the code above doesnt work as expected,
  // so had to fallback to the native shim
  let display = X11Environment.XDisplay
  _X11_SetUseNativeFrame(display, window, useOSWindowFrame ? 1 : 0)
}

// public func supportsEWMH() -> Bool {
//   var supportsEwmh = false

//   var wmWindow = XID(None)
//   let display = X11Environment.XDisplay
//   if !getXIDProperty(window: XDefaultRootWindow(display),
//                      propertyName: "_NET_SUPPORTING_WM_HECK",
//                      value: &wmWindow) {
//     supportsEwmh = false
//     return false
//   }

//   // It's possible that a window manager started earlier in this X session
//   // left a stale _NET_SUPPORTING_WM_HECK property when it was replaced by a
//   // non-EWMH window manager, so we trap errors in the following requests to
//   // avoid crashes (issue 23860).

//   // EWMH requires the supporting-WM window to also have a
//   // _NET_SUPPORTING_WM_HECK property pointing to itself (to avoid a stale
//   // property referencing an ID that's been recycled for another window), so
//   // we check that too.
//   let errTracker = X11ErrorTracker()
//   var wmWindowProperty = 0
//   let result = getIntProperty(
//       window: wmWindow, propertyName:  "_NET_SUPPORTING_WM_HECK", value: &wmWindowProperty)

//   supportsEwmh = !errTracker.foundNewError() &&
//     result && UInt(wmWindowProperty) == wmWindow

//   return supportsEwmh
// }

// TODO: cache if theres a need
// public func supportsEWMH() -> Bool {
//   return true 
// }

public func supportsEWMH() -> Bool {
  var supportsEwmh = false
  
  var wmWindow: XID = XID(None)
  let display = X11Environment.XDisplay
  if !getXIDProperty(window: XDefaultRootWindow(display),
                    propertyName: "_NET_SUPPORTING_WM_HECK",
                    value: &wmWindow) {
    //print("supportsEWMH: failed to get property with getXIDProperty. returning false")
    supportsEwmh = false
    return false
  }

  // It's possible that a window manager started earlier in this X session
  // left a stale _NET_SUPPORTING_WM_HECK property when it was replaced by a
  // non-EWMH window manager, so we trap errors in the following requests to
  // avoid crashes (issue 23860).

  // EWMH requires the supporting-WM window to also have a
  // _NET_SUPPORTING_WM_HECK property pointing to itself (to avoid a stale
  // property referencing an ID that's been recycled for another window), so
  // we check that too.
  let errTracker = X11ErrorTracker()
  var wmWindowProperty: Int = 0
  let result = getIntProperty(
      window: wmWindow, propertyName: "_NET_SUPPORTING_WM_HECK", value: &wmWindowProperty)
  supportsEwmh = !errTracker.foundNewError() &&
                  result &&
                  UInt(wmWindowProperty) == wmWindow
  
  return supportsEwmh
}

public func _XISetMask(mask: inout [UInt8], _ event: Int32) {
  let index = Int(event >> 3)
  mask[index] = mask[index] | (1 << (UInt8(event) & 7))
}
