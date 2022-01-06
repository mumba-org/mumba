// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class XMenuList {
  
  public static let instance: XMenuList = XMenuList()

  var menus: [XID]
  
  var menuTypeAtom: Atom

  public init() {
     menuTypeAtom = XInternAtom(X11Environment.XDisplay, "_NET_WM_WINDOW_TYPE_MENU", False)
     menus = [XID]()
  }

  // Checks if |menu| has _NET_WM_WINDOW_TYPE property set to
  // "_NET_WM_WINDOW_TYPE_MENU" atom and if so caches it.
  public func maybeRegisterMenu(menu: XID) {
    var value = 0;
    if !getIntProperty(window: menu, propertyName: "_NET_WM_WINDOW_TYPE", value: &value) ||
      Atom(value) != menuTypeAtom {
      return
    }
    menus.append(menu)
  }

  // Finds |menu| in cache and if found removes it.
  public func maybeUnregisterMenu(menu: XID) {
    for (index, item) in menus.enumerated() {
      if menu == item {
        menus.remove(at: index)
      }
    }
  }

  // Inserts cached menu XIDs at the beginning of |stack|.
  public func insertMenuWindowXIDs(stack: inout [XID]) {
    stack.append(contentsOf: menus)
  }

}