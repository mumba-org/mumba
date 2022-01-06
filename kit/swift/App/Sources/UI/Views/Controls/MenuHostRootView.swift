// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public final class MenuHostRootView : RootView {

  public private(set) var submenu: SubmenuView?

  fileprivate var menuController: MenuController? {
    if let menuItemController = submenu?.menuItem?.controller {
      return menuItemController
    }
    return nil
  }

  fileprivate var menuControllerForInputEvents: MenuController? {
    if let controller = menuController {
      if controller.canProcessInputEvents {
        return controller
      }
    }
    return nil
  }
  
  public init(widget: UIWidget, submenu: SubmenuView?) {
    self.submenu = submenu
    super.init(widget: widget)
  }

  public func clearSubmenu() {
    submenu = nil 
  }

  // View
  public override func onMousePressed(event: MouseEvent) -> Bool {
    if let controller = menuControllerForInputEvents, let menu = submenu {
      var mouseEvent = event
      return controller.onMousePressed(source: menu, event: &mouseEvent)
    }
    return false
  }

  public override func onMouseDragged(event: MouseEvent) -> Bool {
     if let controller = menuControllerForInputEvents, let menu = submenu {
       return controller.onMouseDragged(source: menu, event: event)
     }
     return false
  }

  public override func onMouseReleased(event: MouseEvent) {
     if let controller = menuControllerForInputEvents, let menu = submenu {
      controller.onMouseReleased(source: menu, event: event)
     }
  }

  public override func onMouseMoved(event: MouseEvent) {
     if let controller = menuControllerForInputEvents, let menu = submenu {
       controller.onMouseMoved(source: menu, event: event)
     }
  }
  
  public override func onMouseWheel(event: MouseWheelEvent) -> Bool {
     if let controller = menuControllerForInputEvents, let menu = submenu {
       return controller.onMouseWheel(source: menu, event: event)
     }
     return false
  }
  
  public override func getTooltipHandlerFor(point: IntPoint) -> View? {
    if let controller = menuControllerForInputEvents, let menu = submenu {
      return controller.getTooltipHandlerForPoint(source: menu, point: point)
    }
    return nil
  }

  public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if let controller = menuControllerForInputEvents, let menu = submenu {
      controller.viewHierarchyChanged(source: menu, details: details)
    }
    super.viewHierarchyChanged(details: details)
  }

  public override func processMousePressed(event: MouseEvent) -> Bool {
    return super.onMousePressed(event: event)
  }
  
  public override func processMouseDragged(event: MouseEvent) -> Bool {
    return super.onMouseDragged(event: event)
  }
  
  public override func processMouseReleased(event: MouseEvent) {
    super.onMouseReleased(event: event)
  }
  
  public func processMouseMoved(event: MouseEvent) {
    super.onMouseMoved(event: event)
  }
  
  public func processGetTooltipHandlerFor(point: IntPoint) -> View? {
    return super.getTooltipHandlerFor(point: point)
  }

  // EventProcessor
  public override func onEventProcessingFinished(event: Event) {
    super.onEventProcessingFinished(event: event)
  
    if let controller = menuController, let menu = submenu {
      if event.isGestureEvent && !event.handled {
        var gestureEvent = event as! GestureEvent
        controller.onGestureEvent(source: menu, event: &gestureEvent)
      }
    }
  }

}