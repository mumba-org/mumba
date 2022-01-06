// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class MenuHost : UIWidget {

  public var isMenuHostVisible: Bool {
    return isVisible
  }

  public var menuHostBounds: IntRect {
    get {
      return bounds
    }
    set {
      bounds = newValue
    }
  }

  public private(set) override var rootView: RootView! {
    get {
      // why a new instance everytime?
      return MenuHostRootView(widget: self, submenu: submenu)
    } 
    set {

    }
  }

  // Parent of the MenuHost widget.
  weak var ownerWidget: UIWidget?

  // The view we contain.
  var submenu: SubmenuView

  // If true, DestroyMenuHost has been invoked.
  var destroying: Bool

  // If true and capture is lost we don't notify the delegate.
  var ignoreCaptureLost: Bool

//#if !os(macOS)
  // Handles raw touch events at the moment.
  var preDispatchHandler: PreMenuEventDispatchHandler?
//#endif
 
  public init(submenu: SubmenuView) {
    self.submenu = submenu
    self.destroying = false
    ignoreCaptureLost = false
    super.init()
     autoReleaseCapture = false
  }

  deinit {
    if let owner = ownerWidget {
      owner.removeObserver(self)
    }
  }

  public func initMenuHost(compositor: UIWebWindowCompositor,
                           parent: UIWidget?,
                           bounds: IntRect,
                           contentsView: View,
                           doCapture: Bool) {
    var params = UIWidget.InitParams()
    params.type = WindowType.Menu
    let menuController = submenu.menuItem!.controller
    let menuConfig = MenuConfig.instance()
    let roundedBorder: Bool = menuController != nil && (menuController!.useTouchableLayout ||
                              (menuConfig.cornerRadius > 0))
    
    let bubbleBorder = submenu.scrollViewContainer.hasBubbleBorder

    params.shadowType = bubbleBorder ? UIWidget.ShadowType.None
                                     : UIWidget.ShadowType.Drop
    params.opacity = (bubbleBorder || roundedBorder) ?
        WindowOpacity.Translucent :
        WindowOpacity.Opaque
    params.parent = parent != nil ? parent!.window : nil
    params.bounds = bounds
  #if os(Windows)
    // On Windows use the software compositor to ensure that we don't block
    // the UI thread blocking issue during command buffer creation. We can
    // revert this change once http://crbug.com/125248 is fixed.
    params.forceSoftwareCompositing = true
  #endif
    try! initialize(compositor: compositor, params: params)

  //#if !defined(OS_MACOSX)
    preDispatchHandler = PreMenuEventDispatchHandler(
        controller: menuController!, submenu: submenu, window: window)
  //#endif

    //DCHECK(!owner_);
    ownerWidget = parent
    if let owner = ownerWidget {
      owner.addObserver(self)
    }

    self.contentsView = contentsView
    showMenuHost(doCapture: doCapture)
  }
  
  public func showMenuHost(doCapture: Bool) {
    //base::AutoReset<bool> reseter(&ignore_capture_lost_, true)
    let ignoreCaptureLostCached = ignoreCaptureLost
    ignoreCaptureLost = true

    showInactive()
    if doCapture {
      if let menuController = submenu.menuItem?.controller, let owner = ownerWidget {
        if menuController.sendGestureEventsToOwner {
          // TransferGesture when owner needs gesture events so that the incoming
          // touch events after MenuHost is created are properly translated into
          // gesture events instead of being dropped.
          transferGesture(source: owner, target: self)
        }
      } else {
        GestureRecognizer.instance().cancelActiveTouchesExcept(notCancelled: nil)
      }
  //#if defined(MACOSX)
      // Cancel existing touches, so we don't miss some touch release/cancel
      // events due to the menu taking capture.
      //destureRecognizer.instance.cancelActiveTouchesExcept(nil)
  //#endif  // defined (OS_MACOSX)
      nativeWidget!.setCapture()
    }

    ignoreCaptureLost = ignoreCaptureLostCached
  }

  public func hideMenuHost() {
    if let menuController = submenu.menuItem?.controller, let owner = ownerWidget {
      if menuController.sendGestureEventsToOwner {
        transferGesture(source: self, target: owner)
      }
    }
    ignoreCaptureLost = true
    releaseMenuHostCapture()
    hide()
    ignoreCaptureLost = false
  }

  public func destroyMenuHost() {
    hideMenuHost()
    destroying = true
    let menuHostRootView = rootView as! MenuHostRootView
    menuHostRootView.clearSubmenu()
 // #if !defined(OS_MACOSX)
    preDispatchHandler = nil
//  #endif
    close()
  }

  public func releaseMenuHostCapture() {
    if nativeWidget!.hasCapture {
      nativeWidget!.releaseCapture()
    }
  }

  public override func onDragWillStart() {
    if let menuController = submenu.menuItem?.controller {
      menuController.onDragWillStart()
    }
  }

  public override func onDragComplete() {
    // If we are being destroyed there is no guarantee that the menu items are
    // available.
    if destroying {
      return
    }

    guard let menuController = submenu.menuItem?.controller else {
      return
    }


    var shouldClose = true
    // If the view came from outside menu code (i.e., not a MenuItemView), we
    // should consult the MenuDelegate to determine whether or not to close on
    // exit.
    if !menuController.didInitiateDrag {
      if let menuDelegate = submenu.menuItem?.delegate {
        shouldClose = menuDelegate.shouldCloseOnDragComplete
      }
    }

    menuController.onDragComplete(shouldClose: shouldClose)

    // We may have lost capture in the drag and drop, but are remaining open.
    // Return capture so we get MouseCaptureLost events.
    if !shouldClose {
      nativeWidget!.setCapture()
    }
  }

  public override func onNativeWidgetDestroyed() {
    if !destroying {
      // We weren't explicitly told to destroy ourselves, which means the menu was
      // deleted out from under us (the window we're parented to was closed). Tell
      // the SubmenuView to drop references to us.
      submenu.menuHostDestroyed()
    }
    super.onNativeWidgetDestroyed()
  }

  public override func onMouseCaptureLost() {
    if destroying || ignoreCaptureLost {
      return
    }

    if let menuController = submenu.menuItem?.controller {
      if !menuController.dragInProgress {
        menuController.cancelAll()
      }
    }
    super.onMouseCaptureLost()
  }

  public override func onOwnerClosing() {
    if destroying {
      return
    }

    if let menuController = submenu.menuItem?.controller {
      if !menuController.dragInProgress {
        menuController.cancelAll()
      }
    }
  }

}

extension MenuHost : UIWidgetObserver {
  
  public func onWidgetDestroying(widget: UIWidget) {
    if let owner = ownerWidget {
      owner.removeObserver(self)
      ownerWidget = nil
    }
  }

}

internal class PreMenuEventDispatchHandler : EventHandler, WindowObserver {

  var menuController: MenuController
  var submenu: SubmenuView
  var window: Window?

  public init(controller: MenuController,
              submenu: SubmenuView,
              window: Window?) {

    self.menuController = controller
    self.submenu = submenu
    self.window = window
    if let w = self.window {
      w.addPreTargetHandler(handler: self)
      w.addObserver(observer: self)
    }
  }

  deinit {
    stopObserving()
  }

  public func onTouchEvent(event: inout TouchEvent) {
    menuController.onTouchEvent(source: submenu, event: event)
  }

  // WindowObserver
  public func onWindowDestroying(window: Window) {
    stopObserving()
  }

  fileprivate func stopObserving() {
    guard let w = window else {
      return
    }

    w.removePreTargetHandler(handler: self)
    w.removeObserver(observer: self)

    window = nil
  }
}

internal func transferGesture(source: UIWidget, target: UIWidget) {
#if os(macOS)
  assert(false)
#else
  GestureRecognizer.instance().transferEventsTo(
      currentConsumer: source.window, newConsumer: target.window, shouldCancelTouches: GestureRecognizer.ShouldCancelTouches.dontCancel)
     // currentConsumer: source.nativeView, newConsumer: target.nativeView, shouldCancelTouches: GestureRecognizer.shouldCancelTouches.dontCancel)
#endif
}