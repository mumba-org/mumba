// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class MenuPreTargetHandler : ActivationChangeObserver,
                                    WindowObserver,
                                    EventHandler {
  // this guy own us
  weak var controller: MenuController?
  var root: Window?
  
  public init(controller: MenuController, owner: UIWidget?) {
    self.controller = controller
    if let window = owner?.window {
      root = window.rootWindow
    }

    UI.addPreTargetHandler(handler: self)//, EventTarget.Priority.System)

    if let r = root {
      if let client = UI.getActivationClient(window: r) {
        client.addObserver(observer: self)
      }
      r.addObserver(observer: self)
    }
  }

  deinit {
    UI.removePreTargetHandler(handler: self)
    cleanup()
  }

  // ActivationChangeObserver
  public func onWindowActivated(
      reason: ActivationReason,
      gainedActive: Window,
      lostActive: Window) {

    if !controller!.dragInProgress {
      controller!.cancelAll()
    }

  }

  public func onAttemptToReactivateWindow(requestActive: Window, actualActive: Window) {}

  // WindowObserver
  public func onWindowDestroying(window: Window) {
    cleanup()
  }

  // EventHandler
  public func onCancelMode(event: CancelModeEvent) {
    controller!.cancelAll()
  }
  
  public func onKeyEvent(event: KeyEvent) {
    let _ = controller!.onWillDispatchKeyEvent(event: event)
  }

  func cleanup() {
    guard let r = root else {
      return
    }
    
    if let client = UI.getActivationClient(window: r) {
      client.removeObserver(observer: self)
    }
    
    r.removeObserver(observer: self)
    root = nil
  }

}