// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Web

public protocol UIWindowMouseLockDispatcherDelegate : class {

}

public class UIWindowMouseLockDispatcher : MouseLockDispatcher {
  
  private weak var delegate: UIWindowMouseLockDispatcherDelegate!
  
  public init(delegate: UIWindowMouseLockDispatcherDelegate) {
    self.delegate = delegate
  }

  public func willHandleMouseEvent(event: WebMouseEvent) -> Bool {
    return false
  }

  public func lockMouse(target: MouseLockDispatcherLockTarget) -> Bool {
    return false
  }

  public func unlockMouse(target: MouseLockDispatcherLockTarget) -> Bool {
    return false
  }

  public func onLockTargetDestroyed(target: MouseLockDispatcherLockTarget) {
    
  }
  
  public func clearLockTarget() {

  }
  
  public func isMouseLockedTo(target: MouseLockDispatcherLockTarget) -> Bool {
    return false
  }
  
  public func onLockMouseACK(succeeded: Bool) {

  }
  
  public func onMouseLockLost() {

  }
  
  public func sendLockMouseRequest() {

  }
  
  public func sendUnlockMouseRequest() {

  }

}