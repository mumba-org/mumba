// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Web

public protocol MouseLockDispatcherLockTarget {
  func onLockMouseAck(succeeded: Bool)
  func onMouseLockLost()
  func handleMouseLockedInputEvent(event: WebMouseEvent) -> Bool
}

public protocol MouseLockDispatcher {
  func lockMouse(target: MouseLockDispatcherLockTarget) -> Bool
  func unlockMouse(target: MouseLockDispatcherLockTarget) -> Bool
  func onLockTargetDestroyed(target: MouseLockDispatcherLockTarget)
  func clearLockTarget()
  func isMouseLockedTo(target: MouseLockDispatcherLockTarget) -> Bool
  func willHandleMouseEvent(event: WebMouseEvent) -> Bool
  func onLockMouseACK(succeeded: Bool)
  func onMouseLockLost()
  func sendLockMouseRequest()
  func sendUnlockMouseRequest()
}

public class LameMouseLockTarget : MouseLockDispatcherLockTarget {
  
  public init() {}

  public func onLockMouseAck(succeeded: Bool) {

  }
  
  public func onMouseLockLost(){

  }
  
  public func handleMouseLockedInputEvent(event: WebMouseEvent) -> Bool {
    return false
  }
}