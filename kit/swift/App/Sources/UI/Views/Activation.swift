// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol ActivationDelegate {
  var shouldActivate: Bool { get }
}

public enum ActivationReason {
  case ActivationClient
  case InputEvent
  case WindowDispositionChanged
}

public protocol ActivationChangeObserver {

  func onWindowActivated(reason: ActivationReason,
                         gainedActive: Window,
                         lostActive: Window)

  func onAttemptToReactivateWindow(requestActive: Window,
                                   actualActive: Window)

}


public protocol ActivationClient {
  var activeWindow: Window? { get }
  func addObserver(observer: ActivationChangeObserver)
  func removeObserver(observer: ActivationChangeObserver)
  func activateWindow(window: Window)
  func deactivateWindow(window: Window)
  func getActivatableWindow(window: Window) -> Window?
  func getToplevelWindow(window: Window) -> Window?
  func canActivateWindow(window: Window) -> Bool
}
