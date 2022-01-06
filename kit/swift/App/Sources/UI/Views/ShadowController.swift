// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class ShadowController {

  private var activationClient: ActivationClient?

  public init(activationClient: ActivationClient?) {
    self.activationClient = activationClient
  }

}

extension ShadowController : ActivationChangeObserver {

  public func onWindowActivated(reason: ActivationReason,
                         gainedActive: Window,
                         lostActive: Window) {}

  public func onAttemptToReactivateWindow(requestActive: Window,
                                   actualActive: Window) {}

}
