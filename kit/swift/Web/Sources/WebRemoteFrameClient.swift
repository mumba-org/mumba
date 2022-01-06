// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor
import Javascript

public protocol WebRemoteFrameClient : WebFrameClient {
  func checkCompleted()
  func forwardPostMessage(sourceFrame: WebLocalFrame?,
                          targetFrame: WebRemoteFrame?,
                          targetOrigin: WebSecurityOrigin,
                          event: WebDOMMessageEvent,
                          hasUserGesture: Bool)
  func navigate(request: WebURLRequest, shouldReplaceCurrentEntry: Bool)
  func reload(loadType: WebFrameLoadType, redirect: ClientRedirectPolicy)
  func frameRectsChanged(localFrame: IntRect, screenSpace: IntRect)
  func updateRemoteViewportIntersection(viewportIntersection: IntRect)
  func visibilityChanged(visible: Bool)
  func setIsInert(_: Bool)
  func updateRenderThrottlingStatus(isThrottled: Bool,
                                    subtreeThrottled: Bool)
  func advanceFocus(type: WebFocusType, source: WebLocalFrame)
}