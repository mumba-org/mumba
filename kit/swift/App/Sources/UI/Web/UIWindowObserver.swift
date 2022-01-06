// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Web

public protocol UIWindowObserver : class {
  func willCommitProvisionalLoad(widget: UIWindow)
  func didCommitProvisionalLoad(widget: UIWindow)
  func didStartProvisionalLoad(widget: UIWindow)
  func didFinishLoad(widget: UIWindow)
  func didClearWindowObject(widget: UIWindow)
  func setFocus(enable: Bool)
  func didChangeVisibleViewport()
  func updateCaptureSequenceNumber(captureSequenceNumber: UInt32)
  func onScreenInfoChanged(screenInfo: ScreenInfo)
  func didUpdateLayout()
  func windowWillClose()
  func willHandleMouseEvent()
  func wasHidden()
  func wasShown()
  func didCommitAndDrawCompositorFrame()
  func networkStateChanged(online: Bool)
}