// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol GLImage {

  var size: IntSize { get }
  var internalFormat: UInt { get }

  func destroy()
  func bindTexImage(target: UInt) -> Bool
  func releaseTexImage(target: UInt)
  func copyTexImage(target: UInt) -> Bool
  func copyTexSubImage(target: UInt,
                       offset: IntPoint,
                       rect: IntRect) -> Bool
  func scheduleOverlayPlane(widget: AcceleratedWidget,
                            zOrder: Int,
                            transform: OverlayTransform,
                            boundsRect: IntRect,
                            cropRect: FloatRect,
                            enableBlend: Bool) -> Bool
}
