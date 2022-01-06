// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform

public protocol WindowDelegate : EventHandler {

  var minimumSize: IntSize { get }
  var maximumSize: IntSize { get }
  var hasHitTestMask: Bool { get }
  var canFocus: Bool { get }

  func getCursor(at point: IntPoint) -> PlatformCursor
  func getHitTestMask(mask: inout Path)
  func onBoundsChanged(oldBounds: IntRect, newBounds: IntRect)
  func getNonClientComponent(point: IntPoint) -> HitTest
  // for 'NativeWindow' UIWidget (who owns) -> (Native)Window
  func shouldDescendIntoChildForEventHandling(
    rootLayer: Layer, child: Window, childLayer: Layer, location: IntPoint) -> Bool
  // meant for soft 'Window' owners (not UIWidget)
  func shouldDescendIntoChildForEventHandling(
    child: Window, location: IntPoint) -> Bool  
  func onCaptureLost()
  func onPaint(context: PaintContext)
  func onDeviceScaleFactorChanged(deviceScaleFactor: Float)
  func onWindowDestroying(window: Window)
  func onWindowDestroyed(window: Window)
  func onWindowTargetVisibilityChanged(visible: Bool)
}


extension WindowDelegate {
  
  public func shouldDescendIntoChildForEventHandling(
    child: Window, location: IntPoint) -> Bool {
    return true
  }
}
