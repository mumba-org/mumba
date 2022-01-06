// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public typealias LayerChangeCallback = (_: IntRect) -> Void

public protocol LayerDelegate : class {
  func onPaintLayer(context: PaintContext)
  func onDeviceScaleFactorChanged(oldScaleFactor: Float, newScaleFactor: Float)
  func onLayerBoundsChanged(oldBounds: IntRect, reason: PropertyChangeReason)
  func onLayerTransformed(oldTransform: Transform, reason: PropertyChangeReason)
  func onLayerOpacityChanged(reason: PropertyChangeReason)
}

extension LayerDelegate {
  public func onPaintLayer(context: PaintContext) {}
  public func onDeviceScaleFactorChanged(oldScaleFactor: Float, newScaleFactor: Float) {}
  public func onLayerBoundsChanged(oldBounds: IntRect, reason: PropertyChangeReason) {}
  public func onLayerTransformed(oldTransform: Transform, reason: PropertyChangeReason) {}
  public func onLayerOpacityChanged(reason: PropertyChangeReason) {}
}