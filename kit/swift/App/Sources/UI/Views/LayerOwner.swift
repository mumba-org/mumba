// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol LayerOwnerDelegate {
  func onLayerRecreated(oldLayer: Layer, newLayer: Layer)
}

public protocol LayerOwner {
  var layer: Layer? { get set }
  var ownsLayer: Bool { get }
  var ownerDelegate: LayerOwnerDelegate? { get set }
  func acquireLayer() -> Layer?
  func recreateLayer() -> Layer?
  func destroyLayer()
}
