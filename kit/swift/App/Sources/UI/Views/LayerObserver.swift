// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol LayerObserver : class {
  func layerDestroyed(layer: Layer)
}

extension LayerObserver {
  public func layerDestroyed(layer: Layer) {}
}