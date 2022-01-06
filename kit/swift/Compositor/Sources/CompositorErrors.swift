// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct CompositorException {
  public let code: Int
  public let message: String

  public static let ClientMissing = CompositorException(code: 100, message: "Compositor: LayerTreeHostClient missing")
  public static let AnimationHostMissing = CompositorException(code: 101, message: "Compositor: AnimationHost missing")
  public static let NativeLayerTreeHost = CompositorException(code: 102, message: "Compositor: LayerTreeHost creation failed")
  public static let NativeLayer = CompositorException(code: 103, message: "Compositor: Layer creation failed")

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}

public enum CompositorError : Error {
  case OnCreateLayerTreeHost(exception: CompositorException)
  case OnCreateLayer(exception: CompositorException)
}
