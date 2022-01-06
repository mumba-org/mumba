// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct GpuException {
  public let code: Int
  public let message: String

  public static let CreateGLInProcessContext = GpuException(code: 100, message: "Gpu: error creating LayerTreeHost")

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}

public enum GpuError : Error {
  case OnCreate(exception: GpuException)
}
