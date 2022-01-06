// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol GLContext {
  var reference: UnsafeMutableRawPointer { get }

  func initialize(surface: GLSurface, gpuPreference: GpuPreference) -> Bool
  func makeCurrent(surface: GLSurface) -> Bool
  func releaseCurrent(surface: GLSurface)
  func isCurrent(surface: GLSurface) -> Bool
}
