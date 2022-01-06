// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol Platform : class {
  func initialize() throws
  func createWindow(delegate: PlatformWindowDelegate, bounds: IntRect) throws -> PlatformWindow
}