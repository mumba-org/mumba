// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import GL

public protocol GLES2Interface {
  func insertSyncPointCHROMIUM() -> GLuint
  func getGraphicsResetStatusKHR() -> GLenum
  func traceBeginCHROMIUM(categoryName: String,
                          traceName: String)
}
