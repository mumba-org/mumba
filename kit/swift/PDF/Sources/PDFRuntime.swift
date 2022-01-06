// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import _C

public class PDFRuntime {
  
  public static func initialize() {
    _C.pdfRuntimeInit()
  }

  public static func shutdown() {
    _C.pdfRuntimeShutdown()
  }

}