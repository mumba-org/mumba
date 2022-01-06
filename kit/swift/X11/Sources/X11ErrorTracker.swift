// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

func X11ErrorHandler(display: XDisplayHandle?, error: UnsafeMutablePointer<XErrorEvent>?) -> Int32 {
  X11ErrorTracker.errorCode = error!.pointee.error_code
  return 0
}

public class X11ErrorTracker {
  static var errorCode: UInt8 = 0
  var oldHandler: XErrorHandler
  
  public init() {
    XSync(X11Environment.XDisplay, False);
    oldHandler = XSetErrorHandler(X11ErrorHandler)
    X11ErrorTracker.errorCode = 0
  }
  
  deinit {
    XSetErrorHandler(oldHandler)
  }
  
  public func foundNewError() -> Bool {
    XSync(X11Environment.XDisplay, False)
    let error = X11ErrorTracker.errorCode
    X11ErrorTracker.errorCode = 0
    return error != 0
  }
  
}