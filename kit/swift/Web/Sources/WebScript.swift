// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Javascript

public enum WebScriptExecutionType : Int {
  case Synchronous = 0
  // Execute script asynchronously.
  case Asynchronous = 1
  // Execute script asynchronously, blocking the window.onload event.
  case AsynchronousBlockingOnload = 2
}

public protocol WebScriptExecutionCallback {
  func completed(values: [JavascriptData])
}