// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class TransientWindowController {

  public init() {}

}

extension TransientWindowController : TransientWindowClient {

  public func addTransientChild(parent: Window, child: Window) {
    
  }

  public func removeTransientChild(parent: Window, child: Window) {

  }

  public func getTransientParent(window: Window) -> Window? {
    return nil
  }

}
