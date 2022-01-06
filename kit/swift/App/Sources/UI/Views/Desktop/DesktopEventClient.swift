// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class DesktopEventClient {
  public init() {}
}

extension DesktopEventClient : EventClient {
  public var toplevelEventTarget: EventTarget? { return nil }
  public func canProcessEventsWithinSubtree(window: Window) -> Bool { return false }
}
