// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class MessageChannel {

  public var port1: MessagePort {
    if _port1 == nil {
      _port1 = MessagePort(reference: MessageChannelGetPort1(reference)!, window: window)
    }
    return _port1!
  }

  public var port2: MessagePort {
    if _port2 == nil {
      _port2 = MessagePort(reference: MessageChannelGetPort2(reference)!, window: window)
    }
    return _port2!
  }

  var reference: MessageChannelRef
  private var window: WebWindow
  private var _port1: MessagePort?
  private var _port2: MessagePort?

  // FIXME: use a generic 'ExecutionContext' instead of WebWindow
  //        as internally its used to get the current context
  //
  //        Its ok if on UI thread but once in a service worker for instance
  //        theres no direct access to window and the V8 context actually is the one
  //        from the service worker
  public init(window: WebWindow) {
    reference = MessageChannelCreate(window.reference)
    self.window = window
  }

  init(reference: MessageChannelRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  deinit {
    MessageChannelDestroy(reference)
  }

}
