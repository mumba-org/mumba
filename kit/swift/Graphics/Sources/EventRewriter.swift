// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum EventRewriteStatus {
  case Continue
  case Rewritten
  case Discard
  case Another
}

// EventRewriter provides a mechanism for Events to be rewritten
// before being dispatched from EventSource to EventProcessor.
public protocol EventRewriter {
  func rewriteEvent(event: Event, rewrittenEvent: Event) -> EventRewriteStatus
  func nextDispatchEvent(lastEvent: Event, newEvent: Event) -> EventRewriteStatus
}
