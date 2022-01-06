// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol EventProcessor : EventDispatcherDelegate {
  var rootTarget: EventTarget? { get }
  func onEventFromSource(event: Event) -> EventDispatchDetails
  func onEventProcessingStarted(event: Event)
  func onEventProcessingFinished(event: Event)
  func sendEventToProcessor(event: Event) -> EventDispatchDetails
}
