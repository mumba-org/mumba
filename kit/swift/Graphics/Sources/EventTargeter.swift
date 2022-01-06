// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol EventTargeter {
  func findTargetForEvent(root: EventTarget, event: Event) -> EventTarget?
  func findNextBestTarget(previousTarget: EventTarget, event: Event) -> EventTarget?
}
