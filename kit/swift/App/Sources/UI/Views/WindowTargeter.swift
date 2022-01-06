// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

// should be a "abstract" class.. not concrete
public class WindowTargeter : EventTargeter {

  init() {}

  public func findTargetForEvent(root: EventTarget, event: Event) -> EventTarget? {
    return nil
  }

  public func findNextBestTarget(previousTarget: EventTarget, event: Event) -> EventTarget? {
    return nil
  }

  public func subtreeShouldBeExploredForEvent(window: Window, event: LocatedEvent) -> Bool {
    return false
  }

  internal func findTargetForLocatedEvent(window: Window, event: LocatedEvent) -> Window? {
    return nil
  }

  internal func subtreeCanAcceptEvent(window: Window, event: LocatedEvent) -> Bool {
    return false
  }

  internal func eventLocationInsideBounds(target: Window, event: LocatedEvent) -> Bool {
    return false
  }

  internal func findTargetForKeyEvent(rootWindow: Window, event: KeyEvent) -> Window? {
    return nil
  }

  internal func findTargetForNonKeyEvent(rootWindow: Window, event: Event) -> Window? {
    return nil
  }

  internal func findTargetInRootWindow(rootWindow: Window, event: LocatedEvent) -> Window? {
    return nil
  }

  internal func findTargetForLocatedEventRecursively(rootWindow: Window, event: LocatedEvent) -> Window? {
    return nil
  }

}
