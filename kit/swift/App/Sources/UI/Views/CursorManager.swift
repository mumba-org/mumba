// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform

public class CursorManager {

  var delegate: PlatformCursorManager

  public init(delegate: PlatformCursorManager) {
    self.delegate = delegate
  }
}

extension CursorManager : CursorClient {

  public var cursor: PlatformCursor { get { return PlatformCursorNil } set {} }
  public var cursorSet: CursorSetType { get { return 0 } set {} }
  public var cursorVisible: Bool { return false }
  public var cursorLocked: Bool { return false }
  public var mouseEventsEnabled: Bool { return false }

  public func showCursor() {}
  public func hideCursor() {}
  public func enableMouseEvents() {}
  public func disableMouseEvents() {}
  public func setDisplay(display: Display) {}
  public func lockCursor() {}
  public func unlockCursor() {}
  public func addObserver(observer: CursorClientObserver) {}
  public func removeObserver(observer: CursorClientObserver) {}
  public func shouldHideCursorOnKeyEvent(event: KeyEvent) -> Bool { return false }
}

extension CursorManager : PlatformCursorManagerDelegate {}
