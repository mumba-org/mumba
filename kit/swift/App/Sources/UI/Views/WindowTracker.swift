// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class WindowTracker : WindowObserver {

  public var windows: [Window] {
    return _windows
  }

  public init() {
    _windows = [Window]()
  }

  public func add(window: Window) {

  }

  public func remove(window: Window) {

  }

  public func contains(window: Window) -> Bool {
    return false
  }

  // WindowObserver
  public func onWindowDestroying(window: Window) {

  }

  private var _windows: [Window]
}
