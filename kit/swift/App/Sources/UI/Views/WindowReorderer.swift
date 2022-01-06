// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class WindowReorderer {

  private var window: Window
  private var rootView: View

  public init(window: Window, rootView: View) {
    self.window = window
    self.rootView = rootView
  }

  public func reorderChildWindows() {
    
  }


}

extension WindowReorderer : WindowObserver {
  public func onWindowAdded(window: Window) {}
  public func onWillRemoveWindow(window: Window) {}
  public func onWindowDestroying(window: Window) {}
}
