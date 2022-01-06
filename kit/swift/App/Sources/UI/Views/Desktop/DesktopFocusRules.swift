// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class DesktopFocusRules {

  private var contentWindow: Window

  public init(contentWindow: Window) {
    self.contentWindow = contentWindow
  }
}

extension DesktopFocusRules : FocusRules {

  public func isToplevelWindow(window: Window) -> Bool {
    return false
  }

  public func canActivateWindow(window: Window) -> Bool {
    return false
  }

  public func canFocusWindow(window: Window) -> Bool {
    return false
  }

  public func getToplevelWindow(window: Window) -> Window? {
    return nil
  }

  public func getActivatableWindow(window: Window) -> Window? {
    return nil
  }

  public func getFocusableWindow(window: Window) -> Window? {
    return nil
  }

  public func getNextActivatableWindow(ignore: Window) -> Window? {
    return nil
  }

}
