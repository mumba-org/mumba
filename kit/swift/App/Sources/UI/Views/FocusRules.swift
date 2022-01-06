// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol FocusRules {

 func isToplevelWindow(window: Window) -> Bool
 func canActivateWindow(window: Window) -> Bool
 func canFocusWindow(window: Window) -> Bool
 func getToplevelWindow(window: Window) -> Window?
 func getActivatableWindow(window: Window) -> Window?
 func getFocusableWindow(window: Window) -> Window?
 func getNextActivatableWindow(ignore: Window) -> Window?

}
