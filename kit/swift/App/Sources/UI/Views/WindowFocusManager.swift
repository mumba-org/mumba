// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class WindowFocusManager {

  public static var instance: WindowFocusManager {
    if WindowFocusManager._instance == nil {
      WindowFocusManager._instance = WindowFocusManager()
    }

    return WindowFocusManager._instance!
  }

  private static var _instance: WindowFocusManager?

  public init() {}

  public func onWindowFocusChanged(window: Window?) {

  }

}
