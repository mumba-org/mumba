// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class DesktopCaptureClient {
  public init(root: Window) {}
}

extension DesktopCaptureClient : CaptureClient {
  public var captureWindow: Window? { return nil }
  public var globalCaptureWindow: Window? { return nil }
  public func setCapture(window: Window) {}
  public func releaseCapture(window: Window) {}
}
