// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol ScreenPositionClient {
  func convertPointToScreen(window: Window, point: inout IntPoint)
  func convertPointFromScreen(window: Window, point: inout IntPoint)
  func convertHostPointToScreen(window: Window, point: inout IntPoint)
  func setBounds(window: Window, bounds: IntRect, display: Display)
}

public class DefaultScreenPositionClient : ScreenPositionClient {

  public init() {}

  public func convertPointToScreen(window: Window, point: inout IntPoint) {
    Window.convertPointToTarget(source: window, target: window.rootWindow!, point: &point)
    let origin: IntPoint = getOriginInScreen(rootWindow: window.rootWindow!)
    point.offset(x: origin.x, y: origin.y)
  }

  public func convertPointFromScreen(window: Window, point: inout IntPoint) {
    let origin = getOriginInScreen(rootWindow: window.rootWindow!)
    point.offset(x: -origin.x, y: -origin.y)
    Window.convertPointToTarget(source: window.rootWindow!, target: window, point: &point)
  }

  public func convertHostPointToScreen(window: Window, point: inout IntPoint) {
    convertPointToScreen(window: window.rootWindow!, point: &point)
  }

  public func setBounds(window: Window, bounds: IntRect, display: Display) {
    window.bounds = bounds
  }

  func getOriginInScreen(rootWindow: Window) -> IntPoint {
    let originInPixels = rootWindow.host!.boundsInPixels.origin
    //let scale = Screen.getScreenFor(rootWindow.id).getDisplayNearestWindow(rootWindow.id).deviceScaleFactor
    let scale = Screen.getDisplayNearestWindow(windowId: rootWindow.id)!.deviceScaleFactor
    return IntPoint.toFloored(point: originInPixels, scale: 1.0 / scale)
  }


}
