// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum ScreenOrientationValues : Int {
  case Default
  case PortraitPrimary
  case PortraitSecondary
  case LandscapePrimary
  case LandscapeSecondary
  case `Any`
  case Landscape
  case Portrait
  case Natural
}

public struct ScreenInfo {
  public var deviceScaleFactor: Float = 1.0
  public var colorSpace: ColorSpace
  public var depth: UInt32 = 24
  public var depthPerComponent: UInt32 = 0
  public var isMonochrome: Bool = false
  public var rect: IntRect = IntRect()//width: 400, height: 400)
  public var availableRect: IntRect = IntRect()//width: 400, height: 400)
  public var orientationType: ScreenOrientationValues = ScreenOrientationValues.Default
  public var orientationAngle: UInt16 = 0

  public init () {
    colorSpace = ColorSpace.createSRGB()
  }
}

@inlinable
public func ==(left: ScreenInfo, right: ScreenInfo) -> Bool {
  return 
    (left.deviceScaleFactor == right.deviceScaleFactor) && 
    (left.colorSpace == right.colorSpace) && 
    (left.depth == right.depth) &&
    (left.depthPerComponent == right.depthPerComponent) &&
    (left.isMonochrome == right.isMonochrome) &&
    (left.rect == right.rect) &&
    (left.availableRect == right.availableRect) &&
    (left.orientationType == right.orientationType) &&
    (left.orientationAngle == right.orientationAngle)
}

@inlinable
public func !=(left: ScreenInfo, right: ScreenInfo) -> Bool {
  return !(left == right)
}