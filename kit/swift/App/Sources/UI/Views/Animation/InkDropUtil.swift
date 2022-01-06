// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
import Graphics

internal func getTransformSubpixelCorrection(transform: Transform,
                                             deviceScaleFactor: Float) -> Transform {
  var origin = FloatPoint3()
  transform.transformPoint(point: &origin)

  let offsetInDIP: FloatVec2 = FloatPoint(origin).offsetFromOrigin

  // Scale the origin to screen space
  origin.scale(by: deviceScaleFactor)

  // Compute the rounded offset in screen space and finally unscale it back to
  // DIP space.
  var alignedOffsetInDIP: FloatVec2 = FloatPoint(origin).offsetFromOrigin
  alignedOffsetInDIP.x = alignedOffsetInDIP.x.rounded()
  alignedOffsetInDIP.y = alignedOffsetInDIP.y.rounded()
  alignedOffsetInDIP.scale(by: 1.0 / deviceScaleFactor)

  // Compute the subpixel offset correction and apply it to the transform.
  var subpixelCorrection = Transform()
  subpixelCorrection.translate(vector: alignedOffsetInDIP - offsetInDIP)

  return subpixelCorrection
}