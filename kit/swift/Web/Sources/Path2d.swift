// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class Path2d {

  let reference: Path2dRef
  var owned: Path2dOwnedRef?

  public init() {
    owned = Path2dCreate()
    reference = Path2dFromOwned(owned!)
  }

  public init(_ pathData: String) {
    owned = pathData.withCString {
      return Path2dCreateWithString($0)
    }
    reference = Path2dFromOwned(owned!)
  }

  init(reference: Path2dRef) {
    self.reference = reference
  }
  
  deinit {
    if owned != nil {
      Path2dDestroy(owned!)
    }
  }

  public func addPath(path: Path2d) {
    Path2dAddPath(reference, path.reference)
  }

  public func addPath(path: Path2d, transform: SvgMatrix) {
    Path2dAddPathWithTransform(reference, path.reference, transform.reference)
  }

  public func closePath() {
    Path2dClosePath(reference)
  }
  
  public func moveTo(_ x: Float, _ y: Float) {
    Path2dMoveTo(reference, x, y)
  }
  
  public func lineTo(_ x: Float, _ y: Float) {
    Path2dLineTo(reference, x, y)
  }
  
  public func quadraticCurveTo(_ cpx: Float, _ cpy: Float, _ x: Float, _ y: Float) {
    Path2dQuadraticCurveTo(reference, cpx, cpy, x, y)
  }
  
  public func bezierCurveTo(_ cp1x: Float,
                            _ cp1y: Float,
                            _ cp2x: Float,
                            _ cp2y: Float,
                            _ x: Float,
                            _ y: Float) {
    Path2dBezierCurveTo(reference, cp1x, cp1y, cp2x, cp2y, x, y)
  }

  public func arcTo(_ x0: Float,
                    _ y0: Float,
                    _ x1: Float,
                    _ y1: Float,
                    _ radius: Float) {
    Path2dArcTo(reference, x0, y0, x1, y1, radius)
  } 

  public func arc(_ x: Float ,
                  _ y: Float,
                  _ radius: Float,
                  _ startAngle: Float,
                  _ endAngle: Float) {
    Path2dArc(reference, x, y, radius, startAngle, endAngle)
  }
  
  public func arc(_ x: Float ,
                  _ y: Float,
                  _ radius: Float,
                  _ startAngle: Float,
                  _ endAngle: Float,
                  anticlockwise: Bool) {
    Path2dArcWithParams(reference, x, y, radius, startAngle, endAngle, anticlockwise ? 1 : 0)
  }

  public func ellipse(_ x: Float,
                      _ y: Float,
                      _ radiusX: Float,
                      _ radiusY: Float,
                      _ rotation: Float,
                      _ startAngle: Float,
                      _ endAngle: Float) {
    Path2dEllipse(reference, x, y, radiusX, radiusY, rotation, startAngle, endAngle)
  }
  
  public func ellipse(_ x: Float,
                      _ y: Float,
                      _ radiusX: Float,
                      _ radiusY: Float,
                      _ rotation: Float,
                      _ startAngle: Float,
                      _ endAngle: Float,
                      anticlockwise: Bool) {
    Path2dEllipseWithParams(reference, x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise ? 1 : 0)
  }

  public func rect(_ x: Float, _ y: Float, _ width: Float, _ height: Float) {
    Path2dRect(reference, x, y, width, height)
  }

}