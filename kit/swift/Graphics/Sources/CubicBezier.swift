// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct CubicBezier {

  static let bezierEpsilon: Double = 1e-7

  public var x1: Double {
    return cx / 3.0
  }
  
  public var y1: Double {
    return cy / 3.0
  }
  
  public var x2: Double {
    return (bx + cx) / 3.0 + x1
  }
  
  public var y2: Double {
    return (by + cy) / 3.0 + y1
  }

  public var defaultEpsilon: Double {
    return CubicBezier.bezierEpsilon
  }

  public private(set) var rangeMin: Double = 0.0
  public private(set) var rangeMax: Double = 0.0

  var ax: Double = 0.0
  var bx: Double = 0.0
  var cx: Double = 0.0

  var ay: Double = 0.0
  var by: Double = 0.0
  var cy: Double = 0.0

  var startGradient: Double = 0.0
  var endGradient: Double = 0.0
  
  public init(_ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) {
    initCoefficients(x0, y0, x1, y1)
    initGradients(x0, y0, x1, y1)
    initRange(y0, y1)
  }

  func sampleCurveX(_ t: Double) -> Double {
    // `ax t^3 + bx t^2 + cx t' expanded using Horner's rule.
    return ((ax * t + bx) * t + cx) * t
  }

  public func sampleCurveY(_ t: Double) -> Double {
    return ((ay * t + by) * t + cy) * t
  }

  public func sampleCurveDerivativeX(_ t: Double) -> Double {
    return (3.0 * ax * t + 2.0 * bx) * t + cx
  }

  public func sampleCurveDerivativeY(_ t: Double) -> Double {
    return (3.0 * ay * t + 2.0 * by) * t + cy
  }

  public func solveWithEpsilon(x: Double, epsilon: Double) -> Double {
    if x < 0.0 {
      return 0.0 + startGradient * x
    }
    if x > 1.0 {
      return 1.0 + endGradient * (x - 1.0)
    }
    return sampleCurveY(solveCurveX(x: x, epsilon: epsilon))
  }

  public func solveCurveX(x: Double, epsilon: Double) -> Double {
    var t0: Double
    var t1: Double
    var t2: Double = x
    var x2: Double
    var d2: Double
//    var i: Int

    // First try a few iterations of Newton's method -- normally very fast.
    for _ in 0..<8 {
      x2 = sampleCurveX(t2) - x
      if abs(x2) < epsilon {
        return t2
      }
      d2 = sampleCurveDerivativeX(t2)
      if abs(d2) < 1e-6 {
        break
      }
      t2 = t2 - x2 / d2
    }

    // Fall back to the bisection method for reliability.
    t0 = 0.0
    t1 = 1.0
    t2 = x

    while t0 < t1 {
      x2 = sampleCurveX(t2)
      if abs(x2 - x) < epsilon {
        return t2
      }
      if x > x2 {
        t0 = t2
      } else {
        t1 = t2
      }
      t2 = (t1 - t0) * 0.5 + t0
    }

    // Failure.
    return t2
  }

  public func solve(x: Double) -> Double {
    return solveWithEpsilon(x: x, epsilon: CubicBezier.bezierEpsilon)
  }

  public func slopeWithEpsilon(x: Double, epsilon: Double) -> Double {
    let nx = min(max(x, 0.0), 1.0)
    let t = solveCurveX(x: nx, epsilon: epsilon)
    let dx = sampleCurveDerivativeX(t)
    let dy = sampleCurveDerivativeY(t)
    return dy / dx
  }

  public func slope(x: Double) -> Double {
    return slopeWithEpsilon(x: x, epsilon: CubicBezier.bezierEpsilon)
  }


  mutating func initCoefficients(_ p1x: Double, _ p1y: Double, _ p2x: Double, _ p2y: Double) {
    cx = 3.0 * p1x
    bx = 3.0 * (p2x - p1x) - cx
    ax = 1.0 - cx - bx

    cy = 3.0 * p1y
    by = 3.0 * (p2y - p1y) - cy
    ay = 1.0 - cy - by
  }
  
  mutating func initGradients(_ p1x: Double, _ p1y: Double, _ p2x: Double, _ p2y: Double) {
    if p1x > 0 {
      startGradient = p1y / p1x
    } else if p1y == 0.0 && p2x > 0 {
      startGradient = p2y / p2x
    } else {
      startGradient = 0
    }

    if p2x < 1 {
      endGradient = (p2y - 1) / (p2x - 1)
    } else if p2x == 1 && p1x < 1 {
      endGradient = (p1y - 1) / (p1x - 1)
    } else {
      endGradient = 0
    }
  }
  
  mutating func initRange(_ p1y: Double, _ p2y: Double) {
    rangeMin = 0
    rangeMax = 1

    if 0 <= p1y && p1y < 1 && 0 <= p2y && p2y <= 1 {
      return
    }

    let epsilon = CubicBezier.bezierEpsilon

    // Represent the function's derivative in the form at^2 + bt + c
    // as in sampleCurveDerivativeY.
    // (Technically this is (dy/dt)*(1/3), which is suitable for finding zeros
    // but does not actually give the slope of the curve.)
    let a = 3.0 * ay
    let b = 2.0 * by
    let c = cy

    // Check if the derivative is constant.
    if abs(a) < epsilon && abs(b) < epsilon {
      return
    }

    // Zeros of the function's derivative.
    var t1: Double = 0.0
    var t2: Double = 0.0

    if abs(a) < epsilon {
      // The function's derivative is linear.
      t1 = -c / b
    } else {
      // The function's derivative is a quadratic. We find the zeros of this
      // quadratic using the quadratic formula.
      let discriminant: Double = b * b - 4 * a * c
      if discriminant < 0 {
        return
      }
      let discriminantSqrt: Double = discriminant.squareRoot()
      t1 = (-b + discriminantSqrt) / (2 * a)
      t2 = (-b - discriminantSqrt) / (2 * a)
    }

    var sol1: Double = 0
    var sol2: Double = 0

    // If the solution is in the range [0,1] then we include it, otherwise we
    // ignore it.

    // An interesting fact about these beziers is that they are only
    // actually evaluated in [0,1]. After that we take the tangent at that point
    // and linearly project it out.
    if 0 < t1 && t1 < 1 {
      sol1 = sampleCurveY(t1)
    }

    if 0 < t2 && t2 < 1 {
      sol2 = sampleCurveY(t2)
    }

    rangeMin = min(min(rangeMin, sol1), sol2)
    rangeMax = max(max(rangeMax, sol1), sol2)
  }

}