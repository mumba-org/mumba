// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import Glibc
#endif

public enum TweenType {
  case Linear              // Linear.
  case EaseOut            // Fast in, slow out (default).
  case EaseIn             // Slow in, fast out.
  case EaseIn2           // Variant of EASE_IN that starts out slower than
                         // EASE_IN.
  case EaseInOut         // Slow in and out, fast in the middle.
  case FastInOut         // Fast in and out, slow in the middle.
  case EaseOutSnap       // Fast in, slow out, snap to final value.
  case SmoothInOut       // Smooth, consistent speeds in and out (sine wave).
  case FastOutSlowIn    // Variant of EASE_IN_OUT which should be used in most
                         // cases.
  case FastOutSlowIn2  // Variant of FAST_OUT_SLOW_IN that starts out quicker.
  case LinearOutSlowIn  // Variant of EASE_OUT which should be used for
                         // fading in from 0% or motion when entering a scene.
  case SlowOutLinearIn  // Reverse of LINEAR_OUT_SLOW_IN which should be used
                         // in reverse animation to create a rubberband effect.
  case FastOutLinearIn  // Variant of EASE_IN which should should be used for
                         // fading out to 0% or motion when exiting a scene.
  case Zero                // Returns a value of 0 always.
}

public struct Tween {

  public static func doubleValueBetween(value: Double, start: Double, target: Double) -> Double {
    return start + (target - start) * value
  }

  public static func floatValueBetween(value: Double, start: Float, target: Float) -> Float {
    return start + (target - start) * Float(value)
  }

  public static func intValueBetween(value: Double, start: Int, target: Int) -> Int {
    if start == target {
      return start
    }
    
    var delta = Double(target - start)
    
    if delta < 0 {
      delta -= 1.0
    } else {
      delta += 1.0
    }

  #if os(Windows)
    return start + Int(value * _nextafter(delta, 0))
  #else
    return start + Int(value * nextafter(delta, 0))
  #endif
  }

  public static func linearIntValueBetween(value: Double, start: Int, target: Int) -> Int {
    return Int(floor(0.5 + doubleValueBetween(value: value, start: Double(start), target: Double(target))))
  }

  public static func rectValueBetween(value: Double,
                               start startBounds: IntRect,
                               target targetBounds: IntRect) -> IntRect {
    return IntRect(
      x: linearIntValueBetween(value: value, start: startBounds.x, target: targetBounds.x),
      y: linearIntValueBetween(value: value, start: startBounds.y, target: targetBounds.y),
      width: linearIntValueBetween(value: value, start: startBounds.width, target: targetBounds.width),
      height: linearIntValueBetween(value: value, start: startBounds.height, target: targetBounds.height))
  }

  public static func calculateValue(type: TweenType, state: Double) -> Double {
    switch type {
      case .EaseIn:
        return pow(state, 2)
      case .EaseIn2:
        return pow(state, 4)
      case .EaseInOut:
        if state < 0.5 {
          return pow(state * 2, 2) / 2.0
        }
        return 1.0 - (pow((state - 1.0) * 2, 2) / 2.0)
      case .FastInOut:
        return (pow(state - 0.5, 3) + 0.125) / 0.25
      case .Linear:
        return state
      case .EaseOutSnap:
        let newState = 0.95 * (1.0 - pow(1.0 - state, 2));
        return newState
      case .EaseOut:
        return 1.0 - pow(1.0 - state, 2)
      case .SmoothInOut:
        return sin(state)
      case .FastOutSlowIn:
        return CubicBezier(0.4, 0, 0.2, 1).solve(x: state)
      case .FastOutSlowIn2:
        return CubicBezier(0.2, 0, 0.2, 1).solve(x: state)
      case .LinearOutSlowIn:
        return CubicBezier(0, 0, 0.2, 1).solve(x: state)
      case .SlowOutLinearIn:
        return CubicBezier(0, 0, 1, 0.2).solve(x: state)
      case .FastOutLinearIn:
        return CubicBezier(0.4, 0, 1, 1).solve(x: state)
      case .Zero:
        return 0.0
    }
  }

  public static func transformValueBetween(
      value: Double,
      startTransform: Transform,
      endTransform: Transform) -> Transform {
    if value >= 1.0 {
      return endTransform
    }
    if value <= 0.0 {
      return startTransform
    }

    var toReturn = endTransform
    let _ = toReturn.blend(from: startTransform, progress: value)

    return toReturn
  }

  public static func colorValueBetween(value: Double, start: Color, target: Color) -> Color {
    let startA = Float(start.a) / 255.0
    let targetA = Float(target.a) / 255.0
    var blendedA = Tween.floatValueBetween(value: value, start: startA, target: targetA)
    if blendedA <= 0.0 {
      return Color(a: 0, r: 0, g: 0, b: 0)
    }
    blendedA = min(blendedA, 1.0)

    let blendedR: UInt8 =
        blendColorComponents(start.r, target.r, startA,
                             targetA, blendedA, value)
    let blendedG: UInt8 =
        blendColorComponents(start.g, target.g, startA,
                             targetA, blendedA, value)
    let blendedB: UInt8 =
        blendColorComponents(start.b, target.b, startA,
                             targetA, blendedA, value)

    return Color(
        a: floatToColorByte(blendedA), r: blendedR, g: blendedG, b: blendedB)
  }

}

fileprivate func toRoundedInt(_ value: Float) -> Int {
  var rounded = value
  if value >= 0.0 {
    rounded = floor(value + 0.5)
  } else {
    rounded = ceil(value - 0.5)
  }
  return Int(rounded)
}

fileprivate func floatToColorByte(_ f: Float) -> UInt8 {
  return UInt8(toRoundedInt(f * 255.0))
}

fileprivate func blendColorComponents(_ start: UInt8,
                                      _ target: UInt8,
                                      _ startAlpha: Float,
                                      _ targetAlpha: Float,
                                      _ blendedAlpha: Float,
                                      _ progress: Double) -> UInt8 {
  // Since progress can be outside [0, 1], blending can produce a value outside
  // [0, 255].
  let blendedPremultiplied: Float = Tween.floatValueBetween(
      value: progress, start: Float(start) / 255.0 * startAlpha, target: Float(target) / 255.0 * targetAlpha)
  return floatToColorByte(blendedPremultiplied / blendedAlpha)
}