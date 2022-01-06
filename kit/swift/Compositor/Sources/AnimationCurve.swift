// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public enum AnimationCurveType : Int {
  case color = 0
  case float = 1
  case transform = 2
  case filter = 3
  case scrollOffset = 4
  case size = 5
}

public protocol AnimationCurve : class {
  var duration: TimeDelta { get }
  var type: AnimationCurveType { get }

  func clone() -> AnimationCurve
}

public class NativeAnimationCurve : AnimationCurve {

  public class func createFloatAnimation(_ state: UnsafeMutableRawPointer, _ cbs: FloatAnimationCurveCallbacks) -> NativeAnimationCurve {
    let ref = _AnimationCurveCreateFloatAnimation(state, cbs)
    return NativeAnimationCurve(reference: ref!, owned: true)
  }

  public class func createTransformAnimation(_ state: UnsafeMutableRawPointer, _ cbs: TransformAnimationCurveCallbacks) -> NativeAnimationCurve {
    let ref = _AnimationCurveCreateTransformAnimation(state, cbs)
    return NativeAnimationCurve(reference: ref!, owned: true)
  }
  
  public var duration: TimeDelta {
    let us = _AnimationCurveGetDuration(reference)
    return TimeDelta(microseconds: us)
  }
  
  public var type: AnimationCurveType { 
    let t = _AnimationCurveGetType(reference)
    return AnimationCurveType(rawValue: Int(t))!
  }

  public func clone() -> AnimationCurve {
    let ref = _AnimationCurveClone(reference)
    // in case of clone, the handle is owned and should
    // be manually deleted when the reference is gone
    return NativeAnimationCurve(reference: ref!, owned: true)
  }

  public private(set) var reference: AnimationCurveRef
  internal var owned: Bool

  public init(reference: AnimationCurveRef, owned: Bool = false) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    if owned {
      _AnimationCurveDestroy(reference)
    }
  }
}

// extension AnimationCurve {
  
//   public func toColorAnimationCurve() -> ColorAnimationCurve? {

//   }
  
//   public func toFloatAnimationCurve() -> FloatAnimationCurve? {

//   }
  
//   public func toTransformAnimationCurve() -> TransformAnimationCurve? {

//   }
  
//   public func toFilterAnimationCurve() -> FilterAnimationCurve? {

//   }
  
//   public func toScrollOffsetAnimationCurve() -> ScrollOffsetAnimationCurve? {

//   }
  
//   public func toSizeAnimationCurve() -> SizeAnimationCurve? {

//   }
  
//   public func toScrollOffsetAnimationCurve() -> ScrollOffsetAnimationCurve? {

//   }
// }

public protocol ColorAnimationCurve : AnimationCurve {
  func getValue(_: TimeDelta) -> Color
}

extension ColorAnimationCurve {
  public var type: AnimationCurveType {
    return AnimationCurveType.color
  }
}

public protocol FloatAnimationCurve : AnimationCurve {
  func getValue(_: TimeDelta) -> Float
}

extension FloatAnimationCurve {
  public var type: AnimationCurveType {
    return AnimationCurveType.float
  }
}

public protocol TransformAnimationCurve : AnimationCurve {
  var isTranslation: Bool { get }
  var preservesAxisAlignment: Bool { get }

  func getValue(_: TimeDelta) -> TransformOperations
  func animatedBoundsForBox(box: FloatBox) -> FloatBox?
  func animationStartScale(forwardDirection: Bool) -> Float?
  func maximumTargetScale(forwardDirection: Bool) -> Float?
}

extension TransformAnimationCurve {
  public var type: AnimationCurveType {
    return AnimationCurveType.transform
  }
}

public protocol FilterAnimationCurve : AnimationCurve {
  var hasFilterThatMovesPixels: Bool { get }
  func getValue(_: TimeDelta) -> FilterOperations
}

extension FilterAnimationCurve {
  public var type: AnimationCurveType {
    return AnimationCurveType.filter
  }
}

public protocol SizeAnimationCurve : AnimationCurve {
  func getValue(_: TimeDelta) -> FloatSize
}

extension SizeAnimationCurve {
  public var type: AnimationCurveType {
    return AnimationCurveType.size
  }
}

// TODO: implement
public class ScrollOffsetAnimationCurve : AnimationCurve {
  
  public var type: AnimationCurveType {
    return AnimationCurveType.scrollOffset
  }

  public private(set) var duration: TimeDelta

  public init () {
    duration = TimeDelta()
  }

  public func getValue(_ t: TimeDelta) -> ScrollOffset {
    return ScrollOffset()
  }

  public func clone() -> AnimationCurve {
    return ScrollOffsetAnimationCurve() 
  }
}

