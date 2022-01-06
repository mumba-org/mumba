// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public typealias Gesture = Int

public protocol GestureConsumer {

}

public protocol GestureEventHelper {

}

public class GestureRecognizer {

  public typealias Gestures = [Gesture]

  public enum ShouldCancelTouches { 
    case cancel
    case dontCancel
  }

  public class func instance() -> GestureRecognizer {
    if _instance == nil {
      _instance = GestureRecognizer()
    }
    return _instance!
  }

  static var _instance: GestureRecognizer?

  public init() {
    
  }

  public func cancelActiveTouchesExcept(notCancelled: GestureConsumer?) {

  }

  public func transferEventsTo(currentConsumer: GestureConsumer,
                               newConsumer: GestureConsumer,
                               shouldCancelTouches: ShouldCancelTouches) {

  }

}

public struct GestureEventDetails {

  public var scrollX: Float {
    return scrollUpdate.x
  }

  public var scrollY: Float {
    return scrollUpdate.y
  }

  public var velocityX: Float {
    return flingVelocity.x
  }

  public var velocityY: Float {
    return flingVelocity.y
  }

  public var touchPoints: Int

  var scrollUpdate: FloatVec2
  var flingVelocity: FloatVec2

  public init() {
    touchPoints = 0
    scrollUpdate = FloatVec2()
    flingVelocity = FloatVec2()
  }

}
