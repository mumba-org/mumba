// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

public class MultiAnimation : Animation {

  public struct Part {
    public var timeMs: Int
    public var startTimeMs: Int
    public var endTimeMs: Int
    public var type: TweenType

    public init() {
      self.init(timeMs: 0, type: TweenType.Zero)
    }

    public init(timeMs: Int, type: TweenType) {
      self.init(timeMs: timeMs, startTimeMs: 0, endTimeMs: timeMs, type: type)
    }

    public init(timeMs: Int, startTimeMs: Int, endTimeMs: Int, type: TweenType) {
      self.timeMs = timeMs
      self.startTimeMs = startTimeMs
      self.endTimeMs = endTimeMs
      self.type = type
    }
  }
  // Default interval.
  static let defaultTimerInterval: TimeDelta = TimeDelta()
  
  public override var currentValue: Double {
    get {
      return _currentValue
    }
    set {
      _currentValue = newValue
    }
  }  
  public override var startTime: TimeTicks {
    get {
      return super.startTime
    }
    set {
      super.startTime = newValue
      _currentValue = 0
      currentPartIndex = 0
    }
  }
  
  public var continuous: Bool
  public private(set) var currentPartIndex: Int
  fileprivate let cycleTimeMs: Int
  fileprivate var parts: [Part]
  fileprivate var _currentValue: Double
 
  public init(parts: [Part], timerInterval: TimeDelta) {
    self.parts = parts
    cycleTimeMs = totalTime(parts)
    _currentValue = 0
    currentPartIndex = 0
    continuous = true

    super.init(timerInterval: timerInterval)
  }

  public override func step(timeNow: TimeTicks) {
    let lastValue = currentValue
    let lastIndex = currentPartIndex

    var delta = Int((timeNow - startTime).milliseconds)
    
    if delta >= cycleTimeMs && !continuous {
      currentPartIndex = parts.count - 1
      currentValue = Tween.calculateValue(type: parts[currentPartIndex].type, state: 1)
      stop()
      return
    }

    delta %= cycleTimeMs
    let part = getPart(milliseconds: &delta, partIndex: &currentPartIndex)
    let percent = Double(delta + part.startTimeMs) / Double(part.endTimeMs)
    //DCHECK(percent <= 1);
    currentValue = Tween.calculateValue(type: part.type, state: percent)

    if delegate != nil && (currentValue != lastValue || currentPartIndex != lastIndex) {
      delegate!.animationProgressed(animation: self)
    }
  }
  
  // Returns the part containing the specified time. |time_Ms| is reset to be
  // relative to the part containing the time and |part_index| the index of the
  // part.
  func getPart(milliseconds: inout Int, partIndex: inout Int ) -> Part {
    for i in 0..<parts.count {
      if milliseconds < parts[i].timeMs {
        partIndex = i
        return parts[i]
      }

      milliseconds -= parts[i].timeMs
    }
    assert(false)
    milliseconds = 0
    partIndex = 0
    return parts[0]
  }

}

fileprivate func totalTime(_ parts: [MultiAnimation.Part]) -> Int {
  var timeMs = 0
  for part in parts {
    timeMs += part.timeMs
  }
  return timeMs
}