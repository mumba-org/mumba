// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import _C

public class KeyframeModel {

  public enum RunState : Int {
    case WaitingForTargetAvailability = 0
    case WaitingForDeletion
    case Starting
    case Running
    case Paused
    case Finished
    case Aborted
    case AbortedButNeedsCompletion
  }

  public enum Direction : Int { 
    case Normal = 0
    case Reverse
    case AlternateNormal
    case AlternateReverse
  }

  public enum FillMode : Int { 
    case None = 0
    case Forwards
    case Backwards
    case Both
    case Auto 
  }

  public class func create(
      curve: NativeAnimationCurve,
      id: Int,
      group: Int,
      property: TargetProperty) -> KeyframeModel {

    return KeyframeModel(
      curve: curve,
      id: id, 
      group: group, 
      property: property)
  }

  public var id: Int {
    return Int(_C.keyframeModelGetId(reference))
  }
  
  public var group: Int {
    return Int(_C.keyframeModelGetGroup(reference))
  }
  
  public var targetProperty: TargetProperty {
    return TargetProperty(rawValue: Int(_C.keyframeModelGetTargetProperty(reference)))!
  }
  
  public var runState: RunState {
    return RunState(rawValue: Int(_C.keyframeModelRunState(reference)))!
  }
  
  public var iterations: Double {
    get {
      return _C.keyframeModelIterations(reference)
    }
    set {
      _C.keyframeModelSetIterations(reference, newValue)
    }
  }
  
  public var iterationStart: Double {

    get {
      return _C.keyframeModelIterationStart(reference)
    }
    
    set {
      _C.keyframeModelSetIterationStart(reference, newValue)
    }
  
  }
  
  public var startTime: TimeTicks {

    get {
      return TimeTicks(microseconds: _C.keyframeModelStartTime(reference))
    }
    
    set {
      _C.keyframeModelSetStartTime(reference, newValue.microseconds)
    }

  }
  
  public var hasSetStartTime: Bool {
    return !startTime.isNull
  }
  
  public var timeOffset: TimeDelta {
    get {
      return TimeDelta(microseconds: _KeyframeModelTimeOffset(reference))
    }
    
    set {
      _KeyframeModelSetTimeOffset(reference, newValue.microseconds)
    }
  }
  
  public var direction: Direction {
    get {
      return Direction(rawValue: Int(_KeyframeModelDirection(reference)))!
    }
    set {
      _KeyframeModelSetDirection(reference, Int32(newValue.rawValue))
    }
  }
  
  public var fillMode: FillMode {
    get {
      return FillMode(rawValue: Int(_KeyframeModelFillMode(reference)))!
    }
    set {
      _KeyframeModelSetFillMode(reference, Int32(newValue.rawValue))
    }
  }
  
  public var playbackRate: Double {
    get {
      return _KeyframeModelPlaybackRate(reference)
    }
    set {
      _KeyframeModelSetPlaybackRate(reference, newValue)
    }
  }
  
  public var isFinished: Bool {
    return runState == .Finished || runState == .Aborted || runState == .WaitingForDeletion
  }
  
  public var curve: AnimationCurve {
    let ref = _KeyframeModelAnimationCurve(reference)
    return NativeAnimationCurve(reference: ref!)
  }
  
  public var needsSynchronizedStartTime: Bool {
    get {
      return Bool(_KeyframeModelNeedsSynchronizedStartTime(reference))
    }
    set {
      _KeyframeModelSetNeedsSynchronizedStartTime(reference, newValue.intValue)
    }
  }
  
  public var receivedFinishedEvent: Bool {
    get {
      return Bool(_KeyframeModelReceivedFinishedEvent(reference))
    }
    set {
      _KeyframeModelSetReceivedFinishedEvent(reference, newValue.intValue)
    }
  }
  
  public private(set) var isControllingInstance: Bool {
    get {
      return Bool(_KeyframeModelIsControllingInstance(reference))
    }
    set {
      _KeyframeModelSetIsControllingInstance(reference, newValue.intValue)
    }
  }
  
  public var isImplOnly: Bool {
    get {
      return Bool(_KeyframeModelIsImplOnly(reference))
    }
    set {
      _KeyframeModelSetIsImplOnly(reference, newValue.intValue)
    }
  }
  
  public var affectsActiveElements: Bool {
    get {
      return Bool(_KeyframeModelAffectsActiveElements(reference))
    }
    set {
      _KeyframeModelSetAffectsActiveElements(reference, newValue.intValue)
    }
  }
  
  public var affectsPendingElements: Bool {
    get {
      return Bool(_KeyframeModelAffectsPendingElements(reference))
    }
    set {
      _KeyframeModelSetAffectsPendingElements(reference, newValue.intValue)
    }
  }
  
  public internal(set) var reference: KeyframeModelRef
  internal var owned: Bool
  
  internal convenience init(
    curve: NativeAnimationCurve, 
    id: Int, 
    group: Int, 
    property: TargetProperty) {
    curve.owned = false  
    let ref = _C.keyframeModelCreate(curve.reference, CInt(id), CInt(group), CInt(property.rawValue))
    self.init(reference: ref, owned: true)
  }

  internal init(reference: KeyframeModelRef, owned: Bool) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    if owned {
      _C.keyframeModelDestroy(reference)
    }
  }

  public func setRunState(runState: RunState, monotonicTime: TimeTicks) {
    _KeyframeModelSetRunState(reference, Int32(runState.rawValue), monotonicTime.microseconds)
  }

  public func isFinishedAt(monotonicTime: TimeTicks) -> Bool {
    return Bool(_KeyframeModelIsFinishedAt(reference, monotonicTime.microseconds))
  }

  public func setRunState(state: RunState, monotonicTime: TimeTicks) {
    _KeyframeModelSetRunState(reference, Int32(state.rawValue), monotonicTime.microseconds)
  }

}