// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor

public class LayerAnimationSequence { 

  public var count: Int {
    return elements.count
  }

  public var firstElement: LayerAnimationElement? {
    guard let first = elements.first else {
      return nil
    }
    return first
  }

  public var startTime: TimeTicks = TimeTicks()
  public var waitingForGroupStart: Bool
  public var properties: LayerAnimationElement.AnimatableProperties
  public var isCyclic: Bool
  public var animationGroupId: Int
  public private(set) var lastProgressedFraction: Double
  fileprivate var currentElement: LayerAnimationElement? {
    if elements.isEmpty {
      return nil
    }

    let currentIndex = lastElement % elements.count
    return elements[currentIndex]
  }
  fileprivate var elements: [LayerAnimationElement] = []
  fileprivate var lastElement: Int
  fileprivate var lastStart: TimeTicks = TimeTicks()
  //fileprivate var observers: [LayerAnimationObserverBase] = []
  fileprivate var observers: [LayerAnimationObserver] = []
  
  public init() {
    properties = LayerAnimationElement.AnimatableProperties(rawValue: LayerAnimationElement.AnimatableProperty.Unknown.rawValue)
    isCyclic = false
    lastElement = 0
    waitingForGroupStart = false
    animationGroupId = 0
    lastProgressedFraction = 0.0
  }

  public init(element: LayerAnimationElement) {
    properties = LayerAnimationElement.AnimatableProperties(rawValue: LayerAnimationElement.AnimatableProperty.Unknown.rawValue)
    isCyclic = false
    lastElement = 0
    waitingForGroupStart = false
    animationGroupId = 0
    lastProgressedFraction = 0.0

    addElement(element: element)
  }

  deinit {
    for observer in observers {
      observer.detachedFromSequence(sequence: self, sendNotification: true)
    }
  }

  public func start(delegate: LayerAnimationDelegate) {
    lastProgressedFraction = 0.0
    guard let element = elements.first else {
      return
    }

    element.requestedStartTime = startTime
    element.start(delegate: delegate, animationGroupId: animationGroupId)

    notifyStarted()
  }

  public func progress(now: TimeTicks, delegate: LayerAnimationDelegate) {
    var redrawRequired = false

    if elements.isEmpty {
      return
    }

    if lastElement == 0 {
      lastStart = startTime
    }

    var currentIndex = lastElement % elements.count
    var elementDuration = TimeDelta()
    while isCyclic || lastElement < elements.count {
      elements[currentIndex].requestedStartTime = lastStart
      if !elements[currentIndex].isFinished(time: now, totalDuration: &elementDuration) {
        break
      }
      if elements[currentIndex].progressToEnd(delegate: delegate) {
        redrawRequired = true
      }
      lastStart = lastStart + elementDuration
      lastElement += 1
      lastProgressedFraction = elements[currentIndex].lastProgressedFraction
      currentIndex = lastElement % elements.count
    }

    if isCyclic || lastElement < elements.count {
      if !elements[currentIndex].started {
        animationGroupId = AnimationIdProvider.nextGroupId
        elements[currentIndex].start(delegate: delegate, animationGroupId: animationGroupId)
      }
      
      if elements[currentIndex].progress(now: now, delegate: delegate) {
        redrawRequired = true
      }

      lastProgressedFraction = elements[currentIndex].lastProgressedFraction
    }

    // Since the delegate may be deleted due to the notifications below, it is
    // important that we schedule a draw before sending them.
    if redrawRequired {
      delegate.scheduleDrawForAnimation()
    }

    if !isCyclic && lastElement == elements.count {
      lastElement = 0
      waitingForGroupStart = false
      animationGroupId = 0
      notifyEnded()
    }
  }

  public func isFinished(time: TimeTicks) -> Bool {
    if isCyclic || waitingForGroupStart {
      return false
    }

    if elements.isEmpty {
      return true
    }

    if lastElement == 0 {
      lastStart = startTime 
    }

    var currentStart = lastStart
    var currentIndex = lastElement
    var elementDuration = TimeDelta()
    while currentIndex < elements.count {
      ////print("LayerAnimationSequence.isFinished: setando LayerAnimationElement[\(currentIndex)].requestedStartTime = \(currentStart)")
      elements[currentIndex].requestedStartTime = currentStart
      if !elements[currentIndex].isFinished(time: time, totalDuration: &elementDuration) {
        break
      }
      currentStart = currentStart + elementDuration
      currentIndex += 1
    }
    return currentIndex == elements.count
  }

  public func progressToEnd(delegate: LayerAnimationDelegate) {
    var redrawRequired = false

    if elements.isEmpty {
      return
    }

    var currentIndex = lastElement % elements.count
    while currentIndex < elements.count {
      if elements[currentIndex].progressToEnd(delegate: delegate) {
        redrawRequired = true
      }
      lastProgressedFraction = elements[currentIndex].lastProgressedFraction
      currentIndex += 1
      lastElement += 1
    }

    if redrawRequired {
      delegate.scheduleDrawForAnimation()
    }

    if !isCyclic {
      lastElement = 0
      waitingForGroupStart = false
      animationGroupId = 0
      notifyEnded()
    }
  }

  public func getTargetValue(target: inout LayerAnimationElement.TargetValue) {
    if isCyclic {
      return
    }

    for i in lastElement..<elements.count {
      elements[i].getTargetValue(target: &target)
    }
  }

  public func abort(delegate: LayerAnimationDelegate) {
    var currentIndex = lastElement % elements.count
    while currentIndex < elements.count {
      elements[currentIndex].abort(delegate: delegate)
      currentIndex += 1
    }
    lastElement = 0
    waitingForGroupStart = false
    notifyAborted()
  }

  public func addElement(element: LayerAnimationElement) {
    properties = LayerAnimationElement.AnimatableProperties(rawValue: properties.rawValue | element.properties.rawValue)
    elements.append(element)
  }

  public func hasConflictingProperty(other: LayerAnimationElement.AnimatableProperties) -> Bool {
    return (properties.rawValue & other.rawValue) != LayerAnimationElement.AnimatableProperty.Unknown.rawValue
  }

  public func isFirstElementThreaded(delegate: LayerAnimationDelegate) -> Bool {
    if !elements.isEmpty {
      return elements[0].isThreaded(delegate: delegate)
    }

    return false
  }

  public func hasObserver(observer: LayerAnimationObserver) -> Bool {
    for elem in observers {
      if observer === elem {
        return true
      }
    }
    return false
  }

  //public func addObserver(observer: LayerAnimationObserverBase) {
  //  if !hasObserver(observer: observer) {
  //    observers.append(observer)
  //    observer.attachedToSequence(sequence: self)
  //  }
  //}
  
  //public func removeObserver(observer: LayerAnimationObserverBase) {
  //  for (i, elem) in observers.enumerated() {
  //    if observer === elem {
  //      observers.remove(at: i)
  //      break
  //    }
  //  }
  //  observer.detachedFromSequence(sequence: self, sendNotification: true)
  //}

  public func addObserver(observer: LayerAnimationObserver) {
    if !hasObserver(observer: observer) {
      observers.append(observer)
      observer.attachedToSequence(sequence: self)
    }
  }
  
  public func removeObserver(observer: LayerAnimationObserver) {
    for (i, elem) in observers.enumerated() {
      if observer === elem {
        observers.remove(at: i)
        break
      }
    }
    observer.detachedFromSequence(sequence: self, sendNotification: true)
  }

  public func onThreadedAnimationStarted(
    monotonicTime: TimeTicks,
    targetProperty: TargetProperty, 
    groupId: Int) {
    
    if elements.isEmpty || groupId != animationGroupId {
      return
    }

    let currentIndex = lastElement % elements.count
    //let eventProperty = LayerAnimationElement.toAnimatableProperty(property: targetProperty)
    elements[currentIndex].effectiveStartTime = monotonicTime
  }

  public func onScheduled() {
    notifyScheduled()
  }

  public func onAnimatorDestroyed() {
    for observer in observers {
      if !observer.requiresNotificationWhenAnimatorDestroyed {
        // Remove the observer, but do not allow notifications to be sent.
        if let index = observers.firstIndex(where: { $0 === observer } ) {
          observers.remove(at: index)
        }
        observer.detachedFromSequence(sequence: self, sendNotification: false)
      }
    }
  }

  public func toString() -> String {
    return ""
  }

  /// PRIVATE STUFF

  fileprivate func elementsToString() -> String {
    return ""
  }

  // Notifies the observers that this sequence has been scheduled.
  fileprivate func notifyScheduled() {
    for observer in observers {
      observer.onLayerAnimationScheduled(sequence: self)
    }
  }

  // Notifies the observers that this sequence has been started.
  fileprivate func notifyStarted() {
    for observer in observers {
      observer.onLayerAnimationStarted(sequence: self)
    }
  }

  // Notifies the observers that this sequence has ended.
  fileprivate func notifyEnded() {
     for observer in observers {
      observer.onLayerAnimationEnded(sequence: self)
     }
  }

  // Notifies the observers that this sequence has been aborted.
  fileprivate func notifyAborted() {
     for observer in observers {
      observer.onLayerAnimationAborted(sequence: self)
     }
  }

}

extension LayerAnimationSequence : Equatable {
  
  public static func ==(lhs: LayerAnimationSequence, rhs: LayerAnimationSequence) -> Bool {
    assert(false)
    return false
  }

}

extension LayerAnimationSequence : Hashable {
   
  public func hash(into hasher: inout Hasher) {
    hasher.combine(properties.rawValue)
    hasher.combine(isCyclic)
    hasher.combine(lastElement)
    hasher.combine(waitingForGroupStart)
    hasher.combine(animationGroupId)
    hasher.combine(lastProgressedFraction)
  }

}