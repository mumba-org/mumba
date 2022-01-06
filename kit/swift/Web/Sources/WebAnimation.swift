// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum WebAnimationTargetProperty : Int {
    case TargetPropertyTransform = 0
    case TargetPropertyOpacity
    case TargetPropertyFilter
    case TargetPropertyScrollOffset
}

public enum WebAnimationDirection : Int {
    case DirectionNormal = 0
    case DirectionReverse
    case DirectionAlternate
    case DirectionAlternateReverse
}

public enum WebAnimationFillMode : Int {
    case FillModeNone = 0
    case FillModeForwards
    case FillModeBackwards
    case FillModeBoth
}

public protocol WebCompositorAnimation {

    var id: Int { get }
    var group: Int { get }
    var targetProperty: WebAnimationTargetProperty { get }
    var iterations: Double { get set }
    var startTime: Double { get set }
	var timeOffset: Double { get set }
    var direction: WebAnimationDirection { get set }
    var playbackRate: Double { get set }
    var fillMode: WebAnimationFillMode { get set }
    var iterationStart: Double { get set }
}

public protocol WebCompositorAnimationDelegate {
	func notifyAnimationStarted(monotonicTime: Double, group: Int)
    func notifyAnimationFinished(monotonicTime: Double, group: Int)
}