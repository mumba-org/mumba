// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public enum WindowVisibilityAnimationType : Int {
  case standard = 0    // Default. Lets the system
                       // decide based on window
                       // type.
  case drop            // Window shrinks in.
  case vertical        // Vertical Glenimation.
  case fade            // Fades in/out.
  case rotate          // Window rotates in.
}

public  enum WindowAnimationType : Int {
  case bounce = 0  // Window scales up and down.
}

public enum WindowVisibilityAnimationTransition : Int {
  case show = 0x1
  case hide = 0x2
  case both = 0x3
  case none = 0x4
}

public protocol WindowAnimationHost : class {
  func setHostTransitionOffsets(_ topLeftDelta: IntVec2, _ bottomRightDelta: IntVec2)
  func onWindowHidingAnimationCompleted()
}

internal class HidingWindowAnimationObserverBase : WindowObserver {
 
  private var window: Window?
  //private var layerOwner: LayerTreeOwner
  private var layer: Layer?

  public init(window: Window) {
    self.window = window
    window.addObserver(observer: self)
  }
  
  deinit {
    if let w = window {
      w.removeObserver(observer: self)
    }
  }

  public func onWindowDestroying(window: Window) {
    windowInvalid()
  }
  
  public func onWindowDestroyed(window: Window) {
    windowInvalid()
  }
  
  public func detachAndRecreateLayers() {
    self.layer = recreateLayers(root: window!)
    if window!.parent != nil {
      let transientChildren = UI.getTransientChildren(window: window!)
      if var index = window!.parent!.children.firstIndex(where: { $0 === window }) {
        var topmostTransientChild: Window?
        while index != window!.parent!.children.endIndex {
          let value = window!.parent!.children[index]
          if let topmostIndex = transientChildren.firstIndex(where: { $0 === value }) {
            topmostTransientChild = transientChildren[topmostIndex]
          }
          index = index.advanced(by: 1)
        }
        if let topmostWindow = topmostTransientChild {
          //window!.parent!.layer!.stackAbove(child: layerOwner.root, other: topmostWindow.layer)
          window!.parent!.layer!.stackAbove(child: layer!, other: topmostWindow.layer!)
        }
      }
    }
    // Reset the transform for the |window_|. Because the animation may have
    // changed the transform, when recreating the layers we need to reset the
    // transform otherwise the recreated layer has the transform installed
    // for the animation.
    window!.layer!.transform = Transform()
  }

  // Invoked when the hiding animation is completed.  It will delete
  // 'this', and no operation should be made on this object after this
  // point.
  internal func onAnimationCompleted() {
    // Window may have been destroyed by this point.
    if let w = window {
      if let animationHost = UI.getAnimationHost(window: w) {
        animationHost.onWindowHidingAnimationCompleted()
      }
      w.removeObserver(observer: self)
    }
    //delete self
  }

  // Invoked when the window is destroyed (or destroying).
  private func windowInvalid() {
    //layerOwner.root.suppressPaint()
    layer!.suppressPaint()
    self.window!.removeObserver(observer: self)
    self.window = nil
  }

}

internal class RotateHidingWindowAnimationObserver : HidingWindowAnimationObserverBase,
                                                     LayerAnimationObserver {

  public var requiresNotificationWhenAnimatorDestroyed: Bool {
    return false
  }
  
  public override init(window: Window) {
    super.init(window: window)
  }

  public func setLastSequence(_ lastSequence: LayerAnimationSequence) {
    lastSequence.addObserver(observer: self)
  }

  public func onLayerAnimationStarted(sequence: LayerAnimationSequence) {}

  public func onLayerAnimationEnded(sequence: LayerAnimationSequence) {
    onAnimationCompleted()
  }

  public func onLayerAnimationAborted(sequence: LayerAnimationSequence) {
    onAnimationCompleted()
  }

  public func onLayerAnimationScheduled(sequence: LayerAnimationSequence) {}
  public func onAttachedToSequence(sequence: LayerAnimationSequence) {}
  public func onDetachedFromSequence(sequence: LayerAnimationSequence) {}
}

internal func animateOnChildWindowVisibilityChanged(_ window: Window, _ visible: Bool) -> Bool {
  if windowAnimationsDisabled(window: window) {
    return false
  }
  if visible {
    return animateShowWindow(window)
  }
  // Don't start hiding the window again if it's already being hidden.
  return window.layer!.targetOpacity != 0.0 && animateHideWindow(window)
}

internal func windowAnimationsDisabled(window: Window) -> Bool {
  // Individual windows can choose to skip animations.
  //if (window && window->GetProperty(aura::client::kAnimationsDisabledKey))
  //  return true;

  // Tests of animations themselves should still run even if the machine is
  // being accessed via Remote Desktop.
  //if (ui::ScopedAnimationDurationScaleMode::duration_scale_mode() ==
  //    ui::ScopedAnimationDurationScaleMode::NON_ZERO_DURATION)
  //  return false;

  // Let the user decide whether or not to play the animation.
  //return !gfx::Animation::ShouldRenderRichAnimation();
  return true
}

internal func animateHideWindow(_ window: Window) -> Bool {
  return false
}

internal func animateShowWindow(_ window: Window) -> Bool {
  if !hasWindowVisibilityAnimationTransition(window, .show) {
    if hasWindowVisibilityAnimationTransition(window, .hide) {
      // Since hide animation may have changed opacity and transform,
      // reset them to show the window.
      window.layer!.opacity = windowAnimationShowOpacity
      window.layer!.transform = Transform()
    }
    return false
  }

  switch getWindowVisibilityAnimationType(window) {
    case .drop:
      animateShowWindowDrop(window)
      return true
    case .vertical:
      animateShowWindowVertical(window)
      return true
    case .fade:
      animateShowWindowFade(window)
      return true
    case .rotate:
      animateShowWindowRotate(window)
      return true
    default:
      return false
  }
}

private func animateShowWindowCommon(window: Window,
                                     startTransform: Transform,
                                     endTransform: Transform) {
  augmentWindowSize(window: window, endTransform: endTransform)

  window.layer!.opacity = windowAnimationHideOpacity
  window.layer!.transform = startTransform
  window.layer!.isVisible = true
  do {
    // Property sets within this scope will be implicitly animated.
    let settings = ScopedLayerAnimationSettings(animator: window.layer!.animator)
    let duration: TimeDelta = getWindowVisibilityAnimationDuration(window)
    if duration > TimeDelta() {
      settings.transitionDuration = duration
    }
    window.layer!.transform = endTransform
    window.layer!.opacity = windowAnimationShowOpacity
  }
}

private func animateShowWindowFade(_ window: Window) {
  animateShowWindowCommon(window: window, startTransform: Transform(), endTransform: Transform())
}

private func animateShowWindowDrop(_ window: Window) {
  animateShowWindowCommon(window: window, startTransform: getScaleForWindow(window), endTransform: Transform())
}

private func animateShowWindowVertical(_ window: Window) {
  var transform = Transform()
  transform.translate(x: 0, y: window.property[UI.windowVisibilityAnimationVerticalPositionKey] as! Float)
  animateShowWindowCommon(window: window, startTransform: transform, endTransform: Transform())
}

private func animateShowWindowRotate(_ window: Window) {
  addLayerAnimationsForRotate(window: window, show: true)
}

fileprivate func augmentWindowSize(window: Window,
                                   endTransform: Transform) {
  guard let animationHost = UI.getAnimationHost(window: window) else {
    return
  }

  let worldAtStart = window.bounds
  let worldAtEnd: IntRect = getLayerWorldBoundsAfterTransform(window.layer!, endTransform)
  
  let unionInWindowSpace: IntRect = unionRects(worldAtStart, worldAtEnd)

  // Calculate the top left and bottom right deltas to be added to the window
  // bounds.
  let topLeftDelta = IntVec2(x: worldAtStart.x - unionInWindowSpace.x,
                             y: worldAtStart.y - unionInWindowSpace.y)

  let bottomRightDelta = IntVec2(
      x: unionInWindowSpace.x + unionInWindowSpace.width -
          (worldAtStart.x + worldAtStart.width),
      y: unionInWindowSpace.y + unionInWindowSpace.height -
          (worldAtStart.y + worldAtStart.height))

  assert(topLeftDelta.x >= 0 && topLeftDelta.y >= 0 &&
         bottomRightDelta.x >= 0 && bottomRightDelta.y >= 0)

  animationHost.setHostTransitionOffsets(topLeftDelta, bottomRightDelta)
}

fileprivate func addLayerAnimationsForRotate(window: Window, show: Bool) {
  
  if show {
    window.layer!.opacity = windowAnimationHideOpacity
  }

  let duration = TimeDelta.from(milliseconds: windowAnimationRotateDurationMS)

  var observer: RotateHidingWindowAnimationObserver? = nil

  if !show {
    observer = RotateHidingWindowAnimationObserver(window: window)
    window.layer!.animator.schedulePauseForProperties(
        duration: duration * (100 - windowAnimationRotateOpacityDurationPercent) / 100,
        propertiesToPause: LayerAnimationElement.AnimatableProperty.Opacity)
  }
  let opacity =
      LayerAnimationElement.createOpacityElement(
          opacity: show ? windowAnimationShowOpacity : windowAnimationHideOpacity,
          duration: duration * windowAnimationRotateOpacityDurationPercent / 100)
  opacity.tweenType = TweenType.EaseInOut
  window.layer!.animator.scheduleAnimation(animation: LayerAnimationSequence(element: opacity))

  let xcenter = Float(window.bounds.width) * 0.5

  var transform = Transform()
  transform.translate(x: xcenter, y: 0)
  transform.applyPerspectiveDepth(depth: windowAnimationRotatePerspectiveDepth)
  transform.translate(x: -xcenter, y: 0)
  let perspective = InterpolatedConstantTransform(transform: transform)

  let scale: InterpolatedTransform = InterpolatedScale(startScale: 1.0, endScale: windowAnimationRotateScaleFactor)
  let scaleAboutPivot: InterpolatedTransform =
      InterpolatedTransformAboutPivot(
          pivot: IntPoint(x: Int(xcenter), y: Int(windowAnimationRotateTranslateY)),
          transform: scale)

  let translation: InterpolatedTransform =
      InterpolatedTranslation(
          startPos: FloatPoint(), endPos: FloatPoint(x: 0, y: windowAnimationRotateTranslateY))

  let rotation: InterpolatedTransform = 
    InterpolatedAxisAngleRotation(
          axis: FloatVec3(x: 1.0, y: 0.0, z: 0.0), startDegrees: 0, endDegrees: windowAnimationRotateDegreesX)

  scaleAboutPivot.child = perspective
  translation.child = scaleAboutPivot
  rotation.child = translation
  rotation.reversed = show

  let transition: LayerAnimationElement = 
    LayerAnimationElement.createInterpolatedTransformElement(interpolatedTransform: rotation, duration: duration)
  let lastSequence: LayerAnimationSequence = LayerAnimationSequence(element: transition)
  window.layer!.animator.scheduleAnimation(animation: lastSequence)

  if let obs = observer {
    obs.setLastSequence(lastSequence)
    obs.detachAndRecreateLayers()
  }
}

fileprivate func hasWindowVisibilityAnimationTransition(
    _ window: Window,
    _ transition: WindowVisibilityAnimationTransition) -> Bool {
  if let prop: WindowVisibilityAnimationTransition = window.property[UI.windowVisibilityAnimationTransitionKey] as? WindowVisibilityAnimationTransition {
    return (prop.rawValue & transition.rawValue) != 0
  }
  return true
}

fileprivate func getWindowVisibilityAnimationType(_ window: Window) -> WindowVisibilityAnimationType {
  if let type: WindowVisibilityAnimationType = window.property[UI.windowVisibilityAnimationTypeKey] as? WindowVisibilityAnimationType {
    if type == WindowVisibilityAnimationType.standard {
      return (window.type == .Menu ||
              window.type == .Tooltip)
                ? WindowVisibilityAnimationType.fade
                : WindowVisibilityAnimationType.drop
    }
    return type
  }
  return WindowVisibilityAnimationType.drop//WindowVisibilityAnimationType.standard
}

fileprivate func getWindowVisibilityAnimationDuration(_ window: Window) -> TimeDelta {
  if let duration: TimeDelta = window.property[UI.windowVisibilityAnimationDurationKey] as? TimeDelta {
    if duration.isZero && window.type == .Menu {
      return TimeDelta.from(milliseconds: defaultAnimationDurationForMenuMS)
    }
    return duration
  }
  return TimeDelta.from(milliseconds: defaultAnimationDurationForMenuMS)
}

fileprivate func getScaleForWindow(_ window: Window) -> Transform {
  let bounds = window.bounds
  let scale: Transform = Graphics.getScaleTransform(
      anchor: IntPoint(x: Int(windowAnimationTranslateFactor) * bounds.width,
                       y: Int(windowAnimationTranslateFactor) * bounds.height),
      scale: windowAnimationScaleFactor)
  return scale
}

fileprivate func getTransformRelativeToRoot(layer: Layer, transform: inout Transform) {
  var root: Layer? = layer
  while root?.parent != nil {
    root = root!.parent
  }
  let _ = layer.getTargetTransformRelativeTo(ancestor: root!, transform: &transform)
}

fileprivate func getLayerWorldBoundsAfterTransform(_ layer: Layer, _ transform: Transform) -> IntRect {
  var inWorld = transform
  getTransformRelativeToRoot(layer: layer, transform: &inWorld)
  var transformed = FloatRect(layer.bounds)
  inWorld.transformRect(rect: &transformed)
  return IntRect.toEnclosingRect(rect: transformed)
}

fileprivate let windowAnimationShowOpacity: Float = 1.0
fileprivate let windowAnimationHideOpacity: Float = 0.0
fileprivate let defaultAnimationDurationForMenuMS: Int64 = 150
fileprivate let windowAnimationRotateDurationMS: Int64 = 180
fileprivate let windowAnimationRotateOpacityDurationPercent: Int = 90
fileprivate let windowAnimationRotateTranslateY: Float = -20.0
fileprivate let windowAnimationRotatePerspectiveDepth: Float = 500.0
fileprivate let windowAnimationRotateDegreesX: Float = 5.0
fileprivate let windowAnimationRotateScaleFactor: Float = 0.99
fileprivate let windowAnimationTranslateFactor: Float = 0.5
fileprivate let windowAnimationScaleFactor: Float = 0.95
