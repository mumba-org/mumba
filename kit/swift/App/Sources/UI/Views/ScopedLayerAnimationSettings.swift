// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class ScopedLayerAnimationSettings {

  public var tweenType: TweenType {
    get {
      return animator.tweenType
    }
    set {
      animator.tweenType = newValue
    }
  }
  public var preemptionStrategy: PreemptionStrategy {
    get {
      return animator.preemptionStrategy
    }
    set {
      animator.preemptionStrategy = newValue
    }
  }
  
  public var transitionDuration: TimeDelta {
    get {
      return animator.transitionDuration
    }
    set {
      animator.transitionDuration = newValue
    }
  }

  public private(set) var animator: LayerAnimator
  
  private var oldIsTransitionDurationLocked: Bool
  private var oldTransitionDuration: TimeDelta
  private var oldTweenType: TweenType
  private var oldPreemptionStrategy: PreemptionStrategy

  private var observers: ContiguousArray<ImplicitAnimationObserver>
 
  public init(animator: LayerAnimator) { 
    observers = ContiguousArray<ImplicitAnimationObserver>()
    self.animator = animator
    oldIsTransitionDurationLocked = animator.isTransitionDurationLocked
    oldTransitionDuration = animator.transitionDuration
    oldTweenType = animator.tweenType
    oldPreemptionStrategy = animator.preemptionStrategy

    self.transitionDuration = TimeDelta.from(milliseconds: scopedLayerAnimationDefaultTransitionDurationMs)
  }

  deinit {
    animator.isTransitionDurationLocked = oldIsTransitionDurationLocked
    animator.transitionDuration = oldTransitionDuration
    animator.tweenType = oldTweenType
    animator.preemptionStrategy = oldPreemptionStrategy
    for observer in observers {
      if let index = animator.observers.firstIndex(where: { $0 === observer }) {
        animator.observers.remove(at: index)
        observer.active = true
      }
    }
  }
  
  public func addObserver(observer: ImplicitAnimationObserver) {
    observers.append(observer)
  }
  
  public func lockTransitionDuration() {
    animator.isTransitionDurationLocked = true
  }

  public func cacheRenderSurface() {
    let observer = ScopedRenderSurfaceCaching(layer: animator.delegate!.uiLayer!)
    addObserverToSettings(settings: self, observer: observer)
  }

  public func deferPaint() {
    addScopedDeferredPaintingObserverRecursive(layer: animator.delegate!.uiLayer!, settings: self)
  }

  public func trilinearFiltering() {
    let observer = ScopedTrilinearFiltering(layer: animator.delegate!.uiLayer!)
    addObserverToSettings(settings: self, observer: observer)
  }

}

fileprivate let scopedLayerAnimationDefaultTransitionDurationMs: Int64 = 200

internal class ScopedLayerAnimationObserver<T: Trait> : ImplicitAnimationObserver, LayerObserver {
  
  fileprivate var layer: Layer?
  
  public init(layer: Layer) {
    self.layer = layer
    super.init()
    layer.addObserver(observer: self)
    T.addRequest(layer: layer)
  }
  
  deinit {
    if let l = layer {
      l.removeObserver(observer: self)
    }
  }

  // ImplicitAnimationObserver
  public override func onImplicitAnimationsCompleted() {
    // If animation finishes before |layer_| is destoyed, we will remove the
    // request applied on the layer and remove |this| from the |layer_|
    // observer list when deleting |this|.
    if let l = layer {
      T.removeRequest(layer: l)
      l.animator.removeAndDestroyOwnedObserver(animationObserver: self)
    }
  }

  // LayerObserver
  public func layerDestroyed(layer destroyed: Layer) {
    // If the animation is still going past layer destruction then we want the
    // layer to keep the request until the animation has finished. We will defer
    // deleting |this| until the animation finishes.
    layer!.removeObserver(observer: self)
    layer = nil
  }
}

protocol Trait {
  static func addRequest(layer: Layer)
  static func removeRequest(layer: Layer)
}

struct RenderSurfaceCachingTrait : Trait {
  static func addRequest(layer: Layer) {
    layer.addCacheRenderSurfaceRequest()
  }
  static func removeRequest(layer: Layer) {
    layer.removeCacheRenderSurfaceRequest()
  }
}

typealias ScopedRenderSurfaceCaching = ScopedLayerAnimationObserver<RenderSurfaceCachingTrait>

struct DeferredPaintingTrait : Trait {
  static func addRequest(layer: Layer) { layer.addDeferredPaintRequest() }
  static func removeRequest(layer: Layer) {
    layer.removeDeferredPaintRequest()
  }
}

typealias ScopedDeferredPainting = ScopedLayerAnimationObserver<DeferredPaintingTrait>

struct TrilinearFilteringTrait : Trait {
  static func addRequest(layer: Layer) {
    layer.addTrilinearFilteringRequest()
  }
  static func removeRequest(layer: Layer) {
    layer.removeTrilinearFilteringRequest()
  }
}

typealias ScopedTrilinearFiltering = ScopedLayerAnimationObserver<TrilinearFilteringTrait>

fileprivate func addObserverToSettings(
    settings: ScopedLayerAnimationSettings,
    observer: ImplicitAnimationObserver ) {
  settings.addObserver(observer: observer)
  settings.animator.addOwnedObserver(animationObserver: observer)
}

fileprivate func addScopedDeferredPaintingObserverRecursive(
    layer: Layer,
    settings: ScopedLayerAnimationSettings) {
  let observer = ScopedDeferredPainting(layer: layer)
  addObserverToSettings(settings: settings, observer: observer)
  for child in layer.children {
    addScopedDeferredPaintingObserverRecursive(layer: child, settings: settings)
  }
}
