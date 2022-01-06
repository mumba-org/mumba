// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate struct Constants {
  fileprivate static let defaultInkDropSize: Int = 24
  fileprivate static let largeInkDropScale: Float = 1.333
  fileprivate static let inkDropVisibleOpacity: Float = 0.175
  fileprivate static let inkDropSmallCornerRadius: Int = 2
  fileprivate static let inkDropLargeCornerRadius: Int = 4
}

public protocol InkDropHost : class {
  func createInkDrop() -> InkDrop?
  func createInkDropRipple() -> InkDropRipple?
  func createInkDropHighlight() -> InkDropHighlight?
  func addInkDropLayer(layer: Layer)
  func removeInkDropLayer(layer: Layer)
}

public class InkDropHostView : View, InkDropHost {

  public enum InkDropMode {
    case Off
    case On
    case OnNoGestureHandler
  }
  
  public var inkDropMode: InkDropMode {
    didSet {
      _inkDrop = nil
      if inkDropMode != InkDropMode.On {
        gestureHandler = nil
      } else if gestureHandler == nil {
        gestureHandler = InkDropGestureHandler(hostView: self)
      }
    }
  }
  public var inkDropVisibleOpacity: Float
  public var inkDropSmallCornerRadius: Int
  public var inkDropLargeCornerRadius: Int

  public var inkDropCenterBasedOnLastEvent: IntPoint {
    return lastRippleTriggeringEvent != nil
             ? lastRippleTriggeringEvent!.location
             : getMirroredRect(rect: contentsBounds).centerPoint
  }

  internal var inkDropBaseColor: Color {
    assert(false)
    return Colors.placeholderColor
  }

  internal var hasInkDrop: Bool {
    return _inkDrop != nil
  }

  internal var inkDrop: InkDrop? {
    if _inkDrop == nil {
      if inkDropMode == InkDropMode.Off {
        _inkDrop = InkDropStub()
      } else {
        _inkDrop = createInkDrop()
      }
      onInkDropCreated()
    }
    return _inkDrop
  }

  fileprivate var lastRippleTriggeringEvent: LocatedEvent?
  
  fileprivate var gestureHandler: InkDropGestureHandler?

  fileprivate var oldPaintToLayer: Bool

  fileprivate var inkDropMask: InkDropMask?

  fileprivate var _inkDrop: InkDrop?

  public override init() {
    inkDropMode = InkDropMode.Off
    inkDropVisibleOpacity = 
          PlatformStyle.useRipples ? Constants.inkDropVisibleOpacity : 0
    inkDropSmallCornerRadius = Constants.inkDropSmallCornerRadius
    inkDropLargeCornerRadius = Constants.inkDropLargeCornerRadius
    oldPaintToLayer = false
  }

  public func setInkDropCornerRadii(smallRadius: Int, largeRadius: Int) {
    inkDropSmallCornerRadius = smallRadius
    inkDropLargeCornerRadius = largeRadius
  }

  public func createInkDropMask() -> InkDropMask? {
    return nil
  }

  public func animateInkDrop(state: InkDropState, event: LocatedEvent?) {
#if os(Windows)
  // On Windows, don't initiate ink-drops for touch/gesture events.
  // Additionally, certain event states should dismiss existing ink-drop
  // animations. If the state is already other than HIDDEN, presumably from
  // a mouse or keyboard event, then the state should be allowed. Conversely,
  // if the requested state is ACTIVATED, then it should always be allowed.
    if let ev = event && (ev.isTouchEvent || ev.isGestureEvent &&
      inkDrop!.targetInkDropState == InkDropState.Hidden &&
      state != InkDropState.Activated) {
      return
    }
#endif
    lastRippleTriggeringEvent = 
        event != nil ? (Event.clone(event!) as! LocatedEvent) : nil
    inkDrop!.animateToState(state: state)
  }

  internal static func calculateLargeInkDropSize(_ smallSize: IntSize) -> IntSize {
     return IntSize.scaleToCeiled(smallSize, scale: Constants.largeInkDropScale)
  }

  internal func createDefaultInkDropRipple(centerPoint: IntPoint,
    size: IntSize = IntSize(width: Constants.defaultInkDropSize, height: Constants.defaultInkDropSize)) -> InkDropRipple {
    let ripple = SquareInkDropRipple(
      largeSize: InkDropHostView.calculateLargeInkDropSize(size), 
      largeCornerRadius: inkDropLargeCornerRadius,
      smallSize: size,
      smallCornerRadius: inkDropSmallCornerRadius,
      centerPoint: centerPoint,
      color: inkDropBaseColor,
      visibleOpacity: inkDropVisibleOpacity)
    return ripple
  }

  internal func createDefaultInkDropHighlight(
      centerPoint: FloatPoint,
      size: IntSize = IntSize(width: Constants.defaultInkDropSize, height: Constants.defaultInkDropSize)) -> InkDropHighlight {
    let highlight = InkDropHighlight(size: size, cornerRadius: inkDropSmallCornerRadius, centerPoint: centerPoint, color: inkDropBaseColor)
    highlight.explodeSize = InkDropHostView.calculateLargeInkDropSize(size)
    return highlight
  }

  public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if !details.isAdd && details.child === self && inkDrop != nil {
      inkDrop!.snapToHidden()
      inkDrop!.isHovered = false
    }
    super.viewHierarchyChanged(details: details)
  }
  
  public override func onBoundsChanged(previousBounds: IntRect) {
    if let inkdrop = inkDrop {
      inkdrop.hostSizeChanged(size: size)
    }
    updateInkDropMaskLayerSize(size: size)
  }
  
  public override func visibilityChanged(startingFrom: View, isVisible: Bool) {
    super.visibilityChanged(startingFrom: startingFrom, isVisible: isVisible)
    if inkDrop != nil && widget != nil && !isVisible {
      inkDrop!.animateToState(state: InkDropState.Hidden)
      inkDrop!.isHovered = false
    }
  }
  
  public override func onFocus() {
    super.onFocus()
    if let inkdrop = inkDrop {
      inkdrop.isFocused = true
    }
  }
  
  public override func onBlur() {
    super.onBlur()
    if let inkdrop = inkDrop {
      inkdrop.isFocused = false
    }
  }
  
  public override func onMouseEvent(event: inout MouseEvent) {
    switch event.type {
      case .MouseEntered:
        inkDrop!.isHovered = true
      case .MouseExited:
        inkDrop!.isHovered = false
      case .MouseDragged:
        inkDrop!.isHovered = localBounds.contains(point: event.location)
      default:
        break
    }
    super.onMouseEvent(event: &event)
  }

  // InkDropHost
  public func createInkDrop() -> InkDrop? {
    return createDefaultInkDropImpl()
  }
  
  public func createInkDropRipple() -> InkDropRipple? {
    return createDefaultInkDropRipple(centerPoint: getMirroredRect(rect: contentsBounds).centerPoint)
  }
  
  public func createInkDropHighlight() -> InkDropHighlight? {
    return createDefaultInkDropHighlight(centerPoint: FloatRect(getMirroredRect(rect: contentsBounds)).centerPoint)
  }
  
  public func addInkDropLayer(layer inkDropLayer: Layer) {
    oldPaintToLayer = layer != nil
    if !oldPaintToLayer {
      setPaintToLayer()
    }

    layer!.fillsBoundsOpaquely = false
    installInkDropMask(layer: inkDropLayer)
    layer!.add(child: inkDropLayer)
    layer!.stackAtBottom(child: inkDropLayer)
  }
  
  public func removeInkDropLayer(layer inkDropLayer: Layer) {
    layer!.remove(child: inkDropLayer)
    // Layers safely handle destroying a mask layer before the masked layer.
    inkDropMask = nil
    if !oldPaintToLayer {
      destroyLayer()
    }
  }

  internal func onInkDropCreated() {}

  internal func installInkDropMask(layer inkDropLayer: Layer) {
    inkDropMask = createInkDropMask()
    if let mask = inkDropMask {
      inkDropLayer.layerMask = mask.layer
    }
  }

  internal func resetInkDropMask() {
    inkDropMask = nil
  }

  // Updates the ink drop mask layer size to |new_size|. It does nothing if
  // |ink_drop_mask_| is null.
  internal func updateInkDropMaskLayerSize(size newSize: IntSize) {
    if let mask = inkDropMask {
      mask.updateLayerSize(size: newSize)
    }
  }

  // Returns an InkDropImpl configured to work well with a
  // flood-fill ink drop ripple.
  internal func createDefaultFloodFillInkDropImpl() -> InkDropImpl {
    let inkDrop = createDefaultInkDropImpl()
    inkDrop.autoHighlightMode = AutoHighlightMode.ShowOnRipple
    return inkDrop
  }

  // Returns an InkDropImpl with default configuration. The base implementation
  // of CreateInkDrop() delegates to this function.
  internal func createDefaultInkDropImpl() -> InkDropImpl {
    let inkDrop = InkDropImpl(inkDropHost: self, hostSize: size)
    inkDrop.autoHighlightMode = AutoHighlightMode.HideOnRipple
    return inkDrop
  }

}

public class InkDropContainerView : View {
  
  public override var canProcessEventsWithinSubtree: Bool {
    get {
      return false
    }
    set {
      
    }
  }

  public override init() {}
  
  public func addInkDropLayer(inkDropLayer: Layer) {
    setPaintToLayer()
    isVisible = true
    layer!.fillsBoundsOpaquely = false
    layer!.add(child: inkDropLayer)
  }
  
  public func removeInkDropLayer(inkDropLayer: Layer) {
    layer!.remove(child: inkDropLayer)
    isVisible = false
    destroyLayer()
  }

}

fileprivate class InkDropStub : InkDrop {
  public var observers: [InkDropObserver] = []
  public var targetInkDropState: InkDropState = .Hidden
  public var isHovered: Bool = false
  public var isFocused: Bool = false
  public var isHighlightFadingInOrVisible: Bool = false
  public var showHighlightOnHover: Bool = false
  public var showHighlightOnFocus: Bool = false

  public init() {}
  public func hostSizeChanged(size :IntSize) {}
  public func animateToState(state: InkDropState) {}
  public func setHoverHighlightFadeDuration(miliseconds: Int) {}
  public func useDefaultHoverHighlightFadeDuration() {}
  public func snapToActivated() {}
  public func snapToHidden() {}
  public func addObserver(observer: InkDropObserver) {}
  public func removeObserver(observer: InkDropObserver) {}
  public func notifyInkDropAnimationStarted() {}
  public func notifyInkDropRippleAnimationEnded(state: InkDropState) {}
}

// TODO: this is not really working as its supposed to
internal class InkDropGestureHandler : GestureEventHandler {
  
  weak var hostView: InkDropHostView?

  init(hostView: InkDropHostView?) {
    self.hostView = hostView
  }
  
  public func onGestureEvent(event: inout GestureEvent) {

  }
}