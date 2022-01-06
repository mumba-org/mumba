// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

let frameViewIndex = 0
let clientViewIndex = 1

public class NonClientFrameView : View {

  internal static let frameShadowThickness: Int = 1
  internal static let clientEdgeThickness: Int = 1

  public var boundsForClientView: IntRect {
    return IntRect()
  }

  public override var className: String {
    return "NonClientFrameView"
  }

  var inactiveRenderingDisabled: Bool

  public override init() {
    inactiveRenderingDisabled = false
    super.init()
    eventTargeter = ViewTargeter(delegate: self)
  }

  public func setInactiveRenderingDisabled(disable: Bool) {
    guard inactiveRenderingDisabled != disable else {
      return
    }

    let shouldPaintAsActiveOld = shouldPaintAsActive()
    inactiveRenderingDisabled = disable

    // The widget schedules a paint when the activation changes.
    if shouldPaintAsActiveOld != shouldPaintAsActive() {
      schedulePaint()
    }
  }

  public func shouldPaintAsActive() -> Bool {
    return inactiveRenderingDisabled || widget!.isActive
  }

  public func getHTComponentForFrame(point: IntPoint,
    topResizeBorderHeight: Int,
    resizeBorderThickness: Int,
    topResizeCornerHeight: Int,
    resizeCornerWidth: Int,
    canResize: Bool) -> HitTest {

    let component: HitTest

    if point.x < resizeBorderThickness {

      if point.y < topResizeCornerHeight {
        component = .HTTOPLEFT
      } else if point.y >= (height - resizeBorderThickness) {
        component = .HTBOTTOMLEFT
      } else {
        component = .HTLEFT
      }
    } else if point.x >= (width - resizeBorderThickness) {
      if point.y < topResizeCornerHeight {
        component = .HTTOPRIGHT
      } else if point.y >= (height - resizeBorderThickness) {
        component = .HTBOTTOMRIGHT
      } else {
        component = .HTRIGHT
      }
    } else if point.y < topResizeBorderHeight {
      if point.x < resizeCornerWidth {
        component = .HTTOPLEFT
      } else if point.x >= (width - resizeCornerWidth) {
        component = .HTTOPRIGHT
      } else {
        component = .HTTOP
      }
    } else if point.y >= (height - resizeBorderThickness) {
      if point.x < resizeCornerWidth {
        component = .HTBOTTOMLEFT
      } else if point.x >= (width - resizeCornerWidth) {
        component = .HTBOTTOMRIGHT
      } else {
        component = .HTBOTTOM
      }
    } else {
      return .HTNOWHERE
    }

    // If the window can't be resized, there are no resize boundaries, just
    // window borders.
    return canResize ? component : .HTBORDER
  }

  public func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect { return IntRect() }

  public func getClientMask(size: IntSize) -> Path? {
    return nil
  }

  public func nonClientHitTest(point: IntPoint) -> HitTest { return .HTNOWHERE }

  public func getWindowMask(size: IntSize) -> Path? {
    return nil
  }

  public func resetWindowControls() {}

  public func updateWindowIcon() {}

  public func updateWindowTitle() {}

  public func sizeConstraintsChanged() {}

  public func activationChanged(active: Bool) {}

  // View:
  public override func getAccessibleState(state: inout AXViewState) {}
  public override func onBoundsChanged(previousBounds: IntRect) {}

  // ViewTargeterDelegate:
  public override func doesIntersectRect(target: View, rect: IntRect) -> Bool {
    assert(target === self)

    // For the default case, we assume the non-client frame view never overlaps
    // the client view.
    return !widget!.clientView!.bounds.intersects(rect: rect)
  }

}

public class NonClientView : View {

  // public override var preferredSize: IntSize {
  //   let clientBounds = IntRect(origin: IntPoint(), size: clientView!.preferredSize)
  //   return getWindowBoundsForClientBounds(clientBounds: clientBounds).size
  // }
  public override var minimumSize: IntSize { return frameView!.minimumSize }
  public override var maximumSize: IntSize { return frameView!.maximumSize }
  public override var className: String { return "NonClientView" }
  public var canClose: Bool { return clientView!.canClose }

  public var frameView: NonClientFrameView? {
    get {
      return _frameView
    }
    set (view) {
      // view.ownedByClient
      if let fview = _frameView {
        removeChild(view: fview)
      }

      _frameView = view

      if parent != nil {
        addChildAt(view: _frameView!, index: frameViewIndex)
      }
    }
  }

  public var clientView: ClientView?

  public var overlayView: View? {
    get {
      return _overlayView
    }

    set (newView) {

      if let view = _overlayView {
        removeChild(view: view)
      }

      guard newView != nil else {
        return
      }

      _overlayView = newView

      if parent != nil {
        if let view = _overlayView {
          addChild(view: view)
        }
      }
    }

  }

  public var mirrorClientInRtl: Bool

  private var _overlayView: View?

  private var _frameView: NonClientFrameView?

  public override init() {
    mirrorClientInRtl = true
    super.init()
    eventTargeter = ViewTargeter(delegate: self)
  }

  deinit {
    if let view = _frameView {
      removeChild(view: view)
    }
  }

  public func windowClosing() {
    clientView!.windowClosing()
  }

  public func updateFrame() {
    frameView = widget!.createNonClientFrameView()
    //window.themeChanged()
    layout()
    schedulePaint()
  }

  public func setInactiveRenderingDisabled(disable: Bool) {
    frameView!.setInactiveRenderingDisabled(disable: disable)
  }

  public func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect {
    return frameView!.getWindowBoundsForClientBounds(clientBounds: clientBounds)
  }

  public func nonClientHitTest(point: IntPoint) -> HitTest {
    return frameView!.nonClientHitTest(point: point)
  }

  public func getWindowMask(size: IntSize, windowMask: inout Path) {
    if let path = frameView!.getWindowMask(size: size) {
      windowMask = path//frameView!.getWindowMask(size: size windowMask: &windowMask)
    }
  }

  public func resetWindowControls() {
    frameView!.resetWindowControls()
  }

  public func updateWindowIcon() {
    frameView!.updateWindowIcon()
  }

  public func updateWindowTitle() {
    frameView!.updateWindowTitle()
  }

  public func sizeConstraintsChanged() {
    frameView!.sizeConstraintsChanged()
  }

  open override func calculatePreferredSize() -> IntSize {
    let clientBounds = IntRect(origin: IntPoint(), size: clientView!.preferredSize)
    return getWindowBoundsForClientBounds(clientBounds: clientBounds).size    
  }

  public func layoutFrameView() {
    frameView!.bounds = IntRect(x: 0, y: 0, width: width, height: height)
    // We need to manually call Layout here because layout for the frame view can
    // change independently of the bounds changing - e.g. after the initial
    // display of the window the metrics of the native window controls can change,
    // which does not change the bounds of the window but requires a re-layout to
    // trigger a repaint. We override OnBoundsChanged() for the NonClientFrameView
    // to do nothing so that SetBounds above doesn't cause Layout to be called
    // twice.
    frameView!.layout()
  }

  public func setAccessibleName(name: String) {

  }

  public override func layout() {
    layoutFrameView()

    // Then layout the ClientView, using those bounds.
    var clientBounds = frameView!.boundsForClientView

    // RTL code will mirror the ClientView in the frame by default.  If this isn't
    // desired, do a second mirror here to get the standard LTR position.
    if i18n.isRTL() && !mirrorClientInRtl {
      clientBounds.x = getMirroredXForRect(rect: clientBounds)
    }

    clientView!.bounds = clientBounds

    if let clientClip = frameView!.getClientMask(size: clientView!.size) {
      clientView!.clipPath = clientClip
    }

    // We need to manually call Layout on the ClientView as well for the same
    // reason as above.
    clientView!.layout()

    if let view = overlayView, view.isVisible {
      view.bounds = localBounds
    }
  }

  public override func getAccessibleState(state: inout AXViewState) {

  }

  public override func getTooltipHandlerFor(point p: IntPoint) -> View? {
    if frameView!.parent === self {
      // During the reset of the frame_view_ it's possible to be in this code
      // after it's been removed from the view hierarchy but before it's been
      // removed from the NonClientView.
      var pointInChildCoords = IntPoint(p)
      View.convertPointToTarget(source: self, target: frameView!, point: &pointInChildCoords)
      if let handler = frameView!.getTooltipHandlerFor(point: pointInChildCoords) {
        return handler
      }
    }

    return super.getTooltipHandlerFor(point: p)
  }

  public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if details.isAdd && widget != nil && details.child === self {
      addChildAt(view: frameView!, index: frameViewIndex)
      assert(clientView != nil)
      addChildAt(view: clientView!, index: clientViewIndex)
      if let view = _overlayView {
        addChild(view: view)
      }
    }
  }

  public override func targetForRect(root: View, rect: IntRect) -> View? {
    assert(root === self)

    if !usePointBasedTargeting(rect: rect) {
      return super.targetForRect(root: root, rect: rect)
    }

    // Because of the z-ordering of our child views (the client view is positioned
    // over the non-client frame view, if the client view ever overlaps the frame
    // view visually (as it does for the browser window), then it will eat
    // events for the window controls. We override this method here so that we can
    // detect this condition and re-route the events to the non-client frame view.
    // The assumption is that the frame view's implementation of HitTest will only
    // return true for area not occupied by the client view.
    if frameView!.parent === self {
      // During the reset of the frame_view_ it's possible to be in this code
      // after it's been removed from the view hierarchy but before it's been
      // removed from the NonClientView.
      var rectInChildCoordsf = FloatRect(rect)
      View.convertRectToTarget(source: self, target: frameView!, rect: &rectInChildCoordsf)
      let rectInChildCoords = IntRect.toEnclosingRect(rect: rectInChildCoordsf)
      if frameView!.hitTest(rect: rectInChildCoords) {
        return frameView!.getEventHandlerFor(rect: rectInChildCoords)
      }
    }

    return super.targetForRect(root: root, rect: rect)
  }

}
