// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Platform

#if os(Linux)
import Glibc // for floor()
#endif

public typealias Views = [View]
public typealias PlatformViewAccessible = Int

let contextMenuOnMousePress = true
let AXEventHover = AXEvent()
let AXEventFocus = AXEvent()
let rectTargetOverlap: Float = 0.6

private func getHierarchyRoot(view: View) -> View {
  var root: View? = view
  while root != nil && root!.parent != nil {
    root = root!.parent
  }
  return root!
}

internal func usePointBasedTargeting(rect: IntRect) -> Bool {
  return rect.width == 1 && rect.height == 1
}

internal func distanceSquaredFromCenterToPoint(point: IntPoint, rect: IntRect) -> Int {
  let centerPoint = rect.centerPoint
  let dx = centerPoint.x - point.x
  let dy = centerPoint.y - point.y
  return (dx * dx) + (dy * dy)
}

internal func percentCoveredBy(r1: IntRect, r2: IntRect) -> Float {
  var intersection = IntRect(r1)
  intersection.intersect(rect: r2)
  let intersectArea = intersection.size.area
  let r1Area = r1.size.area
  //return r1Area != nil ?
      return Float(intersectArea) / Float(r1Area)// : 0
}

public struct ViewHierarchyChangedDetails {
  public var isAdd: Bool
  public var parent: View?
  public var child: View?
  public var moveView: View?
}

 public struct ViewDragInfo {
  var possibleDrag: Bool
  var startPoint: IntPoint

  init() {
    possibleDrag = false
    startPoint = IntPoint()
  }

  mutating func setPossibleDrag(p: IntPoint) {
    possibleDrag = true
    startPoint = p
  }

  mutating func reset() {
    possibleDrag = false
    startPoint = IntPoint()
  }

}

open class View : EventTarget,
                  AcceleratorTarget,
                  ViewTargeterDelegate,
                  DragDropDelegate {

  public enum FocusBehavior {
    case never
    case always
    case accessibleOnly
  }                   

  enum SchedulePaintType {
    case SizeSame
    case SizeChanged
  }

  public enum LayerChangeNotifyBehavior {
    case notify
    case dontNotify
  }

  static public var shouldShowContextMenuOnMousePress: Bool {
    return false
  }

  open var widget: UIWidget? {
    return parent != nil ? parent!.widget : nil
  }

  open var className: String {
    return "View"
  }

  open var isDrawn: Bool {
    return isVisible && (parent != nil ? parent!.isDrawn : false)
  }

  open var childCount: Int {
    return children.count
  }

  open var hasChildren: Bool {
    return children.count > 0
  }

  private (set) public var parent: View?

  open var x: Int {
    get {
      return bounds.x
    }
    set {
      bounds.x = newValue
    }
  }

  open var y: Int {
    get {
      return bounds.y
    }
    set {
      bounds.y = newValue
    }
  }

  open var bounds: IntRect {
    get {
      return _bounds
    }

    set {
      if newValue == _bounds {
        if needsLayout {
          needsLayout = false
          layout()
        }
        return
      }

      if isVisible {
        // Paint where the view is currently.
        schedulePaintBoundsChanged(
          type: _bounds.size == bounds.size ? .SizeSame : .SizeChanged)
      }

      let prev = _bounds
      _bounds = newValue
      boundsChanged(previousBounds: prev)

      for observer in observers {
        observer.onViewBoundsChanged(observed: self)
      }
    }
  }

  public var clipPath: Path = Path()

  open var size: IntSize {
    get {
      return bounds.size
    }
    set (newSize) {
      ////print(" set bounds -> \(className): new \(newSize) old \(bounds.size)")
      bounds = IntRect(x: x, y: y, width: newSize.width, height: newSize.height)
    }
  }

  open var width: Int {
    return bounds.width
  }

  open var height: Int {
    return bounds.height
  }

  open var position: IntPoint {
    get {
      return IntPoint(x: bounds.x, y: bounds.y)
    }
    set (pos) {
      bounds = IntRect(x: pos.x, y: pos.y, width: width, height: height)
    }
  }

  open var contentsBounds: IntRect {
    var cbounds = localBounds
    if let b = border {
      cbounds.inset(insets: b.insets)
    }
    ////print("\(className): \(localBounds) \(cbounds)")
    return cbounds
  }

  open var localBounds: IntRect {
    return IntRect(size: size)
  }

  open var layerBoundsInPixel: IntRect {
    return layer!.targetBounds
  }

  open var insets: IntInsets {
    return border != nil ? border!.insets : IntInsets()
  }

  open var visibleBounds: IntRect {

    if !isDrawn {
      return IntRect()
    }

    var visBounds = localBounds
    var ancestorBounds = IntRect()
    var view: View! = self
    var transform = Transform()

    while view != nil && !visBounds.isEmpty {
      transform.concatTransform(transform: view.transform)
      var translation = Transform()
      translation.translate(x: Float(view.mirroredX),
                            y: Float(view.y))
      transform.concatTransform(transform: translation)

      visBounds = view.convertRectToParent(rect: visBounds)

      let ancestor = view.parent
      if ancestor != nil {
        ancestorBounds.set(x: 0, y: 0, width: ancestor!.width, height: ancestor!.height)
        visBounds.intersect(rect: ancestorBounds)
      } else if view.widget == nil {
        // If the view has no UIWidget, we're not visible. Return an empty rect.
        return IntRect()
      }
      view = ancestor
    }
    if visBounds.isEmpty {
      return visBounds
    }
    // Convert back to this views coordinate system.
    var viewsVisBounds = FloatRect(visBounds)
    let _ = transform.transformRectReverse(rect: &viewsVisBounds)
    // Partially visible pixels should be considered visible.
    return IntRect.toEnclosingRect(rect: viewsVisBounds)
  }

  open var boundsInScreen: IntRect {
    var origin = IntPoint()
    View.convertPointToScreen(src: self, point: &origin)
    return IntRect(origin: origin, size: size)
  }
  
  open var baseline: Int {
    return -1
  }

  open var preferredSize: IntSize {
    get {
      if let size = _preferredSize {
        return size
      }
      return calculatePreferredSize()
    }
    set {
      if let size = _preferredSize, size == newValue {
        return
      }
       _preferredSize = newValue
      preferredSizeChanged()
    }
  }

  open var minimumSize: IntSize {
    return preferredSize
  }

  open var maximumSize: IntSize {
    return IntSize()
  }

  open var transform: Transform {
    get {
      return layer != nil ? layer!.transform : Transform()
    }
    set {
      if transform.isIdentity {
        if let l = layer {
          l.transform = newValue
          if !_paintToLayer {
            destroyLayer()
          }
        } else {
          // Nothing.
        }
      } else {
        if layer == nil {
          createLayer()
        }
        layer!.transform = newValue
        layer!.scheduleDraw()
      }
    }
  }

  open var layoutManager: LayoutManager? {
    get {
      return _layoutManager
    }
    set {
      if _layoutManager != nil {
        _layoutManager!.uninstalled(host: self)
      }

      _layoutManager = newValue
      if _layoutManager != nil {
        _layoutManager!.installed(host: self)
      }
    }
  }

  open var contextMenuController: ContextMenuController?

  open var mirroredBounds: IntRect {
    var bounds = _bounds
    bounds.x = mirroredX
    return bounds
  }

  open var mirroredPosition: IntPoint {
    return IntPoint(x: mirroredX, y: y)
  }

  open var mirroredX: Int {
    return parent != nil ? parent!.getMirroredXForRect(rect: _bounds) : x
  }

  open var isVisible: Bool {
    get {
      return _visible
    }
    set {
      if newValue != _visible {
        // If the View is currently visible, schedule paint to refresh parent.
        // TODO(beng): not sure we should be doing this if we have a layer.
        if _visible {
          schedulePaint()
        }

        _visible = newValue
        advanceFocusIfNecessary()

        // Notify the parent.
        if let p = parent {
          p.childVisibilityChanged(child: self)
        }

        for observer in observers {
          observer.onViewVisibilityChanged(observed: self)
        }

        // This notifies all sub-views recursively.
        propagateVisibilityNotifications(from: self, isVisible: _visible)
        updateLayerVisibility()

        // If we are newly visible, schedule paint.
        if _visible {
          schedulePaint()
        }
      }
    }
  }

  open var isEnabled: Bool {
    get {
      return _enabled
    }
    set {
      if newValue != _enabled {
        _enabled = newValue
        advanceFocusIfNecessary()
        onEnabledChanged()
        for observer in observers {
          observer.onViewEnabledChanged(observed: self)
        }
      }
    }
  }

  // open var paintToLayer: Bool {
  //   get {
  //     return _paintToLayer
  //   }
  //   set {
  //     //print("View.paintToLayer setter")
  //     guard _paintToLayer != newValue else {
  //       return
  //     }
  //     _paintToLayer = newValue
  //     if _paintToLayer && layer == nil {
  //       //print("View.paintToLayer setter")
  //       createLayer()
  //     } else if !_paintToLayer && layer != nil {
  //       destroyLayer()
  //     }
  //   }
  // }

   open var canHandleAccelerators: Bool {
    if let win = widget {
      return isEnabled && isDrawn && win.isVisible
    }
    return false
  }

  private (set) public var targeter: ViewTargeter?

  open override var parentTarget: EventTarget? {
    get {
      return parent
    }
  }

  open override var eventTargeter: EventTargeter? {
    get {
      return targeter
    }
    set {
      targeter = newValue as? ViewTargeter
    }
  }

  open override var targetHandler: EventHandler? {
    get { return nil }
    set {}
  }

  open override var isPreTargetListEmpty: Bool {
    get { return false }
    set {}
  }

  open override var childIterator: EventTargetIterator<EventTarget> {
    return EventTargetIterator<EventTarget>()
  }

  open var focusManager: FocusManager? {
    get {
      if let w = widget {
        return w.focusManager
      }
      return nil
    }
    set {

    }
  }

  open var hasFocus: Bool {
    if let manager = focusManager {
      return manager.focusedView === self
    }
    return false
  }

  open var nextFocusableView: View? {
    get {
      return _nextFocusableView
    }
    set {
      if let v = newValue {
        v.previousFocusableView = self
      }
      _nextFocusableView = newValue
    }
  }

  private (set) public var previousFocusableView: View?

  open var focusable: Bool {
    get {
      return _focusable && isEnabled && isDrawn
    }
    set {
      if _focusable == newValue {
        return
      }
      _focusable = newValue
      advanceFocusIfNecessary()
    }
  }

  open var accessibilityFocusable: Bool {
    get {
      return (_focusable || _accessibilityFocusable) && isEnabled && isDrawn
    }
    set {
      if _accessibilityFocusable == newValue {
        return
      }
      _accessibilityFocusable = newValue
      advanceFocusIfNecessary()
    }
  }

  open var focusTraversable: FocusTraversable? {
    assert(false)
    return nil
  }

  open var paneFocusTraversable: FocusTraversable? {
    assert(false)
    return nil
  }

  open internal(set) var canProcessEventsWithinSubtree: Bool

  open var isMouseHovered: Bool {
    // If we haven't yet been placed in an onscreen view hierarchy, we can't be
    // hovered.
    guard let w = widget else {
      return false
    }

    // If mouse events are disabled, then the mouse cursor is invisible and
    // is therefore not hovering over this button.
    if !w.isMouseEventsEnabled {
      return false
    }

// gfx::IntPoint cursor_pos(gfx::Screen::GetScreenFor(GetWidget()->GetNativeView())->GetCursorScreenPoint());
    var cursorPos = IntPoint(Screen.getScreenFor(windowId: w.window.id).cursorScreenPoint)
    View.convertPointFromScreen(dst: self, point: &cursorPos)
    return hitTest(point: cursorPos)
  }

  open var keyboardContextMenuLocation: IntPoint {
    return IntPoint()
  }

    open var inputMethod: InputMethod? {
    if let w = widget {
      return w.inputMethod
    }
    return nil
  }

  open var effectiveViewTargeter: ViewTargeter? {
    var viewTargeter = targeter
    if viewTargeter == nil {
      if let view = widget?.rootView {
        viewTargeter = view.targeter
      }
    }
    return viewTargeter
  }

  open var dragInfo: ViewDragInfo? {
    if let p = parent {
      return p.dragInfo
    }
    return nil
  }

  public var focusBehavior: FocusBehavior {
    didSet {
      advanceFocusIfNecessary()
    }
  }

  public var theme: Theme {
    get {
      if let t = _theme {
        return t
      }

      if let p = parent {
        return p.theme
      }

      //if let w = widget {
      //  return w.theme
     // }

      return Theme.instanceForNativeUi()
    }
    set {
      let oldTheme = theme
      _theme = newValue
      if _theme !== oldTheme {
        propagateThemeChanged(theme: theme)
      }
    }

  }

  public var paintScaleType: PaintInfo.ScaleType {
    return PaintInfo.ScaleType.scaleWithEdgeSnapping
  }

  private var shouldPaint: Bool {
    return isVisible && !size.isEmpty
  }

  open var id: Int

  open var group: Int

  open var background: Background?

  open var border: Border?
 
  open var dragController: DragController?

  open var notifyEnterExitOnChild: Bool

  static let horizontalDragThreshold: Int = 8
  static let verticalDragThreshold: Int = 8

  fileprivate (set) public var needsLayout: Bool

  public fileprivate (set) var children: Views
  internal var _theme: Theme?
  fileprivate var descendantsToNotify: Views
  fileprivate var accelerators: [Accelerator]
  fileprivate var clipInsets: IntInsets
  fileprivate var paintCache: PaintCache
  fileprivate var registeredForVisibleBoundsNotification: Bool
  fileprivate var acceleratorFocusManager: FocusManager?
  fileprivate var registeredAcceleratorCount: Int
  fileprivate var observers: [ViewObserver]
  fileprivate var _layer: Layer?
  fileprivate var _layoutManager: LayoutManager?
  fileprivate var _ownerDelegate: LayerOwnerDelegate?
  fileprivate var _nextFocusableView: View?
  fileprivate var _flipCanvasOnPaintForRTLUI: Bool
  fileprivate var _focusable: Bool
  fileprivate var _bounds: IntRect
  fileprivate var _visible: Bool
  fileprivate var _enabled: Bool
  fileprivate var _paintToLayer: Bool
  fileprivate var _snapLayerToPixelBoundary: Bool
  fileprivate var _accessibilityFocusable: Bool
  fileprivate var _preferredSize: IntSize?
  
  public override init() {
    children = Views()
    accelerators = []
    descendantsToNotify = Views()
    focusBehavior = FocusBehavior.never
    id = UI.nextViewId
    group = -1
    clipInsets = IntInsets()
    needsLayout = true
    registeredForVisibleBoundsNotification = false
    paintCache = PaintCache()
    registeredAcceleratorCount = 0
    observers = []
    notifyEnterExitOnChild = false
    canProcessEventsWithinSubtree = false
    _visible = true
    _enabled = true
    _bounds = IntRect()
    _flipCanvasOnPaintForRTLUI = false
    _focusable = false
    _paintToLayer = false
    _snapLayerToPixelBoundary = false
    _accessibilityFocusable = false
    super.init()
  }

  deinit {

    if let p =  parent {
      p.removeChild(view: self)
    }

    ViewStorage.instance.viewRemoved(view: self)

    for child in children {
      child.parent = nil
    }

    for observer in observers {
      observer.onViewIsDeleting(observed: self)
    }

   }

  open override class func convertPointToTarget(source: EventTarget,
                                                target: EventTarget,
                                                point: inout IntPoint) {
    if source === target {
      return
    }

    let targetView = target as! View
    let sourceView = source as! View

    let root = getHierarchyRoot(view: targetView)
    assert(getHierarchyRoot(view: sourceView) === root)

    if sourceView !== root {
      let _ = sourceView.convertPointForAncestor(ancestor: root, point: &point)
    }

    if targetView !== root {
      let _ = targetView.convertPointFromAncestor(ancestor: root, point: &point)
    }
  }

  public static func convertRectToTarget(source: View,
                                         target: View,
                                         rect: inout FloatRect) {
    if source === target {
      return
    }

    let root = getHierarchyRoot(view: target)
    assert(getHierarchyRoot(view: source) === root)

    if source !== root {
      let _ = source.convertRectForAncestor(ancestor: root, rect: &rect)
    }

    if target !== root {
      let _ = target.convertRectFromAncestor(ancestor: root, rect: &rect)
    }
  }

  public static func convertPointToWindow(src: View, point: inout IntPoint) {
    let _ = src.convertPointForAncestor(ancestor: nil, point: &point)
  }

  public static func convertPointFromWindow(dest: View, point: inout IntPoint) {
    let _ = dest.convertPointFromAncestor(ancestor: nil, point: &point)
  }

  public static func convertPointToScreen(src: View, point: inout IntPoint) {
    if let win = src.widget {
      View.convertPointToWindow(src: src, point: &point)
      point = point + win.clientAreaBoundsInScreen.offsetFromOrigin
    }
  }

  public static func convertPointFromScreen(dst: View, point: inout IntPoint) {
    if let win = dst.widget {
      point = point - win.clientAreaBoundsInScreen.offsetFromOrigin
      View.convertPointFromWindow(dest: dst, point: &point)
    }
  }

  public static func convertRectToScreen(src: View, rect: inout IntRect) {
    var newOrigin = rect.origin
    View.convertPointToScreen(src: src, point: &newOrigin)
    rect.origin = newOrigin
  }

  static public func exceededDragThreshold(delta: IntVec2) -> Bool {
    return (abs(delta.x) > horizontalDragThreshold || abs(delta.y) > verticalDragThreshold)
  }

  public func addObserver(observer: ViewObserver) {
    observers.append(observer)
  }
  
  public func removeObserver(observer: ViewObserver) {
    for (index, elem) in observers.enumerated() {
      if observer === elem {
        observers.remove(at: index)
        return
      }
    }
  }
  
  public func hasObserver(observer: ViewObserver) -> Bool {
    for elem in observers {
      if observer === elem {
        return true
      }
    }
    return false
  }

  open func addChild(view child: View) {
    if let myLayer = layer, let childLayer = child.layer {
      //print("View: adding layer \(childLayer.id) as child of \(myLayer.id)")
    }
    guard child.parent !== self else {
      return
    }
    addChildAt(view: child, index: childCount)
  }

  open func addChildAt(view child: View, index: Int) {
    assert(child !== self)
    var oldTheme: Theme?
    var oldWidget: UIWidget?
    
   // //print("View.addChildAt: view \(id) adding child at pos \(index)")

    if let p = child.parent {
      oldWidget = child.widget
      oldTheme = child.theme
      if p === self {
        reorderChild(view: child, at: index)
        return
      }
      p.doRemoveChild(
        view: child,
        updateFocusCycle: true,
        tooltipUpdate: true,
        newParent: self
      )
    }

    initFocusSiblings(view: child, index: index)

    child.parent = self
    children.insert(child, at: index)

    // Ensure the layer tree matches the view tree before calling to any client
    // code. This way if client code further modifies the view tree we are in a
    // sane state.
    let didReparentAnyLayers = child.updateParentLayers()
    if let w = self.widget, didReparentAnyLayers {
      w.layerTreeChanged()
    }

    reorderLayers()

    // Make sure the visibility of the child layers are correct.
    // If any of the parent View is hidden, then the layers of the subtree
    // rooted at |this| should be hidden. Otherwise, all the child layers should
    // inherit the visibility of the owner View.
    child.updateLayerVisibility()

    if widget != nil {
      let newTheme = child.theme
      if newTheme !== oldTheme {
        child.propagateThemeChanged(theme: newTheme)
      }
    }

    let details = ViewHierarchyChangedDetails(isAdd: true, parent: self, child: child, moveView: parent) 

    var v: View? = self
    while v != nil {
      v!.viewHierarchyChangedImpl(registerAccelerators: false, details: details)
      v = v!.parent
    }

    child.propagateAddNotifications(details: details, isAddedToWidget: widget != nil && widget !== oldWidget)

    updateTooltip()

    if widget != nil {
      View.registerChildrenForVisibleBoundsNotification(view: child)
      if child.isVisible {
       child.schedulePaint()
      }
    }

    if let manager = layoutManager {
      manager.viewAdded(host: self, view: child)
    }

    for observer in observers {
      observer.onChildViewAdded(observed: self, child: child)
    }

  }

  open func reorderChild(view: View, at: Int) {
    var index = at
    if index < 0 {
      index = childCount - 1
    } else if index >= childCount {
      return
    }

    if children[index] === view {
      return
    }

    for (index, child) in children.enumerated() {
      if child === view {
        children.remove(at: index)
      }
    }

    // Unlink the view first
    let nextFocusable = view.nextFocusableView
    let prevFocusable = view.previousFocusableView
    if prevFocusable != nil {
      prevFocusable!.nextFocusableView = nextFocusable
    }
    if nextFocusable != nil {
      nextFocusable!.previousFocusableView = prevFocusable
    }

    // Add it in the specified index now.
    initFocusSiblings(view: view, index: index)
    children.insert(view, at: index)

    for observer in observers {
      observer.onChildViewReordered(observed: self, child: view)
    }

    reorderLayers()
  }

  open func removeChild(view child: View) {
    doRemoveChild(
      view: child,
      updateFocusCycle: true,
      tooltipUpdate: true,
      newParent: nil
    )
  }

  open func removeAllChildren(deleteChildren: Bool) {
    for child in children {
      doRemoveChild(
        view: child,
        updateFocusCycle: false,
        tooltipUpdate: false,
        newParent: nil
      )
    }
   updateTooltip()
  }

  open func childAt(index: Int) -> View? {
    guard index >= 0 && index < childCount else {
      return nil
    }
    return children[index]
  }

  open func contains(view aView: View) -> Bool {
    var v: View? = aView
    while v != nil {
      if v === self {
        return true
      }
      v = v!.parent
    }
    return false
  }

  open func getIndexOf(view: View) -> Int {
    for (index, item) in children.enumerated() {
      if view === item {
        return index
      }
    }
    return -1
  }

  open func sizeToPreferredSize() {
    let size = preferredSize
    if size.width != width || size.height != height {
      bounds = IntRect(x: x, y: y, width: size.width, height: size.height)
    }
  }

  open func getHeightFor(width w: Int) -> Int {
    if let manager = layoutManager {
      return manager.getPreferredHeightForWidth(host: self, width: w)
    }
    return preferredSize.height
  }

  open func setFillsBoundsOpaquely(fillsBoundsOpaquely: Bool) {
    if let l = layer {
      l.fillsBoundsOpaquely = fillsBoundsOpaquely
    }
  }

  open func setClipInsets(clipInsets: IntInsets) {
    self.clipInsets = clipInsets
  }

  open func getMirroredRect(rect: IntRect) -> IntRect {
    var mirroredRect = rect
    mirroredRect.x = getMirroredXForRect(rect: rect)
    return mirroredRect
  }

  open func getMirroredXForRect(rect: IntRect) -> Int {
    return i18n.isRTL() ?
        (width - bounds.x - bounds.width) : bounds.x
  }

  open func getMirroredXInView(x: Int) -> Int {
    return i18n.isRTL() ? width - x : x
  }

  open func getMirroredXWithWidthInView(x: Int, width: Int) -> Int {
    return i18n.isRTL() ? self.width - x - width : x
  }

  open func layout() {
    needsLayout = false

    // If we have a layout manager, let it reference the layout for us.
    if let manager = layoutManager {
      manager.layout(host: self)
    }

    // Make sure to propagate the Layout() call to any children that haven't
    // received it yet through the layout manager and need to be laid out. This
    // is needed for the case when the child requires a layout but its bounds
    // weren't changed by the layout manager. If there is no layout manager, we
    // just propagate the Layout() call down the hierarchy, so whoever receives
    // the call can take appropriate action.
    for child in children {
      if child.needsLayout || layoutManager == nil {
        //TRACE_EVENT1("views", "View.layout", "class", child.GetClassName())
        child.needsLayout = false
        child.layout()
      }
    }
  }

  open func invalidateLayout() {
    needsLayout = true
    if let p = parent {
      p.invalidateLayout()
    }
  }

  open func snapLayerToPixelBoundary() {
    guard let snapLayer = layer else {
      return
    }

    if _snapLayerToPixelBoundary && snapLayer.compositor != nil {
      if let layerParent = snapLayer.parent {
        UI.snapLayerToPhysicalPixelBoundary(snappedLayer: layerParent, toSnap: snapLayer)
      }
    } else {
      // Reset the offset.
      snapLayer.subpixelPositionOffset = FloatVec2()
    }
  }

  open func getAncestorWith(name ancestor: String) -> View? {
    var view: View? = self

    while view != nil {
      if view!.className == ancestor {
        return view
      }
      view = view!.parent
    }
    return nil
  }

  // TODO: create a subscript for this ?
  open func getViewBy(id: Int) -> View? {
    if id == self.id {
      return self
    }

    for child in children {
      let view = child.getViewBy(id: id)
      if view != nil {
        return view
      }
    }
    return nil
  }

  open func isGroupFocusTraversable() -> Bool {
    return true
  }

  open func getViewsInGroup(group: Int, views: inout Views) {
    if self.group == group {
      views.append(self)
    }

    for child in children {
      child.getViewsInGroup(group: group, views: &views)
    }
  }

  open func getSelectedViewForGroup(group: Int) -> View? {
    var views = Views()
    widget!.rootView!.getViewsInGroup(group: group, views: &views)
    return views.count == 0 ? nil : views[0]
  }

  open func convertRectToParent(rect: IntRect) -> IntRect {
    var xrect = FloatRect(rect)
    transform.transformRect(rect: &xrect)
    xrect.offset(distance: FloatVec2(mirroredPosition.offsetFromOrigin))
    // Pixels we partially occupy in the parent should be included.
    return IntRect.toEnclosingRect(rect: xrect)
  }

  open func convertRectToWidget(rect: IntRect) -> IntRect {
    var xrect = rect
    var view: View? = self
    while view != nil {
      xrect = view!.convertRectToParent(rect: xrect)
      view = view!.parent
    }
    return xrect
  }

  open func schedulePaint() {
    schedulePaintInRect(rect: localBounds)
  }

  open func schedulePaintInRect(rect: IntRect) {
    if !isVisible {
      return
    }

    if let paintLayer = layer {
      let _ = paintLayer.schedulePaint(invalidRect: rect)
    } else if let parentLayer = parent {
      // Translate the requested paint rect to the parent's coordinate system
      // then pass this notification up to the parent.
      parentLayer.schedulePaintInRect(rect: convertRectToParent(rect: rect))
    }
  }

  internal func paintFromPaintRoot(context: PaintContext) {
    //print("\n\nView.paintFromPaintRoot\n\n")
    let paintInfo = PaintInfo.createRootPaintInfo(
      context: context, size: layer != nil ? layer!.size : size)
    paint(info: paintInfo)
  }

  open func paint(info parentPaintInfo: PaintInfo) {
    //print("View.paint: \(className)")
    guard shouldPaint else {
      //print("View.paint: \(className): shouldPaint = false. visible: \(isVisible) bounds: \(bounds) cancelling.")
      return
    }
    let parentBounds = parent != nil ? parent!.mirroredBounds : mirroredBounds
    let paintInfo = PaintInfo.createChildPaintInfo(
      info: parentPaintInfo,
      bounds: mirroredBounds,
      size: parentBounds.size,
      scaleType: paintScaleType,
      isLayer: layer != nil)
    let context = paintInfo.context
    var isInvalidated = true
    if paintInfo.context.canCheckInvalid {
      isInvalidated = context.isRectInvalid(bounds: IntRect(size: paintInfo.paintRecordingSize))
    }
    
    // NOTE: this is disabled just because the DisplayItemList comming from
    //       canvas is already setup
    // but we should enable it as soon as we can

    let clipRecorder = ClipRecorder(context: parentPaintInfo.context)
    if layer == nil {
      if self.clipPath.isEmpty {
        let clipRect = IntRect(size: paintInfo.paintRecordingSize) + paintInfo.offsetFromParent
        clipRecorder.clipRect(clipRect: clipRect)
      } else {
        let clipPathInParent = self.clipPath
        var toParentRecordingSpace = Transform()
        toParentRecordingSpace.translate(vector: FloatVec2(paintInfo.offsetFromParent))
        toParentRecordingSpace.scale(x: paintInfo.paintRecordingScaleX, y: paintInfo.paintRecordingScaleY)
        clipPathInParent.transform(matrix: toParentRecordingSpace.matrix.toMat3())
        clipRecorder.clipPathWithAntiAliasing(clipPath: clipPathInParent)
      }
    }

    var transformRecorder = TransformRecorder(context: context)
    setUpTransformRecorderForPainting(offsetFromParent: paintInfo.offsetFromParent,
                                      recorder: &transformRecorder)

    // FIXME: we disabled cache manually for now.. when we manage to make it work
    //       we need to enable it again
    //let useCache: Bool = false//self.paintCache.useCache(context: context, size: paintInfo.paintRecordingSize)
    if isInvalidated {//|| !useCache {
       let recorder = PaintRecorder(
        context: context,
        recordingSize: paintInfo.paintRecordingSize,
        scaleX: paintInfo.paintRecordingScaleX,
        scaleY: paintInfo.paintRecordingScaleY,
        cache: nil)
      let canvas = recorder.canvas
      canvas.withinScope(width: self.width, flip: _flipCanvasOnPaintForRTLUI) { canvas in
        onPaint(canvas: canvas)
      }
      
    }
    paintChildren(info: paintInfo)
  }

  open func addedToWidget() {}
  open func removedFromWidget() {}

  // open func paint(context parentContext: PaintContext) {
  // //open func paint(info: PaintInfo) {
  //   /// To eventually debug the layer tree being rendered
  //   //print("*** View.paint()\n  name = \(className)\n  visible = \(_visible)\n  size = \(size)\n  children = \(childCount)\n  isDrawn = \(isDrawn)\n  parent: \(parent != nil ? parent!.className : "<null>")")
  //   guard _visible && !size.isEmpty else {
  //     return
  //   }

  //   var offsetToParent = IntVec2()
  //   if layer == nil {
  //     // If the View has a layer() then it is a paint root. Otherwise, we need to
  //     // add the offset from the parent into the total offset from the paint root.
  //     assert(parent != nil || bounds.origin == IntPoint())
  //     offsetToParent = mirroredPosition.offsetFromOrigin
  //   }
  //   let context = PaintContext(other: parentContext, offset: offsetToParent)

  //   var isInvalidated = true
  //   if context.canCheckInvalid {
  // //#if _isDebugAssertConfiguration()
  // //    var offset = IntVec2()
  // //    context.visited(self)
  // //    var view: View? = self
  // //    while view.parent != nil && view.layer == nil {
  // //      assert(view.transform.isIdentity)
  // //      offset = offset + view.mirroredPosition.offsetFromOrigin
  // //      view = view.parent
  // //    }
  // //    // The offset in the PaintContext should be the offset up to the paint root,
  // //    // which we compute and verify here.
  // //    assert(context.paintOffset.x == offset.x)
  // //    assert(context.paintOffset.y == offset.y)
  // //    // The above loop will stop when |view| is the paint root, which should be
  // //    // the root of the current paint walk, as verified by storing the root in
  // //    // the PaintContext.
  // //    assert(context.rootVisited == view)
  // //#endif

  //     // If the View wasn't invalidated, don't waste time painting it, the output
  //     // would be culled.
  //     isInvalidated = context.isRectInvalid(bounds: localBounds)
  //   }

  //   //TRACE_EVENT1("views", "View::Paint", "class", GetClassName())

  //   // If the view is backed by a layer, it should paint with itself as the origin
  //   // rather than relative to its parent.
  //   let clipRecorder = ClipRecorder(context: parentContext)
  //   if layer == nil {
      
  //     // TODO: the current Chromium paint method rely on input from 'PaintInfo'
  //     //       we are behind here, and maybe this is not suppose to be
  //     //       like this anymore
  //     var clipRectInParent = bounds
  //      clipRectInParent.inset(insets: self.clipInsets)
  //      if let p = parent {
  //        clipRectInParent.x = p.getMirroredXForRect(rect: clipRectInParent)
  //      }
  //     // clipRecorder.clipRect(clipRect: clipRectInParent)

  //     // var transformFromParent = Transform()
  //     // let offsetFromParent = mirroredPosition.offsetFromOrigin
  //     // transformFromParent.translate(x: Float(offsetFromParent.x),
  //     //                               y: Float(offsetFromParent.y))
  //     // transformFromParent.preconcatTransform(transform: self.transform)
  //     // clipRecorder.transform(transform: transformFromParent)
  //     if clipPath.isEmpty {
  //       clipRecorder.clipRect(clipRect: clipRectInParent)
  //     } else {
  //       let clipPathInParent = clipPath
  //       // Transform |clip_path_| from local space to parent recording space.
  //       var toParentRecordingSpace = Transform()
  //       let offsetFromParent = mirroredPosition.offsetFromOrigin
  //       toParentRecordingSpace.translate(vector: FloatVec2(offsetFromParent))//paintInfo.offsetFromParent)
  //       toParentRecordingSpace.scale(
  //         //x: paintInfo.paintRecordingScaleX,
  //         //y: paintInfo.paintRecordingScaleY)
  //         x: context.deviceScaleFactor,
  //         y: context.deviceScaleFactor)

  //       clipPathInParent.transform(matrix: toParentRecordingSpace.matrix.toMat3())
  //       clipRecorder.clipPathWithAntiAliasing(clipPath: clipPathInParent)
  //     }
  //   }

  //   var transformRecorder = TransformRecorder(context: context)
  //   let offsetFromParent = mirroredPosition.offsetFromOrigin
        
  //   setUpTransformRecorderForPainting(offsetFromParent: offsetFromParent, //paintInfo.offsetFromParent,
  //                                     recorder: &transformRecorder)

  //   if isInvalidated || !paintCache.useCache(context: context, size: self.size /*paintInfo.paintRecordingSize*/) {
  //     let recorder = PaintRecorder(
  //       context: context,
  //       recordingSize: self.size, // paintInfo.paintRecordingSize
  //       //scaleX: paintInfo.paintRecordingScaleX,
  //       //scaleY: paintInfo.paintRecordingScaleY,
  //       scaleX: context.deviceScaleFactor,
  //       scaleY: context.deviceScaleFactor,
  //       cache: paintCache)
  //     let canvas = recorder.canvas

  //     // If the View we are about to paint requested the canvas to be flipped, we
  //     // should change the transform appropriately.
  //     // The canvas mirroring is undone once the View is done painting so that we
  //     // don't pass the canvas with the mirrored transform to Views that didn't
  //     // request the canvas to be flipped.
  //     if flipCanvasOnPaintForRTLUI() {
  //       canvas.translate(offset: IntVec2(x: self.width, y: 0))
  //       canvas.scale(x: -1, y: 1)
  //     }

  //     // Delegate painting the contents of the View to the virtual onPaint method.
  //     onPaint(canvas: canvas)
  //   }

  //   // View.paint() recursion over the subtree.
  //   paintChildren(context: context)
  // }

  open func flipCanvasOnPaintForRTLUI() -> Bool {
    if _flipCanvasOnPaintForRTLUI {
     return i18n.isRTL()
    }
    return false
  }

  open func enableCanvasFlippingForRTLUI(enable: Bool) {
    _flipCanvasOnPaintForRTLUI = enable
  }

  open func getEventHandlerFor(point p: IntPoint) -> View? {
    return getEventHandlerFor(rect: IntRect(origin: p, size: IntSize(width: 1, height: 1)))
  }

  open func getEventHandlerFor(rect r: IntRect) -> View? {
    return effectiveViewTargeter?.targetForRect(root: self, rect: r)
  }

  open func getTooltipHandlerFor(point p: IntPoint) -> View? {
    // TODO(tdanderson): Move this implementation into ViewTargetDelegate.
    if !hitTest(point: p) || !canProcessEventsWithinSubtree {
      return nil
    }

    // Walk the child Views recursively looking for the View that most
    // tightly encloses the specified point.

    for child in children.reversed() {
    //for int i = child_count() - 1; i >= 0; --i {
    //  View* child = child_at(i);
      if !child.isVisible {
        continue
      }

      var pointInChildCoords = IntPoint(p)
      View.convertPointToTarget(source: self, target: child, point: &pointInChildCoords)
      let handler = child.getTooltipHandlerFor(point: pointInChildCoords)
      if handler != nil {
        return handler
      }
    }
    return self
  }

  open func getCursor(event: MouseEvent) -> PlatformCursor {
    return PlatformCursorNil
  }

  open func onThemeChanged(theme: Theme) {}

  open func hitTest(point p: IntPoint) -> Bool {
    return hitTest(rect: IntRect(origin: p, size: IntSize(width: 1, height: 1)))
  }

  open func hitTest(rect r: IntRect) -> Bool {
    return effectiveViewTargeter!.doesIntersectRect(target: self, rect: r)
  }

  // EventTarget
  open override func canAcceptEvent(event: Graphics.Event) -> Bool {
    return isDrawn
  }

  open override func convertEventToTarget(target: EventTarget, event: LocatedEvent) {
    let view = target as! View
    event.convertLocationToTarget(source: self, target: view)
  }

  // EventHandler
  open override func onKeyEvent(event: inout KeyEvent) {
    let consumed = (event.type == EventType.KeyPressed) ? onKeyPressed(event: event) :
                                                          onKeyReleased(event: event)
    if consumed {
      event.stopPropagation()
    }
  }

  open override func onMouseEvent(event: inout MouseEvent) {

    switch event.type {
      case .MousePressed:
        if processMousePressed(event: event) {
          event.handled = true
        }
        return
      case .MouseMoved:
        if (event.flags.rawValue & (EventFlags.LeftMouseButton.rawValue |
           EventFlags.RightMouseButton.rawValue |
           EventFlags.MiddleMouseButton.rawValue)) == 0 {
          onMouseMoved(event: event)
        }
        return
    case .MouseDragged:
      if processMouseDragged(event: event) {
        event.handled = true
      }
      return
    case .MouseReleased:
      processMouseReleased(event: event)
      return
    case .MouseWheel:
      let mwe: MouseWheelEvent = event as! MouseWheelEvent
      if onMouseWheel(event: mwe) {
        event.handled = true
      }
      break
    case .MouseEntered:
      if event.flags.rawValue & EventFlags.TouchAccessibility.rawValue != 0 {
        //notifyAccessibilityEvent(ui::AX_EVENT_HOVER, true)
        notifyAccessibilityEvent(eventType: AXEventHover, sendNativeEvent: true)
      }
      onMouseEntered(event: event)
      break
    case .MouseExited:
      onMouseExited(event: event)
      break
    default:
      return
    }
  }

  open override func onScrollEvent(event: inout ScrollEvent) {

  }

  open override func onTouchEvent(event: inout TouchEvent) {

  }

  open override func onGestureEvent(event: inout GestureEvent) {

  }

  open func requestFocus() {
    if focusable {
      if let manager = focusManager {
        manager.focusedView = self
      }
    }
  }

  // TODO: this looks incovenient and out of place here (assuming the view is tabbed)
  // but on the other way, we can use this, when switching windows, from one app to another in the host OS
  open func aboutToRequestFocusFromTabTraversal(reverse: Bool) {

  }

  open func skipDefaultKeyEventProcessing(event: KeyEvent) -> Bool {
    return false
  }

  open func getTooltipText(p: IntPoint) -> String? {
    return nil
  }

  open func getTooltipTextOrigin(p: IntPoint) -> IntPoint? {
    return nil
  }

  open func showContextMenu(point p: IntPoint, sourceType: MenuSourceType) {
    if let menuController = contextMenuController {
      menuController.showContextMenuForView(source: self, point: p, sourceType: sourceType)
    }
  }

  open func getDropFormats(formats: inout Int, formatTypes: inout [ClipboardFormatType]) -> Bool {
    return false
  }

  open func areDropTypesRequired() -> Bool {
    return false
  }

  open func canDrop(data: OSExchangeData) -> Bool {
    return false
  }

  open func onDragDone() {

  }

  open func getAccessibleState(state: inout AXViewState) {

  }

  open func getPlatformViewAccessible() -> PlatformViewAccessible {
    return PlatformViewAccessible()
  }

  open func notifyAccessibilityEvent(eventType: AXEvent, sendNativeEvent: Bool) {

  }

  open func scrollRectToVisible(rect: IntRect) {
    if let p = parent {
      var scrollRect = IntRect(rect)
      scrollRect.offset(horizontal: mirroredX, vertical: y)
      p.scrollRectToVisible(rect: scrollRect)
    }
  }

  open func getPageScrollIncrement(scrollView: ScrollView, isHorizontal: Bool, isPositive: Bool) -> Int {
    return 0
  }

  open func getLineScrollIncrement(scrollView: ScrollView, isHorizontal: Bool, isPositive: Bool) -> Int {
    return 0
  }

  open func onPaint(canvas: Canvas) {
    onPaintBackground(canvas: canvas)
    onPaintBorder(canvas: canvas)
  }

  open func onMousePressed(event: MouseEvent) -> Bool {
    return false
  }

  open func onMouseDragged(event: MouseEvent) -> Bool {
    return false
  }

  open func onMouseReleased(event: MouseEvent) {

  }

  open func onMouseCaptureLost() {

  }

  open func onMouseMoved(event: MouseEvent) {

  }

  open func onMouseEntered(event: MouseEvent) {

  }

  open func onMouseExited(event: MouseEvent) {

  }

  open func onMouseWheel(event: MouseWheelEvent) -> Bool {
    return false
  }

  open func onKeyPressed(event: KeyEvent) -> Bool {
    return false
  }

  open func onKeyReleased(event: KeyEvent) -> Bool {
    return false
  }

  open func setMouseHandler(handler: View) {
    if let p = parent {
      p.setMouseHandler(handler: handler)
    }
  }

  //public func setPaintToLayer(type: LayerType = .Textured) {
  public func setPaintToLayer(type: LayerType = .PictureLayer) {
    if _paintToLayer && layer?.type == type {
      return
    }

    destroyLayerImpl(.dontNotify)
    createLayer(type: type)
    _paintToLayer = true

    // Notify the parent chain about the layer change.
    notifyParentsOfLayerChange()
  }

  // TODO: já que nao existe conceito de ownership no swift, passar
  // o antigo view targeter pode ser desnecessario
  open func setEventTargeter(targeter: ViewTargeter) -> ViewTargeter? {
    let oldTargeter = targeter
    self.targeter = targeter
    return oldTargeter
  }


  // AcceleratorTarget

  open func addAccelerator(accelerator: Accelerator) {
    accelerators.append(accelerator)
    registerPendingAccelerators()
  }

  open func removeAccelerator(accelerator: Accelerator) {
    for (index, item) in accelerators.enumerated() {
      if item === accelerator {
        accelerators.remove(at: index)
      }
    }
  }

  open func resetAccelerators() {
    unregisterAccelerators(leaveDataIntact: false)
  }

  open func acceleratorPressed(accelerator: Accelerator) -> Bool {
    return false
  }
  
  open func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {
    _snapLayerToPixelBoundary = (Double(deviceScaleFactor) - floor(Double(deviceScaleFactor))) != 0.0
    snapLayerToPixelBoundary()
  }

  // ViewTargetDelegate
  // Hack: so we can use the default implementation from ViewTargeterDelegate
  // even if a given class already implements it, and have a view as a parent
  // so we can call super.targetForRect, for instance

  open func doesIntersectRect(target: View, rect: IntRect) -> Bool {
    return target.localBounds.intersects(rect: rect)
  }

  open func targetForRect(root: View, rect: IntRect) -> View? {
    // |rect_view| represents the current best candidate to return
    // if rect-based targeting (i.e., fuzzing) is used.
    // |rect_view_distance| is used to keep track of the distance
    // between the center point of |rect_view| and the center
    // point of |rect|.
    var rectView: View? = nil
    var rectViewDistance = Int.max

    // |point_view| represents the view that would have been returned
    // from this function call if point-based targeting were used.
    var pointView: View? = nil

    for child in root.children.reversed() {

      if !child.canProcessEventsWithinSubtree {
        continue
      }

      // Ignore any children which are invisible or do not intersect |rect|.
      if !child.isVisible {
        continue
      }

      var rectInChildCoordsf = FloatRect(rect)
      View.convertRectToTarget(source: root, target: child, rect: &rectInChildCoordsf)
      let rectInChildCoords = IntRect.toEnclosingRect(rect: rectInChildCoordsf)

      if !child.hitTest(rect: rectInChildCoords) {
        continue
      }

      let curView = child.getEventHandlerFor(rect: rectInChildCoords)

      if usePointBasedTargeting(rect: rect) {
        return curView
      }

      var curViewBoundsf = FloatRect(curView!.localBounds)
      View.convertRectToTarget(source: curView!, target: root, rect: &curViewBoundsf)
      let curViewBounds = IntRect.toEnclosingRect(rect: curViewBoundsf)

      if percentCoveredBy(r1: curViewBounds, r2: rect) >= rectTargetOverlap {
        // |cur_view| is a suitable candidate for rect-based targeting.
        // Check to see if it is the closest suitable candidate so far.
        let touchCenter = rect.centerPoint
        let curDist = distanceSquaredFromCenterToPoint(point: touchCenter,
                                                       rect: curViewBounds)
        if rectView == nil || curDist < rectViewDistance {
          rectView = curView
          rectViewDistance = curDist
        }
      } else if rectView == nil && pointView == nil {
        // IntRect-based targeting has not yielded any candidates so far. Check
        // if point-based targeting would have selected |cur_view|.
        let pointInChildCoords = rectInChildCoords.centerPoint
        if child.hitTest(point: pointInChildCoords) {
          pointView = child.getEventHandlerFor(point: pointInChildCoords)
        }
      }
    }

    if usePointBasedTargeting(rect: rect) || rectView == nil && pointView == nil {
      return root
    }

   // If |root| is a suitable candidate for rect-based targeting, check to
   // see if it is closer than the current best suitable candidate so far.
   let localBounds = root.localBounds
   if percentCoveredBy(r1: localBounds, r2: rect) >= rectTargetOverlap {
     let touchCenter = rect.centerPoint
     let curDist = distanceSquaredFromCenterToPoint(point: touchCenter,
                                                    rect: localBounds)
     if rectView == nil || curDist < rectViewDistance {
      rectView = root
     }
   }

   return rectView != nil ? rectView : pointView
  }

  open func onBoundsChanged(previousBounds: IntRect) {}

  open func calculatePreferredSize() -> IntSize {
    if let manager = layoutManager {
      return manager.getPreferredSize(host: self)
    }
    return IntSize()
  }

  open func childPreferredSizeChanged(child: View) {}

  open func childVisibilityChanged(child: View) {}

  func preferredSizeChanged() {
    invalidateLayout()
    if let p = parent {
      p.childPreferredSizeChanged(child: self)
    }
    for observer in observers {
      observer.onViewPreferredSizeChanged(observed: self)
    }
  }

  open func getNeedsNotificationWhenVisibleBoundsChange() -> Bool {
    return false
  }

  open func onVisibleBoundsChanged() {

  }

  open func onEnabledChanged() {
    schedulePaint()
  }

  open func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {}

  open func visibilityChanged(startingFrom: View, isVisible: Bool) {}

  public func onDragEntered(event: DropTargetEvent) {}
  public func onDragUpdated(event: DropTargetEvent) -> DragOperation { return .DragNone }
  public func onDragExited() {}
  public func onPerformDrop(event: DropTargetEvent) -> DragOperation { return .DragNone }

  func nativeViewHierarchyChanged() {
    if acceleratorFocusManager !== focusManager {
      unregisterAccelerators(leaveDataIntact: true)
      if focusManager != nil {
        registerPendingAccelerators()
      }
    }
  }

  open func paintChildren(info: PaintInfo) {
    for child in children {
      if child.layer == nil {
        child.paint(info: info)
      }
    }
  }

  // open func paintChildren(context: PaintContext) {
  //   //print("*** View.paintChildren()")
  //   for child in children {
  //     //print("*** View.paintChildren: painting child '\(child.className)''")
  //     if child.layer == nil {
  //       //print("*** View.paintChildren: child.layer == nil calling paint() on child '\(child.className)''")
  //       child.paint(context: context)
  //     }
  //   }
  // }

  public func onPaintBackground(canvas: Canvas) {
    if let b = background {
      b.paint(canvas: canvas, view: self)
    }
  }

  public func onPaintBorder(canvas: Canvas) {
    if let b = border {
      b.paint(view: self, canvas: canvas)
    }
  }

  func calculateOffsetToAncestorWithLayer(layerParent: inout Layer?) -> IntVec2 {
    if let l = layer {
      layerParent = l
      return IntVec2()
    }
    if let p = parent {
      return IntVec2(x: mirroredX, y: y) + p.calculateOffsetToAncestorWithLayer(layerParent: &layerParent)
    }
    return IntVec2()
  }

  func updateParentLayer() {
    guard layer != nil else {
      return
    }

    var parentLayer: Layer? = nil
    var offset = IntVec2(x: mirroredX, y: y)

    if let p = parent {
      offset = offset + p.calculateOffsetToAncestorWithLayer(layerParent: &parentLayer)
    }

    reparentLayer(offset: offset, parentLayer: parentLayer)
  }

  func moveLayerToParent(parentLayer: Layer, point: IntPoint) {
    var localPoint = IntPoint(point)
    if parentLayer !== layer {
      localPoint.offset(x: mirroredX, y: y)
    }
    if parentLayer !== layer {
      if let l = layer {
        parentLayer.add(child: l)
        setLayerBounds(boundsInDip: IntRect(x: localPoint.x, y: localPoint.y, width: width, height: height))
      }
    } else {
      for child in children {
        child.moveLayerToParent(parentLayer: parentLayer, point: localPoint)
      }
    }
  }

  func updateChildLayerBounds(offset: IntVec2) {

    if layer != nil {
      setLayerBounds(boundsInDip: localBounds + offset)
    } else {
      for child in children {
        child.updateChildLayerBounds(offset: offset + IntVec2(x: child.mirroredX, y: child.y))
      }
    }
  }

  func reorderLayers() {
    var v: View? = self

    while v != nil && v!.layer == nil {
      v = v!.parent
    }

    if v == nil {
      if let w = widget, let l = w.layer {
        w.rootView!.reorderChildLayers(parentLayer: l)
      }
    } else {
      v!.reorderChildLayers(parentLayer: v!.layer!)
    }

    if let w = widget {
      w.reorderNativeViews()
    }
  }

  func reorderChildLayers(parentLayer: Layer) {
    if let l = layer {
      if l !== parentLayer {
        parentLayer.stackAtBottom(child: l)
      }
    } else {
      for child in children.reversed() {
        child.reorderChildLayers(parentLayer: parentLayer)
      }
    }
  }

  func notifyParentsOfLayerChange() {
    var viewParent: View? = parent
    while viewParent != nil {
      viewParent!.onChildLayerChanged(self)
      viewParent = viewParent!.parent
    }
  }

  func onChildLayerChanged(_ child: View) {}

  open func onFocus() {
    if let manager = focusManager {
      manager.clearNativeFocus()
    }
    // Notify assistive technologies of the focus change.
    notifyAccessibilityEvent(eventType: AXEventFocus, sendNativeEvent: true)
  }

  open func onBlur() {}

  func setUpTransformRecorderForPainting(offsetFromParent: IntVec2, recorder: inout TransformRecorder) {
    // If the view is backed by a layer, it should paint with itself as the origin
    // rather than relative to its parent.
    if layer != nil {
      return
    }

    // Translate the graphics such that 0,0 corresponds to where this View is
    // located relative to its parent.
    var transformFromParent = Transform()
    transformFromParent.translate(x: Float(offsetFromParent.x),
                                  y: Float(offsetFromParent.y))
    recorder.transform(transform: transformFromParent)
  }

  func focus() {
    onFocus()
  }

  func blur() {
    onBlur()
  }

  func onLocaleChanged() {

  }

  func tooltipTextChanged() {
    if let manager = widget?.tooltipManager {
      manager.tooltipTextChanged(view: self)
    }
  }

  func getDragOperations(pressPoint: IntPoint) -> DragOperation {
    if let controller = dragController {
      let _ = controller.getDragOperationsForView(sender: self, point: pressPoint)
    }
    return .DragNone
  }

  func writeDragData(pressPoint: IntPoint, data: OSExchangeData) {
    if let controller = dragController {
      controller.writeDragDataForView(sender: self, pressPoint: pressPoint, data: data)
    }
  }

  func inDrag() -> Bool {
    if let w = widget {
      return w.draggedView === self
    }
    return false
  }

  func schedulePaintBoundsChanged(type: SchedulePaintType) {
    if layer == nil || type == .SizeChanged {
      schedulePaint()
    } else if parent != nil && type == .SizeSame {
      layer!.scheduleDraw()
    }
  }

  func doRemoveChild(view child : View,
                     updateFocusCycle: Bool,
                     tooltipUpdate : Bool,
                     // deleteRemovedView: Bool,
                     newParent: View?) {

    var index = -1

    for (i, item) in children.enumerated() {
      if child === item {
        index = i
      }
    }

    //var viewToBeDeleted: View? = nil

    if index != -1 {
      if updateFocusCycle {
        // Let's remove the view from the focus traversal.
        let nextFocusable = child.nextFocusableView
        let prevFocusable = child.previousFocusableView
        if prevFocusable != nil {
          prevFocusable!.nextFocusableView = nextFocusable
        }
        if nextFocusable != nil {
          nextFocusable!.previousFocusableView = prevFocusable
        }
      }
      if let w = widget {
        View.unregisterChildrenForVisibleBoundsNotification(view: child)
        if child.isVisible {
          child.schedulePaint()
        }
        w.notifyWillRemoveView(view: child)
      }

      child.propagateRemoveNotifications(oldParent: self, newParent: newParent)
      child.parent = nil
      child.updateLayerVisibility()

      //if deleteRemovedView && !view.ownedByclient {
      //  viewToBeDeleted = child
      //}

      children.remove(at: index)
    }

    if tooltipUpdate {
      updateTooltip()
    }

    if let manager = layoutManager {
      manager.viewRemoved(host: self, view: child)
    }

    for observer in observers {
      observer.onChildViewRemoved(observed: self, child: child)
    }
  }

  func propagateRemoveNotifications(oldParent: View, newParent: View?) {
    for child in children {
      child.propagateRemoveNotifications(oldParent: oldParent, newParent: newParent)
    }

    let details = ViewHierarchyChangedDetails(isAdd: false, parent: oldParent, child: self, moveView: newParent)
    var v: View? = self
    while v != nil {
      v!.viewHierarchyChangedImpl(registerAccelerators: true, details: details)
      v = v!.parent
    }
  }

  func propagateAddNotifications(details: ViewHierarchyChangedDetails, isAddedToWidget: Bool) {
    for child in children {
      child.propagateAddNotifications(details: details, isAddedToWidget: isAddedToWidget)
    }
    viewHierarchyChangedImpl(registerAccelerators: true, details: details)
    if isAddedToWidget {
      addedToWidget()
    }
  }

  func propagateNativeViewHierarchyChanged() {
    for child in children {
      child.propagateNativeViewHierarchyChanged()
    }
    nativeViewHierarchyChanged()
  }

  func viewHierarchyChangedImpl(registerAccelerators register: Bool,
                                details: ViewHierarchyChangedDetails) {
    if register {
      if details.isAdd {
        // If you get this registration, you are part of a subtree that has been
        // added to the view hierarchy.
        if focusManager != nil {
          registerPendingAccelerators()
        }
      } else {
        if details.child === self {
          unregisterAccelerators(leaveDataIntact: true)
        }
      }
    }

    // if details.isAdd && layer != nil && layer!.parent == nil {
    //   updateParentLayer()
    //   if let w = widget {
    //     w.updateRootLayers()
    //   }
    // } else if !details.isAdd && details.child === self {
    //   // Make sure the layers belonging to the subtree rooted at |child| get
    //   // removed from layers that do not belong in the same subtree.
    //   orphanLayers()
    //   if let w = widget {
    //     w.updateRootLayers()
    //   }
    // }

    viewHierarchyChanged(details: details)
    details.parent!.needsLayout = true
  }

  func propagateThemeChanged(theme: Theme) {
    guard _theme === theme else {
      return
    }

    for child in children {
      child.propagateThemeChanged(theme: theme)
    }
    
    onThemeChanged(theme: theme)
    
    for observer in observers {
      observer.onViewThemeChanged(observed: self)
    }
  }


  func propagateVisibilityNotifications(from: View, isVisible: Bool) {
    for child in children {
      child.propagateVisibilityNotifications(from: from, isVisible: isVisible)
    }
    visibilityChangedImpl(startingFrom: from, isVisible: isVisible)
  }

  func visibilityChangedImpl(startingFrom: View, isVisible: Bool) {
    visibilityChanged(startingFrom: startingFrom, isVisible: isVisible)
  }

  func boundsChanged(previousBounds: IntRect) {

    if isVisible {
      // Paint the new bounds.
      schedulePaintBoundsChanged(
          type: bounds.size == previousBounds.size ? SchedulePaintType.SizeSame : SchedulePaintType.SizeChanged)
    }

    var nilLayer: Layer? = nil

    if layer != nil {
      if let p = parent {
        let newBounds = localBounds + IntVec2(x: mirroredX, y: y) + p.calculateOffsetToAncestorWithLayer(layerParent: &nilLayer)
        setLayerBounds(boundsInDip: newBounds)
      } else {
        setLayerBounds(boundsInDip: bounds)
      }

      // In RTL mode, if our width has changed, our children's mirrored bounds
      // will have changed. Update the child's layer bounds, or if it is not a
      // layer, the bounds of any layers inside the child.
      if i18n.isRTL() && bounds.width != previousBounds.width {
        for child in children {
          child.updateChildLayerBounds(offset: IntVec2(x: child.mirroredX, y: child.y))
        }
      }
    } else {
      var nilLayer: Layer? = nil
      // If our bounds have changed, then any descendant layer bounds may have
      // changed. Update them accordingly.
      updateChildLayerBounds(offset: calculateOffsetToAncestorWithLayer(layerParent: &nilLayer))
    }

    onBoundsChanged(previousBounds: previousBounds)

    if previousBounds.size != size {
      needsLayout = false
      layout()
    }

    if getNeedsNotificationWhenVisibleBoundsChange() {
      onVisibleBoundsChanged()
    }

    // Notify interested Views that visible bounds within the root view may have
    // changed.
    if descendantsToNotify.count > 0 {
      for descendant in descendantsToNotify {
        descendant.onVisibleBoundsChanged()
      }
    }
  }

  static func registerChildrenForVisibleBoundsNotification(view: View) {
    if (view.getNeedsNotificationWhenVisibleBoundsChange()) {
      view.registerForVisibleBoundsNotification()
    }
    for child in view.children {
      registerChildrenForVisibleBoundsNotification(view: child)
    }
  }

  static func unregisterChildrenForVisibleBoundsNotification(view: View) {
    if view.getNeedsNotificationWhenVisibleBoundsChange() {
      view.unregisterForVisibleBoundsNotification()
    }
    for child in view.children {
      View.unregisterChildrenForVisibleBoundsNotification(view: child)
    }
  }

  func registerForVisibleBoundsNotification() {
    guard !registeredForVisibleBoundsNotification else {
      return
    }

    registeredForVisibleBoundsNotification = true

    var ancestor = parent
    while ancestor != nil {
      ancestor!.addDescendantToNotify(view: self)
      ancestor = ancestor!.parent
    }
  }

  func unregisterForVisibleBoundsNotification() {
    guard registeredForVisibleBoundsNotification else {
      return
    }

    registeredForVisibleBoundsNotification = false

    var ancestor = parent
    while ancestor != nil {
      ancestor!.removeDescendantToNotify(view: self)
      ancestor = ancestor!.parent
    }
  }

  func addDescendantToNotify(view: View) {
    descendantsToNotify.append(view)
  }

  func removeDescendantToNotify(view: View) {
    for (index, item) in descendantsToNotify.enumerated() {
      if item === view {
        descendantsToNotify.remove(at: index)
      }
    }
  }

  func setLayerBounds(boundsInDip: IntRect) {
    layer!.bounds = boundsInDip
    snapLayerToPixelBoundary()
  }

  func getTransformRelativeTo(ancestor: View, transform: inout Transform) -> Bool {
    var p: View? = self

    while p != nil && p !== ancestor {
      transform.concatTransform(transform: p!.transform)
      var translation = Transform()
      translation.translate(x: Float(p!.mirroredX), y: Float(p!.y))
      transform.concatTransform(transform: translation)
      p = p!.parent
    }

    return p === ancestor
  }

  func convertPointForAncestor(ancestor: View?, point: inout IntPoint) -> Bool {
    var trans = Transform()
    let result = getTransformRelativeTo(ancestor: ancestor!, transform: &trans)
    var p = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    trans.transformPoint(point: &p)
    point = IntPoint.toFloored(point: FloatPoint(p))
    return result
  }

  func convertPointFromAncestor(ancestor: View?, point: inout IntPoint) -> Bool {
    var trans = Transform()
    let result = getTransformRelativeTo(ancestor: ancestor!, transform: &trans)
    var p = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    let _ = trans.transformPointReverse(point: &p)
    point = IntPoint.toFloored(point: FloatPoint(p))
    return result
  }

  func convertRectForAncestor(ancestor: View?, rect: inout FloatRect) -> Bool {
    var trans = Transform()
    let result = getTransformRelativeTo(ancestor: ancestor!, transform: &trans)
    trans.transformRect(rect: &rect)
    return result
  }

  func convertRectFromAncestor(ancestor: View?, rect: inout FloatRect) -> Bool {
    var trans = Transform()
    let result = getTransformRelativeTo(ancestor: ancestor!, transform: &trans)
    let _ = trans.transformRectReverse(rect: &rect)
    return result
  }

  func createLayer(type: LayerType = .PictureLayer) {
  //func createLayer(type: LayerType = .Textured) {
    do {
      for child in children {
        child.updateChildLayerVisibility(ancestorVisible: true)
      }

      layer = try Layer(type: type)
      layer!.delegate = self
      layer!.name = className
      let _ = updateParentLayers()
      updateLayerVisibility()

      // The new layer needs to be ordered in the layer tree according
      // to the view tree. Children of this layer were added in order
      // in updateParentLayers().
      if let p = parent {
        p.reorderLayers()
      }

      if let w = widget {
        //w.updateRootLayers()
        w.layerTreeChanged()
      }
      schedulePaintOnParent()
    } catch {
      //print("View: error creating layer")
    }
  }

  func schedulePaintOnParent() {
    if let p = parent {
      // Translate the requested paint rect to the parent's coordinate system
      // then pass this notification up to the parent.
      p.schedulePaintInRect(rect: convertRectToParent(rect: localBounds))
    }
  }

  func updateParentLayers() -> Bool {
    if let l = layer {
      if l.parent == nil {
        updateParentLayer()
        return true
      }
      return false
    }
    var result = false
    for child in children {
      if child.updateParentLayers() {
        result = true
      }
    }
    return result
  }

  func reparentLayer(offset: IntVec2, parentLayer: Layer?) {
    if let l = layer {
      l.bounds = localBounds + offset
      assert(l !== parentLayer)
      if let p = parentLayer {
        p.add(child: l)
      }
      let _ = l.schedulePaint(invalidRect: localBounds)
      moveLayerToParent(parentLayer: l, point: IntPoint())
    }
  }

  func updateLayerVisibility() {
    var vis = isVisible
    var view = parent
    while vis && view != nil && view!.layer == nil {
      vis = view!.isVisible
      view = view!.parent
    }
    updateChildLayerVisibility(ancestorVisible: vis)
  }

  func updateChildLayerVisibility(ancestorVisible: Bool) {
    if let l = layer {
      l.isVisible = ancestorVisible && isVisible
    } else {
      for child in children {
        child.updateChildLayerVisibility(ancestorVisible: ancestorVisible && isVisible)
      }
    }
  }

  func orphanLayers() {
    if let l = layer {
      if let p = l.parent {
        p.remove(child: l)
      }
      // The layer belonging to this View has already been orphaned. It is not
      // necessary to orphan the child layers.
      return
    }
    for child in children {
      child.orphanLayers()
    }
  }

  public func destroyLayer() {
    destroyLayerImpl(.notify)
  }

  public func destroyLayerImpl(_ notifyParents: LayerChangeNotifyBehavior) {
    guard _paintToLayer else {
      return
    }

    _paintToLayer = false
    guard let l = layer else {
      return
    }

    let newParent: Layer? = l.parent
    let children = l.children
    for i in 0..<children.count {
      l.remove(child: children[i])
      if let p = newParent {
        p.add(child: children[i])
      }
    }

    // LayerOwner.destroyLayer() part
    layer = nil

    if newParent != nil {
      reorderLayers()
    }

    var nilLayer: Layer? = nil
    updateChildLayerBounds(offset: calculateOffsetToAncestorWithLayer(layerParent: &nilLayer))

    schedulePaint()

    // Notify the parent chain about the layer change.
    if notifyParents == LayerChangeNotifyBehavior.notify {
      notifyParentsOfLayerChange()
    }

    if let w = widget {
      w.layerTreeChanged()
    }
  }
  
  // public func destroyLayerImpl(_ notifyParents: LayerChangeNotifyBehavior) {
  //   //print("destroyLayerImpl: let newParent = layer!.parent. layer = nil ? \(layer == nil)")
  //   let newParent = layer!.parent

  //   //print("destroyLayerImpl: for child in layer!.children")
  //   for child in layer!.children {
  //     layer!.remove(child: child)
  //     if newParent != nil {
  //       newParent!.add(child: child)
  //     }
  //   }

  //   // LayerOwner.destroyLayer()
  //   //  or
  //   // super.destroyLayer()

  //   //print("destroyLayerImpl: if newParent != nil")
  //   if newParent != nil {
  //     reorderLayers()
  //   }
  //   var nilLayer: Layer? = nil
  //   //print("destroyLayerImpl: updateChildLayerBounds")
  //   updateChildLayerBounds(offset: calculateOffsetToAncestorWithLayer(layerParent: &nilLayer))
  //   //print("destroyLayerImpl: schedulePaint()")
  //   schedulePaint()

  //   if notifyParents == .notify {
  //     //print("destroyLayerImpl: notifyParentsOfLayerChange()")
  //     notifyParentsOfLayerChange()
  //   }

  //   if let w = widget {
  //     //print("destroyLayerImpl: w.layerTreeChanged()")
  //     w.layerTreeChanged()
  //   }

  // }

  func processMousePressed(event: MouseEvent)  -> Bool {
    var dragOperations = DragOperation(rawValue: 0)!

    if isEnabled && event.onlyLeftMouseButton && hitTest(point: event.location) {
      dragOperations = getDragOperations(pressPoint: event.location)
    }

    var contextMenu: ContextMenuController? = nil

    if event.isRightMouseButton {
      contextMenu = contextMenuController
    }

    var storageId = 0
    var info = dragInfo!

    if event.onlyRightMouseButton && contextMenu != nil &&
      contextMenuOnMousePress && hitTest(point: event.location) {
        let viewStorage = ViewStorage.instance
        storageId = viewStorage.createStorageID()
        viewStorage.storeView(storageId: storageId, view: self)
    }

    let result = onMousePressed(event: event)

    if !isEnabled {
      return result
    }

    if event.onlyRightMouseButton && contextMenu != nil && contextMenuOnMousePress {
      // Assume that if there is a context menu controller we won't be deleted
      // from mouse pressed.
      var location = IntPoint(event.location)
      if hitTest(point: location) {
        if storageId != 0 {
          assert(self === ViewStorage.instance.retrieveView(storageId: storageId))
        }
        View.convertPointToScreen(src: self, point: &location)
        showContextMenu(point: location, sourceType: .Mouse)
        return true
      }
    }

    // WARNING: we may have been deleted, don't use any View variables.
    if dragOperations != DragOperation.DragNone {
      info.setPossibleDrag(p: event.location)
      return true
    }
    return contextMenu != nil || result
  }

  func processMouseDragged(event: MouseEvent) -> Bool {
    if let info = dragInfo {
      let possibleDrag = info.possibleDrag
      if possibleDrag && View.exceededDragThreshold(delta: info.startPoint - event.location) &&
        (dragController == nil ||
          dragController!.canStartDragForView(
           sender: self, pressPoint: info.startPoint, point: event.location)) {
             let _ = doDrag(event: event, pressPoint: info.startPoint, source: DragEventSource.Mouse)
      } else {
        if onMouseDragged(event: event) {
          return true
        }
      }
     return contextMenuController != nil || possibleDrag
    }
    return false
  }

  func processMouseReleased(event: MouseEvent) {

    if !contextMenuOnMousePress && contextMenuController != nil &&
      event.onlyRightMouseButton {
        var location = IntPoint(event.location)
        onMouseReleased(event: event)
        if hitTest(point: location) {
          View.convertPointToScreen(src: self, point: &location)
          showContextMenu(point: location, sourceType: .Mouse)
        }
    } else {
     onMouseReleased(event: event)
    }
  }

  func registerPendingAccelerators() {
    guard registeredAcceleratorCount == accelerators.count || widget != nil else {
      return
    }

    if let acceleratorFocusManager = focusManager {
      for accel in accelerators {
        acceleratorFocusManager.registerAccelerator(
          accelerator: accel,
          priority: AcceleratorManager.HandlerPriority.NormalPriority,
          target: self)
      }
      registeredAcceleratorCount = accelerators.count
    }
  }

  func unregisterAccelerators(leaveDataIntact: Bool) {

    if widget != nil {

      if let manager = acceleratorFocusManager {
        manager.unregisterAccelerators(target: self)
        acceleratorFocusManager = nil
      }

      if !leaveDataIntact {
        accelerators.removeAll()
      }
      registeredAcceleratorCount = 0
    }

  }

  func initFocusSiblings(view: View, index: Int) {
    let count = children.count

    if count == 0 {
      view.nextFocusableView = nil
      view.previousFocusableView = nil
    } else {
      if index == count {
        // We are inserting at the end, but the end of the child list may not be
        // the last focusable element. Let's try to find an element with no next
        // focusable element to link to.
        var lastFocusView: View? = nil
        for child in children {
          if child.nextFocusableView == nil {
            lastFocusView = child
            break
          }
        }
        if lastFocusView == nil {
          // Hum... there is a cycle in the focus list. Let's just insert ourself
          // after the last child.
          let prev = children[index - 1]
          view.previousFocusableView = prev
          view.nextFocusableView = prev.nextFocusableView
          prev.nextFocusableView!.previousFocusableView = view
          prev.nextFocusableView = view
        } else {
          lastFocusView!.nextFocusableView = view
          view.nextFocusableView = nil
          view.previousFocusableView = lastFocusView
        }
      } else {
        let prev = children[index].previousFocusableView
        view.previousFocusableView = prev
        view.nextFocusableView = children[index]
        if let p = prev {
          p.nextFocusableView = view
        }
        children[index].previousFocusableView = view
      }
    }
  }

  func advanceFocusIfNecessary() {

    if accessibilityFocusable || !hasFocus {
      return
    }

    if let manager = focusManager {
      manager.advanceFocusIfNecessary()
    }
  }

    //func propagateThemeChanged() {
    // for child in children.reversed() {
    //  child.propagateThemeChanged()
    // }
    // onThemeChanged()
  //}

  func propagateLocaleChanged() {
    for child in children.reversed() {
      child.propagateLocaleChanged()
    }
    onLocaleChanged()
  }

  func propagateDeviceScaleFactorChanged(deviceScaleFactor: Float) {
    for child in children.reversed() {
      child.propagateDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    }
    if layer == nil {
      onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    }
  }

  func updateTooltip() {
    if let manager = widget?.tooltipManager {
      manager.updateTooltip()
    }
  }

  func doDrag(event: LocatedEvent,
              pressPoint: IntPoint,
              source: DragEventSource) -> Bool {

    let dragOperations = getDragOperations(pressPoint: pressPoint)

    if dragOperations == .DragNone {
      return false
    }

    guard let win = widget else {
      return false
    }

    // Don't attempt to start a drag while in the process of dragging. This is
    // especially important on X where we can get multiple mouse move events when
    // we start the drag.
    if win.draggedView != nil {
      return false
    }

    let data = OSExchangeData()
    writeDragData(pressPoint: pressPoint, data: data)

    var windowLocation = IntPoint(event.location)
    View.convertPointToWindow(src: self, point: &windowLocation)
    win.runShellDrag(view: self, data: data, location: windowLocation, operation: dragOperations, source: source)
    // WARNING: we may have been deleted.
    return true
  }

}

extension View : LayerDelegate {

  public func onPaintLayer(context: PaintContext) {
    //print("\n\nView.onPaintLayer\n\n")
    paintFromPaintRoot(context: context)
    //paint(context: context)
  }

  public func onDelegatedFrameDamage(damageRectInDip: IntRect) {

  }

  public func prepareForLayerBoundsChange() -> LayerChangeCallback? {
    return nil
  }

}

extension View: LayerOwner {

  public var layer: Layer? {
    get {
      return _layer
    }
    set {
      _layer = newValue
    }
  }

  public var ownerDelegate: LayerOwnerDelegate? {
    get {
      return _ownerDelegate
    }
    set {
      _ownerDelegate = newValue
    }
  }

  public var ownsLayer: Bool {
    return _layer != nil
  }

  public func acquireLayer() -> Layer? {
    assert(false) // make sure this is not called for now
    return nil
  }

  public func recreateLayer() -> Layer? {
    assert(false) // make sure this is not called for now
    return nil
  }

}
