// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Platform
import Foundation
import Compositor
import Base

public class Window : EventTarget {

  public enum StackDirection {
    case StackAbove
    case StackBelow
  }

  public enum VisibilityAnimationTransition : Int {
    case AnimateShow = 0x1
    case AnimateHide = 0x2
    case AnimateBoth = 0x3
    case AnimateNone = 0x4
  }

  public var id: Int

  public var type: WindowType

  public var name: String {
    didSet {
      if layer != nil {
        updateLayerName()
      }
    }
  }

  public var title: String {
    didSet {
      for observer in observers {
        observer.onWindowTitleChanged(window: self)
      }
    }
  }

  // weak because the UIWidget, a natural delegate, own this
  private(set) public weak var delegate: WindowDelegate?

  public var host: WindowTreeHost? {
    get {
      if let root = rootWindow {
          return root._host
      }
      return nil
    }
    set {
      _host = newValue
    }
  }

  public var transparent: Bool {
    didSet {
      if let l = layer {
        l.fillsBoundsOpaquely = !transparent
      }
    }
  }

  public var fillsBoundsCompletely: Bool {
     get {
       return layer!.fillsBoundsCompletely
     }
     set {
      layer!.fillsBoundsCompletely = newValue
     }
   }

  public var bounds: IntRect {
    get {
      return _bounds
    }
    set {

      // CRAPWARE
      //if isRoot {
      //  //print("root window: \(newValue.size)")
      //}
      // END OF CRAPWARE

      if let p = parent, let layout = p.layoutManager {
        layout.setChildBounds(child: self, requestedBounds: newValue)
      } else {
        // Ensure we don't go smaller than our minimum bounds.
        var finalBounds = newValue
        if let d = delegate {
          let minSize = d.minimumSize
          finalBounds.width = max(minSize.width, finalBounds.width)
          finalBounds.height = max(minSize.height, finalBounds.height)
        }
        setBoundsInternal(newBounds: finalBounds)
      }
    }
  }

  public var targetBounds: IntRect {
    get {
      if let layerTarget = layer {
        return layerTarget.targetBounds
      }
      return _bounds
    }
  }

  private(set) public weak var parent: Window?

  public var rootWindow: Window? {
    if isRoot {
      return self
    } else if parent != nil {
      return parent!.rootWindow
    }
    return nil
  }

  public var isRoot: Bool {
    if _host != nil {
      return true
    }
    return false
  }

  public var isVisible: Bool {
    get {
      if let x = layer {
        if _visible && x.isDrawn {
          return true
        }
      }
      return false
    }
    set {
      if let x = layer {
        if newValue == x.targetVisibility {
          return
        }
      }

      for observer in observers {
        observer.onWindowVisibilityChanging(window: self, visible: newValue)
      }

      if let visibilityClient = UI.getVisibilityClient(window: self) {
        //print("Window.isVisible = \(newValue) -> visibilityClient.updateLayerVisibility")
        visibilityClient.updateLayerVisibility(window: self, visible: newValue)
      } else {
        //print("Window.isVisible = \(newValue) -> layer!.isVisible = \(newValue)")
        layer!.isVisible = newValue
      }

      _visible = newValue

      schedulePaint()

      if let p = parent, let layout = p.layoutManager {
        layout.onChildWindowVisibilityChanged(child: self, visible: newValue)
      }

      if let d = delegate {
        d.onWindowTargetVisibilityChanged(visible: newValue)
      }

      notifyWindowVisibilityChanged(target: self, visible: newValue)
    }
  }

  public var boundsInRootWindow: IntRect {
    guard let root = rootWindow else {
      return bounds
    }
    var boundsInRoot = IntRect(size: bounds.size)
    Window.convertRectToTarget(source: self, target: root, rect: &boundsInRoot)
    return boundsInRoot
  }

  public var boundsInScreen: IntRect {
      var bounds = IntRect(self.boundsInRootWindow)
      if let root = rootWindow, let screenPositionClient = UI.getScreenPositionClient(window: root) {
          var origin = IntPoint(bounds.origin)
          screenPositionClient.convertPointToScreen(window: root, point: &origin)
          bounds.origin = origin
      }
      return bounds
  }

  public var layoutManager: WindowLayoutManager? {
    didSet {
      if let manager = layoutManager {
        for window in children {
          manager.onWindowAddedToLayout(child: window)
        }
      }
    }
  }

  public var children: [Window]
  public var ignoreEvents: Bool

  public var toplevelWindow: Window? {
    var topmostWindowWithDelegate: Window? = nil
    var window = parent
    while window != nil {
      if window!.delegate != nil {
        topmostWindowWithDelegate = window
      }
      window = window!.parent
    }
    return topmostWindowWithDelegate
  }

  public var hasFocus: Bool {
    if let client = UI.getFocusClient(window: rootWindow) {
      return client.focusedWindow === self
    }
    return false
  }

  public var canFocus: Bool {
    if isRoot {
      return _visible
    }

    guard let p = parent, let d = delegate else {
      return false
    }

    if !d.canFocus {
      return false
    }

    if let client = UI.getEventClient(window: rootWindow) {
      if !client.canProcessEventsWithinSubtree(window: self) {
        return false
      }
    }

    return p.canFocus
  }

  public var canReceiveEvents: Bool {
    if isRoot {
      return _visible
    }

    if let client = UI.getEventClient(window: rootWindow) {
      if !client.canProcessEventsWithinSubtree(window: self) {
        return false
      }
    }

    return parent != nil && _visible && parent!.canReceiveEvents
  }

  public var hasCapture: Bool {
    if let captureClient = UI.getCaptureClient(window: rootWindow) {
      return captureClient.captureWindow === self
    }
    return false
  }

  public var localSurfaceId: LocalSurfaceId {
    if !_localSurfaceId.isValid {
      allocateSurfaceId()
    }
    return _localSurfaceId
  }

  // Clients: should only be available on root window
  public var property: [String: Any] = [:]
  public var cursorClient: CursorClient?
  public var parentingClient: WindowParentingClient?
  public var captureClient: CaptureClient?
  public var eventClient: EventClient?
  public var windowTreeClient: WindowTreeClient?
  public var focusClient: FocusClient?
  public var screenPositionClient: ScreenPositionClient?
  public var windowStackingClient: WindowStackingClient?
  public var windowMoveClient: WindowMoveClient?
  public var transientWindowClient: TransientWindowClient?
  public var visibilityClient: VisibilityClient?
  public var focusChangeObserver: FocusChangeObserver?
  public var activationChangeObserver: ActivationChangeObserver?
  public var activationClient: ActivationClient?
  public var activationDelegate: ActivationDelegate?
  public var dispatcherClient: DispatcherClient?
  public var dragDropClient: DragDropClient?
  public var dragDropDelegate: DragDropDelegate?
  public var tooltipController: TooltipController?
  public var animationHost: WindowAnimationHost?
  public var canMaximize: Bool
  public var canMinimize: Bool
  public var canResize: Bool
  public var showState: WindowShowState
  public var childWindowVisibilityChangesAnimated: Bool
  public var visibilityAnimationDuration: TimeTicks
  public var visibilityAnimationTransition: VisibilityAnimationTransition
  public weak var widget: UIWidget?
  private var _localSurfaceId: LocalSurfaceId = LocalSurfaceId()
  private var parentLocalSurfaceIdAllocator: ParentLocalSurfaceIdAllocator
  // EventTarget
  public override var parentTarget: EventTarget? {
    if isRoot {
      if let clientEvent = UI.getEventClient(window: self) {
        return clientEvent.toplevelEventTarget
      } else {
        return UI
      }
    }
    return parent
  }

  public override var childIterator: EventTargetIterator<EventTarget> {
    //return EventTargetIterator<EventTarget>(elems: children)
    return EventTargetIterator<EventTarget>()
  }

  // property
  weak var viewsWindow: Window?
  // property
  weak var windowManager: TransientWindowManager?

  private var observers: [WindowObserver]
  private var hitTestBoundsOverrideInner: IntInsets
  private var _host: WindowTreeHost?
  private var _bounds: IntRect
  private var _visible: Bool
  private var _layer: Layer?
  private var _ownerDelegate: LayerOwnerDelegate?

  public init(delegate: WindowDelegate? = nil) {

    id = 0
    type = .Normal
    name = ""
    title = ""
    transparent = false
    ignoreEvents = false
    children = [Window]()
    observers = [WindowObserver]()
    hitTestBoundsOverrideInner = IntInsets()
    canMaximize = true
    canMinimize = true
    canResize = true
    showState = .Default
    childWindowVisibilityChangesAnimated = false
    visibilityAnimationDuration = TimeTicks()
    visibilityAnimationTransition = .AnimateNone
    parentLocalSurfaceIdAllocator = ParentLocalSurfaceIdAllocator()
    _bounds = IntRect()
    _visible = false
    self.delegate = delegate
    super.init()
    self.targetHandler = delegate
  }

  deinit {
    // if initialize was not called(on a exception), we dont have layer, so we can exit gracefully
    guard let ourLayer = layer else {
      return
    }

    if let layerOwner = ourLayer.owner {
      if layerOwner as! Window === self {
        ourLayer.completeAllAnimations()
      }
    }

    ourLayer.suppressPaint()

    if let dx = delegate {
      dx.onWindowDestroying(window: self)
    }

    for observer in observers {
      observer.onWindowDestroying(window: self)
    }

    targetHandler = nil

    if let windowHost = host {
      windowHost.dispatcher!.onPostNotifiedWindowDestroying(window: self)
    }

    let windowIncorrectlyCleanedUp = cleanupGestureState()
    assert(!windowIncorrectlyCleanedUp)

    removeChildren()

    if let px = parent {
      px.removeChild(child: self)
    }

    if let dx = delegate {
      dx.onWindowDestroyed(window: self)
    }

    for observer in observers {
      removeObserver(observer: observer)
      observer.onWindowDestroyed(window: self)
    }

    // Clear properties.
    //for (std::map<const void*, Value>::const_iterator iter = prop_map_.begin();
    //     iter != prop_map_.end();
    //     ++iter) {
    //  if (iter->second.deallocator)
    //    (*iter->second.deallocator)(iter->second.value);
    //}
    //prop_map_.clear();

    // The layer will either be destroyed by |layer_owner_|'s dtor, or by whoever
    // acquired it.
    ourLayer.delegate = nil
    // likely unnecessary to us
    destroyLayer()
  }

  public static func convertPointToTarget(source: Window, target: Window, point: inout IntPoint) {
    if source.rootWindow !== target.rootWindow {
      if let sourceClient = UI.getScreenPositionClient(window: source.rootWindow) {
        sourceClient.convertPointToScreen(window: source, point: &point)
      }

      if let targetClient = UI.getScreenPositionClient(window: target.rootWindow) {
        targetClient.convertPointFromScreen(window: target, point: &point)
      }
    } else {
      Layer.convertPointToLayer(source: source.layer!, target: target.layer!, point: &point)
    }
  }

  public static func convertRectToTarget(source: Window, target: Window, rect: inout IntRect) {
    var origin = rect.origin
    Window.convertPointToTarget(source: source, target: target, point: &origin)
    rect.origin = origin
  }

  public func destroyLayer() {}

  public func show() {
    //print("Window.show")
    isVisible = true
  }

  public func hide() {
    isVisible = false
  }

  public func getCursor(at point: IntPoint) -> PlatformCursor? {
    if let d = delegate {
      return d.getCursor(at: point)
    }
    return nil
  }

  public func setTransform(transform: Transform) {
    for observer in observers {
      observer.onWindowTransforming(window: self)
    }

    layer!.transform = transform

    for observer in observers {
      observer.onWindowTransformed(window: self)
    }

    notifyAncestorWindowTransformed(source: self)
  }

  public func schedulePaintInRect(rect: IntRect) {
    let _ = layer?.schedulePaint(invalidRect: rect)
  }

  public func stackChildAtTop(child: inout Window) {
    if children.count <= 1 {
      return
    }
    var last = children[children.endIndex - 1]
    if child !== last {
      stackChildAbove(child: &child, target: &last)
    }
  }

  public func stackChildAbove(child: inout Window, target: inout Window) {
    var dir: StackDirection = .StackAbove
    stackChildRelativeTo(child: &child, target: &target, direction: &dir)
  }

  public func stackChildAtBottom(child: inout Window) {
    if children.count <= 1 {
      return
    }

    var first = children[0]
    if child === first {
      stackChildBelow(child: &child, target: &first)
    }
  }

  public func stackChildBelow(child: inout Window, target: inout Window) {
    var dir: StackDirection = .StackBelow
    stackChildRelativeTo(child: &child, target: &target, direction: &dir)
  }

  public func addChild(child: Window) throws {
    if let myLayer = layer, let childLayer = child.layer {
      //print("Window: adding layer \(myLayer.id) as child of \(childLayer.id)")
    }
    guard layer != nil && child.layer != nil else {
      throw UIError.OnAddChild(exception: UIException.AddChildWindow)
    }

    var params = WindowObserverHierarchyChangeParams()
    params.target = child
    params.newParent = self
    params.oldParent = child.parent
    params.phase = WindowObserverHierarchyChangePhase.HierarchyChanging
    notifyWindowHierarchyChange(params: params)

    let oldRoot = child.rootWindow

    //DCHECK(std::find(children_.begin(), children_.end(), child) ==
    //    children_.end());

    if let p = child.parent {
      p.removeChildImpl(child: child, newParent: self)
    }

    child.parent = self
    layer!.add(child: child.layer!)

    children.append(child)
    if let layout = layoutManager {
      layout.onWindowAddedToLayout(child: child)
    }

    for observer in observers {
      observer.onWindowAdded(window: child)
    }

    child.onParentChanged()

    if let root = rootWindow {
      if oldRoot !== root {
        root.host!.dispatcher!.onWindowAddedToRootWindow(window: child)
        child.notifyAddedToRootWindow()
      }
    }

    params.phase = .HierarchyChanged
    notifyWindowHierarchyChange(params: params)
  }

  public func removeChild(child: Window) {
    var params = WindowObserverHierarchyChangeParams()
    params.target = child
    params.newParent = nil
    params.oldParent = self
    params.phase = .HierarchyChanging
    notifyWindowHierarchyChange(params: params)

    removeChildImpl(child: child, newParent: nil)

    params.phase = .HierarchyChanged
    notifyWindowHierarchyChange(params: params)
  }

  public func contains(other: Window) -> Bool {
    var parent: Window? = other
    while parent != nil {
      if parent === self {
        return true
      }
      parent = parent!.parent
    }
    return false
  }

  public func getChildById(id: Int) -> Window? {
    for child in children {
      if child.id == id {
        return child
      }
      if let innerChild = child.getChildById(id: id) {
        return innerChild
      }
    }
    return nil
  }

  public func moveCursorTo(pointInWindow: IntPoint) {
    if let root = rootWindow {
      var pointInRoot = IntPoint(pointInWindow)
      Window.convertPointToTarget(source: self, target: root, point: &pointInRoot)
      root.host!.moveCursorToLocationInDIP(location: pointInRoot)
    }
  }

  public func addObserver(observer: WindowObserver) {
    observer.onObservingWindow(window: self)
    observers.append(observer)
  }

  public func removeObserver(observer: WindowObserver) {
    observer.onUnobservingWindow(window: self)
    for (index, other) in observers.enumerated() {
      if observer === other {
        observers.remove(at: index)
      }
    }
  }

  public func hasObserver(observer: WindowObserver) -> Bool {
    for other in observers {
      if observer === other {
        return true
      }
    }
    return false
  }

  public func containsPointInRoot(pointInRoot: IntPoint) -> Bool {
    guard let root = rootWindow else {
      return false
    }
    var localPoint = IntPoint(pointInRoot)
    Window.convertPointToTarget(source: root, target: self, point: &localPoint)
    return IntRect(size: targetBounds.size).contains(point: localPoint)
  }

  public func containsPoint(localPoint: IntPoint) -> Bool {
    return IntRect(size: _bounds.size).contains(point: localPoint)
  }

  public func getEventHandlerForPoint(localPoint: IntPoint) -> Window? {
    return getWindowForPoint(localPoint: localPoint, returnTightest: true, forEventHandling: true)
  }

  public func getTopWindowContainingPoint(localPoint: IntPoint) -> Window? {
    return getWindowForPoint(localPoint: localPoint, returnTightest: false, forEventHandling: false)
  }

  public func focus() {
    if let client = UI.getFocusClient(window: rootWindow) {
      client.focusWindow(window: self)
    }
  }

  public func setCapture() {
    if !_visible {
      return
    }
    if let captureClient = UI.getCaptureClient(window: rootWindow) {
      captureClient.setCapture(window: self)
    }
  }

  public func releaseCapture() {
    if let root = rootWindow, let captureClient = UI.getCaptureClient(window: root) {
      captureClient.releaseCapture(window: self)
    }
  }

  public func suppressPaint() {
    layer!.suppressPaint()
  }


  public func removeChildren() {
    for child in children {
     removeChild(child: child)
    }
  }

  //public func prepareForLayerBoundsChange() -> () -> Void {
  //}

  public override func canAcceptEvent(event: Graphics.Event) -> Bool {
    if let client = UI.getEventClient(window: rootWindow) {
      if !client.canProcessEventsWithinSubtree(window: self) {
        return false
      } 
    }

    if event.isEndingEvent {
      return true
    }

    if !_visible {
      return false
    }

    // The top-most window can always process an event.
    if parent == nil {
      return true
    }

    // For located events (i.e. mouse, touch etc.), an assumption is made that
    // windows that don't have a default event-handler cannot process the event
    // (see more in GetWindowForPoint()). This assumption is not made for key
    // events.
    return event.isKeyEvent || targetHandler != nil
  }

  public override func convertEventToTarget(target: EventTarget, event: LocatedEvent) {
    let window = target as! Window
    event.convertLocationToTarget(source: self, target: window)
  }

  public func cleanupGestureState() -> Bool {
    return true
  }

  public func initialize(type: LayerType) throws {
    layer = try Layer(type: type)

    layer!.isVisible = false
    layer!.delegate = self
    updateLayerName()
    layer!.fillsBoundsOpaquely = !transparent

    UI.notifyWindowInitialized(window: self)

    //print("Window: created layer \(layer!.id) layer.fillsBoundsOpaquely = \(layer!.fillsBoundsOpaquely)")
  }

  public func updateLocalSurfaceIdFromEmbeddedClient(surfaceId localSurfaceId: LocalSurfaceId?) {
    allocateSurfaceId()
  }

  public func allocateSurfaceId() {
    _localSurfaceId = parentLocalSurfaceIdAllocator.generateId()
  }

  // TODO: implement
  public func setNativeWindowProperty(name: String, value: UnsafeMutableRawPointer) {
    
  }

  // TODO: implement
  public func getNativeWindowProperty(name: String) -> UnsafeMutableRawPointer? {
    return nil
  }

  func hitTest(localPoint: IntPoint) -> Bool {
    let localBounds = IntRect(size: bounds.size)

    if let d = delegate {
      if !d.hasHitTestMask {
        return localBounds.contains(point: localPoint)
      }
    }

    var mask = Path()
    delegate!.getHitTestMask(mask: &mask)

    let clipRegion = Region()
    clipRegion.setRect(x: localBounds.x, y: localBounds.y, width: localBounds.width, height: localBounds.height)
    let maskRegion = Region()
    return maskRegion.setPath(mask: mask, clip: clipRegion) && maskRegion.contains(x: localPoint.x, y: localPoint.y)
  }

  func setBoundsInternal(newBounds: IntRect) {
    let oldBounds = targetBounds
    layer!.bounds = newBounds

    if layer!.delegate !== self {
      onLayerBoundsChanged(oldBounds: oldBounds, reason: .NotFromAnimation)
    }
  }

  func schedulePaint() {
    schedulePaintInRect(rect: IntRect(x: 0, y: 0, width: bounds.width, height: bounds.height))
  }

  func paint(context: PaintContext) {
    if let d = delegate {
      d.onPaint(context: context)
    }
  }
  // this is not implemented in .cc
  func paintLayerlessChildren(context: PaintContext) {}

  func getWindowForPoint(localPoint: IntPoint, returnTightest: Bool, forEventHandling: Bool) -> Window? {
    if !_visible {
      return nil
    }

    if (forEventHandling && !hitTest(localPoint: localPoint)) || (!forEventHandling && !containsPoint(localPoint: localPoint)) {
      return nil
    }

    if forEventHandling && !hitTestBoundsOverrideInner.isEmpty {
      var insetLocalBounds = IntRect(origin: IntPoint(), size: bounds.size)
      insetLocalBounds.inset(insets: hitTestBoundsOverrideInner)

      assert(hitTest(localPoint: localPoint))
      if !insetLocalBounds.contains(point: localPoint) {
        if delegate != nil {
          return self
        }
        return nil
      }
    }

    if !returnTightest && delegate != nil {
      return self
    }

    // TODO: check if this is right!!
    for i in (children.startIndex ... children.endIndex).reversed() {
      let child = children[i-1]

      if forEventHandling {
        if child.ignoreEvents {
          continue
        }
        // The client may not allow events to be processed by certain subtrees.
        if let client = UI.getEventClient(window: rootWindow) {
          if !client.canProcessEventsWithinSubtree(window: child) {
            continue
          }
        }
        if let d = delegate {
          if !d.shouldDescendIntoChildForEventHandling(child: child, location: localPoint) {
            continue
          }
        }
      }

      var pointInChildCoords = IntPoint(localPoint)
      Window.convertPointToTarget(source: self, target: child, point: &pointInChildCoords)
      let match = child.getWindowForPoint(localPoint: pointInChildCoords, returnTightest: returnTightest, forEventHandling: forEventHandling)
      return match ?? nil
    }

    if delegate != nil {
      return self
    }

    return nil
  }

  func removeChildImpl(child: Window, newParent: Window?) {
    if let layout = layoutManager {
      layout.onWillRemoveWindowFromLayout(child: child)
    }
    for observer in observers {
      observer.onWillRemoveWindow(window: child)
    }

    let root = child.rootWindow
    var newRootWindow: Window? = nil
    if newParent != nil {
      newRootWindow = newParent!.rootWindow
    }
    if root != nil && root !== newRootWindow && newRootWindow != nil {
      child.notifyRemovingFromRootWindow(newRoot: newRootWindow!)
    }

    if child.ownsLayer {
      layer!.remove(child: child.layer!)
    }

    child.parent = nil
    for (index, win) in children.enumerated() {
      if child === win {
        children.remove(at: index)
      }
    }

    child.onParentChanged()
    if let layout = layoutManager {
      layout.onWindowRemovedFromLayout(child: child)
    }
  }

  func onParentChanged() {
    for observer in observers {
      observer.onWindowParentChanged(window: self, parent: parent!)
    }
  }

  // TODO: check if implementation is right..
  func stackChildRelativeTo(child: inout Window, target: inout Window, direction: inout StackDirection) {

    if let root = rootWindow, let stackingClient = UI.getWindowStackingClient(window: root) {
      if !stackingClient.adjustStacking(child: &child, target: &target, direction: &direction){
        return
      }
    }

    var childIndex = 0, targetIndex = 0
    for (index, window) in children.enumerated() {
      if window === child {
        childIndex = index
        break
      }
    }

    for (index, window) in children.enumerated() {
      if window === target {
        targetIndex = index
        break
      }
    }

    // Don't move the child if it is already in the right place.
    if (direction == .StackAbove && childIndex == targetIndex + 1) ||
       (direction == .StackBelow && childIndex + 1 == targetIndex) {
      return
    }

    var destIndex = 0
    if direction == .StackAbove {
      if childIndex < targetIndex {
        destIndex = targetIndex
      } else {
        destIndex = targetIndex + 1
      }
    } else {
      if childIndex < targetIndex {
        destIndex = targetIndex - 1
      } else {
        destIndex = targetIndex
      }
    }

    children.remove(at: childIndex)
    children.insert(child, at: destIndex)

    stackChildLayerRelativeTo(child: child, target: target, direction: direction)

    child.onStackingChanged()
  }

  func stackChildLayerRelativeTo(child: Window, target: Window, direction: StackDirection) {
    if (direction == .StackAbove) {
      layer!.stackAbove(child: child.layer!, other: target.layer!)
    } else {
      layer!.stackBelow(child: child.layer!, other: target.layer!)
    }
  }

  public func setBoundsInScreen(newBoundsInScreen: IntRect, dstDisplay: Display) {
    if let root = rootWindow {
      if let screenClient = UI.getScreenPositionClient(window: root) {
        screenClient.setBounds(window: self, bounds: newBoundsInScreen, display: dstDisplay)
      }
      return
    }
    bounds = newBoundsInScreen
  }

  func onStackingChanged() {
    for observer in observers {
      observer.onWindowStackingChanged(window: self)
    }
  }

  func notifyRemovingFromRootWindow(newRoot: Window) {
    for observer in observers {
      observer.onWindowRemovingFromRootWindow(window: self, newRoot: newRoot)
    }
    for window in children {
      window.notifyRemovingFromRootWindow(newRoot: newRoot)
    }
  }

  func notifyAddedToRootWindow() {
    for observer in observers {
      observer.onWindowAddedToRootWindow(window: self)
    }
    for window in children {
      window.notifyAddedToRootWindow()
    }
  }

  func notifyWindowVisibilityChanged(target: Window, visible: Bool) {
    if !notifyWindowVisibilityChangedDown(target: target, visible: visible) {
      return
    }
    notifyWindowVisibilityChangedUp(target: target, visible: visible)
  }

  func notifyWindowVisibilityChangedAtReceiver(target: Window, visible: Bool) -> Bool {
    let tracker = WindowTracker()
    tracker.add(window: self)
    for observer in observers {
      observer.onWindowVisibilityChanged(window: target, visible: visible)
    }
    return tracker.contains(window: self)
  }

  func notifyWindowVisibilityChangedDown(target: Window, visible: Bool) -> Bool {
    return false
  }

  func notifyWindowVisibilityChangedUp(target: Window, visible: Bool) {
    var win = parent
    while win != nil {
      let ret = win!.notifyWindowVisibilityChangedAtReceiver(target: target, visible: visible)
      win = win!.parent
      assert(ret)
    }
  }

  func notifyAncestorWindowTransformed(source: Window) {
    for observer in observers {
      observer.onAncestorWindowTransformed(source: source, window: self)
    }

    for window in children {
      window.notifyAncestorWindowTransformed(source: source)
    }
  }

  func notifyWindowHierarchyChange(params: WindowObserverHierarchyChangeParams) {
    if let target = params.target {
      target.notifyWindowHierarchyChangeDown(params: params)
    }
    switch params.phase {
    case .HierarchyNone:
      break
    case .HierarchyChanging:
      if let oldParent = params.oldParent {
        oldParent.notifyWindowHierarchyChangeUp(params: params)
      }
    case .HierarchyChanged:
      if let newParent = params.newParent {
        newParent.notifyWindowHierarchyChangeUp(params: params)
      }
    }
  }

  func notifyWindowHierarchyChangeDown(params: WindowObserverHierarchyChangeParams) {
    notifyWindowHierarchyChangeAtReceiver(params: params)
    for child in children {
      child.notifyWindowHierarchyChangeDown(params: params)
    }
  }

  func notifyWindowHierarchyChangeUp(params: WindowObserverHierarchyChangeParams) {
    var window: Window? = self
    while window != nil {
      window!.notifyWindowHierarchyChangeAtReceiver(params: params)
      window = window!.parent
    }
  }

  func notifyWindowHierarchyChangeAtReceiver(params: WindowObserverHierarchyChangeParams) {
    var localParams = params
    localParams.receiver = self
    switch params.phase {
      case .HierarchyNone:
        break
      case .HierarchyChanging:
        for observer in observers {
          observer.onWindowHierarchyChanging(params: localParams)
        }
      case .HierarchyChanged:
        for observer in observers {
          observer.onWindowHierarchyChanged(params: localParams)
        }
    }
  }

  func updateLayerName() {
    var layerName = name
    if layerName.isEmpty {
      layerName = "Unnamed Window";
    }

    if id != -1 {
      layerName += " " + String(id)
    }

    layer!.name = layerName
  }

}

extension Window : LayerDelegate {

  public func onPaintLayer(context: PaintContext) {
    paint(context: context)
  }

  public func onDeviceScaleFactorChanged(oldScaleFactor: Float, newScaleFactor: Float) {
    //let hider = ScopedCursorHider(self)
    if let d = delegate {
      d.onDeviceScaleFactorChanged(deviceScaleFactor: newScaleFactor)
    }
  }

  public func onLayerBoundsChanged(oldBounds: IntRect, reason: PropertyChangeReason) {
    _bounds = layer!.bounds
    
    if let layout = layoutManager {
      layout.onWindowResized()
    }

    if let d = delegate {
      d.onBoundsChanged(oldBounds: oldBounds, newBounds: bounds)
    }

    for observer in observers {
      observer.onWindowBoundsChanged(window: self, oldBounds: oldBounds, newBounds: bounds)
    }
  }

  public func onLayerTransformed(oldTransform: Transform, reason: PropertyChangeReason) {
    for observer in observers {
      // TODO: update to pass the transform and reason
      observer.onWindowTransformed(window: self)
    }
  }
  
  public func onLayerOpacityChanged(reason: PropertyChangeReason) {
    for observer in observers {
      observer.onWindowOpacitySet(window: self, reason: reason)
    }
  }
}

extension Window : LayerOwner {

  public var layer: Layer? {
    get {
      return _layer
    }
    set {
      _layer = newValue
      _layer!.owner = self
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

extension Window : GestureConsumer {}


public func recreateLayers(root: Window) -> Layer? {
  return recreateLayersWithClosure(
      root: root, { (owner: LayerOwner) -> Layer? in
       return owner.recreateLayer()
  })
}

public func recreateLayersWithClosure(root: Window, _ mapfn: (_: LayerOwner) -> Layer?) -> Layer? {
  let layer = mapfn(root)
  if layer == nil {
    return nil
  }
  cloneChildren(root.layer!, layer!, mapfn)
  return layer
}

fileprivate func cloneChildren(_ toClone: Layer,
                               _ parent: Layer,
                               _ mapFunc: (_: LayerOwner) -> Layer?) {
  // Make a copy of the children since RecreateLayer() mutates it.
  let children = toClone.children
  for child in children {
    let owner: LayerOwner? = child.owner
    let oldLayer: Layer? = owner != nil ? mapFunc(owner!) : nil
    if let old = oldLayer {
      parent.add(child: old)
      // RecreateLayer() moves the existing children to the new layer. Create a
      // copy of those.
      cloneChildren(owner!.layer!, old, mapFunc)
    }
  }
}