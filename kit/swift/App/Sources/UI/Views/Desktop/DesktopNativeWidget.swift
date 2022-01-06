// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

internal let desktopNativeWidgetKey: String = "DesktopNativeWidget"

public class DesktopNativeWidget : NativeWidget,
                                   WindowDelegate,
                                   ActivationDelegate,
                                   ActivationChangeObserver,
                                   FocusChangeObserver,
                                   DragDropDelegate,
                                   WindowTreeHostObserver {

  public static func forWindow(window: Window) -> DesktopNativeWidget? {
    if let object = window.property[desktopNativeWidgetKey] {
      return object as? DesktopNativeWidget
    }
    return nil
  }

  // NativeWidget
  public static func createNativeWidget(delegate: NativeWidgetDelegate) -> NativeWidget {
    return DesktopNativeWidget(delegate: delegate)
  }
  
  public static func getNativeWidgetForWindow(window: Window) -> NativeWidget {
    //return window.nativeWidget
    return window.property[desktopNativeWidgetKey] as! NativeWidget
  }
  
  public static func getTopLevelNativeWidget(window: Window) -> NativeWidget {
    var topLevelNativeWidget: NativeWidget?
    var w: Window? = window
    while w != nil {
      topLevelNativeWidget = DesktopNativeWidget.getNativeWidgetForWindow(window: w!)
      w = w!.parent
    }
    return topLevelNativeWidget!
  }
  
  public static func getAllChildWidgets(window: Window, children: inout Widgets) {
    if let widget = window.widget  {
      children.append(widget)
    }
    // do the same for each children
    for w in window.children {
      DesktopNativeWidget.getAllChildWidgets(window: w, children: &children)
    }
  }
  
  public static func getAllOwnedWidgets(window: Window, owned: inout Widgets) {
    let transientChildren = UI.getTransientChildren(window: window)
    for transientChild in transientChildren {
      let nativeWidget = DesktopNativeWidget.getNativeWidgetForWindow(window: transientChild)
      owned.append(nativeWidget.widget)
      
      DesktopNativeWidget.getAllOwnedWidgets(window: transientChild, owned: &owned)
    }

    // Add all child windows.
    for child in window.children {
      DesktopNativeWidget.getAllChildWidgets(window: child, children: &owned)
    }
  }
  
  public static func reparentWindow(window: Window, parent newParent: Window?) {
    let previousParent = window.parent
    if previousParent === newParent {
      return
    }

    var widgets = Widgets()
    DesktopNativeWidget.getAllChildWidgets(window: window, children: &widgets)

    // First notify all the widgets that they are being disassociated
    // from their previous parent.
    for widget in widgets {
      widget.notifyNativeViewHierarchyWillChange()
    }

    if let p = newParent {
      try! p.addChild(child: window)
    } else {
      // The following looks weird, but it's the equivalent of what aura has
      // always done. (The previous behaviour of aura::Window::SetParent() used
      // NULL as a special value that meant ask the WindowParentingClient where
      // things should go.)
      //
      // This probably isn't strictly correct, but its an invariant that a Window
      // in use will be attached to a RootWindow, so we can't just call
      // RemoveChild here. The only possible thing that could assign a RootWindow
      // in this case is the stacking client of the current RootWindow. This
      // matches our previous behaviour; the global stacking client would almost
      // always reattach the window to the same RootWindow.
      let rootWindow = window.rootWindow
      try! UI.parentWindowWithContext(window: window, context: rootWindow!, screenBounds: rootWindow!.boundsInScreen)
    }

    // And now, notify them that they have a brand new parent.
    for widget in widgets {
      widget.notifyNativeViewHierarchyChanged()
    }
  }

  public static func registerNativeWidgetForWindow(
      nativeWidget: NativeWidget,
      window: Window) {
     window.property[desktopNativeWidgetKey] = nativeWidget
  }


  // NativeWidget
  public static var isMouseButtonDown: Bool {
    return UI.isMouseButtonDown
  }

  public static var windowTitleFontList: FontList { 
    return FontList() 
  }
  
  public var shouldUseNativeFrame: Bool {
    return desktopWindowTreeHost!.shouldUseNativeFrame
  }
  
  public var shouldWindowContentsBeTransparent: Bool {
    return desktopWindowTreeHost!.shouldWindowContentsBeTransparent
  }
  
  public var widget: UIWidget {
    return nativeWidgetDelegate!.asWidget()
  }
  
  public var window: Window {
    return contentWindow!
  }

  public var topLevelWidget: UIWidget {
    return widget
  }
  
  public var compositor: UICompositor? {
    return contentWindow?.layer?.compositor ?? nil
  }

  public var layer: Layer? {
    return contentWindow?.layer ?? nil
  }

  public private(set) var tooltipManager: TooltipManager?
  public var inputMethod: InputMethod? {
    return host!.inputMethod// ?? nil
  }

  public var windowBoundsInScreen: IntRect {
    if contentWindow != nil {
      return desktopWindowTreeHost!.windowBoundsInScreen
    }
    return IntRect()
  }
  
  public var bounds: IntRect {
    get {
      return desktopWindowTreeHost!.asWindowTreeHost().boundsInPixels
    }
    set {
      guard contentWindow != nil else {
        return
      }
      let root = host!.window
      let screen = Screen.instance
      let boundsInPixels = screen.DIPToScreenRectInWindow(window: root.id, dipRect: newValue)
      desktopWindowTreeHost!.asWindowTreeHost().setBoundsInPixels(bounds: boundsInPixels)
    }
  }
  public var size: IntSize { 
    get {
      if contentWindow != nil {
        return desktopWindowTreeHost!.size
      }
      return IntSize()
    }

    set {
      if contentWindow != nil {
        desktopWindowTreeHost!.size = newValue
      }
    } 
  }

  public var clientAreaBoundsInScreen: IntRect {
    if contentWindow != nil {
      return desktopWindowTreeHost!.clientAreaBoundsInScreen
    }
    return IntRect()
  }
  public var restoredBounds: IntRect {
    if contentWindow != nil {
      return desktopWindowTreeHost!.restoredBounds
    }
    return IntRect()
  }

  public var workAreaBoundsInScreen: IntRect {
    return desktopWindowTreeHost?.workAreaBoundsInScreen ?? IntRect()
  }

  public var workspace: String {
    if contentWindow != nil {
      return desktopWindowTreeHost!.workspace
    }
    return String()
  }

  public var isVisible: Bool {
    return contentWindow != nil && contentWindow!.isVisible && desktopWindowTreeHost!.isVisible
  }
  public var isActive: Bool {
    return contentWindow != nil && desktopWindowTreeHost!.isActive
  }
  public var isMouseEventsEnabled: Bool {
    if contentWindow == nil {
      return false
    }
    if let cursorClient = UI.getCursorClient(window: host!.window) {
      return cursorClient.mouseEventsEnabled
    }
    return true
  }
  
  public var isFullscreen: Bool { 
    get {
      return contentWindow != nil && desktopWindowTreeHost!.isFullscreen
    }
    set {
      if contentWindow != nil {
        desktopWindowTreeHost!.isFullscreen = newValue
      }
    }
  }
  
  public var isAlwaysOnTop: Bool { 
    get {
      return contentWindow != nil && desktopWindowTreeHost!.isAlwaysOnTop
    } 
    set {
      if contentWindow != nil {
        desktopWindowTreeHost!.isAlwaysOnTop = newValue
      }
    }
  }
  
  public var isVisibleOnAllWorkspaces: Bool { 
    get {
      return contentWindow != nil && desktopWindowTreeHost!.isVisibleOnAllWorkspaces
    }
    set {
      if contentWindow != nil {
        desktopWindowTreeHost!.isVisibleOnAllWorkspaces = newValue
      }
    }
  }
  
  public var isMaximized: Bool {
    return contentWindow != nil && desktopWindowTreeHost!.isMaximized
  }
  
  public var isMinimized: Bool {
    return contentWindow != nil && desktopWindowTreeHost!.isMinimized
  }

  public var isTranslucentWindowOpacitySupported: Bool {
    return contentWindow != nil &&
      desktopWindowTreeHost!.translucentWindowOpacitySupported
  }
  
  public var hasCapture: Bool {
    return contentWindow != nil && contentWindow!.hasCapture && desktopWindowTreeHost!.hasCapture
  }

  // WindowDelegate
  public var minimumSize: IntSize {
    return nativeWidgetDelegate!.minimumSize
  }
  
  public var maximumSize: IntSize {
    return nativeWidgetDelegate!.maximumSize
  }

  public var hasHitTestMask: Bool {
    return nativeWidgetDelegate!.hasHitTestMask
  }

  public var canFocus: Bool {
    return true
  }

  // ActivationDelegate
  public var shouldActivate: Bool {
    return nativeWidgetDelegate!.canActivate
  }

  public var host: WindowTreeHost? {
    return desktopWindowTreeHost?.asWindowTreeHost()
  }
 
  public private(set) var name: String = String()
  // internal
  // dont retain because desktopWindowTreeHost is the owner, we need just the reference without ref-count
  //public private(set) weak var host: WindowTreeHost?
  //public private(set) var host: WindowTreeHost?
  public private(set) var desktopWindowTreeHost: DesktopWindowTreeHost?
  public private(set) var widgetType: WindowType
  public private(set) var contentWindow: Window?
  public private(set) var rootWindowEventFilter: CompoundEventFilter?
  private weak var nativeWidgetDelegate: NativeWidgetDelegate? // own us
  //private var name: String = String()
  private var captureClient: DesktopCaptureClient?
  private var focusClient: FocusController?
  private var positionClient: ScreenPositionClient?
  private var dragDropClient: DragDropClient?
  private var windowParentingClient: WindowParentingClient?
  private var eventClient: DesktopEventClient?
  private var focusManagerEventHandler: FocusManagerEventHandler?
  private var dropHelper: DropHelper?
  private var lastDropOperation: Int = 0
  private var tooltipController: TooltipController?
  private var visibilityController: VisibilityController?
  private var windowModalityController: WindowModalityController?
  private var restoreFocusOnActivate: Bool
  private var cursor: PlatformCursor
  private var shadowController: ShadowController?
  private var windowReorderer: WindowReorderer?
  private var useDesktopNativeCursorManager = false
  private var ownership: UIWidget.Ownership
  private static var cursorReferenceCount: Int = 0
  private static var cursorManager: CursorManager?
  private static var nativeCursorManager: DesktopNativeCursorManager?
  
  public init(delegate: NativeWidgetDelegate) {
    // we might need this later
    ownership = UIWidget.Ownership.NativeWidgetOwnsWidget
    widgetType = WindowType.Normal
    nativeWidgetDelegate = delegate
    lastDropOperation = DragOperation.DragNone.rawValue
    restoreFocusOnActivate = false
    cursor = PlatformCursorNil
    
    contentWindow = Window(delegate: self)
    // was aura::client::
    UI.setFocusChangeObserver(window: contentWindow!, observer: self)
    // was wm::
    UI.setActivationChangeObserver(window: contentWindow!, observer: self)
  }

  deinit {
    //if host != nil {
    //  host = nil
    //}
    if ownership != .NativeWidgetOwnsWidget {
      closeNow()
    }
  }

  public func setDesktopWindowTreeHost(_ desktopWindowTreeHost: DesktopWindowTreeHost) {
    self.desktopWindowTreeHost = desktopWindowTreeHost
    //self.host = desktopWindowTreeHost.asWindowTreeHost()
  }

  public func onHostClosed() {
    if windowModalityController != nil {
      windowModalityController = nil
    }

    if let capture = captureClient?.captureWindow {
      if host!.window.contains(other: capture) {
        capture.releaseCapture()
      }
    }

    shadowController = nil
    tooltipManager = nil
    if tooltipController != nil {
      host!.window.removePreTargetHandler(handler: tooltipController!)
      UI.setTooltipClient(window: host!.window, client: nil)
      tooltipController = nil
    }

    windowParentingClient = nil
    captureClient = nil
    focusManagerEventHandler = nil

    host!.window.removePreTargetHandler(handler: focusClient!)
    UI.setFocusClient(window: host!.window, client: nil)
    UI.setActivationClient(window: host!.window, client: nil)
    focusClient = nil

    host!.removeObserver(observer: self)

    //host = nil
    desktopWindowTreeHost = nil
    contentWindow = nil

    nativeWidgetDelegate!.onNativeWidgetDestroyed()
  }

  public func onDesktopWindowTreeHostDestroyed(host: WindowTreeHost) {
    if useDesktopNativeCursorManager {
      DesktopNativeWidget.nativeCursorManager!.removeHost(host: host)
    }

    UI.setScreenPositionClient(window: host.window, client: nil)
    positionClient = nil

    UI.setDragDropClient(window: host.window, client: nil)
    dragDropClient = nil

    UI.setEventClient(window: host.window, client: nil)
    eventClient = nil
  }

  public func initNativeWidget(compositor: UIWebWindowCompositor, params: UIWidget.InitParams) {
    ownership = params.ownership
    widgetType = params.type
    name = params.name
    // was NativeWidgetAura::
    DesktopNativeWidget.registerNativeWidgetForWindow(nativeWidget: self, window: contentWindow!)
    contentWindow!.type = params.type
     
    // TODO: Review Window.initialize!!
    // (contentWindow) transparency and bounds were being setted here 
    try! contentWindow!.initialize(type: params.layerType)
    // was wm::
    UI.setShadowElevation(window: contentWindow!, elevation: shadowElevationNone)
    if desktopWindowTreeHost == nil {
      if params.desktopWindowTreeHost != nil {
        desktopWindowTreeHost = params.desktopWindowTreeHost
      
      // NOTE: ommiting a constructor which uses ViewsDelegate as factory
      } else {
#if os(Linux)        
        desktopWindowTreeHost =
          DesktopWindowTreeHostX11.create(
            nativeWidgetDelegate: nativeWidgetDelegate!, 
            desktopNativeWidget: self)
#endif
      }
      //host = desktopWindowTreeHost!.asWindowTreeHost()
    }

    try! desktopWindowTreeHost!.initialize(compositor: compositor, params: params)
    try! host!.window.addChild(child: contentWindow!)
    host!.window.property[desktopNativeWidgetKey] = self
    host!.window.addObserver(observer: RootWindowDestructionObserver(parent: self))
    
    if params.type == .Normal {
     windowModalityController = WindowModalityController(target: host!.window)
    }

    rootWindowEventFilter = CompoundEventFilter()
    host!.window.addPreTargetHandler(handler: rootWindowEventFilter!)

    useDesktopNativeCursorManager = desktopWindowTreeHost!.shouldUseDesktopNativeCursorManager
    if useDesktopNativeCursorManager {
      DesktopNativeWidget.cursorReferenceCount += 1
      if DesktopNativeWidget.nativeCursorManager == nil {
        DesktopNativeWidget.nativeCursorManager = DesktopNativeCursorManager()
      }
      if DesktopNativeWidget.cursorManager == nil {
        DesktopNativeWidget.cursorManager = CursorManager(delegate: DesktopNativeWidget.nativeCursorManager!)
      }
      DesktopNativeWidget.nativeCursorManager!.addHost(host: host!)
      UI.setCursorClient(window: host!.window, client: DesktopNativeWidget.cursorManager!)
    }

    host!.window.name = params.name
    contentWindow!.name = "DesktopNativeWidget - content window"
    desktopWindowTreeHost!.onNativeWidgetCreated(params: params)

    updateWindowTransparency()

    captureClient = DesktopCaptureClient(root: host!.window)

    let focusController = FocusController(rules: DesktopFocusRules(contentWindow: contentWindow!))
    focusClient = focusController
    UI.setFocusClient(window: host!.window, client: focusController)
    UI.setActivationClient(window: host!.window, client: focusController)
    host!.window.addPreTargetHandler(handler: focusController)

    positionClient = DesktopScreenPositionClient(rootWindow: host!.window)

    dragDropClient = desktopWindowTreeHost!.createDragDropClient(cursorManager: DesktopNativeWidget.nativeCursorManager!)!
    UI.setDragDropClient(window: host!.window, client: dragDropClient!)
    UI.setActivationDelegate(window: contentWindow!, delegate: self)

    UI.getFocusClient(window: contentWindow!)!.focusWindow(window: contentWindow!)

    onHostResized(host: host!)

    host!.addObserver(observer: self)
    
    windowParentingClient = DesktopNativeWidgetWindowParentingClient(rootWindow: host!.window)
    dropHelper = DropHelper(rootView: widget.rootView!)
    UI.setDragDropDelegate(window: contentWindow!, delegate: self)

    if params.type != .Tooltip {
      tooltipManager = TooltipManager(widget: widget)
      tooltipController = TooltipController(tooltip: desktopWindowTreeHost!.createTooltip())
      UI.setTooltipClient(window: host!.window, client: tooltipController!)
      host!.window.addPreTargetHandler(handler: tooltipController!)
    }

    if params.opacity == .Translucent && 
        desktopWindowTreeHost!.shouldCreateVisibilityController {
      //print("DesktopNativeWidget.initNativeWidget: params.opacity == .Translucent? \(params.opacity == .Translucent) desktopWindowTreeHost!.shouldCreateVisibilityController = \(desktopWindowTreeHost!.shouldCreateVisibilityController)\n SETANDO VisibilityClient")
      visibilityController = VisibilityController()
      UI.setVisibilityClient(window: host!.window, client: visibilityController!)
      host!.window.childWindowVisibilityChangesAnimated = true
      //contentWindowContainer.childWindowVisibilityChangesAnimated = true
      // was wm::
      UI.setChildWindowVisibilityChangesAnimated(window: host!.window)
    } 

    if params.type == .Normal {
      focusManagerEventHandler = FocusManagerEventHandler(widget: widget, window: host!.window)
      //host!.window.addPreTargetHandler(handler: focusManagerEventHandler!)
    }

    eventClient = DesktopEventClient()
    UI.setEventClient(window: host!.window, client: eventClient!)
    
    shadowController = ShadowController(
      activationClient: UI.getActivationClient(window: host!.window))//, nil)

    onSizeConstraintsChanged()
    
    windowReorderer = WindowReorderer(window: contentWindow!, rootView: widget.rootView!)
  }

  public func onWidgetInitDone() {
    desktopWindowTreeHost!.onWidgetInitDone()
  }

  public func createNonClientFrameView() -> NonClientFrameView? {
    return desktopWindowTreeHost!.createNonClientFrameView()
  }

  public func frameTypeChanged() {
    desktopWindowTreeHost!.frameTypeChanged()
    updateWindowTransparency()
  }

  public func reorderNativeViews() {
    windowReorderer!.reorderChildWindows()
  }

  public func viewRemoved(view: View) {
    dropHelper!.resetTargetViewIfEquals(view: view)
  }

  public func setNativeWindowProperty(name: String, value: UnsafeMutableRawPointer) {
    if let window = contentWindow {
      window.setNativeWindowProperty(name: name, value: value)
    }
  }

  public func getNativeWindowProperty(name: String) -> UnsafeMutableRawPointer? {
    if let window = contentWindow {
      return window.getNativeWindowProperty(name: name)
    }
    return nil
  }
  
  public func setCapture() {
    guard let window = contentWindow else {
      return
    }
    window.setCapture()
  }
  
  public func releaseCapture() {
    guard let window = contentWindow else {
      return
    }
    window.releaseCapture()
  }
  
  public func centerWindow(size: IntSize) {
    if contentWindow != nil {
      desktopWindowTreeHost!.centerWindow(size: size)
    }
  }
  
  public func getWindowPlacement(bounds: inout IntRect, showState: inout WindowShowState) {
    if contentWindow != nil {
      desktopWindowTreeHost!.getWindowPlacement(bounds: &bounds, showState: &showState)
    }
  }
  
  public func setWindowTitle(title: String) -> Bool {
    if contentWindow == nil {
      return false
    }
    return desktopWindowTreeHost!.setWindowTitle(title: title)
  }
  
  public func setWindowIcons(windowIcon: ImageSkia?,
                             appIcon: ImageSkia?) {
    guard let windowImg = windowIcon, let appImg = appIcon else {
      return
    }
    
    if contentWindow != nil {
      desktopWindowTreeHost!.setWindowIcons(
        windowIcon: windowImg,
        appIcon: appImg)
    }
    // was NativeWidgetAura::AssignIconToAuraWindow
    // it just define them as properties of the window
    // DesktopNativeWidget.assignIconToWindow(contentWindow, windowIcon, appIcon)
  }
  
  public func initModalType(modalType: ModalType) {
    desktopWindowTreeHost!.initModalType(modalType: modalType)
  }
  
  public func setBoundsConstrained(bounds: IntRect) {
    guard contentWindow != nil else {
      return
    }
    self.bounds = DesktopNativeWidget.constrainBoundsToDisplayWorkArea(bounds: bounds)
  }
  
  public func stackAbove(window: Window) {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.stackAbove(window: window)
  }
  
  public func stackAtTop() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.stackAtTop()
  }
  
  public func setShape(shape: UIWidget.ShapeRects) {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.setShape(nativeShape: shape)
  }
  
  public func close() {
    guard let content = contentWindow else {
      return
    }
    content.suppressPaint()
    content.hide()
    desktopWindowTreeHost!.close()
  }
  
  public func closeNow() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.closeNow()
  }
  
  public func show() {
    guard let content = contentWindow else {
      return
    }
    desktopWindowTreeHost!.asWindowTreeHost().show()
    content.show()
  }
  
  public func hide() {
    guard let content = contentWindow else {
      return
    }
    desktopWindowTreeHost!.asWindowTreeHost().hide()
    content.hide()
  }
  
  public func showMaximizedWithBounds(restoredBounds: IntRect) {
    guard let content = contentWindow else {
      return
    }
    desktopWindowTreeHost!.showMaximizedWithBounds(restoredBounds: restoredBounds)
    content.show()
  }
  
  public func showWithWindowState(showState: WindowShowState) {
    guard let content = contentWindow else {
      return
    }
    desktopWindowTreeHost!.showWindowWithState(showState: showState)
    content.show()
  }
  
  public func activate() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.activate()
  }
  
  public func deactivate() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.deactivate()
  }
  
  public func maximize() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.maximize()
  }
  
  public func minimize() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.minimize()
  }
  
  public func restore() {
    guard contentWindow != nil else {
      return
    }
    desktopWindowTreeHost!.restore()
  }

  public func setOpacity(opacity: Float) {
    if contentWindow != nil {
      desktopWindowTreeHost!.setOpacity(opacity: opacity)
    }
  }
  
  public func flashFrame(flash: Bool) {
    if contentWindow != nil {
      desktopWindowTreeHost!.flashFrame(flash)
    }
  }
  
  public func runShellDrag(view: View,
                    data: OSExchangeData,
                    location: IntPoint,
                    operation: Int,
                    source: DragEventSource) {
    // was views::
    UI.runShellDrag(view: contentWindow!,
                    data: data,
                    location: location,
                    operation: DragOperation(rawValue: operation)!,
                    source: source)
  }
  
  public func schedulePaintInRect(rect: IntRect) {
    if let content = contentWindow {
      content.schedulePaintInRect(rect: rect)
    }
  }
  
  public func setCursor(cursor: PlatformCursor) {
    self.cursor = cursor
    if var cursorClient = UI.getCursorClient(window: host!.window) {
      cursorClient.cursor = cursor
    }
  }
  
  public func clearNativeFocus() {
    desktopWindowTreeHost!.clearNativeFocus()
    if shouldActivate {
      UI.getFocusClient(window: contentWindow)!.resetFocusWithinActiveWindow(window: contentWindow!)
    }
  }
  
  public func runMoveLoop(
      dragOffset: IntVec2,
      source: UIWidget.MoveLoopSource,
      escapeBehavior: UIWidget.MoveLoopEscapeBehavior) -> UIWidget.MoveLoopResult {
    if contentWindow == nil {
      return UIWidget.MoveLoopResult.Canceled
    }
    return desktopWindowTreeHost!.runMoveLoop(dragOffset: dragOffset, source: source, escapeBehavior: escapeBehavior)
  }
  
  public func endMoveLoop() {
    if contentWindow != nil {
      desktopWindowTreeHost!.endMoveLoop()
    }
  }
  
  public func setVisibilityChangedAnimationsEnabled(value: Bool) {
    if contentWindow != nil {
      desktopWindowTreeHost!.setVisibilityChangedAnimationsEnabled(value: value)
    }
  }
  
  public func setVisibilityAnimationDuration(duration: TimeDelta) {
    UI.setWindowVisibilityAnimationDuration(window: contentWindow!, duration: duration)
  }
  
  public func setVisibilityAnimationTransition(transition: UIWidget.VisibilityTransition) {
    var wmTransition = Window.VisibilityAnimationTransition.AnimateNone
    switch transition {
      case .AnimateShow:
        wmTransition = Window.VisibilityAnimationTransition.AnimateShow
      case .AnimateHide:
        wmTransition = Window.VisibilityAnimationTransition.AnimateHide
      case .AnimateBoth:
        wmTransition = Window.VisibilityAnimationTransition.AnimateBoth
      case .AnimateNone:
        wmTransition = Window.VisibilityAnimationTransition.AnimateNone
    }
    UI.setWindowVisibilityAnimationTransition(window: contentWindow!, transition: wmTransition)
  }
  
  public func onSizeConstraintsChanged() {
    //var behavior: Int32 = mojom.kResizeBehaviorNone
    //if let delegate = widget.widgetDelegate {
    //  behavior = delegate.resizeBehavior
    //}

    // was aura::client::ResizeBehaviorKey
    //contentWindow!.property[UI.resizeBehaviorKey] = behavior
    desktopWindowTreeHost!.sizeConstraintsChanged()
  }
  
  public func repostNativeEvent(nativeEvent: inout PlatformEvent) {
    var event = Event(nativeEvent)
    onEvent(event: &event)
  }

  // WindowDelegate
  public func getCursor(at point: IntPoint) -> PlatformCursor {
    return PlatformCursorNil
  }
  
  public func getHitTestMask(mask: inout Path) {
    if let hitMask = nativeWidgetDelegate!.hitTestMask {
      mask = hitMask
    }
  }

  public func onBoundsChanged(oldBounds: IntRect, newBounds: IntRect) {}

  public func getNonClientComponent(point: IntPoint) -> HitTest {
    return HitTest(rawValue: nativeWidgetDelegate!.getNonClientComponent(point: point))!
  }
  // for 'NativeWindow' UIWidget (who owns) -> (Native)Window
  public func shouldDescendIntoChildForEventHandling(
    rootLayer: Layer, child: Window, childLayer: Layer, location: IntPoint) -> Bool {
    return nativeWidgetDelegate!.shouldDescendIntoChildForEventHandling(
      rootLayer: rootLayer, child: child, childLayer: childLayer, location: location)
  }
  // meant for soft 'Window' owners (not UIWidget)
  
  public func shouldDescendIntoChildForEventHandling(
    child: Window, location: IntPoint) -> Bool  {
      return nativeWidgetDelegate!.shouldDescendIntoChildForEventHandling(
      rootLayer: contentWindow!.layer!, child: child, childLayer: child.layer!, location: location)
  }

  public func onCaptureLost() {
    nativeWidgetDelegate!.onMouseCaptureLost()
  }
  public func onPaint(context: PaintContext) {
    nativeWidgetDelegate!.onNativeWidgetPaint(context: context)
  }

  // nothing here
  public func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {}
  public func onWindowDestroying(window: Window) {}
  public func onWindowDestroyed(window: Window) {}
  public func onWindowTargetVisibilityChanged(visible: Bool) {}

  public func handleActivationChanged(active: Bool) {
    guard nativeWidgetDelegate!.onNativeWidgetActivationChanged(active: active) else {
      return
    }

    guard let activationClient = UI.getActivationClient(window: host!.window) else {
      return
    }

    if active {
      if widget.hasFocusManager {
        // This function can be called before the focus manager has had a
        // chance to set the focused view. In which case we should get the
        // last focused view.
        let focusManager = widget.focusManager!
        var viewForActivation = focusManager.focusedView ?? focusManager.storedFocusView
        if viewForActivation == nil || viewForActivation!.widget == nil {
          viewForActivation = widget.rootView
        } else if viewForActivation == focusManager.storedFocusView {
          // When desktop native widget has modal transient child, we don't
          // restore focused view here, as the modal transient child window will
          // get activated and focused. Thus, we are not left with multiple
          // focuses. For aura child widgets, since their views are managed by
          // |focus_manager|, we then allow restoring focused view.
          // was wm::
          if UI.getModalTransient(window: widget.window) == nil {
            let _ = focusManager.restoreFocusedView()
            // Set to false if desktop native widget has activated activation
            // change, so that aura window activation change focus restore
            // operation can be ignored.
            restoreFocusOnActivate = false
          }
        }
        activationClient.activateWindow(window: viewForActivation!.widget!.window)
        inputMethod!.onFocus()
     }
    } else {
      if let activeWindow = activationClient.activeWindow {
        activationClient.deactivateWindow(window: activeWindow)
        inputMethod!.onBlur()
      }
    }
  }

  // EventHandler
  public func onKeyEvent(event: inout KeyEvent) {
    if event.isChar {
      return
    }
    if !contentWindow!.isVisible {
      return
    }
    nativeWidgetDelegate!.onKeyEvent(event: &event)
  }
  
  public func onMouseEvent(event: inout MouseEvent) {
    if let tooltip = tooltipManager {
      tooltip.updateTooltip()
    }
    TooltipManager.updateTooltipManagerForCapture(source: widget)
    nativeWidgetDelegate!.onMouseEvent(event: &event)
  }

  public func onScrollEvent(event: inout ScrollEvent) {
    if event.type == EventType.Scroll {
      nativeWidgetDelegate!.onScrollEvent(event: &event)
      if event.handled {
        return
      }

      // Convert unprocessed scroll events into wheel events.
      let mwe = MouseWheelEvent(event: event)
      var me = mwe as MouseEvent
      nativeWidgetDelegate!.onMouseEvent(event: &me)
      if mwe.handled {
        event.handled = true
      }
    } else {
      nativeWidgetDelegate!.onScrollEvent(event: &event)
    }
  }

  public func onGestureEvent(event: inout GestureEvent) {
    nativeWidgetDelegate!.onGestureEvent(event: &event)
  }

  // ActivationChangeObserver
  public func onWindowActivated(reason: ActivationReason,
                                gainedActive: Window,
                                lostActive: Window) {
     if gainedActive === contentWindow && restoreFocusOnActivate {
      restoreFocusOnActivate = false
      // For OS_LINUX, desktop native widget may not be activated when child
      // widgets gets aura activation changes. Only when desktop native widget is
      // active, we can rely on aura activation to restore focused view.
      if widget.isActive {
        let _ = widget.focusManager!.restoreFocusedView()
      }
    } else if lostActive === contentWindow && widget.hasFocusManager {
      restoreFocusOnActivate = true
      // Pass in false so that ClearNativeFocus() isn't invoked
      widget.focusManager!.storeFocusedView(clearNativeFocus: false)
    }

    // Give the native widget a chance to handle any specific changes it needs.
    desktopWindowTreeHost!.onActiveWindowChanged(active: contentWindow === gainedActive)
  }

  public func onAttemptToReactivateWindow(requestActive: Window,
                                          actualActive: Window) {}

  // FocusChangeObserver
  public func onWindowFocused(gainedFocus: Window, lostFocus: Window) {
    if contentWindow === gainedFocus {
      nativeWidgetDelegate!.onNativeFocus()
    } else if contentWindow === lostFocus {
      nativeWidgetDelegate!.onNativeBlur()
    }
  }

  // DragDropDelegate
  public func onDragEntered(event: DropTargetEvent) {
    lastDropOperation = dropHelper!.onDragOver(data: event.data, rootViewLocation: event.location, dragOperation: DragOperation(rawValue: event.sourceOperations)!).rawValue
  }
  
  public func onDragUpdated(event: DropTargetEvent) -> DragOperation {
    lastDropOperation = dropHelper!.onDragOver(data: event.data, rootViewLocation: event.location, dragOperation: DragOperation(rawValue: event.sourceOperations)!).rawValue
    return DragOperation(rawValue: lastDropOperation)!
  }
  
  public func onDragExited() {
    dropHelper!.onDragExit()
  }
  
  public func onPerformDrop(event: DropTargetEvent) -> DragOperation {
    if shouldActivate {
      activate()
    }
    return dropHelper!.onDrop(data: event.data, rootViewLocation: event.location, dragOperation: DragOperation(rawValue: lastDropOperation)!)
  }

  // WindowTreeHostObserver
  public func onHostResized(host: WindowTreeHost) {
    if desktopWindowTreeHost!.isAnimatingClosed {
      return
    }
    let newBounds = IntRect(size: host.window.bounds.size)
    contentWindow!.bounds = newBounds
    nativeWidgetDelegate!.onNativeWidgetSizeChanged(newSize: newBounds.size)
  }

  public func onHostWorkspaceChanged(host: WindowTreeHost) {
    nativeWidgetDelegate!.onNativeWidgetWorkspaceChanged()
  }
  
  public func onHostMovedInPixels(host: WindowTreeHost, newOrigin: IntPoint) {
    nativeWidgetDelegate!.onNativeWidgetMove()
  }
  
  public func onHostCloseRequested(host: WindowTreeHost) {
    widget.close()
  }

  private func updateWindowTransparency() {
    if !desktopWindowTreeHost!.shouldUpdateWindowTransparency {
      return
    }

    contentWindow!.transparent = desktopWindowTreeHost!.shouldWindowContentsBeTransparent
    // Regardless of transparency or not, this root content window will always
    // fill its bounds completely, so set this flag to true to avoid an
    // unecessary clear before update.
    contentWindow!.fillsBoundsCompletely = true
  }
  
  internal func rootWindowDestroyed() {
    DesktopNativeWidget.cursorReferenceCount = DesktopNativeWidget.cursorReferenceCount - 1
    if DesktopNativeWidget.cursorReferenceCount == 0 {
      // We are the last DesktopNativeWidgetAura instance, and we are responsible
      // for cleaning up |cursor_manager_|.
      DesktopNativeWidget.nativeCursorManager = nil
      DesktopNativeWidget.cursorManager = nil
    }
  }
  
}

extension DesktopNativeWidget : Hashable {
  
  //public var hashValue: Int {
  //  let hash = Unmanaged.passUnretained(self).toOpaque().hashValue
  //  return hash
  //}
  
  // broken but, we need for hashable
  public static func ==(lhs: DesktopNativeWidget, rhs: DesktopNativeWidget) -> Bool {
    return lhs === rhs
  }

  public func hash(into hasher: inout Hasher) {
    let hash = Unmanaged.passUnretained(self).toOpaque().hashValue
    hasher.combine(hash)
  }

}

fileprivate class DesktopNativeWidgetTopLevelHandler : WindowObserver {

  var topLevelWidget: UIWidget?
  var childWindow: Window?

  static func createParentWindow(childWindow: Window,
                                 compositor: UIWebWindowCompositor,
                                 bounds: IntRect,
                                 fullscreen: Bool,
                                 rootIsAlwaysOnTop: Bool) throws -> Window? {
    // This instance will get deleted when the widget is destroyed.
    let topLevelHandler = DesktopNativeWidgetTopLevelHandler()
    childWindow.bounds = IntRect(size: bounds.size)

    let widgetType: WindowType = fullscreen ? .Normal : .Popup
    
    var params = UIWidget.InitParams()
    params.type = widgetType
    params.bounds = bounds
    params.state = fullscreen ? .Maximized : .Minimized
    params.layerType = .None
    params.activatable = fullscreen ? UIWidget.Activatable.Yes : UIWidget.Activatable.No
    params.onTop = rootIsAlwaysOnTop
    
    topLevelHandler.topLevelWidget = UIWidget()
    try topLevelHandler.topLevelWidget!.initialize(compositor: compositor, params: params)
    topLevelHandler.topLevelWidget!.isFullscreen = fullscreen
    topLevelHandler.topLevelWidget!.show()

    let nativeWindow = topLevelHandler.topLevelWidget!.window
    childWindow.addObserver(observer: topLevelHandler)
    nativeWindow.addObserver(observer: topLevelHandler)
    topLevelHandler.childWindow = childWindow
    return nativeWindow
  }

  // WindowObserver
  public func onWindowDestroying(window: Window) {
    window.removeObserver(observer: self)

    if let topLevelWindow = topLevelWidget?.window {
      if topLevelWindow === window {
        self.topLevelWidget = nil
        return
      }
    }

    if let widget = topLevelWidget {
      widget.window.removeObserver(observer: self)
      // When we receive a notification that the child of the window created
      // above is being destroyed we go ahead and initiate the destruction of
      // the corresponding widget.
      widget.close()
      topLevelWidget = nil
    }
    //delete this
  }

  public func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect) {
    // The position of the window may have changed. Hence we use SetBounds in
    // place of SetSize. We need to pass the bounds in screen coordinates to
    // the UIWidget::SetBounds function.
    if let widget = topLevelWidget, window === childWindow {
      widget.bounds = window.boundsInScreen
    }
  }

  init() {}
}

fileprivate class DesktopNativeWidgetWindowParentingClient : WindowParentingClient {
  
  private var rootWindow: Window?

  init(rootWindow: Window) {
    //from 'aura::client::SetWindowParentingClient(root_window_, this)'
    self.rootWindow = rootWindow
    UI.setWindowParentingClient(window: rootWindow, client: self)
  }
  
  deinit {
    UI.setWindowParentingClient(window: rootWindow!, client: nil)
  }

  public func getDefaultParent(window: Window, compositor: UIWebWindowCompositor, bounds: IntRect) -> Window? {
    // was aura::client::kShowStateKey
    var isFullscreen = false 
    if let state = window.property[UI.showStateKey] as? WindowShowState { 
      isFullscreen = state == WindowShowState.Fullscreen
    }
    let isMenu = window.type == WindowType.Menu
    if isFullscreen || isMenu {
      var rootIsAlwaysOnTop = false
      if let nativeWidget = DesktopNativeWidget.forWindow(window: rootWindow!) {
        rootIsAlwaysOnTop = nativeWidget.isAlwaysOnTop
      }
      return try! DesktopNativeWidgetTopLevelHandler.createParentWindow(
        childWindow: window,
        compositor: compositor,
        bounds: bounds,
        fullscreen: isFullscreen,
        rootIsAlwaysOnTop: rootIsAlwaysOnTop)
    }
    return rootWindow
  }

}

fileprivate class RootWindowDestructionObserver : WindowObserver {

  init(parent: DesktopNativeWidget) {
    self.parent = parent
  }

  // WindowObserver
  func onWindowDestroyed(window: Window) {
    parent!.rootWindowDestroyed()
    window.removeObserver(observer: self)
    //delete this
  }
  // guess we dont need to retain anything.. this thing will (probably? ) outlive us
  weak var parent: DesktopNativeWidget?
}

// fileprivate class DesktopNativeWidgetAuraWindowParentingClient : WindowParentingClient {
//  private var rootWindow: Window?

//  public init(rootWindow: Window?) {
//     self.rootWindow = rootWindow 
//     UI.setWindowParentingClient(window: rootWindow, client: self)
//   }
  
//   deinit {
//     UI.setWindowParentingClient(window: rootWindow, client: nil)
//   }

//   public func getDefaultParent(window: Window, bounds: IntRect) -> Window? {
//      let isFullscreen = window.property[UI.showStateKey] == WindowShowState.Fullscreen
//     let isMenu = window.type == WindowType.Menu

//     if isFullscreen || isMenu {
//       var rootIsAlwaysOnTop = false
//       if let nativeWidget = DesktopNativeWidget.forWindow(rootWindow) {
//         rootIsAlwaysOnTop = nativeWidget.isAlwaysOnTop
//       }

//       return DesktopNativeWidgetTopLevelHandler.createParentWindow(
//         window, bounds, isFullscreen, rootIsAlwaysOnTop)
//     }
//     return rootWindow
//   }

// }