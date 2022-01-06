// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Platform
import Foundation

public typealias Widgets = [UIWidget]

//public class DefaultWidgetDelegate : WidgetDelegateView {}

// This class provides functionality to create a top level widget to host a
// child window.
public class WidgetTopLevelHandler : WindowObserver {

  var topLevelWidget: UIWidget?
  var childWindow: Window?

  static func createParentWindow(childWindow: Window,
                                 bounds: IntRect,
                                 fullscreen: Bool,
                                 rootIsAlwaysOnTop: Bool) throws -> Window? {
    // This instance will get deleted when the widget is destroyed.
    let topLevelHandler = WidgetTopLevelHandler()

    childWindow.bounds = IntRect(size: bounds.size)

    let widgetType: WindowType = fullscreen ? .Normal : .Popup

    topLevelHandler.topLevelWidget = UIWidget()
    var params = UIWidget.InitParams()
    params.type = widgetType
    params.bounds = bounds
    params.state = fullscreen ? .Maximized : .Minimized
    params.layerType = .NotDrawn
    params.onTop = rootIsAlwaysOnTop

    try topLevelHandler.topLevelWidget?.initialize(params: params)

    topLevelHandler.topLevelWidget?.fullscreen = fullscreen

    topLevelHandler.topLevelWidget?.show()

    if let nativeWindow = topLevelHandler.topLevelWidget?.window {
      childWindow.addObserver(observer: topLevelHandler)
      nativeWindow.addObserver(observer: topLevelHandler)
      topLevelHandler.childWindow = childWindow
      return nativeWindow
    }
    return nil
  }

  // WindowObserver
  public func onWindowDestroying(window: Window) {
    window.removeObserver(observer: self)

    if topLevelWidget != nil && window === topLevelWidget?.window {
      topLevelWidget = nil
      return
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
    if topLevelWidget != nil && window === childWindow {
      topLevelWidget?.bounds = window.boundsInScreen
    }
  }

  init() {}
}

public class WidgetTreeClient : WindowTreeClient {

  var rootWindow: Window

  init(rootWindow: Window) {
    self.rootWindow = rootWindow
    UI.setWindowTreeClient(window: self.rootWindow, treeClient: self)
  }

  deinit {
    UI.setWindowTreeClient(window: rootWindow, treeClient: nil)
  }

  public func getDefaultParent(context: Window,
                               window: Window,
                               bounds: IntRect) throws -> Window? {
    let isFullscreen = window.showState == .Fullscreen
    let isMenu = window.type == WindowType.Menu

    if isFullscreen || isMenu {
      
      var rootIsAlwaysOnTop = false

      if let nativeWindow = UIWidget.getForWindow(window: rootWindow) {
        rootIsAlwaysOnTop = nativeWindow.alwaysOnTop
      }

      return try WidgetTopLevelHandler.createParentWindow(childWindow: window, bounds: bounds, fullscreen: isFullscreen, rootIsAlwaysOnTop: rootIsAlwaysOnTop)
    }
    return rootWindow
  }

}

public class FocusManagerEventHandler : EventHandler {

  weak var widget: UIWidget?

  init(widget: UIWidget?) {
    self.widget = widget
  }

  // EventHandler
  public func onKeyEvent(event: inout KeyEvent) {
    if let manager = widget?.focusManager {
      if manager.focusedView != nil && !manager.onKeyEvent(event: event) {
        event.handled = true
      }
    }
  }

  public func onEvent(event: inout Graphics.Event) {}
  public func onMouseEvent(event: inout MouseEvent) {}
  public func onScrollEvent(event: inout ScrollEvent) {}
  public func onTouchEvent(event: inout TouchEvent) {}
  public func onGestureEvent(event: inout GestureEvent) {}
  public func onCancelMode(event: inout CancelModeEvent) {}
}

class RootWindowDestructionObserver : WindowObserver {

  init(parent: UIWidget) {
    self.parent = parent
  }

  // WindowObserver
  func onWindowDestroyed(window: Window) {
    if let p = parent {
      p.onRootWindowDestroyed()
    }
    window.removeObserver(observer: self)
    //delete this
  }

  var parent: UIWidget?
}

func notifyCaretBoundsChanged(inputMethod: InputMethod?) {
  guard let ime = inputMethod else {
    return
  }
  if let client = ime.textInputClient {
    ime.onCaretBoundsChanged(client: client)
  }
}

public class UIWidget : EventSource,
                      WindowDelegate,
                      EventHandler,
                      FocusTraversable,
                      WindowObserver,
                      ActivationDelegate,
                      ActivationChangeObserver,
                      FocusChangeObserver,
                      DragDropDelegate,
                      WindowTreeHostObserver,
                      NativewWidgetDelegate {

  public typealias ShapeRects = [IntRect]

  public enum FrameType {
    case Default
    case ForceCustom
    case ForceNative
  }

  public enum MoveLoopResult {
    case Successful
    case Canceled
  }

  // Source that initiated the move loop.
  public enum MoveLoopSource {
    case Mouse
    case Touch
  }

  // Behavior when escape is pressed during a move loop.
  public enum MoveLoopEscapeBehavior {
    case Hide
    case DontHide
  }

  public enum WindowOpacity {
    case InferOpacity
    case Opaque
    case Translucent
  }

  public enum Activatable {
    case Default
    case Yes
    case No
  }

  public enum ShadowType {
    case Default
    case None
    case Drop
  }

  public enum Ownership {
    case NativeWidgetOwnsWidget
    case WidgetOwnsNativeWidget
  }

  public struct InitParams {
    public var activatable: Activatable
    public var type: WindowType
    public var ownership: Ownership
    public var delegate: WidgetDelegate?
    public var bounds: IntRect
    public var state: WindowShowState
    public var layerType: LayerType
    public var opacity: WindowOpacity
    public var onTop: Bool
    public var shadowType: ShadowType
    public var removeStandardFrame: Bool
    public var parent: Window?
    public var context: Window?
    public var forceShowInTaskbar: Bool
    public var visibleOnAllWorkspaces: Bool
    public var wmClassName: String
    public var wmClassClass: String
    public var wmRoleName: String
    public var acceptEvents: Bool
    public var child: Bool 

    public init() {
      activatable = .Default
      type = .Unknown
      ownership = .NativeWidgetOwnsWidget
      bounds = IntRect()
      state = .Default
      layerType = .Textured
      opacity = .InferOpacity
      onTop = false
      removeStandardFrame = false
      forceShowInTaskbar = false
      visibleOnAllWorkspaces = false
      wmClassName = String()
      wmClassClass = String()
      wmRoleName = String()
      acceptEvents = true
      shadowType = .Default
      child = false
    }
  }

  public private(set) var rootView: RootView!

  public var isMaximized: Bool {
    return host.isMaximized
  }

  public var isMinimized: Bool {
    return host.isMinimized
  }

  public var isFullscreen: Bool {
    get {
      return host.isFullscreen
    }
    set {
      host.isFullscreen = newValue
    }
  }

  public var isVisible: Bool {
    return host.isVisible
  }

  public var isClosed: Bool {
    return false
  }

  public var isActive: Bool {
    return host.isActive
  }

  public var isAlwaysOnTop: Bool {
   get {
     return host.isAlwaysOnTop
   }
   set {
     host.isAlwaysOnTop = newValue
   }
  }

  public var isModal: Bool {
    return delegate!.modalType != .None
  }

  public var isDialogBox: Bool {
    return delegate!.asDialogDelegate() != nil
  }

  public var canActivate: Bool {
    return delegate!.canActivate
  }

  public var inactiveRenderingDisabled: Bool {
    return _disableInactiveRendering
  }

  public var hasFocusManager: Bool {
    return focusManager != nil
  }

  public var accelerator: Accelerator? {
    assert(false)
    return nil
  }

  public var topLevelWidget: UIWidget? {
    return self
  }

  public var delegate: WidgetDelegate?

  public var contentsView: View? {
    get {
      return rootView.contentsView
    }
    set (view) {
      guard view !== contentsView else {
        return
      }
      rootView.contentsView = view
      if nonClientView !== view {
        nonClientView = nil
      }
    }
  }

  public var rootLayers: [Layer] {
    return [Layer]()
  }

  public var focusTraversable: FocusTraversable? {
    return rootView
  }

  public var shouldUseNativeFrame: Bool {
    return host.shouldUseNativeFrame
  }

  public var shouldWindowContentsBeTransparent: Bool {
    return host.shouldWindowContentsBeTransparent
  }

  public private(set) var nativeWidget: NativeWidget? {
    get {
      return ownership == .NativeWidgetOwnsWidget ? _nativeWidget : _ownedNativeWidget
    }
    set {
      if ownership == .NativeWidgetOwnsWidget {
        _nativeWidget = newValue
      } else {
        _ownedNativeWidget = newValue
      }
    }
  }

  private(set) public var nonClientView: NonClientView?

  public var clientView: ClientView? {
    if let view = nonClientView {
      return view.clientView
    }
    return nil
  }

  public var layer: Layer? {
    return contentWindow?.layer
  }

  public var compositor: UICompositor? {
    if let l = contentWindow?.layer {
      return l.compositor
    }
    return nil
  }

  public var window: Window {
    return nativeWidget.window
  }

  public var bounds: IntRect {
    get {
      return host.tree.bounds
    }
    set {
      let root = host.tree.window
      //var scale = Screen.getScreenFor(root.id).getDisplayNearestWindow(root.id).deviceScaleFactor
      let scale = Screen.getDisplayNearestWindow(windowId: root.id)!.deviceScaleFactor
      let boundsInPixels = Graphics.scaleToEnclosingRect(rect: newValue, xScale: scale, yScale: scale)
      host.tree.bounds = boundsInPixels
    }
  }

  public var size: IntSize {
    get {
      return host.size
    }
    set {
      host.size = newValue
    }
  }

  public var windowBoundsInScreen: IntRect {
    return host.windowBoundsInScreen
  }

  public var clientAreaBoundsInScreen: IntRect {
    return host.clientAreaBoundsInScreen
  }

  public var restoredBounds: IntRect {
    return host.restoredBounds
  }

  public var focusManager: FocusManager? {
    get {
      if let topWidget = topLevelWidget {
        return topWidget._focusManager
      }
      return nil
    }
    set {
      assert(false)
    }
  }

  public var inputMethod: InputMethod? {
    return host.tree.inputMethod
  }

  public var mouseEventsEnabled: Bool {
    if let cursorClient = UI.getCursorClient(window: host.tree.window) {
      return cursorClient.mouseEventsEnabled
    }
    return true
  }

  public var hasCapture: Bool {
    return contentWindow!.hasCapture && host.hasCapture
  }

  public override var eventProcessor: EventProcessor {
    return rootView
  }

  public var translucentWindowOpacitySupported: Bool {
    return host.translucentWindowOpacitySupported
  }

  public var minimumSize: IntSize {
    if let view = nonClientView {
      return view.minimumSize
    }
    return IntSize()
  }

  public var maximumSize: IntSize {
    if let view = nonClientView {
      return view.maximumSize
    }
    return IntSize()
  }

  public var hasHitTestMask: Bool {
    return delegate!.widgetHasHitTestMask
  }

  public var hitTestMask: Path? {
    if let outMask = delegate!.widgetHitTestMask {
      return outMask  
    }
    return nil
  }

  public var canFocus: Bool {
    return true
  }

  public var focusSearch: FocusSearch? {
    return rootView.focusSearch
  }

  public var focusTraversableParent: FocusTraversable? {
    get {
      assert(false)
      return nil
    }
    set {

    }
  }

  public var focusTraversableParentView: View? {
    get {
      assert(false)
      return nil
    }
    set {

    }
  }

  public var viewsWithLayers: Views {
    if viewsWithLayersDirty {
      viewsWithLayersDirty = false
      _viewsWithLayers.removeAll()
      buildViewsWithLayers(rootView, &_viewsWithLayers)
    }
    return _viewsWithLayers
  }

  public var shouldActivate: Bool {
    return delegate!.canActivate
  }

  public var theme: Theme {
    if _theme == nil {
      _theme = Theme.instanceForNativeUi()
    }
    return _theme!
  }

  public var frameType: FrameType

  public var alwaysRenderAsActive: Bool {
    didSet {
      if let nonClient = nonClientView, !active {
        nonClient.frameView!.schedulePaint()
      }
    }
  }
  
  private var _theme: Theme?

  var workAreaBoundsInScreen: IntRect {
    return host.workAreaBoundsInScreen
  }

  private (set) public var type: WindowType

  private (set) public var draggedView: View?

  private (set) public var host: DesktopWindowTreeHost!

  private (set) public var tooltipManager: TooltipManager?

  private (set) public var widgetClosed: Bool

  internal var rootWindowEventFilter: CompoundEventFilter?

  internal var contentWindow: Window?
 
  internal var autoReleaseCapture: Bool

  private var observers: [WidgetObserver]

  private var removalObservers: [WidgetRemovalObserver]

  private var savedShowState: WindowShowState

  private var cursorReferenceCount: Int

  private var cursorManager: CursorManager?

  private var platformCursorManager: DesktopCursorManager?

  private var shadowController: ShadowController?

  private var windowReorderer: WindowReorderer?

  private var topLevel: Bool

  private var contentWindowContainer: Window

  private var movementDisabled: Bool

  private var cursor: PlatformCursor

  private var savedWindowState: WindowShowState

  private var lastDropOperation: DragOperation?

  private var dropHelper: DropHelper?

  private var focusClient: FocusController?

  private var dispatcherClient: DesktopDispatcherClient?

  private var positionClient: ScreenPositionClient?

  private var dragDropClient: DragDropClient?

  private var windowTreeClient: WindowTreeClient?

  private var eventClient: DesktopEventClient?

  private var focusManagerEventHandler: FocusManagerEventHandler?

  private var tooltipController: TooltipController?

  private var visibilityController: VisibilityController?

  private var windowModalityController: WindowModalityController?

  private var captureClient: DesktopCaptureClient?

  private var restoreFocusOnActivate: Bool

  private var mouseButtonPressed: Bool

  private var mouseButtonDown: Bool

  private var ignoreCaptureLoss: Bool

  private var lastMouseEventWasMove: Bool

  private var lastMouseEventPosition: IntPoint

  //private var rootLayersDirty: Bool

  private var focusOnCreation: Bool

  private var initialRestoredBounds: IntRect

  private var _disableInactiveRendering: Bool

  private var _focusManager: FocusManager?

  private var _viewsWithLayers: Views

  private var viewsWithLayersDirty: Bool

  private var ownership: Ownership

  // if we own the nativeWidget
  private weak var _nativeWidget: NativeWidget?
  // if nativeWidget owns us, we need to use this weak reference
  private var _ownedNativeWidget: NativeWidget?

  public static func getForWindow(window: Window) -> UIWidget? {
    assert(false)
    return nil
  }

  public class func make(delegate: WidgetDelegate) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized

    try widget.initialize(params: params)

    return widget
  }

  public class func make(delegate: WidgetDelegate, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .Textured

    try widget.initialize(params: params)

    return widget
  }

  public class func makeWithParent(delegate: WidgetDelegate, parent: Window) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized
    params.layerType = .Textured
    params.parent = parent

    try widget.initialize(params: params)

    return widget
  }

  public class func makeWithParent(delegate: WidgetDelegate, parent: Window, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .Textured
    params.parent = parent

    try widget.initialize(params: params)

    return widget
  }

  public class func makeWithContext(delegate: WidgetDelegate, context: Window) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized
    params.layerType = .Textured
    params.context = context

    try widget.initialize(params: params)

    return widget
  }

  public class func makeWithContext(delegate: WidgetDelegate, context: Window, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .Textured
    params.context = context

    try widget.initialize(params: params)

    return widget
  }

  public static func getAllChildWidgets(window: Window, children: inout Widgets) {
   // Code expects widget for |native_view| to be added to |children|.

   if let widget = window.widget  {
     children.append(widget)
   }

   // do the same for each children
   for w in window.children {
     getAllChildWidgets(window: w, children: &children)
   }
  }

  public class func reparentWindow(window: Window, newParent: Window?) throws {

    let previousParent = window.parent
    if previousParent === newParent {
      return
    }

    var widgets = Widgets()
    getAllChildWidgets(window: window, children: &widgets)

    // First notify all the windows that they are being disassociated
    // from their previous parent.
    for widget in widgets {
        widget.notifyNativeViewHierarchyWillChange()
    }

    if let p = newParent {
      try p.addChild(child: window)
    } else {
      // The following looks weird, but it's the equivalent of what aura has
      // always done. (The previous behaviour of aura::Window::SetParent() used
      // NULL as a special value that meant ask the WindowTreeClient where things
      // should go.)
      //
      // This probably isn't strictly correct, but its an invariant that a Window
      // in use will be attached to a RootWindow, so we can't just call
      // RemoveChild here. The only possible thing that could assign a RootWindow
      // in this case is the stacking client of the current RootWindow. This
      // matches our previous behaviour; the global stacking client would almost
      // always reattach the window to the same RootWindow.
      if let rootWindow = window.rootWindow {
        try UI.parentWindowWithContext(
          window: window, context: rootWindow, screenBounds: rootWindow.boundsInScreen)
      }
    }

    for widget in widgets {
        widget.notifyNativeViewHierarchyChanged()
    }
  }

  // TODO: Não precisamos do initialize depois!!!
  // se somarmos as duas coisas, podemos tirar o optional
  // do host e da rootView que são MUITO usadas nessa classe
  // e que são definitivamente "owned"

  public override init() {
    observers = [WidgetObserver]()
    removalObservers = [WidgetRemovalObserver]()
    cursor = PlatformCursorNil
    savedWindowState = .Default
    type = .Normal
    lastDropOperation = .DragNone
    mouseButtonPressed = false
    mouseButtonDown = false
    alwaysRenderAsActive = false
    ignoreCaptureLoss = false
    lastMouseEventWasMove = false
    lastMouseEventPosition = IntPoint()
    //rootLayersDirty = false
    widgetClosed = false
    savedShowState = .Default
    focusOnCreation = true
    initialRestoredBounds = IntRect()
    cursorReferenceCount = 0
    autoReleaseCapture = true
    topLevel = true
    frameType = .Default
    movementDisabled = false
    restoreFocusOnActivate = true
    _disableInactiveRendering = false
    _viewsWithLayers = Views()
    viewsWithLayersDirty = false
    contentWindowContainer = Window(delegate: nil)
    ownership = .NativeWidgetOwnsWidget
    // Warning: alteração aqui -> estava no initialize.. ver se não fode tudo

    super.init()

    // rootView = RootView(widget: self)
    // host = DesktopWindowTreeHostFactory.instance.make(widget: self)!
    // contentWindow = Window(delegate: self)
    // contentWindow!.widget = self
  }

  deinit {
    destroyRootView()
    nativeWidget = nil
  }

  public func initialize(params inParams: InitParams) throws {
    var params = inParams
    if params.name.isEmpty && params.delegate != nil {
      params.name = params.delegate!.contentsView.className
    }
    params.child = params.child || params.type == .Control
    self.isTopLevel = !params.child

    if params.opacity == .InferOpacity &&
       params.type != .Normal &&
       params.type != .Panel {
      params.opacity = .Opaque
    }

    if let viewsDelegate = ViewsDelegate.instance {
      viewsDelegate.onBeforeWidgetInit(params: &params, widget: self)
    }

    if params.opacity == .InferOpacity {
      params.opacity = .Opaque
    }

    var canActivate = params.canActivate
    params.activatable = canActivate ? Activatable.Yes : Activatable.No

    self.delegate = params.delegate ?? DefaultWidgetDelegate(self)
    self.delegate!.canActivate = canActivate
    ownership = params.ownership

    nativeWidget = createNativeWidget(params: params, delegate: self)
    rootView = createRootView()
    defaultThemeProvider = DefaultThemeProvider()

    if params.type == .Menu {
      self.isMouseButtonPressed = NativeWidget.isMouseButtonDown
    }

    nativeWidget!.initNativeWidget(params: params)

    if inParams.type == .Normal || inParams.type == .Panel || inParams.type == .Bubble {
      nonClientView = NonClientView()
      nonClientView!.frameView = createNonClientFrameView()
    
      nonClientView!.clientView = self.delegate!.createClientView(widget: self)
      nonClientView!.overlayView = self.delegate!.createOverlayView()
    
      rootView.contentsView = nonClientView!

      updateWindowIcon()
      updateWindowTitle()
      nonClientView!.resetWindowControls()
      setInitialBounds(bounds: params.bounds)

      rootView.layout()

      if inParams.showState == .Maximized {
        maximize()
      } else if inParams.showState == .Minimized {
        minimize()
        savedShowState = .Minimized
      }
    } else if let d = params.delegate {
       contentsView = d.contentsView
       setInitialBoundsForFramelessWindow(bounds: params.bounds)
    }

    // This must come after SetContentsView() or it might not be able to find
    // the correct NativeTheme (on Linux). See http://crbug.com/384492
    observerManager.add(theme)
    nativeWidgetInitialized = true
    nativeWidget.onWidgetInitDone()
  }

  public func initialize(params: InitParams) throws {
    // (mudado aqui.. inicializacao do host, etc.. acima)
    // continue the initialization
    delegate = params.delegate ?? DefaultWidgetDelegate()
    
    var canActivate = false

    if params.type != .Popup && params.type != .Control && params.type != .Drag && params.type != .Menu && params.type != .Tooltip {
      canActivate = true
    }

    self.delegate!.canActivate = canActivate

    var opaque: Bool = params.opacity == WindowOpacity.Opaque

    if params.opacity == .InferOpacity {
      opaque = true
    }

    var inParams = params
    ViewsDelegate.instance.onBeforeWindowInit(params: &inParams, widget: self)
    ownership = params.ownership

    contentWindow = Window(delegate: self)
    contentWindow!.widget = self

    // init native widget section
    //TODO: checar se a content window do chrome é bounds(0,0)
    // como essa aqui, e ver quem é responsavel pelos layers
    // drawables.. seriam as Views???
    contentWindow!.type = inParams.type
    contentWindow!.transparent = opaque != true
    try contentWindow!.initialize(type: inParams.layerType)
    contentWindow!.bounds = params.bounds

    UI.setFocusChangeObserver(window: contentWindow!, observer: self)
    UI.setActivationChangeObserver(window: contentWindow!, observer: self)

    try contentWindowContainer.initialize(type: .NotDrawn)
    contentWindowContainer.show()
    try contentWindowContainer.addChild(child: contentWindow!)

    host = DesktopWindowTreeHostFactory.instance.make(widget: self)!
    
    try host.initialize(window: contentWindow!, params: inParams)

    try host.tree.initHost()
    try host.tree.window.addChild(child: contentWindowContainer)
    host.tree.window.widget = self

    alwaysOnTop = inParams.onTop

    host.tree.window.addObserver(observer: RootWindowDestructionObserver(parent: self))

    if params.type == .Normal {
     windowModalityController = WindowModalityController(target: host.tree.window)
    }

    rootWindowEventFilter = CompoundEventFilter()
    host.tree.window.addPreTargetHandler(handler: rootWindowEventFilter!)

    cursorReferenceCount = cursorReferenceCount + 1

    if platformCursorManager == nil {
      platformCursorManager = DesktopCursorManager(cursorLoaderUpdater:
        DesktopCursorLoaderUpdater())
    }

    if cursorManager == nil {
      cursorManager = CursorManager(delegate: platformCursorManager!)
    }

    platformCursorManager!.addHost(host: host.tree)
    UI.setCursorClient(window: host.tree.window, client: cursorManager)

    host.onWindowCreated(params: inParams)

    updateWindowTransparency()

    captureClient = DesktopCaptureClient(root: host.tree.window)

    let focusController = FocusController(rules: DesktopFocusRules(contentWindow: contentWindow!))
    focusClient = focusController
    UI.setFocusClient(window: host.tree.window, client: focusController)
    UI.setActivationClient(window: host.tree.window, client: focusController)
    host.tree.window.addPreTargetHandler(handler: focusController)

    dispatcherClient = DesktopDispatcherClient()
    UI.setDispatcherClient(window: host.tree.window, client: dispatcherClient)

    positionClient = DesktopScreenPositionClient(rootWindow: host.tree.window)

    dragDropClient = host.createDragDropClient(cursorManager: platformCursorManager!)
    UI.setDragDropClient(window: host.tree.window, client: dragDropClient)

    focusClient!.focusWindow(window: contentWindow!)

    rootView = RootView(widget: self)

    onHostResized(host: host.tree)

    host.tree.addObserver(observer: self)
    
    windowTreeClient = WidgetTreeClient(rootWindow: host.tree.window)
    dropHelper = DropHelper(rootView: rootView)
    UI.setDragDropDelegate(window: contentWindow!, delegate: self)

    if inParams.type != .Tooltip {
      tooltipManager = TooltipManager(widget: self)
      tooltipController = TooltipController(tooltip: host.createTooltip())
      UI.setTooltipClient(window: host.tree.window, client: tooltipController)
      host.tree.window.addPreTargetHandler(handler: tooltipController!)
    }

    if inParams.opacity == .Translucent {
      visibilityController = VisibilityController()
      UI.setVisibilityClient(window: host.tree.window, client: visibilityController)
      host.tree.window.childWindowVisibilityChangesAnimated = true
      contentWindowContainer.childWindowVisibilityChangesAnimated = true
    }

    if inParams.type == .Normal {
      focusManagerEventHandler = FocusManagerEventHandler(widget: self)
      host.tree.window.addPreTargetHandler(handler: focusManagerEventHandler!)
    }

    eventClient = DesktopEventClient()
    UI.setEventClient(window: host.tree.window, client: eventClient)
    UI.getFocusClient(window: contentWindow)!.focusWindow(window: contentWindow!)
    UI.setActivationDelegate(window: contentWindow!, delegate: self)

    shadowController = ShadowController(activationClient: UI.getActivationClient(window: host.tree.window))

    onSizeConstraintsChanged()
    
    windowReorderer = WindowReorderer(window: contentWindow!, rootView: rootView)

    // end init native widget
    if inParams.type == .Normal || inParams.type == .Panel || inParams.type == .Bubble {
      nonClientView = NonClientView()
      nonClientView!.frameView = createNonClientFrameView()
      // Create the ClientView, add it to the NonClientView and add the
      // NonClientView to the RootView. This will cause everything to be parented.
      nonClientView!.clientView = self.delegate!.createClientView(widget: self)
      nonClientView!.overlayView = self.delegate!.createOverlayView()
      contentsView = nonClientView
      // Initialize the window's icon and title before setting the window's
      // initial bounds; the frame view's preferred height may depend on the
      // presence of an icon or a title.
      updateWindowIcon()
      updateWindowTitle()
      nonClientView!.resetWindowControls()
      setInitialBounds(bounds: bounds)

      if inParams.state == .Maximized {
        maximize()
      } else if inParams.state == .Minimized {
        minimize()
      }
    } else if let d = delegate {
       contentsView = d.contentsView
       setInitialBoundsForFramelessWindow(bounds: bounds)
    }

  }

  public func asWidget() -> UIWidget {
    return self
  }

  public func getCursor(at point: IntPoint) -> PlatformCursor {
    return cursor
  }

  public func onBoundsChanged(oldBounds: IntRect, newBounds: IntRect) {}

  public func getNonClientComponent(point: IntPoint) -> HitTest {

    var component = HitTest.HTNOWHERE

    if let nview = nonClientView {
      component = nview.nonClientHitTest(point: point)
    }

    if movementDisabled && (component == HitTest.HTCAPTION || component == HitTest.HTSYSMENU) {
      return HitTest.HTNOWHERE
    }

    return component
  }

  public func shouldDescendIntoChildForEventHandling(
    rootLayer: Layer,
    child: Window, 
    childLayer: Layer,
    location: IntPoint) -> Bool {
    if let d = delegate {
      if !d.shouldDescendIntoChildForEventHandling(child: child, location: location) {
        return false
      }
    }

    let views = viewsWithLayers
    if views.isEmpty {
      return true
    }

    guard let childLayerIndex = rootLayer.children.firstIndex(where: { $0 === childLayer }) else {
      return true
    } 

    for view in views {
      guard let layer = view.layer else {
        return true
      }
    
      if layer.isVisible && layer.bounds.contains(point: location) {
 
        guard let rootLayerIndex = rootLayer.children.firstIndex(where: { $0 === layer }) else {
          return true
        }
 
        if childLayerIndex > rootLayerIndex {
          // |child| is on top of the remaining layers, no need to continue.
          return true;
        }

        // Event targeting uses the visible bounds of the View, which may differ
        // from the bounds of the layer. Verify the view hosting the layer
        // actually contains |location|. Use GetVisibleBounds(), which is
        // effectively what event targetting uses.
        let visBounds = view.visibleBounds
        var pointInView = location
        View.convertPointToTarget(source: rootView, target: view, point: &pointInView)
        if visBounds.contains(point: pointInView) {
          return false
        }
      }
    }
    return true
  }

  public func onCaptureLost() {
    if ignoreCaptureLoss {
      return
    }

    rootView.onMouseCaptureLost()

    mouseButtonPressed = false
  }

  public func onPaint(context: PaintContext) {
    rootView!.paintFromPaintRoot(context: context)
  }

  /// NOTIMPLEMENTED
  public func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {}
  /// NOTIMPLEMENTED
  public func onWindowDestroying(window: Window) {}
  /// NOTIMPLEMENTED
  public func onWindowDestroyed(window: Window) {}
  /// NOTIMPLEMENTED
  public func onWindowTargetVisibilityChanged(visible: Bool) {}

  public func addObserver(observer: WidgetObserver) {
    observers.append(observer)
  }

  public func removeObserver(observer: WidgetObserver) {
    for (index, item) in observers.enumerated() {
      if item === observer {
        observers.remove(at: index)
      }
    }
  }

  public func hasObserver(observer: WidgetObserver) -> Bool {
    for item in observers {
      if item === observer {
        return true
      }
    }
    return false
  }

  public func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if !details.isAdd {
      if details.child === draggedView {
        draggedView = nil
      }

      if let manager = focusManager {
        manager.viewRemoved(removed: details.child!)
      }

      ViewStorage.instance.viewRemoved(view: details.child!)
      viewRemoved(view: details.child!)
    }
  }

  public func notifyNativeViewHierarchyWillChange() {
    if let manager = focusManager {
      manager.viewRemoved(removed: rootView)
    }
  }

  public func notifyNativeViewHierarchyChanged() {
    rootView.notifyNativeViewHierarchyChanged()
  }

  public func notifyWillRemoveView(view: View) {
    for observer in removalObservers {
      observer.onWillRemoveView(widget: self, view: view)
    }
  }

  public func centerWindow(size: IntSize) {
    host.centerWindow(size: size)
  }

  public func setBoundsConstrained(bounds: IntRect) {
    //let workArea = Screen.getScreenFor(contentWindow!.id).getDisplayNearestPoint(
    //      bounds.origin).workArea
    var workArea = Screen.getDisplayNearestPoint(point: bounds.origin)!.workArea
    if workArea.isEmpty {
      self.bounds = bounds
    } else {
      // Inset the work area slightly.
      workArea.inset(left: 10, top: 10, right: 10, bottom: 10)
      workArea.adjustToFit(rect: bounds)
      self.bounds = workArea
    }
  }

  public func setVisibilityChangedAnimationsEnabled(value: Bool) {
    host.setVisibilityChangedAnimationsEnabled(value: value)
  }

  public func setVisibilityAnimationDuration(duration: TimeTicks) {
    contentWindow!.visibilityAnimationDuration = duration
  }

  public func setVisibilityAnimationTransition(transition: Window.VisibilityAnimationTransition) {
    contentWindow!.visibilityAnimationTransition = transition
  }

  public func runMoveLoop(dragOffset: IntVec2,
                          source: MoveLoopSource,
                          escapeBehavior: MoveLoopEscapeBehavior) -> MoveLoopResult {
    return host.runMoveLoop(dragOffset: dragOffset, source: source, escapeBehavior: escapeBehavior)
  }

  public func endMoveLoop() {
    host.endMoveLoop()
  }

  public func stackAboveWidget(widget: UIWidget) {
    stackAbove(window: widget.window)
  }

  public func stackAbove(window: Window) {
    host.stackAbove(window: window)
  }

  public func stackAtTop() {
    host.stackAtTop()
  }

  public func stackBelow(window: Window) {
    assert(false)
  }

  public func setShape(shape: ShapeRects?) {
    host.setShape(nativeShape: shape)
  }

  public func close() {
    var canClose = true
    if let ncView = nonClientView {
      canClose = ncView.canClose
    }

    if canClose {
      saveWindowPlacement()

      if topLevel {
        if let manager = focusManager {
          manager.focusedView = nil
        }
      }

      for observer in observers {
        observer.onWidgetClosing(widget: self)
      }

      contentWindow!.suppressPaint()
      contentWindow!.hide()
      host.close()

      widgetClosed = true
    }
  }

  public func closeNow() {
    for observer in observers {
      observer.onWidgetClosing(widget: self)
    }
    host.closeNow()
  }

  public func show() {
    host.tree.show()
    contentWindow!.show()
  }

  public func hide() {
    host.tree.hide()
    contentWindow!.hide()
  }

  public func showMaximizedWithBounds(restoredBounds: IntRect) {
    host.showMaximizedWithBounds(restoredBounds: restoredBounds)
    contentWindow!.show()
  }

  public func showWithWindowState(state: WindowShowState) {
    host.showWindowWithState(showState: state)
    contentWindow!.show()
  }

  public func showInactive() {
    if savedShowState == .Maximized &&
      !initialRestoredBounds.isEmpty {
     bounds = initialRestoredBounds
     savedShowState = .Normal
    }
    showWithWindowState(state: .Inactive)
  }

  public func activate() {
    host.activate()
  }

  public func deactivate() {
    host.deactivate()
  }

  public func disableInactiveRendering() {
    setInactiveRenderingDisabled(value: true)
  }

  public func setVisibleOnAllWorkspaces(alwaysVisible: Bool) {
    host.setVisibleOnAllWorkspaces(alwaysVisible: alwaysVisible)
  }

  public func maximize() {
    host.maximize()
  }

  public func minimize() {
    host.minimize()
  }

  public func restore() {
    host.restore()
  }

  public func setOpacity(opacity: UInt8) {
    host.setOpacity(opacity: opacity)
  }

  public func setUseDragFrame(useDragFrame: Bool) {}

  public func flashFrame(flash: Bool) {
    host.flashFrame(flashFrame: flash)
  }

  public func runShellDrag(view: View?,
                           data: OSExchangeData,
                           location: IntPoint,
                           operation: DragOperation,
                           source: DragEventSource) {
    draggedView = view
    
    onDragWillStart()

    let widgetDeletionObserver = WidgetDeletionObserver(widget: self)
    
    if let window = contentWindow {
      UI.runShellDrag(
        view: window,
        data: data,
        location: location,
        operation: operation,
        source: source)
    }
  //native_widget_->RunShellDrag(view, data, location, operation, source);

  // The widget may be destroyed during the drag operation.
    if !widgetDeletionObserver.widgetAlive {
      return
    }

  // If the view is removed during the drag operation, dragged_view_ is set to
  // NULL.
    if let v = view, draggedView === view {
      draggedView = nil
      v.onDragDone()
    }

    onDragComplete()
  }

  public func schedulePaintInRect(rect: IntRect) {
    if let window = contentWindow {
     window.schedulePaintInRect(rect: rect)
    }
  }

  public func setCursor(cursor: PlatformCursor) {
    self.cursor = cursor
    var cursorClient = UI.getCursorClient(window: host.tree.window)
    cursorClient?.cursor = cursor
  }

  public func setWindowTitle(title: String) -> Bool {
    return host.setWindowTitle(title: title)
  }

  public func setWindowIcons(windowIcon: Image?, appIcon: Image?) {
    host.setWindowIcons(windowIcon: windowIcon, appIcon: appIcon)
  }

  public func initModalType(modalType: ModalType) {
    host.initModalType(modalType: modalType)
  }

  public func updateWindowTitle() {

    guard let view = nonClientView else {
      return
    }

    let windowTitle = delegate!.windowTitle
    // todo: fix this and make it work
    // i18n.adjustStringForLocaleDirection(&windowTitle)
    if !setWindowTitle(title: windowTitle) {
      return
    }

    view.updateWindowTitle()
    view.layout()
  }

  public func updateWindowIcon() {
    if let v = nonClientView {
      v.updateWindowIcon()
    }
    setWindowIcons(windowIcon: delegate!.windowIcon,
                   appIcon: delegate!.windowAppIcon)
  }

  public func localeChanged() {
    rootView.localeChanged()
  }

  public func deviceScaleFactorChanged(deviceScaleFactor: Float) {
    rootView.deviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
  }

  public func setFocusTraversableParent(parent: FocusTraversable) {
    rootView.focusTraversableParent = parent
  }

  public func setFocusTraversableParentView(parentView: View) {
    rootView.focusTraversableParentView = parentView
  }

  public func clearNativeFocus() {
    host.clearNativeFocus()

    if shouldActivate {
      if let win = contentWindow, let focusClient = UI.getFocusClient(window: win) {
        focusClient.resetFocusWithinActiveWindow(window: win)
      }
    }
  }

  public func createNonClientFrameView() -> NonClientFrameView? {
    var view: NonClientFrameView? = nil
    view = delegate!.createNonClientFrameView(widget: self)
    if view == nil {
      view = shouldUseNativeFrame ? DesktopFrameView(frame: self) : nil
    }
    if view == nil {
      view = ViewsDelegate.instance.createDefaultNonClientFrameView(widget: self)
    }
    if view != nil {
      return view
    }

    let customFrameView = CustomFrameView()
    customFrameView.initialize(frame: self)
    return customFrameView
  }

  public func debugToggleFrameType() {
    if frameType == .Default {
      frameType = shouldUseNativeFrame ? .ForceCustom : .ForceNative
    } else {
      frameType = frameType == .ForceCustom ? .ForceNative : .ForceCustom
    }
    frameTypeChanged()
  }

  public func frameTypeChanged() {
    host.frameTypeChanged()
    updateWindowTransparency()
  }

  public func reorderNativeViews() {
    windowReorderer!.reorderChildWindows()
  }

  public func viewRemoved(view: View) {
    if let drop = dropHelper {
      drop.resetTargetViewIfEquals(view: view)
    }
  }

  //public func updateRootLayers() {
  //  rootLayersDirty = true
  //}

  public func setCapture(view: View) {
    if !hasCapture {
      contentWindow!.setCapture()

      // Early return if setting capture was unsuccessful.
      if !hasCapture {
        return
      }
    }

    if mouseButtonDown {
      mouseButtonPressed = true
    }

    rootView.setMouseHandler(handler: view)
  }

  public func releaseCapture() {
    contentWindow!.releaseCapture()
  }

  public func synthesizeMouseMoveEvent() {
    var mouseLocation = EventMonitor.lastMouseLocation
    if !windowBoundsInScreen.contains(point: mouseLocation) {
      return
    }

    // Convert: screen coordinate -> widget coordinate.
    View.convertPointFromScreen(dst: rootView, point: &mouseLocation)
    lastMouseEventWasMove = false

    // TODO: fix time
    // on chrome this is = base::TimeDelta::FromInternalValue(base::TimeTicks::Now().ToInternalValue())

    let mouseEvent = MouseEvent(type: .MouseMoved,
                                location: mouseLocation,
                                rootLocation: mouseLocation,
                                timestamp: 0,  //eventTimeForNow(),
                                flags: EventFlags.IsSynthesized,
                                changedButtonFlags: 0)

    rootView.onMouseMoved(event: mouseEvent)
  }

  public func onRootViewLayout() {
    host.onRootViewLayout()
  }

  public func onSizeConstraintsChanged() {
    contentWindow!.canMaximize = delegate!.canMaximize
    contentWindow!.canMinimize = delegate!.canMinimize
    contentWindow!.canResize = delegate!.canResize
    host.sizeConstraintsChanged()
    if let view = nonClientView {
      view.sizeConstraintsChanged()
    }
  }

  public func enableInactiveRendering() {
    setInactiveRenderingDisabled(value: false)
  }

  public func onVisibilityChanging(visible: Bool) {
    for observer in observers {
      observer.onWidgetVisibilityChanging(widget: self, visible: visible)
    }
  }

  public func onVisibilityChanged(visible: Bool) {

    rootView.propagateVisibilityNotifications(from: rootView, isVisible: visible)

    for observer in observers {
      observer.onWidgetVisibilityChanged(widget: self, visible: visible)
    }

    if compositor != nil {
      if let layer = rootView.layer {
        layer.isVisible = visible
      }
    }
  }

  public func onCreated(widget: Bool) {
    if topLevel {
      _focusManager = FocusManager(widget: self, delegate: nil)
    }

    initModalType(modalType: delegate!.modalType)

    for observer in observers {
      observer.onWidgetCreated(widget: self)
    }
  }

  public func onMove() {
    delegate!.onWidgetMove()
    notifyCaretBoundsChanged(inputMethod: inputMethod)

    for observer in observers {
      observer.onWidgetBoundsChanged(widget: self, newBounds: windowBoundsInScreen)
    }
  }

  public func onDestroying() {
    if let manager = focusManager {
      manager.viewRemoved(removed: rootView)
    }

    for observer in observers {
      observer.onWidgetDestroying(widget: self)
    }

    if let view = nonClientView {
      view.windowClosing()
    }
    delegate!.windowClosing()
  }

  public func onDestroyed() {
    for observer in observers {
      observer.onWidgetDestroyed(widget: self)
    }
    delegate!.deleteDelegate()
    delegate = nil
  }

  public func onOwnerClosing() {}

  // methods used in UIWidget, that are called by DesktopNativeWidgetAura
  // that we have implemented directly here, so they have no use anymore

  //public func onWindowMove() {}
  //public func onWindowSizeChanged(newSize: IntSize) {}
  //public func onWindowShowStateChanged() {}
  //public func onWindowBeginUserBoundsChange() {}
  //public func onWindowEndUserBoundsChange() {}
  //public func onWindowPaint(context: PaintContext) {}
  //public func onMouseCaptureLost() {}

  public func executeCommand(commandId: Int) -> Bool {
    return delegate!.executeWindowsCommand(commandId: commandId)
  }

  public func setInitialFocus(showState: WindowShowState) -> Bool {
    let view = delegate!.initiallyFocusedView
    if !focusOnCreation || showState == .Inactive || showState == .Minimized {
      // If not focusing the window now, tell the focus manager which view to
      // focus when the window is restored.
      if view != nil {
        focusManager!.storedFocusView = view
      }
     return true
    }

    if view != nil {
      view!.requestFocus()
    }

    return view != nil
  }

  public func onNativeWidgetActivationChanged(active: Bool) -> Bool {
    if !active { // && native_widget_initialized_
      saveWindowPlacement()
    }

    for observer in observers {
      observer.onWidgetActivationChanged(widget: self, active: active)
    }

    if let view = nonClientView?.frameView {
      view.activationChanged(active: active)
    }

    return true
  }

  // public func handleActivationChanged(active: Bool) {
  //   if !active { // && native_widget_initialized_
  //     saveWindowPlacement()
  //   }

  //   for observer in observers {
  //     observer.onWidgetActivationChanged(widget: self, active: active)
  //   }

  //   if visible {
  //     if let view = nonClientView?.frameView {
  //       view.schedulePaint()
  //     }
  //   }

  //   guard let activationClient = UI.getActivationClient(window: host.tree.window) else {
  //     return
  //   }

  //   if active {
  //     if hasFocusManager {
  //       // This function can be called before the focus manager has had a
  //       // chance to set the focused view. In which case we should get the
  //       // last focused view.
  //       var viewForActivation = focusManager!.focusedView ?? focusManager!.storedFocusView
  //       if viewForActivation == nil {
  //         viewForActivation = rootView
  //       }

  //       activationClient.activateWindow(window: viewForActivation!.widget!.window)
  //       inputMethod!.onFocus()
  //    }
  //   } else {
  //     if let activeWindow = activationClient.activeWindow {
  //       activationClient.deactivateWindow(window: activeWindow)
  //       inputMethod!.onBlur()
  //     }
  //   }

  // }

  // EventHandler
  public func onEvent(event: inout Graphics.Event) {
    if event.isKeyEvent {
      var keyEvent = event as! KeyEvent
      onKeyEvent(event: &keyEvent)
    } else if event.isMouseEvent {
      var mouseEvent = event as! MouseEvent
      onMouseEvent(event: &mouseEvent)
    } else if event.isScrollEvent {
      var scrollEvent = event as! ScrollEvent
      onScrollEvent(event: &scrollEvent)
    } else if event.isTouchEvent {
      var touchEvent = event as! TouchEvent
      onTouchEvent(event: &touchEvent)
    } else if event.isGestureEvent {
      var gestureEvent = event as! GestureEvent
      onGestureEvent(event: &gestureEvent)
    } else if event.type == .CancelMode {
      var cancelEvent = event as! CancelModeEvent
      onCancelMode(event: &cancelEvent)
    }
  }

  // EventHandler
  public func onKeyEvent(event: inout KeyEvent) {
    if event.isChar {
      // If a InputMethod object is attached to the root window, character
      // events are handled inside the object and are not passed to this function.
      // If such object is not attached, character events might be sent (e.g. on
      // Windows). In this case, we just skip these.
      return
    }
    // Renderer may send a key event back to us if the key event wasn't handled,
    // and the window may be invisible by that time.
    if !contentWindow!.visible {
      return
    }

    let _ = sendEventToProcessor(event: event)

    if event.handled {
      return
    }

    if hasFocusManager && !focusManager!.onKeyEvent(event: event) {
      event.handled = true
    }
  }

  // EventHandler
  public func onMouseEvent(event: inout MouseEvent) {
    guard contentWindow!.visible else {
      return
    }

    if let manager = tooltipManager {
      manager.updateTooltip()
    }

    TooltipManager.updateTooltipManagerForCapture(source: self)

    switch event.type {
      case .MousePressed:
        lastMouseEventWasMove = false
        let windowDeletionObserver = WidgetDeletionObserver(widget: self)

        if rootView.onMousePressed(event: event) && 
          windowDeletionObserver.widgetAlive && visible && mouseButtonDown {
            mouseButtonPressed = true
            if !hasCapture {
              contentWindow!.setCapture()
            }
          event.handled = false
        }
        
        return
      case .MouseReleased:
          lastMouseEventWasMove = false
          mouseButtonPressed = false
          // Release capture first, to avoid confusion if OnMouseReleased blocks.
          if autoReleaseCapture && hasCapture {
            //base::AutoReset<bool> resetter(&ignore_capture_loss_, true);
            releaseCapture()
            ignoreCaptureLoss = true
          }
          
          rootView.onMouseReleased(event: event)
         
          if event.flags.rawValue & EventFlags.IsNonClient.rawValue == 0 {
            event.handled = false
          }
          return
      case .MouseMoved, .MouseDragged:
        if hasCapture && mouseButtonPressed {
          lastMouseEventWasMove = false
            let _ = rootView.onMouseDragged(event: event)
          } else if !lastMouseEventWasMove || lastMouseEventPosition != event.location {
            lastMouseEventPosition = event.location
            lastMouseEventWasMove = true
            rootView.onMouseMoved(event: event)
          }
        return
      case .MouseExited:
        lastMouseEventWasMove = false
        rootView.onMouseExited(event: event)
        return
      case .MouseWheel:
        if rootView.onMouseWheel(event: event as! MouseWheelEvent) {
          event.handled = false
        }
        return
      default:
        return
    }
  }

  // EventHandler
  public func onScrollEvent(event: inout ScrollEvent) {
    if event.type == .Scroll {
      let _ = sendEventToProcessor(event: event)

      //onScrollEvent(event)
      if event.handled {
        return
      }
      // Convert unprocessed scroll events into wheel events.
      var mwe: MouseEvent = MouseWheelEvent(event: event)
      onMouseEvent(event: &mwe)
      if mwe.handled {
        event.handled = true
      }
    } else {
      let _ = sendEventToProcessor(event: event)
      if event.handled {
        return
      }
      // Convert unprocessed scroll events into wheel events.
      var mwe: MouseEvent = MouseWheelEvent(event: event)
      onMouseEvent(event: &mwe)
      if mwe.handled {
        event.handled = true
      }
    }
  }

  // EventHandler
  public func onTouchEvent(event: inout TouchEvent) {}

  // EventHandler
  public func onGestureEvent(event: inout GestureEvent) {
    let _ = sendEventToProcessor(event: event)
  }

  public func onCancelMode(event: inout CancelModeEvent) {

  }

  public func onWindowActivated(reason: ActivationReason,
                                gainedActive: Window,
                                lostActive: Window) {
    guard contentWindow === gainedActive || contentWindow === lostActive else {
      return
    }
    if gainedActive === contentWindow && restoreFocusOnActivate {
      restoreFocusOnActivate = false
      let _ = focusManager!.restoreFocusedView()
    } else if lostActive === contentWindow && hasFocusManager {
      guard !restoreFocusOnActivate else {
        return
      }
      restoreFocusOnActivate = true
      // Pass in false so that ClearNativeFocus() isn't invoked.
      focusManager!.storeFocusedView(clearNativeFocus: false)
    }
  }

  public func onAttemptToReactivateWindow(requestActive: Window,
                                   actualActive: Window) {

  }

  public func onWindowFocused(gainedFocus: Window, lostFocus: Window) {
    if contentWindow === gainedFocus {
      host.onWindowFocus()
      WindowFocusManager.instance.onWindowFocusChanged(window: contentWindow)
    } else if contentWindow === lostFocus {
      host.onWindowBlur()
      WindowFocusManager.instance.onWindowFocusChanged(window: nil)
    }
  }

  public func onDragEntered(event: DropTargetEvent) {
    guard let helper = dropHelper, let dragOps = DragOperation(rawValue: event.sourceOperations) else {
      return
    }

    lastDropOperation = helper.onDragOver(data: event.data,
      rootViewLocation: event.location,
      dragOperation: dragOps)
  }

  public func onDragUpdated(event: DropTargetEvent) -> DragOperation {

    guard let helper = dropHelper, let dragOps = DragOperation(rawValue: event.sourceOperations) else {
      return DragOperation.DragNone
    }

    lastDropOperation = helper.onDragOver(data: event.data,
      rootViewLocation: event.location, dragOperation: dragOps)

    return lastDropOperation!
  }

  public func onDragExited() {
    guard let helper = dropHelper else {
      return
    }
    helper.onDragExit()
  }

  public func onPerformDrop(event: DropTargetEvent) -> DragOperation {
    guard let helper = dropHelper else {
      return DragOperation.DragNone
    }
    if shouldActivate {
      activate()
    }

    return helper.onDrop(data: event.data, rootViewLocation: event.location, dragOperation: lastDropOperation!)
  }

  /// unimplemented
  public func onDragWillStart() {}
  /// unimplemented
  public func onDragComplete() {}

  public func onHostResized(host windowTreeHost: WindowTreeHost) {

    if host.isAnimatingClosed {
      return
    }

    let newBounds = IntRect(size: windowTreeHost.window.bounds.size)
    contentWindow!.bounds = newBounds
    contentWindowContainer.bounds = newBounds

    rootView.size = newBounds.size
   
    notifyCaretBoundsChanged(inputMethod: inputMethod)
    saveWindowPlacement()

    for observer in observers {
      observer.onWidgetBoundsChanged(widget: self,  newBounds: windowBoundsInScreen)
    }
  }

  public func onHostMoved(host windowTreeHost: WindowTreeHost, newOrigin: IntPoint) {
    delegate!.onWidgetMove()
    notifyCaretBoundsChanged(inputMethod: inputMethod)

    for observer in observers {
      observer.onWidgetBoundsChanged(widget: self, newBounds: windowBoundsInScreen)
    }
  }

  public func onHostCloseRequested(host windowTreeHost: WindowTreeHost) {
    close()
  }

  internal func layerTreeChanged() {
    // Calculate the layers requires traversing the tree, and since nearly any
    // mutation of the tree can trigger this call we delay until absolutely
    // necessary.
    viewsWithLayersDirty = true
  }

  func repostPlatformEvent(event: PlatformEvent) {
    var localEvent = Graphics.Event(event)
    onEvent(event: &localEvent)
  }

  func setInactiveRenderingDisabled(value: Bool) {
    if value == _disableInactiveRendering {
      return
    }

    _disableInactiveRendering = value
    if let view = nonClientView {
      view.setInactiveRenderingDisabled(disable: value)
    }
  }

  func saveWindowPlacement() {
    guard let d = delegate else {
      return
    }

    var showState = WindowShowState.Normal
    var bounds = IntRect()

    getWindowPlacement(bounds: &bounds, showState: &showState)
    d.saveWindowPlacement(bounds: bounds, showState: showState)
  }

  func setInitialBounds(bounds initialBounds: IntRect) {

    guard nonClientView != nil else {
      return
    }

    var savedBounds = IntRect()

    if getSavedWindowPlacement(bounds: &savedBounds, showState: &self.savedShowState) {
      if savedShowState == .Maximized {
        // If we're going to maximize, wait until Show is invoked to set the
        // bounds. That way we avoid a noticeable resize.
        initialRestoredBounds = savedBounds
      } else if !savedBounds.isEmpty {
      // If the saved bounds are valid, use them.
        bounds = savedBounds
      }
    } else {
      if initialBounds.isEmpty {
        // No initial bounds supplied, so size the window to its content and
        // center over its parent.
        centerWindow(size: nonClientView!.preferredSize)
      } else {
        // Use the supplied initial bounds.
        setBoundsConstrained(bounds: initialBounds)
      }
    }
  }

  func setInitialBoundsForFramelessWindow(bounds: IntRect) {
    if bounds.isEmpty {
      if let view = contentsView {
        // No initial bounds supplied, so size the window to its content and
        // center over its parent if preferred size is provided.
        let size = view.preferredSize
        if !size.isEmpty {
          centerWindow(size: size)
        }
      }
    } else {
      // Use the supplied initial bounds.
      setBoundsConstrained(bounds: bounds)
    }
  }

  func getWindowPlacement(bounds: inout IntRect,
                          showState: inout WindowShowState) {
    host.getWindowPlacement(bounds: &bounds, showState: &showState)
  }

  func getSavedWindowPlacement(bounds: inout IntRect,
                               showState: inout WindowShowState) -> Bool {
    if delegate!.getSavedWindowPlacement(widget: self, bounds: &bounds, showState: &showState) {
      if !delegate!.shouldRestoreWindowSize {
        bounds.size = nonClientView!.preferredSize
      } else {
        let size = minimumSize
        // Make sure the bounds are at least the minimum size.
        if bounds.width < size.width {
          bounds.width = size.width
        }

        if bounds.height < size.height {
          bounds.height = size.height
        }
      }
      return true
    }
    return false
  }

  // called by DesktopWindowTreeHost
  // func onHostClosed() {

  //   if windowModalityController != nil {
  //     windowModalityController = nil
  //   }

  //   if let capture = captureClient?.captureWindow {
  //     if host.tree.window.contains(other: capture) {
  //       capture.releaseCapture()
  //     }
  //   }

  //   shadowController = nil
  //   tooltipManager = nil
  //   if tooltipController != nil {
  //     host.tree.window.removePreTargetHandler(handler: tooltipController!)
  //     UI.setTooltipClient(window: host.tree.window, client: nil)
  //     tooltipController = nil
  //   }

  //   windowTreeClient = nil // Uses host_->dispatcher() at destruction.

  //   captureClient = nil  // Uses host_->dispatcher() at destruction.

  //   host.tree.window.removePreTargetHandler(handler: focusClient!)
  //   UI.setFocusClient(window: host.tree.window, client: nil)
  //   UI.setActivationClient(window: host.tree.window, client: nil)
  //   focusClient = nil

  //   host.tree.removeObserver(observer: self)

  //   for observer in observers {
  //     observer.onWidgetDestroyed(widget: self)
  //   }
  //   delegate!.deleteDelegate()
  //   delegate = nil
  // }

  // called by DesktopWindowTreeHost
  // func onWindowTreeHostDestroyed(host: WindowTreeHost) {
  //   UI.setDispatcherClient(window: host.window, client: nil)
  //   dispatcherClient = nil

  //   platformCursorManager!.removeHost(host: host)

  //   UI.setScreenPositionClient(window: host.window, client: nil)
  //   positionClient = nil

  //   UI.setDragDropClient(window: host.window, client: nil)
  //   dragDropClient = nil

  //   UI.setEventClient(window: host.window, client: nil)
  //   eventClient = nil
  // }

  func onRootWindowDestroyed() {
    cursorReferenceCount = cursorReferenceCount - 1
    if cursorReferenceCount == 0 {
      platformCursorManager = nil
      cursorManager = nil
    }
  }

  func updateWindowTransparency() {
      contentWindow!.transparent =  host.shouldWindowContentsBeTransparent
      contentWindow!.fillsBoundsCompletely = true
  }

}

fileprivate func buildViewsWithLayers(_ view: View, _ views: inout Views) {
  if view.layer != nil {
    views.append(view)
  } else {
    for i in 0..<view.childCount {
      buildViewsWithLayers(view.childAt(index: i)!, &views)
    }
  }
}

fileprivate func createNativeWidget(params: UIWidget.InitParams,
                                    delegate: NativeWidgetDelegate) -> NativeWidget {
  if params.nativeWidget != nil {
    return params.nativeWidget!
  }
  return NativeWidget.createNativeWidget(delegate: delegate)
}
