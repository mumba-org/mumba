// Copyright (c) 2016-2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Platform
import Compositor

public typealias Widgets = [UIWidget]

public class UIWidget : EventSource,
                        FocusTraversable,
                        NativeWidgetDelegate {//,
                      //ThemeObserver {

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

  public enum VisibilityTransition : Int {
    case AnimateShow = 0x1
    case AnimateHide = 0x2
    case AnimateBoth = 0x3
    case AnimateNone = 0x4
  }

  public struct InitParams {
    public var activatable: Activatable
    public var type: WindowType
    public var ownership: Ownership
    public var delegate: UIWidgetDelegate?
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
    public var desktopWindowTreeHost: DesktopWindowTreeHost?
    public var nativeWidget: NativeWidget?
    public var name: String
    public var child: Bool

    public var canActivate: Bool {
      if activatable != .Default {
        return activatable == .Yes
      }
      
      return type != .Control && type != .Popup &&
         type != .Menu && type != .Tooltip &&
         type != .Drag
    }

    public init() {
      activatable = .Default
      type = .Unknown
      ownership = .NativeWidgetOwnsWidget
      bounds = IntRect()
      state = .Default
      layerType = .PictureLayer//.Textured
      opacity = .InferOpacity
      onTop = false
      removeStandardFrame = false
      forceShowInTaskbar = false
      visibleOnAllWorkspaces = false
      wmClassName = String()
      wmClassClass = String()
      wmRoleName = String()
      name = String()
      acceptEvents = true
      shadowType = .Default
      child = false
    }
  }

  public class func make(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized

    try widget.initialize(compositor: compositor, params: params)

    return widget
  }

  public class func make(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .PictureLayer//.Textured

    try widget.initialize(compositor: compositor, params: params)

    return widget
  }

  public class func makeWithParent(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor, parent: Window) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized
    params.layerType = .PictureLayer//.Textured
    params.parent = parent

    try widget.initialize(compositor: compositor, params: params)

    return widget
  }

  public class func makeWithParent(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor, parent: Window, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .PictureLayer//.Textured
    params.parent = parent

    try widget.initialize(compositor: compositor, params: params)

    return widget
  }

  public class func makeWithContext(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor, context: Window) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.state = .Maximized
    params.layerType = .PictureLayer//.Textured
    params.context = context

    try widget.initialize(compositor: compositor, params: params)

    return widget
  }

  public class func makeWithContext(delegate: UIWidgetDelegate, compositor: UIWebWindowCompositor, context: Window, bounds: IntRect) throws -> UIWidget {
    let widget = UIWidget()
    var params = InitParams()

    params.type = .Normal
    params.delegate = delegate
    params.bounds = bounds
    params.state = .Maximized
    params.layerType = .PictureLayer//.Textured
    params.context = context

    try widget.initialize(compositor: compositor, params: params)

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

  public static func reparentWindow(window: Window, newParent: Window?) throws {

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

  public var window: Window {
    return nativeWidget!.window
  }

  public var topLevelWidget: UIWidget? {
    return isTopLevel ? self : nativeWidget!.topLevelWidget
  }

  public var contentsView: View? {
    get {
      return rootView!.contentsView
    }
    set (view) {
      guard view !== contentsView else {
        return
      }
      rootView!.contentsView = view
      if nonClientView !== view {
        nonClientView = nil
      }
    }
  }

  public var windowBoundsInScreen: IntRect {
    return nativeWidget!.windowBoundsInScreen
  }

  public var clientAreaBoundsInScreen: IntRect {
    return nativeWidget!.clientAreaBoundsInScreen
  }

  public var restoredBounds: IntRect {
    return nativeWidget!.restoredBounds
  }

  public var workspace: String {
    return nativeWidget!.workspace 
  }

  public var bounds: IntRect { 
    get {
      return nativeWidget!.bounds
    } 
    set {
      nativeWidget!.bounds = newValue
    }
  }

  public var size: IntSize { 
    get {
      return nativeWidget!.size
    } 
    set {
      nativeWidget!.size = newValue
    } 
  }
  
  public var isClosed: Bool {
    return widgetClosed
  }

  public var isActive: Bool {
    return nativeWidget!.isActive
  }

  public var isMinimized: Bool {
    return nativeWidget!.isMinimized
  }

  public var isMaximized: Bool {
    return nativeWidget!.isMaximized
  }

  public var isAlwaysOnTop: Bool {
    get {
      return nativeWidget!.isAlwaysOnTop
    }
    set {
      nativeWidget!.isAlwaysOnTop = newValue
    }
  }

  public var isVisibleOnAllWorkspaces: Bool {
    get {
      return nativeWidget!.isVisibleOnAllWorkspaces
    }
    set {
      nativeWidget!.isVisibleOnAllWorkspaces = newValue
    }
  }

  public var isVisible: Bool {
    return nativeWidget!.isVisible
  }

  public var focusManager: FocusManager? {
    return topLevelWidget?._focusManager ?? nil
  }

  public var inputMethod: InputMethod? {
    if isTopLevel {
      return nativeWidget!.inputMethod
    } else {
      if let topLevel = topLevelWidget, topLevel !== self {
        return topLevel.inputMethod
      }
      return nil
    }
  }

  public var isMouseEventsEnabled: Bool {
    return nativeWidget!.isMouseEventsEnabled
  }

  public var isTranslucentWindowOpacitySupported: Bool {
    return nativeWidget!.isTranslucentWindowOpacitySupported
  }

  public var focusTraversable: FocusTraversable? {
    return rootView
  }

  public var shouldUseNativeFrame: Bool {
    if frameType != FrameType.Default {
      return frameType == FrameType.ForceNative
    }
    return nativeWidget!.shouldUseNativeFrame
  }

  public var shouldWindowContentsBeTransparent: Bool {
    return nativeWidget!.shouldWindowContentsBeTransparent
  }

  public var layer: Layer? {
    return nativeWidget!.layer
  }

  public var compositor: UICompositor? {
    return nativeWidget!.compositor
  }

  public var hasCapture: Bool {
    return nativeWidget!.hasCapture
  }

  public var tooltipManager: TooltipManager? { 
    return nativeWidget!.tooltipManager
  }

  public var workAreaBoundsInScreen: IntRect {
    return nativeWidget!.workAreaBoundsInScreen
  }

  public var name: String {
    return nativeWidget!.name
  }

  public var isModal: Bool {
    return widgetDelegate!.modalType != .None
  }
  
  public var isDialogBox: Bool {
    if widgetDelegate!.asDialogDelegate() != nil {
      return true
    }
    return false
  }
  
  public var canActivate: Bool {
    return widgetDelegate!.canActivate
  }
  
  public var isAlwaysRenderAsActive: Bool { 
    get {
      return alwaysRenderAsActive
    } 
    set {
      alwaysRenderAsActive = newValue
      if nonClientView != nil && !isActive {
        nonClientView!.frameView!.schedulePaint()
      }
    } 
  }
  
  public var minimumSize: IntSize {
    return nonClientView?.minimumSize ?? IntSize()
  }
  
  public var maximumSize: IntSize {
    return nonClientView?.maximumSize ?? IntSize()
  }
  
  public var hasFocusManager: Bool {
    return focusManager != nil
  } 
  
  public var hasHitTestMask: Bool {
    return widgetDelegate!.widgetHasHitTestMask
  }
  
  public var hitTestMask: Path? {
    return widgetDelegate!.widgetHitTestMask
  }

  public var isFullscreen: Bool {
    get {
      return nativeWidget!.isFullscreen
    }
    set {
      guard newValue != isFullscreen else {
        return
      }
      nativeWidget!.isFullscreen = newValue
      if let ncView = nonClientView {
        ncView.layout()
      }
    }
  }

  open override var eventSink: EventSink? {
    return rootView as? EventSink
  }

  public var viewsWithLayers: Views {
    if viewsWithLayersDirty {
      viewsWithLayersDirty = false
      _viewsWithLayers.removeAll()
      buildViewsWithLayers(rootView!, &_viewsWithLayers)
    }
    return _viewsWithLayers
  }

  public var focusSearch: FocusSearch? {
    return rootView?.focusSearch
  }

  public var focusTraversableParent: FocusTraversable? { 
    get {
      return nil
    } 
    set {

    } 
  }
  
  public var focusTraversableParentView: View? { 
    get {
      return nil
    } 
    set {

    } 
  }

  public var clientView: ClientView? {
    return nonClientView?.clientView ?? nil
  }

  public private(set) var rootView: RootView?
  // TODO: see if we have a non-weak delegate scenario
  public weak var widgetDelegate: UIWidgetDelegate?
  internal var nonClientView: NonClientView?
  private var observers: Array<UIWidgetObserver> = Array<UIWidgetObserver>()
  private var removalObservers: Array<UIWidgetRemovalsObserver> = Array<UIWidgetRemovalsObserver>()
  private var _focusManager: FocusManager?
  //private let defaultThemeProvider: DefaultThemeProvider
  private (set) public var draggedView: View?
  private var ownership: Ownership
  private var isSecondaryWidget: Bool
  internal var frameType: FrameType
  private var alwaysRenderAsActive: Bool
  private var widgetClosed: Bool
  private var windowShowState: WindowShowState = .Default
  private var initialRestoredBounds: IntRect = IntRect()
  private var focusOnCreation: Bool
  private var isTopLevel: Bool
  private var nativeWidgetInitialized: Bool
  private var nativeWidgetDestroyed: Bool
  private var isMouseButtonPressed: Bool
  private var ignoreCaptureLoss: Bool
  private var lastMouseEventWasMove: Bool
  private var lastMouseEventPosition: IntPoint = IntPoint()
  internal var autoReleaseCapture: Bool
  private var _viewsWithLayers: Views = Views()
  private var viewsWithLayersDirty: Bool
  private var movementDisabled: Bool
  private var savedShowState: WindowShowState = WindowShowState.Default
  // if nativeWidget owns us, we need to use this weak reference instead to avoid cycles
  private weak var _nativeWidget: NativeWidget?
  // if we own the nativeWidget
  private var _ownedNativeWidget: NativeWidget?

  public override init() {
    isSecondaryWidget = false
    isMouseButtonPressed = false
    focusOnCreation = false
    nativeWidgetInitialized = false
    nativeWidgetDestroyed = false
    alwaysRenderAsActive = false
    ignoreCaptureLoss = false
    lastMouseEventWasMove = false
    widgetClosed = false
    autoReleaseCapture = true
    isTopLevel = false
    frameType = .Default
    movementDisabled = false
    viewsWithLayersDirty = false
    ownership = .NativeWidgetOwnsWidget
    super.init()
  }

  deinit {
    destroyRootView()
    nativeWidget = nil
  }

  //public func initialize(params inParams: InitParams) throws {
  public func initialize(compositor: UIWebWindowCompositor, params inParams: InitParams) throws {
    var params = inParams
    if let contents = params.delegate?.contentsView, params.name.isEmpty {
      params.name = contents.className
    }
    params.child = params.child || params.type == .Control
    self.isTopLevel = !params.child

    if params.opacity == .InferOpacity &&
       params.type != .Normal &&
       params.type != .Panel {
      params.opacity = .Opaque
    }

    //if let viewsDelegate = ViewsDelegate.instance {
      //viewsDelegate.onBeforeWidgetInit(params: &params, widget: self)
    //}
    ViewsDelegate.instance.onBeforeWidgetInit(params: &params, widget: self)

    if params.opacity == .InferOpacity {
      params.opacity = .Opaque
    }

    let canActivate = params.canActivate
    params.activatable = canActivate ? Activatable.Yes : Activatable.No

    self.widgetDelegate = params.delegate ?? DefaultWidgetDelegate(self)
    self.widgetDelegate!.canActivate = canActivate
    self.ownership = params.nativeWidget != nil ? .NativeWidgetOwnsWidget : .WidgetOwnsNativeWidget
    nativeWidget = createNativeWidget(params: params, delegate: self)
    guard nativeWidget != nil else {
      throw UIError.OnInit(exception: UIException(code: 1000, message: "UI: error creating NativeWidget"))
    }
    rootView = createRootView()
    //defaultThemeProvider = DefaultThemeProvider()

    if params.type == .Menu {
      self.isMouseButtonPressed = DesktopNativeWidget.isMouseButtonDown
    }

    //nativeWidget!.initNativeWidget(params: params)
    nativeWidget!.initNativeWidget(compositor: compositor, params: params)

    if inParams.type == .Normal || inParams.type == .Panel || inParams.type == .Bubble {
      nonClientView = NonClientView()
      nonClientView!.frameView = createNonClientFrameView()
    
      nonClientView!.clientView = self.widgetDelegate!.createClientView(widget: self)
      nonClientView!.overlayView = self.widgetDelegate!.createOverlayView()
    
      rootView!.contentsView = nonClientView!

      updateWindowIcon()
      updateWindowTitle()
      nonClientView!.resetWindowControls()
      setInitialBounds(bounds: params.bounds)

      rootView!.layout()

      if inParams.state == .Maximized {
        maximize()
      } else if inParams.state == .Minimized {
        minimize()
        savedShowState = .Minimized
      }
    } else if let d = params.delegate {
       contentsView = d.contentsView
       setInitialBoundsForFramelessWindow(bounds: params.bounds)
    }

    // This must come after SetContentsView() or it might not be able to find
    // the correct NativeTheme (on Linux). See http://crbug.com/384492
    //observerManager.add(theme)
    nativeWidgetInitialized = true
    nativeWidget!.onWidgetInitDone()
  }

  public func addObserver(_ observer: UIWidgetObserver) {
    observers.append(observer)
  }

  public func removeObserver(_ observer: UIWidgetObserver) {
    if let index = observers.firstIndex(where: { $0 === observer }) {
      observers.remove(at: index)
    }
  }

  public func hasObserver(_ observer: UIWidgetObserver) -> Bool {
    if observers.firstIndex(where: { $0 === observer }) != nil {
      return true
    }
    return false
  }

  public func addRemovalsObserver(_ observer: UIWidgetRemovalsObserver) {
    removalObservers.append(observer)
  }

  public func removeRemovalsObserver(_ observer: UIWidgetRemovalsObserver) {
    if let index = removalObservers.firstIndex(where: { $0 === observer }) {
      removalObservers.remove(at: index)
    }
  }

  public func hasRemovalsObserver(_ observer: UIWidgetRemovalsObserver) -> Bool {
    if removalObservers.firstIndex(where: { $0 === observer }) != nil {
      return true
    }
    return false
  }

  public func getAccelerator(commandId: Int) -> Accelerator? {
    return nil
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
      nativeWidget!.viewRemoved(view: details.child!)
    }
  }

  public func notifyNativeViewHierarchyWillChange() {
    if let manager = focusManager {
      manager.viewRemoved(removed: rootView!)
    }
  }

  public func notifyNativeViewHierarchyChanged() {
    rootView!.notifyNativeViewHierarchyChanged()
  }

  public func notifyWillRemoveView(view: View) {
    for observer in removalObservers {
      observer.onWillRemoveView(widget: self, view: view)
    }
  }

  public func centerWindow(size: IntSize) {
    nativeWidget!.centerWindow(size: size)
  }

  public func setBoundsConstrained(bounds: IntRect) {
    nativeWidget!.setBoundsConstrained(bounds: bounds)
  }

  public func setVisibilityChangedAnimationsEnabled(value: Bool) {
    nativeWidget!.setVisibilityChangedAnimationsEnabled(value: value)
  }

  public func setVisibilityAnimationDuration(duration: TimeDelta) {
    nativeWidget!.setVisibilityAnimationDuration(duration: duration)
  }

  public func runMoveLoop(dragOffset: IntVec2,
                          source: MoveLoopSource,
                          escapeBehavior: MoveLoopEscapeBehavior) -> MoveLoopResult {
    return nativeWidget!.runMoveLoop(dragOffset: dragOffset, source: source, escapeBehavior: escapeBehavior)
  }

  public func endMoveLoop() {
    nativeWidget!.endMoveLoop()
  }

  public func stackAboveWidget(widget: UIWidget) {
    nativeWidget!.stackAbove(window: widget.window)
  }

  public func stackAbove(window: Window) {
    nativeWidget!.stackAbove(window: window)
  }

  public func stackAtTop() {
    nativeWidget!.stackAtTop()
  }

  public func setShape(shape: UIWidget.ShapeRects) {
    nativeWidget!.setShape(shape: shape)
  }

  public func close() {
    guard !widgetClosed else {
      return
    }

    if let ncView = nonClientView {
      if !ncView.canClose {
        return
      }
    }

    widgetClosed = true
    saveWindowPlacement()

    if isTopLevel && focusManager != nil {
      focusManager!.focusedView = nil
    }

    for observer in observers {
      observer.onWidgetClosing(widget: self)
    }
    
    nativeWidget!.close()
  }

  public func closeNow() {
    for observer in observers {
      observer.onWidgetClosing(widget: self)
    }
    nativeWidget!.closeNow()
  }

  public func show() {
    //let l = layer
    if nonClientView != nil {
      // While initializing, the kiosk mode will go to full screen before the
      // widget gets shown. In that case we stay in full screen mode, regardless
      // of the |saved_show_state_| member.
      if savedShowState == WindowShowState.Maximized &&
          !initialRestoredBounds.isEmpty &&
          !isFullscreen {
        nativeWidget!.showMaximizedWithBounds(restoredBounds: initialRestoredBounds)
      } else {
        nativeWidget!.showWithWindowState(
            showState: isFullscreen ? WindowShowState.Fullscreen : savedShowState)
      }
      // |saved_show_state_| only applies the first time the window is shown.
      // If we don't reset the value the window may be shown maximized every time
      // it is subsequently shown after being hidden.
      savedShowState = WindowShowState.Normal
    } else {
      canActivate
          ? nativeWidget!.show()
          : nativeWidget!.showWithWindowState(showState: WindowShowState.Inactive)
    }
  }

  public func hide() {
    nativeWidget!.hide()
  }

  public func showInactive() {
    if savedShowState == .Maximized &&
      !initialRestoredBounds.isEmpty {
     bounds = initialRestoredBounds
     savedShowState = .Normal
    }
    nativeWidget!.showWithWindowState(showState: .Inactive)
  }

  public func activate() {
    nativeWidget!.activate()
  }

  public func deactivate() {
    nativeWidget!.deactivate()
  }

  public func maximize() {
    nativeWidget!.maximize()
  }

  public func minimize() {
    nativeWidget!.minimize()
  }

  public func restore() {
    nativeWidget!.restore()
  }

  public func setOpacity(opacity: Float) {
    nativeWidget!.setOpacity(opacity: opacity)
  }

  public func flashFrame(flash: Bool) {
    nativeWidget!.flashFrame(flash: flash)
  }

  public func runShellDrag(view: View?,
                           data: OSExchangeData,
                           location: IntPoint,
                           operation: DragOperation,
                           source: DragEventSource) {
      draggedView = view
      onDragWillStart()

      let widgetDeletionObserver = UIWidgetDeletionObserver(widget: self) 
      
      nativeWidget!.runShellDrag(
          view: view!,//window,
          data: data,
          location: location,
          operation: operation.rawValue,
          source: source)
     
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
    nativeWidget!.schedulePaintInRect(rect: rect)
  } 

  public func setCursor(cursor: PlatformCursor) {
    nativeWidget!.setCursor(cursor: cursor)
  }

  public func updateWindowTitle() {
  guard let ncView = nonClientView else {
    return
  }
  let windowTitle = widgetDelegate!.windowTitle
  // todo: fix this and make it work
  // i18n.adjustStringForLocaleDirection(&windowTitle)
  if !nativeWidget!.setWindowTitle(title: windowTitle) {
    return
  }
  ncView.updateWindowTitle()
  ncView.layout()
  }

  public func updateWindowIcon() {
    if let v = nonClientView {
    v.updateWindowIcon()
    }
    nativeWidget!.setWindowIcons(windowIcon: widgetDelegate!.windowIcon,
                                appIcon: widgetDelegate!.windowAppIcon)
  }
  
  public func deviceScaleFactorChanged(deviceScaleFactor: Float) {
    rootView!.deviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
  }

  public func setFocusTraversableParent(parent: FocusTraversable) {
    rootView!.focusTraversableParent = parent
  }

  public func clearNativeFocus() {
    nativeWidget!.clearNativeFocus()
  }

  public func createNonClientFrameView() -> NonClientFrameView? {
    var view: NonClientFrameView? = nil
    view = widgetDelegate!.createNonClientFrameView(widget: self)
    if view == nil {
      view = nativeWidget!.createNonClientFrameView()
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
    nativeWidget!.frameTypeChanged()
  }

  public func layerTreeChanged() {
    viewsWithLayersDirty = true
  }

  public func setCapture(view: View) {
    if !nativeWidget!.hasCapture {
      nativeWidget!.setCapture()

      // Early return if setting capture was unsuccessful.
      if !nativeWidget!.hasCapture {
        return
      }
    }

    if DesktopNativeWidget.isMouseButtonDown {
      isMouseButtonPressed = true
    }

    rootView!.setMouseHandler(handler: view)
  }

  public func releaseCapture() {
    if nativeWidget!.hasCapture {
      nativeWidget!.releaseCapture()
    }
  }

    public func synthesizeMouseMoveEvent() {
      var mouseLocation = EventMonitor.lastMouseLocation
      if !windowBoundsInScreen.contains(point: mouseLocation) {
        return
      }

      // Convert: screen coordinate -> widget coordinate.
      View.convertPointFromScreen(dst: rootView!, point: &mouseLocation)
      lastMouseEventWasMove = false

      let mouseEvent = MouseEvent(type: .MouseMoved,
                                  location: mouseLocation,
                                  rootLocation: mouseLocation,
                                  timestamp: TimeTicks.now.microseconds,
                                  flags: EventFlags.IsSynthesized,
                                  changedButtonFlags: 0)

      rootView!.onMouseMoved(event: mouseEvent)
    }

    public func onSizeConstraintsChanged() {
      nativeWidget!.onSizeConstraintsChanged()
      nonClientView!.sizeConstraintsChanged()
    }

    public func asWidget() -> UIWidget {
      return self
    }

    public func onNativeWidgetActivationChanged(active: Bool) -> Bool {
       if !active && nativeWidgetInitialized {
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

    public func onNativeFocus() {
      WidgetFocusManager.instance.onNativeFocusChanged(focusedNow: window)
    }

    public func onNativeBlur() {
      WidgetFocusManager.instance.onNativeFocusChanged(focusedNow: nil)
    }

    public func onNativeWidgetVisibilityChanging(visible: Bool) {
      for observer in observers {
        observer.onWidgetVisibilityChanging(widget: self, visible: visible)
      }
    }

    public func onNativeWidgetVisibilityChanged(visible: Bool) {
      if rootView != nil {
        rootView!.propagateVisibilityNotifications(from: rootView!, isVisible: visible)
      }
      for observer in observers {
        observer.onWidgetVisibilityChanged(widget: self, visible: visible)
      }
      if compositor != nil && rootView != nil && rootView!.layer != nil {
        rootView!.layer!.isVisible = visible
      }
    }

    public func onNativeWidgetCreated(visible: Bool) {
      if isTopLevel {
        _focusManager = FocusManager(widget: self, delegate: nil)//visible)
      }
      
      nativeWidget!.initModalType(modalType: widgetDelegate!.modalType)

      for observer in observers {
        observer.onWidgetCreated(widget: self)
      }
    }

    public func onNativeWidgetDestroying() {
      if let manager = focusManager, let root = rootView {
        manager.viewRemoved(removed: root)
      }

      for observer in observers {
        observer.onWidgetDestroying(widget: self)
      }

      if let ncView = nonClientView {
        ncView.windowClosing()
      }
      widgetDelegate!.windowClosing()
    }

    public func onNativeWidgetDestroyed() {
      for observer in observers {
        observer.onWidgetDestroyed(widget: self)
      }
      widgetDelegate!.deleteDelegate()
      widgetDelegate = nil
      nativeWidgetDestroyed = true
    }

    public func onNativeWidgetMove() {
      widgetDelegate!.onWidgetMove()
      notifyCaretBoundsChanged(inputMethod: inputMethod)

      for observer in observers {
        observer.onWidgetBoundsChanged(widget: self, newBounds: windowBoundsInScreen)
      }
    }

    public func onNativeWidgetSizeChanged(newSize: IntSize) {
      if let root = rootView {
        root.size = newSize
      }

      notifyCaretBoundsChanged(inputMethod: inputMethod)
      saveWindowPlacementIfInitialized()

      for observer in observers {
        observer.onWidgetBoundsChanged(widget: self, newBounds: windowBoundsInScreen)
      }
    }

    public func onNativeWidgetWorkspaceChanged() {}

    public func onNativeWidgetWindowShowStateChanged() {
      saveWindowPlacementIfInitialized()
    }

    public func onNativeWidgetBeginUserBoundsChange() {
      widgetDelegate!.onWindowBeginUserBoundsChange()
    }

    public func onNativeWidgetEndUserBoundsChange() {
      widgetDelegate!.onWindowEndUserBoundsChange()
    }

    public func onNativeWidgetPaint(context: PaintContext) {
      guard nativeWidgetInitialized else {
        return
      }
      rootView!.paintFromPaintRoot(context: context)
    }

    public func getNonClientComponent(point: IntPoint) -> Int {
      var component = HitTest.HTNOWHERE

      if let nview = nonClientView {
        component = nview.nonClientHitTest(point: point)
      }

      if movementDisabled && (component == HitTest.HTCAPTION || component == HitTest.HTSYSMENU) {
        return HitTest.HTNOWHERE.rawValue
      }

      return component.rawValue
    }

    public func onKeyEvent(event: inout KeyEvent) {
      sendEventToSink(event: event)
      if !event.handled && focusManager != nil &&
        !focusManager!.onKeyEvent(event: event) {
        event.stopPropagation()
      }
    }

    public func onMouseEvent(event: inout MouseEvent) {
      switch event.type {
        case .MousePressed:
          lastMouseEventWasMove = false
          let windowDeletionObserver = UIWidgetDeletionObserver(widget: self)

          if rootView != nil && rootView!.onMousePressed(event: event) && 
            windowDeletionObserver.widgetAlive && isVisible && DesktopNativeWidget.isMouseButtonDown {
              isMouseButtonPressed = true
              if !nativeWidget!.hasCapture {
                nativeWidget!.setCapture()
              }
            event.handled = false
          }
          
          return
        case .MouseReleased:
            lastMouseEventWasMove = false
            isMouseButtonPressed = false
            // Release capture first, to avoid confusion if OnMouseReleased blocks.
            if autoReleaseCapture && nativeWidget!.hasCapture {
              //base::AutoReset<bool> resetter(&ignore_capture_loss_, true);
              let lastIgnoreCaptureLoss = ignoreCaptureLoss
              ignoreCaptureLoss = true
              defer {
                ignoreCaptureLoss = lastIgnoreCaptureLoss
              }

              nativeWidget!.releaseCapture()
            }
            
            if let root = rootView {
              root.onMouseReleased(event: event)
            }
          
            if event.flags.rawValue & EventFlags.IsNonClient.rawValue == 0 {
              event.handled = false
            }
            return
        case .MouseMoved, .MouseDragged:
          if nativeWidget!.hasCapture && isMouseButtonPressed {
            lastMouseEventWasMove = false
            if let root = rootView {
              let _ = root.onMouseDragged(event: event)
            }
            } else if !lastMouseEventWasMove || lastMouseEventPosition != event.location {
              lastMouseEventPosition = event.location
              lastMouseEventWasMove = true
              if let root = rootView {
                root.onMouseMoved(event: event)
              }
            }
          return
        case .MouseExited:
          lastMouseEventWasMove = false
          if let root = rootView {
            root.onMouseExited(event: event)
          }
          return
        case .MouseWheel:
          if let root = rootView, root.onMouseWheel(event: event as! MouseWheelEvent) {
            event.handled = false
          }
          return
        default:
          return
      }
    }

    public func onMouseCaptureLost() {
      guard !ignoreCaptureLoss else {
        return
      }

      if let root = rootView {
        root.onMouseCaptureLost()
      }

      isMouseButtonPressed = false
    }

    public func onScrollEvent(event: inout ScrollEvent) {
      //var eventCopy = event
      sendEventToSink(event: event)//eventCopy)

      //if !eventCopy.handled && eventCopy.type == .Scroll {
      if !event.handled && event.type == .Scroll {
        //let wheel = event as MouseWheelEvent
        var mev = event as MouseEvent 
        onMouseEvent(event: &mev)
      }
    }

    public func reorderNativeViews() {
      nativeWidget!.reorderNativeViews();
    }

    public func onGestureEvent(event: inout GestureEvent) {
      sendEventToSink(event: event)
    }

    public func onDragWillStart() {}
    public func onDragComplete() {}
    public func onOwnerClosing() {}

    public func executeCommand(commandId: Int) -> Bool {
      return widgetDelegate!.executeWindowsCommand(commandId: commandId)
    }

    public func setInitialFocus(showState: WindowShowState) -> Bool {
      let focusedView = widgetDelegate!.initiallyFocusedView
      if !self.focusOnCreation || showState == .Inactive || showState == .Minimized {
        // If not focusing the window now, tell the focus manager which view to
        // focus when the window is restored.
        if let v = focusedView, let manager = focusManager {
          manager.storedFocusView = v
        }
        return true
      }
      if let v = focusedView {
        v.requestFocus()
        // If the UIWidget is active (thus allowing its child Views to receive focus),
        // but the request for focus was unsuccessful, fall back to using the first
        // focusable View instead.
        if let manager = focusManager, manager.focusedView == nil && isActive {
          manager.advanceFocus(reverse: false)
        }
      }
      return focusManager?.focusedView != nil
    }

    public func shouldDescendIntoChildForEventHandling(
        rootLayer: Layer,
        child: Window,
        childLayer: Layer,
        location: IntPoint) -> Bool {
      if let d = widgetDelegate {
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
          View.convertPointToTarget(source: rootView!, target: view, point: &pointInView)
          if visBounds.contains(point: pointInView) {
            return false
          }
        }
      }
      return true
    }

    private func createRootView() -> RootView {
      return RootView(widget: self)
    }

    private func destroyRootView() {
      if isTopLevel && focusManager != nil {
        focusManager!.focusedView = nil
      }
      notifyWillRemoveView(view: rootView!)
      nonClientView = nil
      rootView = nil
    }

    private func saveWindowPlacement() {
      guard let d = widgetDelegate else {
        return
      }

      var showState = WindowShowState.Normal
      var bounds = IntRect()

      nativeWidget!.getWindowPlacement(bounds: &bounds, showState: &showState)
      d.saveWindowPlacement(bounds: bounds, showState: showState)
    }

    private func saveWindowPlacementIfInitialized() {
      if nativeWidgetInitialized {
        saveWindowPlacement()
      }
    }

    private func setInitialBounds(bounds initialBounds: IntRect) {

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

    private func setInitialBoundsForFramelessWindow(bounds: IntRect) {
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
    
    private func getSavedWindowPlacement(bounds: inout IntRect,
                               showState: inout WindowShowState) -> Bool {
      if widgetDelegate!.getSavedWindowPlacement(widget: self, bounds: &bounds, showState: &showState) {
        if !widgetDelegate!.shouldRestoreWindowSize {
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

}

internal class WidgetFocusChangeListener {
  public init() {}

  public func onNativeFocusChanged(focusedNow: Window?) {

  }
}

internal class WidgetFocusManager {

  public static let instance: WidgetFocusManager = WidgetFocusManager()

  public init() {}

  public func addFocusChangeListener(listener: WidgetFocusChangeListener) {

  }
  
  public func removeFocusChangeListener(listener: WidgetFocusChangeListener) {

  }

  public func onNativeFocusChanged(focusedNow: Window?) {}

  public func enableNotifications() {}
  
  public func disableNotifications() {}

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
  return DesktopNativeWidget.createNativeWidget(delegate: delegate)
}

fileprivate func notifyCaretBoundsChanged(inputMethod: InputMethod?) {
  guard let ime = inputMethod else {
    return
  }
  if let client = ime.textInputClient {
    ime.onCaretBoundsChanged(client: client)
  }
}

fileprivate class DefaultWidgetDelegate : UIWidgetDelegate {
  
  public var widget: UIWidget? { return self._widget }
  public var shouldAdvanceFocusToTopLevelWidget: Bool { return true }
  weak var _widget: UIWidget?
  
  public init(_ widget: UIWidget) {
    self._widget = widget
  }
}
