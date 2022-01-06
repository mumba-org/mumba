// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Platform
import X11

public class WindowTreeHostPlatform : WindowTreeHost,
                                      PlatformWindowDelegate {

  public override var eventSource: EventSource? {
    return self
  }

  public override var acceleratedWidget: AcceleratedWidget? {
    return widget
  }

  public override var boundsInPixels: IntRect {
    return platformWindow != nil ? platformWindow!.bounds : IntRect()
  }

  internal override var locationOnScreenInPixels: IntPoint {
    return platformWindow!.bounds.origin
  }

  public var platformWindow: PlatformWindow?
  private var widget: AcceleratedWidget
  private var currentCursor: PlatformCursor
  private var bounds: IntRect = IntRect() 
  private var pendingLocalSurfaceId: LocalSurfaceId = LocalSurfaceId()
  private var pendingSize: IntSize = IntSize()

  public convenience init(compositor: UIWebWindowCompositor, bounds: IntRect) {
    self.init()
    self.bounds = bounds
    try! createCompositor(compositor: compositor)
    createAndSetDefaultPlatformWindow()
  }

  internal override init() {
    widget = NullAcceleratedWidget
    currentCursor = PlatformCursorNil
    super.init()
  }

  deinit {
    destroyCompositor()
    destroyDispatcher()
    platformWindow!.close()
  }

  public override func setBoundsInPixels(bounds: IntRect, localSurfaceId: LocalSurfaceId = LocalSurfaceId()) {
    pendingSize = bounds.size
    self.pendingLocalSurfaceId = localSurfaceId
    platformWindow!.bounds = bounds
  }

  public override func setCapture() {
    platformWindow!.setCapture()
  }
  
  public override func releaseCapture() {
    platformWindow!.releaseCapture()
  }

  internal override func showImpl() {
    platformWindow!.show()
  }

  internal override func hideImpl() {
    platformWindow!.hide()
  }

  internal override func setCursorNative(cursor: PlatformCursor) {
    guard cursor != currentCursor else {
      return
    }

    currentCursor = cursor

    #if os(Windows)
    let cursorLoader = CursorLoaderWin()
    cursorLoader.platformCursor = cursor
    #endif

    //platformWindow!.cursor = cursor.platform
    platformWindow!.cursor = cursor
  }

  internal override func moveCursorToScreenLocationInPixels(location locationInPixels: IntPoint) {
    platformWindow!.moveCursorTo(location: locationInPixels)
  }

  internal override func onCursorVisibilityChangedNative(show: Bool) {
    assert(false)
  }

  internal func createAndSetDefaultPlatformWindow() {
  #if os(Windows)
    platformWindow = WinWindow(self, bounds)
  #elseif os(Android)
    platformWindow = PlatformWindowAndroid(self)
  #elseif os(Linux)
    let display = X11Environment.XDisplay
    platformWindow = try! X11Window(self, bounds: bounds, display: display)
  #else
    assert(false)
  #endif
  }
  
  // PlatformWindowDelegate
  public func onBoundsChanged(newBounds: IntRect) {
    let currentScale = compositor!.deviceScaleFactor
    let newScale = UI.getScaleFactorForWindow(window: window)
    let oldBounds = self.bounds
    self.bounds = newBounds
    if self.bounds.origin != oldBounds.origin {
      onHostMovedInPixels(newLocation: self.bounds.origin)
    }
    if pendingLocalSurfaceId.isValid || bounds.size != oldBounds.size || currentScale != newScale {
      let localSurfaceId = bounds.size == pendingSize
                                  ? pendingLocalSurfaceId
                                  : LocalSurfaceId()
      pendingLocalSurfaceId = LocalSurfaceId()
      pendingSize = IntSize()
      onHostResizedInPixels(bounds.size, localSurfaceId: localSurfaceId)
    }
  }
  
  public func onDamageRect(damagedRegion: IntRect) {
    compositor!.scheduleRedrawRect(damaged: damagedRegion)
  }
  
  public func dispatchEvent(event: Graphics.Event) {
    let details: EventDispatchDetails = sendEventToSink(event: event)
    if details.dispatcherDestroyed {
      event.handled = true
    }
  }
  
  public func onCloseRequest() {
  #if os(Windows)
    // TODO: this obviously shouldn't be here.
    RunLoop.quitCurrentWhenIdleDeprecated()
  #else
    onHostCloseRequested()
  #endif
  }
  
  public func onClosed() {}
  
  public func onWindowStateChanged(newState: PlatformWindowState) {}
  
  public func onLostCapture() {
    onHostLostWindowCapture()
  }
  
  public func onAcceleratedWidgetAvailable(newWidget widget: AcceleratedWidget,
                                           devicePixelRatio: Float) {
    self.widget = widget
    // This may be called before the Compositor has been created.
    if compositor != nil {
      super.onAcceleratedWidgetAvailable()
    }
  }
  
  public func onAcceleratedWidgetDestroyed() {
    let _ = compositor!.releaseAcceleratedWidget()
    self.widget = Graphics.NullAcceleratedWidget
  }
  
  public func onActivationChanged(active: Bool) {
    if active {
      onHostActivated()
    }
  }
  
  internal override func releaseSystemKeyEventCapture() {}
  
  internal override func isKeyLocked(nativeKeyCode: Int) -> Bool {
    assert(false)
    return false
  }

  internal override func captureSystemKeyEventsImpl(nativeKeyCodes: [Int]?) -> Bool {
    assert(false)
    return false
  }

  public func schedulePaint() {
    
  }

  public func onHostEnterWindow() {
    
  }
  
  public func onHostMoved(newLocation: IntPoint) {
    
  }
  
  public func onHostResized(newSize: IntSize) {
    
  }

  public func translateAndDispatchLocatedEvent(event: Graphics.LocatedEvent) {

  }

}
