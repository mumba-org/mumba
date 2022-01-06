// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum PlatformWindowState {
   case PlatformWindowStateUnknown
   case PlatformWindowStateMaximied
   case PlatformWindowStateMinimized
   case PlatformWindowStateNormal
   case PlatformWindowStateFullscreen
}

public protocol PlatformWindowDelegate {
  var deviceScaleFactor: Float { get }
  func onBoundsChanged(newBounds: IntRect)
  func onDamageRect(damagedRegion: IntRect)
  // we nee a UI.Event here.. so to avoid layer violation
  // its off for now

  //func dispatchEvent(event: PlatformEvent)
  func onCloseRequest()
  func onClosed()
  func onWindowStateChanged(newState: PlatformWindowState)
  func onLostCapture()
  func onAcceleratedWidgetAvailable(newWidget: AcceleratedWidget,
                                    devicePixelRatio: Float) throws
  func onAcceleratedWidgetDestroyed()
  func onActivationChanged(active: Bool)
  func onHostMoved(newLocation: IntPoint)
  func onHostResized(newSize: IntSize)
  func onHostLostWindowCapture()
  func onHostEnterWindow()
  func onHostCloseRequested()
  func sendEventToProcessor(event: Event) -> EventDispatchDetails
  func translateAndDispatchLocatedEvent(event: LocatedEvent)
  func schedulePaint()
}


public typealias PlatformImeController = Int

public protocol PlatformWindow : PlatformEventDispatcher {

    var bounds: IntRect { get set }
    var delegate: PlatformWindowDelegate { get }
    var nativeImeController: PlatformImeController { get }
    var acceleratedWidget: AcceleratedWidget { get }
    var cursor: PlatformCursor { get set }

    func show()
    func hide()
    func close()
    func setTitle(title: String)
    func setCapture()
    func releaseCapture()
    func toggleFullscreen()
    func maximize()
    func minimize()
    func restore()
    func setCursor(cursor: PlatformCursor)
    func moveCursorTo(location: IntPoint)
    func confineCursorToBounds(bounds: IntRect)
}
