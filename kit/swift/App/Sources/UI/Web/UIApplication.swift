// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import MumbaShims
import Compositor
import Graphics
import Web
import Channel
import Route

public protocol UIApplicationDelegate : class {
  var window: UIWindow? { get }
  func createWindow(application: UIApplication, dispatcher: UIDispatcher) -> UIWindow
  func initializeVisualProperties(params: VisualProperties)
  func onExternalTextureLayerRequested()
}

public class UIApplication {
  
  //public static var instance: UIApplication {
  //  return UIApplication._instance!
  //}

  public var applicationProcessHostId: Int32 {
    return _ApplicationInstanceGetApplicationProcessHostId(reference)
  }

  public var applicationWindowHostId: Int32 {
    return _ApplicationInstanceGetApplicationWindowHostId(reference)
  }

  public var routingId: Int32 {
    return _ApplicationInstanceGetRoutingId(reference) 
  }

  public var initialUrl: String {
    if _initialUrl == nil {
      var sz: CInt = 0
      let ref = _ApplicationInstanceGetInitialUrl(reference, &sz)
      _initialUrl = String(bytesNoCopy: ref!, length: Int(sz), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _initialUrl!
  }

  public var isHeadless: Bool {
    return _ApplicationInstanceIsHeadless(reference) != 0
  }

  public var routeRegistry: RouteRegistry!
  public var channelRegistry: ChannelRegistry!
  
  //public var window: UIWebWindow?
  public var reference: ApplicationInstanceRef?
  private var dispatcher: UIDispatcher?
  private weak var delegate: UIApplicationDelegate?
  private var requestLayerTreeFrameSinkCallback: ((_: LayerTreeFrameSink) -> Void)?
  private var _initialUrl: String?
  //private static var _instance: UIApplication?

  public init(delegate: UIApplicationDelegate) {
    self.delegate = delegate

    let windowCallbacks = UIDispatcher.createCallbacks()
    dispatcher = UIDispatcher()
    
    var appCallbacks = CApplicationCallbacks()

    memset(&appCallbacks, 0, MemoryLayout<CApplicationCallbacks>.stride)

    appCallbacks.CreateNewWindow = { (handle: UnsafeMutableRawPointer?,
      surfaceIdParentSequenceNumber: UInt32,
      surfaceIdChildSequenceNumber: UInt32,
      surfaceIdTokenHigh: UInt64, 
      surfaceIdTokenLow: UInt64,
      screenInfoDeviceScaleFactor: Float,
      screenInfoDepth: UInt32,
      screenInfoDepthPerComponent: UInt32,
      screenInfoIsMonochrome: CInt,
      screenInfoRectX: CInt,
      screenInfoRectY: CInt,
      screenInfoRectW: CInt,
      screenInfoRectH: CInt,
      screenInfoAvailableRectX: CInt,
      screenInfoAvailableRectY: CInt,
      screenInfoAvailableRectW: CInt,
      screenInfoAvailableRectH: CInt,
      screenInfoOrientationType: CInt,
      screenInfoOrientationAngle: UInt16,
      autoResizeEnabled: CInt,
      minSizeForAutoResizeW: CInt, 
      minSizeForAutoResizeH: CInt, 
      maxSizeForAutoResizeW: CInt, 
      maxSizeForAutoResizeH: CInt,
      newSizeW: CInt, 
      newSizeH: CInt,
      compositorViewportSizeW: CInt,
      compositorViewportSizeH: CInt,   
      visibleViewportSizeW: CInt,
      visibleViewportSizeH: CInt,
      captureSequenceNumber: Int32) in
      let state = unsafeBitCast(handle, to: UIApplication.self)
      var properties = VisualProperties()
      properties.screenInfo.deviceScaleFactor = screenInfoDeviceScaleFactor
      properties.screenInfo.depth = screenInfoDepth
      properties.screenInfo.depthPerComponent = screenInfoDepthPerComponent
      properties.screenInfo.isMonochrome = screenInfoIsMonochrome != 0
      properties.screenInfo.rect = IntRect(x: Int(screenInfoRectX), y: Int(screenInfoRectY), width: Int(screenInfoRectW), height: Int(screenInfoRectH))
      properties.screenInfo.availableRect = IntRect(x: Int(screenInfoAvailableRectX), y: Int(screenInfoAvailableRectY), width: Int(screenInfoAvailableRectW), height: Int(screenInfoAvailableRectH))
      properties.screenInfo.orientationType = ScreenOrientationValues(rawValue: Int(screenInfoOrientationType))!
      properties.screenInfo.orientationAngle = screenInfoOrientationAngle
      properties.autoResizeEnabled = autoResizeEnabled != 0
      properties.minSizeForAutoResize = IntSize(width: Int(minSizeForAutoResizeW), height: Int(minSizeForAutoResizeH))
      properties.maxSizeForAutoResize = IntSize()
      properties.newSize = IntSize(width: Int(newSizeW), height: Int(newSizeH))
      properties.compositorViewportPixelSize = IntSize(width: Int(compositorViewportSizeW), height: Int(compositorViewportSizeH))
      properties.localSurfaceId = LocalSurfaceId()
      properties.localSurfaceId!.parentSequenceNumber = surfaceIdParentSequenceNumber
      properties.localSurfaceId!.childSequenceNumber = surfaceIdChildSequenceNumber
      properties.localSurfaceId!.token = UnguessableToken(high: surfaceIdTokenHigh, low: surfaceIdTokenLow)
      properties.visibleViewportSize = IntSize(width: Int(visibleViewportSizeW), height: Int(visibleViewportSizeH))
      properties.captureSequenceNumber = UInt32(captureSequenceNumber)
      state.initializeVisualProperties(properties)
    }

    appCallbacks.OnExternalTextureLayerRequested = { (handle: UnsafeMutableRawPointer?) in
      let state = unsafeBitCast(handle, to: UIApplication.self)
      state.delegate!.onExternalTextureLayerRequested()
    }
    
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    reference = CommandLine.unsafeArgv.withMemoryRebound(to: UnsafePointer<Int8>?.self, capacity: 1) { (args: UnsafeMutablePointer<UnsafePointer<Int8>?>) -> ApplicationInstanceRef in
      return _ApplicationInstanceCreate(selfPtr, CommandLine.argc, args, dispatcher!.unmanagedSelf, windowCallbacks, appCallbacks)
    }
    
    routeRegistry = RouteRegistry(reference: _RouteRegistryCreateFromApp(reference))
    channelRegistry = ChannelRegistry(reference: _ChannelRegistryCreateFromApp(reference))
    
    //window = UIWindowHost(application: self, dispatcher: self.dispatcher!)
    let _ = self.delegate!.createWindow(application: self, dispatcher: self.dispatcher!)
    self.dispatcher!.state = _WindowCreate(reference)
  }

  deinit {
    _ApplicationInstanceDestroy(reference)
  }

  public func run() {
    _ApplicationInstanceRunLoop(reference)
  }

  public func createNewWindow() {
    // this is totally wrong, but its just as a sample
    delegate!.window!.createNewWindow()
  }

  public func sendWindowCreatedAck() {
    _ApplicationInstanceSendWindowCreatedAck(reference)
  }

  public func requestNewLayerTreeFrameSink(layerTreeHost: LayerTreeHost, callback: @escaping (_: LayerTreeFrameSink) -> Void) {
    requestLayerTreeFrameSinkCallback = callback
    let selfInstance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationInstanceRequestNewLayerTreeFrameSink(reference, layerTreeHost.reference, selfInstance, {
      (handle: UnsafeMutableRawPointer?, frameSinkRef: UnsafeMutableRawPointer?) in
         let this = unsafeBitCast(handle, to: UIApplication.self)
         this.onNewLayerTreeFrameSink(frameSink: LayerTreeFrameSink(reference: frameSinkRef!))
      })
  }

  public func setRenderingColorSpace(_ colorSpace: ColorSpace) {
    _ApplicationInstanceSetColorSpace(
      reference, 
      colorSpace.primaries.rawValue,
      colorSpace.transfer.rawValue,
      colorSpace.matrix.rawValue,
      colorSpace.range.rawValue,
      colorSpace.iccProfileId)  
  }

  public func windowCreated() {
    _ApplicationInstanceWindowCreated(reference)
  }

  public func windowHidden() {
    _ApplicationInstanceWindowHidden(reference)
  }

  public func windowRestored() {
    _ApplicationInstanceWindowRestored(reference)
  }

  public func addRefProcess() {
    _ApplicationInstanceAddRefProcess(reference)
  }

  public func releaseProcess() {
    _ApplicationInstanceReleaseProcess(reference) 
  }

  public func exit() {
    _ApplicationInstanceExitLoop(reference) 
  }

  public func queueVisualStateResponse(sourceFrameNumber: Int, id: UInt64) -> SwapPromise? {
    if let swapPromiseRef = _ApplicationInstanceQueueVisualStateResponse(reference, Int32(sourceFrameNumber), id) {
      return SwapPromise(reference: swapPromiseRef, managed: true)
    }
    return nil
  }

  private func initializeVisualProperties(_ properties: VisualProperties) {
    delegate!.initializeVisualProperties(params: properties)
  }

  internal func onNewLayerTreeFrameSink(frameSink: LayerTreeFrameSink) {
    if let cb = requestLayerTreeFrameSinkCallback {
      cb(frameSink)
      requestLayerTreeFrameSinkCallback = nil
    }
  }

}
