// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Compositor
import Gpu
import GL

public class InProcessContextFactory : UIContextFactory, UIContextFactoryPrivate {
  
  //public var sharedBitmapManager: SharedBitmapManager {
  //  return _sharedBitmapManager
  //}

  //public var gpuMemoryBufferManager: GpuMemoryBufferManager? {
  //  return _gpuMemoryBufferManager
 // }

  //public var taskGraphRunner: TaskGraphRunner? {
  //  return _taskGraphRunner
  //}

  //public var imageFactory: ImageFactory {
  //  return _imageFactory
  //}

  public var refreshRate: Double { 
    return 60.0
  }
  
  public var sharedMainThreadContextProvider: ContextProvider? {
    if sharedMainThreadContexts != nil { //&&
      //sharedMainThreadContexts!.contextGL.getGraphicsResetStatusKHR() == GLNoError {
        return sharedMainThreadContexts!
    }

    sharedMainThreadContexts = InProcessContextProvider.createOffscreen()
    if sharedMainThreadContexts != nil &&
      !sharedMainThreadContexts!.bindToCurrentThread() {
        sharedMainThreadContexts = nil
    }

   return sharedMainThreadContexts!
  }

  public var sharedMainThreadContexts: InProcessContextProvider?
  public var sharedWorkerContextProvider: InProcessContextProvider?
  public var surfaceManager: SurfaceManager?
  public var nextSurfaceIdNamespace: Int
  public var hostFrameSinkManager: HostFrameSinkManager
  public var frameSinkManager: FrameSinkManagerImpl
  //var _sharedBitmapManager: TestSharedBitmapManager
  //var _gpuMemoryBufferManager: TestGpuMemoryBufferManager
  //var _imageFactory: TestImageFactory
  //var _taskGraphRunner: TestTaskGraphRunner
  private var disableVsync: Bool = false
  private var perCompositorData: [PerCompositorData]
  private var frameSinkIdAllocator: FrameSinkIdAllocator

  public init() {
    nextSurfaceIdNamespace = 1
   //  _sharedBitmapManager = TestSharedBitmapManager()
   // _gpuMemoryBufferManager = TestGpuMemoryBufferManager()
   // _imageFactory = TestImageFactory()
   // _taskGraphRunner = TestTaskGraphRunner()
    perCompositorData = []
    frameSinkManager = FrameSinkManagerImpl()
    hostFrameSinkManager = HostFrameSinkManager()
    hostFrameSinkManager.setLocalManager(frameSinkManager)
    frameSinkManager.setLocalClient(hostFrameSinkManager)
    frameSinkIdAllocator = FrameSinkIdAllocator(clientId: 100)
    Layer.initializeUILayerSettings()
  }

   public init(hostFrameSinkManager: HostFrameSinkManager, frameSinkManager: FrameSinkManagerImpl) {
    nextSurfaceIdNamespace = 1
  //   _sharedBitmapManager = TestSharedBitmapManager()
  //  _gpuMemoryBufferManager = TestGpuMemoryBufferManager()
  //  _imageFactory = TestImageFactory()
 //   _taskGraphRunner = TestTaskGraphRunner()
    perCompositorData = []
    self.frameSinkManager = frameSinkManager
    self.hostFrameSinkManager = hostFrameSinkManager
    frameSinkIdAllocator = FrameSinkIdAllocator(clientId: 100)
    Layer.initializeUILayerSettings()
  }

  public init(surfaceManager: SurfaceManager) {
    nextSurfaceIdNamespace = 1
    self.surfaceManager = surfaceManager

//     _sharedBitmapManager = TestSharedBitmapManager()
//    _gpuMemoryBufferManager = TestGpuMemoryBufferManager()
//    _imageFactory = TestImageFactory()
//    _taskGraphRunner = TestTaskGraphRunner()
    perCompositorData = []
    hostFrameSinkManager = HostFrameSinkManager()
    frameSinkManager = FrameSinkManagerImpl()
    frameSinkIdAllocator = FrameSinkIdAllocator(clientId: 100)
    Layer.initializeUILayerSettings()
  }

  // public func createOutputSurface(compositor: UICompositor) {

  //   var attribs = ContextCreationAttribHelper()
  //   attribs.alphaSize = 8
  //   attribs.blueSize = 8
  //   attribs.greenSize = 8
  //   attribs.redSize = 8
  //   attribs.depthSize = 0
  //   attribs.stencilSize = 0
  //   attribs.samples = 0
  //   attribs.sampleBuffers = 0
  //   attribs.failIfMajorPerfCaveat = false
  //   attribs.bindGeneratesResource = false

  //   let contextProvider = InProcessContextProvider.create(
  //     attributes: attribs,
  //     //gpuMemoryBufferManager: gpuMemoryBufferManager,
  //     //imageFactory: self.imageFactory,
  //     //widget: compositor.nativeWidget,
  //     widget: compositor.widget!,
  //     name: "UICompositor")

  //   if sharedWorkerContextProvider == nil {
  //     sharedWorkerContextProvider = InProcessContextProvider.createOffscreen()
  //     if sharedWorkerContextProvider != nil && !sharedWorkerContextProvider!.bindToCurrentThread() {
  //       sharedWorkerContextProvider = nil
  //     }
  //     //if sharedWorkerContextProvider != nil {
  //     //  sharedWorkerContextProvider!.setupLock()
  //     //}
  //   }

  //   let realOutputSurface = DirectOutputSurface(contextProvider: contextProvider, workerProvider: sharedWorkerContextProvider!)

  //   //if surfaceManager != nil {
  //   //} else {
  //   compositor.setOutputSurface(surface: realOutputSurface)
  //   //}
  //   ////print("warning: InProcessContextFactory not working anymore.. we need to reimplement with viz:: codebase")
  // }

  public func createLayerTreeFrameSink(compositor: UICompositor) {
    
    var attribs = ContextCreationAttribHelper()
    attribs.alphaSize = 8
    attribs.blueSize = 8
    attribs.greenSize = 8
    attribs.redSize = 8
    attribs.depthSize = 0
    attribs.stencilSize = 0
    attribs.samples = 0
    attribs.sampleBuffers = 0
    attribs.failIfMajorPerfCaveat = false
    attribs.bindGeneratesResource = false

    
    var data: PerCompositorData? = getData(compositor)
    if data == nil {
      data = createPerCompositorData(compositor)
    } 

    let contextProvider = InProcessContextProvider.create(
       attributes: attribs,
       widget: data!.surfaceHandle,
       name: "UICompositor")

    //if !contextProvider.bindToCurrentThread() {
    //  //print("InProcessContextFactory.createLayerTreeFrameSink: InProcessContextProvider.bindToCurrentThread failed")  
    //  return
    //}

    let displayOutputSurface = DirectOutputSurface(contextProvider: contextProvider, workerProvider: contextProvider)//reference: contextProvider)

    var beginFrameSource: BeginFrameSource?
    if self.disableVsync {
      beginFrameSource = BackToBackBeginFrameSource()
    } else {
      beginFrameSource = DelayBasedBeginFrameSource(delta: TimeDelta.from(microseconds: Time.MicrosecondsPerSecond / Int64(refreshRate)))
    }

    
    data!.display = CompositorDisplay(
        outputSurface: displayOutputSurface, 
        frameSinkId: compositor.frameSinkId,
        beginFrameSource: beginFrameSource!)

    frameSinkManager.registerBeginFrameSource(beginFrameSource: beginFrameSource!,
                                              frameSinkId: compositor.frameSinkId)
    // Note that we are careful not to destroy a prior |data->begin_frame_source|
    // until we have reset |data->display|.
    data!.beginFrameSource = beginFrameSource!

    //guard let display = getData(compositor)?.display else {
    //  //print("error: no display found for Compositor")
    //  return
    //}
    
    let layerTreeFrameSink = DirectLayerTreeFrameSink(
        frameSinkId: compositor.frameSinkId, 
        hostFrameSinkManager: self.hostFrameSinkManager,
        frameSinkManager: self.frameSinkManager, 
        display: data!.display!,
        contextProvider: contextProvider)
    
    compositor.setLayerTreeFrameSink(surface: layerTreeFrameSink)   
    
    data!.display!.resize(size: compositor.size)
  }

  public func createReflector(mirroredCompositor: UICompositor, mirroringLayer: Layer) -> Reflector? {
    return FakeReflector()
  }

  public func removeReflector(reflector: Reflector) {
  }

  public func getImageTextureTarget(format: BufferFormat, usage: BufferUsage) -> UInt32 {
    return 0
  }

  public func createSurfaceIdAllocator() -> SurfaceIdAllocator {
    return SurfaceIdAllocator()
  }
 
  public func removeCompositor(compositor: UICompositor) {
    if let index = perCompositorData.firstIndex(where: { $0 === compositor }) {
      perCompositorData.remove(at: index)
    }
  }
  
  public func addObserver(observer: UIContextFactoryObserver) {

  }
  
  public func removeObserver(observer: UIContextFactoryObserver) {

  }

  public func allocateFrameSinkId() -> FrameSinkId {
    let frameSink = frameSinkIdAllocator.nextFrameSinkId()
    ////print("allocated framesink: clientId\(frameSink.clientId) sinkId\(frameSink.sinkId)")
    return frameSink
  }

  public func resizeDisplay(compositor: UICompositor, size: IntSize) {
    if let data = getData(compositor) {
      data.display!.resize(size: size)
    }
  }

  public func setDisplayVisible(compositor: UICompositor, visible: Bool) {
    if let data = getData(compositor) {
      data.display!.setVisible(visible)
    }
  }

  public func setDisplayColorMatrix(compositor: UICompositor, matrix: Mat4) {
    if let data = getData(compositor) {
      data.display!.setColorMatrix(matrix)
    }
  }

  public func setDisplayColorSpace(compositor: UICompositor, blendingColorSpace: ColorSpace, outputColorSpace: ColorSpace) {
    if let data = getData(compositor) {
      data.display!.setColorSpace(blendingColorSpace: blendingColorSpace, deviceColorSpace: outputColorSpace)
    }
  }
  
  public func setAuthoritativeVSyncInterval(compositor: UICompositor, interval: TimeDelta) {
    //print("warning: InProcessContextFactory.setAuthoritativeVSyncInterval not implemented")
  }
  
  public func setDisplayVSyncParameters(compositor: UICompositor, timebase: TimeTicks, interval: TimeDelta) {
    //print("warning: InProcessContextFactory.setDisplayVSyncParameters not implemented")
  }
  
  public func issueExternalBeginFrame(compositor: UICompositor, args: BeginFrameArgs) {
    //print("warning: InProcessContextFactory.issueExternalBeginFrame not implemented")
  }
  
  public func setOutputIsSecure(compositor: UICompositor, secure: Bool) {
    //print("warning: InProcessContextFactory.setOutputIsSecure not implemented")
  }

  private func createPerCompositorData(_ compositor: UICompositor) -> PerCompositorData {
    let data = PerCompositorData(compositor: compositor)
    //if let accelWidget = compositor.widget {
    //data.surfaceHandle = GpuSurface.addSurfaceForNativeWidget(accelWidget)
    //} 
    data.surfaceHandle = compositor.widget!
    //perCompositorData[compositor] = data
    perCompositorData.append(data)
    return data
  }

  private func getData(_ compositor: UICompositor) -> PerCompositorData? {
    for item in perCompositorData {
      if item.compositor === compositor {
        return item
      }
    }
    return nil
  }

  
}

fileprivate class PerCompositorData {
  internal var compositor: UICompositor?
  internal var surfaceHandle: SurfaceHandle = NullSurfaceHandle
  internal var beginFrameSource: BeginFrameSource?
  internal var display: CompositorDisplay?
  internal var outputColorMatrix: Mat4 = Mat4()
  
  init(compositor: UICompositor) {
    self.compositor = compositor
  }
}

class FakeReflector : Reflector {
  init() {}
  func onMirroringCompositorResized(){}
  func addMirroringLayer(layer: Layer) {}
  func removeMirroringLayer(layer: Layer) {}
};
