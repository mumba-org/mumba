// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor
import Graphics
import Gpu
import Base

// This is privileged interface to the compositor. It is a global object.
public protocol UIContextFactoryPrivate : class {
  
  var frameSinkManager: FrameSinkManagerImpl { get }
  var hostFrameSinkManager: HostFrameSinkManager { get }
  
  func createReflector(mirroredCompositor: UICompositor, mirroringLayer: Layer) -> Reflector?
  func removeReflector(reflector: Reflector) 
  func allocateFrameSinkId() -> FrameSinkId
  func setDisplayVisible(compositor: UICompositor, visible: Bool)
  func resizeDisplay(compositor: UICompositor, size: IntSize)
  func setDisplayColorMatrix(compositor: UICompositor, matrix: Mat4)
  func setDisplayColorSpace(compositor: UICompositor, blendingColorSpace: ColorSpace, outputColorSpace: ColorSpace)
  func setAuthoritativeVSyncInterval(compositor: UICompositor, interval: TimeDelta)
  func setDisplayVSyncParameters(compositor: UICompositor, timebase: TimeTicks, interval: TimeDelta)
  func issueExternalBeginFrame(compositor: UICompositor, args: BeginFrameArgs)
  func setOutputIsSecure(compositor: UICompositor, secure: Bool)
}

public protocol UIContextFactoryObserver : class {
  func onLostResources()
}

// This class abstracts the creation of the 3D context for the compositor. It is
// a global object.
public protocol UIContextFactory : UIContextFactoryPrivate {//class {

  var refreshRate: Double { get }
  var sharedMainThreadContextProvider: ContextProvider? { get }
  //var gpuMemoryBufferManager: GpuMemoryBufferManager? { get }
  //var taskGraphRunner: TaskGraphRunner? { get } 
  
  func createLayerTreeFrameSink(compositor: UICompositor)
  func removeCompositor(compositor: UICompositor)
  func addObserver(observer: UIContextFactoryObserver)
  func removeObserver(observer: UIContextFactoryObserver)
}

// public protocol UIContextFactory {
//   var sharedBitmapManager: SharedBitmapManager { get }
//   var gpuMemoryBufferManager: TestGpuMemoryBufferManager { get }
//   var taskGraphRunner: TaskGraphRunner { get }
//   var imageFactory: TestImageFactory { get }
//   func createOutputSurface(compositor: UICompositor)
//   func createReflector(mirroredCompositor: UICompositor, mirroringLayer: Layer) -> Reflector
//   func removeReflector(reflector: Reflector)
//   func sharedMainThreadContextProvider() throws -> ContextProvider
//   func removeCompositor(compositor: UICompositor)
//   func getImageTextureTarget(format: BufferFormat, usage: BufferUsage) -> UInt32
//   func createSurfaceIdAllocator() -> SurfaceIdAllocator
//   func resizeDisplay(compositor: UICompositor, size: IntSize)
// }
