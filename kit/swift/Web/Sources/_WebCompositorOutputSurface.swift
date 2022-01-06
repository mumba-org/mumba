// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor

public typealias CompositorForwardingMessageFilter = Int
public typealias CompositorForwardingMessageFilterHandler = Int
public typealias CompositorOutputSurfaceProxy = Int
public typealias FrameSwapMessageQueue = Int
public typealias IPCSyncMessageFilter = Int
public typealias ContextProviderCommandBuffer = Int
public typealias SoftwareOutputDevice = Int

public final class WebCompositorOutputSurface : OutputSurface {

 private var outputSurfaceId: UInt32 = 0
 private var useSwapCompositorFrameMessage: Bool = false
 private var outputSurfaceFilter: CompositorForwardingMessageFilter? = nil
 private var outputSurfaceFilterHandler: CompositorForwardingMessageFilterHandler? = nil
 private var outputSurfaceProxy: CompositorOutputSurfaceProxy? = nil
 private var messageSender: IPCSyncMessageFilter? = nil
 private var frameSwapMessageQueue: FrameSwapMessageQueue? = nil
 private var routingId: Int = 0

 public init(routingId: Int,
      outputSurfaceId: UInt,
      contextProvider: ContextProviderCommandBuffer,
      workerContextProvider: ContextProviderCommandBuffer,
      software: SoftwareOutputDevice,
      swapFrameMessageQueue: FrameSwapMessageQueue,
      useSwapCompositorFrameMessage: Bool) {
   super.init(reference: nil)
 }

  // OutputSurface
  //override public func bindToClient(client: OutputSurfaceClient) -> Bool {
  //  return false
  //}

  override public func detachFromClient() {}

  override public func swapBuffers(frame: CompositorFrame) {}

  override public func updateSmoothnessTakesPriority(preferSmoothness: Bool) {}

  func shortcutSwapAck(outputSurfaceId: UInt32,
                  glFrameData: GLFrameData) {}

  func onSwapAck(outputSurfaceId: UInt32,
                 ack: CompositorFrameAck) {}

  func onReclaimResources(outputSurfaceId: UInt,
                          ack: CompositorFrameAck) {}

}
