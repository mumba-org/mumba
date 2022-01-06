// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public enum DidNotSwapReason : Int {
  case DidSwap = -1
  case SwapFails = 0
  case CommitFails = 1
  case CommitNoUpdate = 2
  case ActivationFails = 3
}

public typealias SwapPromiseCallback = (_: Bool, _: DidNotSwapReason, _: Double) -> Void
public typealias SwapPromiseNativeCallback = @convention(c) (UnsafeMutableRawPointer?, _: WebSwapResultEnum, _: Double) -> Void

public class SwapPromise {
  
  public var traceId: Int64 { 
    //print("called SwapPromise.traceId getter: big mistake (should be on the native reference)")
    return 0 
  }
  
  public func didActivate() {
    //print("called SwapPromise.didActivate: big mistake (should be on the native reference)")
  }
  public func didSwap(metadata: CompositorFrameMetadata) {
    //print("called SwapPromise.didSwap: big mistake (should be on the native reference)")
  }
  public func didNotSwap(reason: DidNotSwapReason) {
    //print("called SwapPromise.didNotSwap: big mistake (should be on the native reference)")
  }
  public func onCommit() {
    //print("called SwapPromise.onCommit: big mistake (should be on the native reference)")
  }

  internal var reference: SwapPromiseRef?
  internal var managed: Bool = true

  internal init() {
    self.reference = nil
    self.managed = true
  }

  deinit {
    //print("SwapPromise destructor: managed ? \(managed)")
    if managed {
      _SwapPromiseDestroy(reference)      
    }
  }
  
  public init(reference: SwapPromiseRef, managed: Bool = false) {
    self.reference = reference
    self.managed = managed
  }
}

public class LatencyInfoSwapPromise : SwapPromise {
  
  //private var callback: SwapPromiseCallback?
  private var latency: LatencyInfo

  public init(latency: LatencyInfo, host: LayerTreeHost) {
    //self.callback = callback
    self.latency = latency
    super.init()

    var count: Int = 0
    // key
    var types = ContiguousArray<CInt>()
    // component
    var eventTimes = ContiguousArray<Int64>()

    for kv in latency.components {
      types.append(CInt(kv.key.rawValue))
      eventTimes.append(kv.value.microseconds)
      count += 1
    }

    //let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    latency.traceName.withCString { traceNameCstr in
      types.withUnsafeBufferPointer { typebuf in
        eventTimes.withUnsafeBufferPointer { evtbuf in
          let reference = _SwapPromiseCreateLatency(
            host.reference,
            latency.traceId,
            traceNameCstr,
            latency.ukmSourcedId,
            latency.coalesced ? 1 : 0,
            latency.began ? 1 : 0,
            latency.terminated ? 1 : 0,
            CInt(latency.sourceEventType.rawValue),
            latency.scrollUpdateDelta,
            latency.predictedScrollUpdateDelta,
            CInt(count),
            typebuf.baseAddress,
            evtbuf.baseAddress)
            //selfptr,
            //{ (state: UnsafeMutableRawPointer?, swap: CInt, reason: CInt, time: Double) in
            //    let ptr = unsafeBitCast(state, to: LatencyInfoSwapPromise.self)
            //    ptr.onSwap(didSwap: swap != 0, reason: DidNotSwapReason(rawValue: Int(reason))!, time: time) 
            //})
          self.reference = reference!
          self.managed = true
        }
      }
    }
  }

  //private func onSwap(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
  //  if let cb = callback {
  //    cb(didSwap, reason, time)
  //  }
  //}

}

public class AlwaysDrawSwapPromise : SwapPromise {
  private var callback: SwapPromiseCallback?
  private var latency: LatencyInfo

  public init(latencyInfo: LatencyInfo, host: LayerTreeHost, callback: SwapPromiseCallback?) {
    self.callback = callback
    self.latency = latencyInfo
    super.init()

    var count: Int = 0
    // key
    var types = ContiguousArray<CInt>()
    // component
    var eventTimes = ContiguousArray<Int64>()
   
    for kv in latency.components {
      types.append(CInt(kv.key.rawValue))
      eventTimes.append(kv.value.microseconds)
      count += 1
    }

    let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    latency.traceName.withCString { traceNameCstr in
      types.withUnsafeBufferPointer { typebuf in
        eventTimes.withUnsafeBufferPointer { evtbuf in
          let reference = _SwapPromiseCreateAlwaysDraw(
            host.reference,
            latency.traceId,
            traceNameCstr,
            latency.ukmSourcedId,
            latency.coalesced ? 1 : 0,
            latency.began ? 1 : 0,
            latency.terminated ? 1 : 0,
            CInt(latency.sourceEventType.rawValue),
            latency.scrollUpdateDelta,
            latency.predictedScrollUpdateDelta,
            CInt(count),
            typebuf.baseAddress,
            evtbuf.baseAddress,
            selfptr,
            { (state: UnsafeMutableRawPointer?, swap: CInt, reason: CInt, time: Double) in
                if state != nil {
                  let ptr = unsafeBitCast(state, to: AlwaysDrawSwapPromise.self)
                  ptr.onSwap(didSwap: swap != 0, reason: DidNotSwapReason(rawValue: Int(reason))!, time: time) 
                }
            })
          self.reference = reference!
          self.managed = true
        }
      }
    }
  }

  private func onSwap(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
    if let cb = callback {
      cb(didSwap, reason, time)
    }
  }
}

public class ReportTimeSwapPromise : SwapPromise {

  private var callback: SwapPromiseCallback?
  // public init (host: LayerTreeHost, callback: SwapPromiseCallback?) {
  //   self.callback = callback
  //   super.init()

  //   let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

  //   let reference = _SwapPromiseCreateReportTime(host.reference, selfptr, { 
  //     (state: UnsafeMutableRawPointer?, swap: CInt, reason: CInt, time: Double) in
  //       if state != nil {
  //         let ptr = unsafeBitCast(state, to: ReportTimeSwapPromise.self)
  //         ptr.onSwap(didSwap: swap != 0, reason: DidNotSwapReason(rawValue: Int(reason))!, time: time) 
  //       }
  //   })  
  //   self.reference = reference!    
  //   self.managed = true
  // }

  public init(host: LayerTreeHost, callbackState: UnsafeMutableRawPointer?) {
    super.init()
    let reference = _SwapPromiseCreateReportTime(host.reference, callbackState!)  
    self.reference = reference!    
    // dont destroy it yet
    self.managed = false 
  }

  private func onSwap(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
    if let cb = callback {
      cb(didSwap, reason, time)
    }
  }
}

//public protocol SwapPromiseMonitor {
//  func onSetNeedsCommitOnMain()
//  func onSetNeedsRedrawOnImpl()
//  func onForwardScrollUpdateToMainThreadOnImpl()
//}

// TODO: check if this can really be on the swift side
//       or if we will need a wrapper
public class LatencyInfoSwapPromiseMonitor {
  
  //var layerTreeHost: LayerTreeHost
  //var latency: LatencyInfo
  internal var reference: SwapPromiseMonitorRef?

  public init(latency: LatencyInfo, layerTreeHost: LayerTreeHost) {
    var count: Int = 0
    // key
    var types = ContiguousArray<CInt>()
    // component
    var eventTimes = ContiguousArray<Int64>()
    
    for kv in latency.components {
      types.append(CInt(kv.key.rawValue))
      eventTimes.append(kv.value.microseconds)
      count += 1
    }

    latency.traceName.withCString { traceNameCstr in
      types.withUnsafeBufferPointer { typebuf in
        eventTimes.withUnsafeBufferPointer { evtbuf in
          let reference = _SwapPromiseMonitorCreateLatency(
            layerTreeHost.reference,
            latency.traceId,
            traceNameCstr,
            latency.ukmSourcedId,
            latency.coalesced ? 1 : 0,
            latency.began ? 1 : 0,
            latency.terminated ? 1 : 0,
            CInt(latency.sourceEventType.rawValue),
            latency.scrollUpdateDelta,
            latency.predictedScrollUpdateDelta,
            CInt(count),
            typebuf.baseAddress,
            evtbuf.baseAddress)
          self.reference = reference!         
        }
      }
    }
  }

  //internal init(reference: SwapPromiseMonitorRef) {
  //  self.reference = reference
  //}

  deinit {
    //print("LatencyInfoSwapPromiseMonitor: destroying swap monitor")
    _SwapPromiseMonitorDestroy(reference!) 
  }

  //private func onSwap(didSwap: Bool, reason: DidNotSwapReason, time: Double) {
  //  if let cb = callback {
  //    cb(didSwap, reason, time)
  //  }
  //}

  //public init(layerTreeHost: LayerTreeHost, latency: LatencyInfo) {
  //  self.layerTreeHost = layerTreeHost
  //  self.latency = latency
  //}

  // func addRenderingScheduledComponent(latencyInfo: LatencyInfo, onMain: Bool) -> Bool {
    
  //   let latencyType: LatencyComponentType =
  //     onMain ? .InputEventLatencyRenderingScheduledMainComponent : .InputEventLatencyRenderingScheduledImplComponent
    
  //   if latencyInfo.findLatency(type: latencyType, id: 0, output: nil) {
  //     return false
  //   }

  //   latencyInfo.addLatencyNumber(component: latencyType, id: 0, sequence: 0)
    
  //   return true

  // }

  // func addForwardingScrollUpdateToMainComponent(latencyInfo: LatencyInfo) -> Bool {
    
  //   if latencyInfo.findLatency(type: .InputEventLatencyForwardScrollUpdateToMainComponent, id: 0, output: nil) {
  //     return false
  //   }
    
  //   latencyInfo.addLatencyNumber(component: .InputEventLatencyForwardScrollUpdateToMainComponent, id: 0, sequence: latencyInfo.traceId)
  
  //   return true
  // }

}

// extension LatencyInfoSwapPromiseMonitor : SwapPromiseMonitor {
  
//   public func onSetNeedsCommitOnMain() {

//     if addRenderingScheduledComponent(latencyInfo: latency, onMain: true) {
//       let swapPromise = LatencyInfoSwapPromise(latency: latency)
//       layerTreeHost.queueSwapPromise(swapPromise: swapPromise)
//     }

//   }
  
//   public func onSetNeedsRedrawOnImpl() {
//     //print("LatencyInfoSwapPromiseMonitor.onSetNeedsRedrawOnImpl: called on the swift side. not implemented") 
//     //if addRenderingScheduledComponent(latencyInfo: latency, onMain: false) {
//     //  let swapPromise = LatencyInfoSwapPromise(latency: latency)
//     //  layerTreeHost.activeTree.queuePinnedSwapPromise(swapPromise)
//     //}
//   }
  
//   public func onForwardScrollUpdateToMainThreadOnImpl() {
//     //print("LatencyInfoSwapPromiseMonitor.onForwardScrollUpdateToMainThreadOnImpl: called on the swift side. not implemented") 
//     // if addForwardingScrollUpdateToMainComponent(latencyInfo: latency) {
      
//     //   var newSequenceNumber: Int64 = 0

//     //   for (key, component) in latency.components {
        
//     //     if key == .InputEventLatencyBeginRWHComponent {
          
//     //       let selfaddress = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UInt64.self)
          
//     //       newSequenceNumber = ((Int64(PlatformThread.currentId) << 32) ^ (selfaddress << 32)) | (component.sequenceNumber & 0xffffffff)
          
//     //       if newSequenceNumber == component.sequenceNumber {
//     //         return
//     //       }

//     //       break
//     //     }

//     //   }

//     //   if newSequenceNumber == 0 {
//     //     return
//     //   }

//     //   let newLatency = LatencyInfo()

//     //   newLatency.addLatencyNumber(
//     //       component: .LatencyBeginScrollListenerUpdateMainComponent, 
//     //       id: 0,
//     //       sequence: newSequenceNumber, 
//     //       name: "ScrollUpdate")

//     //   newLatency.copyLatencyFrom(other: latency, type: .InputEventLatencyForwardScrollUpdateToMainComponent)
      
//     //   let swapPromise = LatencyInfoSwapPromise(latency: newLatency)      
//     //   layerTreeHost.queueSwapPromiseForMainThreadScrollUpdate(swapPromise: swapPromise)
//     }

//   }