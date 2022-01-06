// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base

public protocol ServerSession: class {
  //var callId: Int { get }
  var handler: RpcHandler { get }
  var requestMetadata: RpcMetadata { get }
  var initialMetadata: RpcMetadata { get set }
  
  func cancel()
  func run(callId: Int) -> ServerStatus?
}

open class ServerSessionBase: ServerSession {
  public var handler: RpcHandler
  public var requestMetadata: RpcMetadata { return handler.requestMetadata }
  //public var callId: Int = -1
  public var initialMetadata: RpcMetadata = RpcMetadata()
  
  //public var call: RpcCall { return handler.call }

  public init(handler: RpcHandler) {
    //self.callId = callId
    self.handler = handler
  }
  
  public func cancel() {
   // call.cancel()
    handler.shutdown()
  }

  public func run(callId: Int) -> ServerStatus? {
    return nil
  }

  func sendInitialMetadataAndWait() throws {
    //let sendMetadataSignal = DispatchSemaphore(value: 0)
    //var success = false
    //try handler.sendMetadata(initialMetadata: initialMetadata) {
    //  success = $0
    //  sendMetadataSignal.signal()
    //}
    //sendMetadataSignal.wait()
    
    //if !success {
      throw ServerStatus.sendingInitialMetadataFailed
    //}
  }
  
  func receiveRequestAndWait(callId: Int, method: RpcMethodType) throws -> Data? {
    //print("ServerSession.receiveRequestAndWait() call: \(callId)")
    //self.callId = callId
    let sendMetadataSignal = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    var requestData: Data?
    // try handler.receiveMessage(initialMetadata: initialMetadata, method: method) {
    try handler.receiveMessage(callId: callId, method: method) {
      requestData = $0
      //print("receiveRequestAndWait: received data!")
      sendMetadataSignal.signal()
    }
    //print("receiveRequestAndWait: waiting..")
    sendMetadataSignal.wait()
    
    return requestData
  }
}