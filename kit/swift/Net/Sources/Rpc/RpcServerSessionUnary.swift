// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import ProtocolBuffers

public protocol ServerSessionUnary: ServerSession {}

open class ServerSessionUnaryBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: ServerSessionBase, ServerSessionUnary {
  public typealias SentType = OutputType
  
  public typealias ProviderBlock = (Int, InputType, ServerSessionUnaryBase) throws -> OutputType
  private var providerBlock: ProviderBlock

  public init(handler: RpcHandler, providerBlock: @escaping ProviderBlock) {
    self.providerBlock = providerBlock
    handler.shouldSendStatus = false
    super.init(handler: handler)
  }
  
  public override func run(callId: Int) -> ServerStatus? {
    print("ServerSessionUnaryBase.run()")
    guard let requestData = try! receiveRequestAndWait(callId: callId, method: RpcMethodType.normal) else {
      print("ServerSessionUnaryBase.run: error no request data! failed")
      //handler.sendStatus(ServerStatus.ok)
      return ServerStatus.noRequestData
    }
    
    print("ServerSessionUnaryBase.run: calling InputType.parseFrom(data: requestData) ..")
    let requestMessage = try! InputType.parseFrom(data: requestData)
  
    let responseMessage: OutputType
    do {
      print("ServerSessionUnaryBase.run: calling providerBlock")
      responseMessage = try self.providerBlock(callId, requestMessage, self)
    } catch {
      print("ServerSessionUnaryBase.run: exception on self.providerBlock() call")
      // Errors thrown by `providerBlock` should be logged in that method;
      // we return the error as a status code to avoid `ServiceServer` logging this as a "really unexpected" error.
      return (error as? ServerStatus) ?? .processingError
    }
  
    //let sendResponseSignal = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    var sendResponseError: Error?

    // TODO: i guess we dont need to use call here.. can call 'sendMessage' directly
    //       which will trigger a IpC request to the shell process
    print("ServerSessionUnaryBase.run: sending message")
    try! self.handler.sendMessage(callId: callId, data: responseMessage.data(), method: RpcMethodType.normal) {
      sendResponseError = $0
      //sendResponseSignal.signal()
    }
    
    //print("sending reply. waiting...")
    //sendResponseSignal.wait()
    //print("back from sending reply")
    if sendResponseError != nil {
      print("ServerSessionUnaryBase.run: returned error")
      //throw sendResponseError
      return nil
    }
    return .ok
  }
}