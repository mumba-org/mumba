/*
 * Copyright 2018, gRpc Authors All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Dispatch
import Foundation
import ProtocolBuffers

public protocol ServerSessionServerStreaming: ServerSession {
  func waitForSendOperationsToFinish()
}

open class ServerSessionServerStreamingBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: ServerSessionBase, ServerSessionServerStreaming, StreamSending {
  public typealias SentType = OutputType
  
  public typealias ProviderBlock = (Int, InputType, ServerSessionServerStreamingBase) throws -> ServerStatus?
  private var providerBlock: ProviderBlock
  
  public init(handler: RpcHandler, providerBlock: @escaping ProviderBlock) {
    self.providerBlock = providerBlock
    handler.shouldSendStatus = true
    super.init(handler: handler)
  }
  
  public override func run(callId: Int) -> ServerStatus? {
   // print("ServerSessionServerStreaming.run() call: \(callId)")
    guard let requestData = try! receiveRequestAndWait(callId: callId, method: .serverStream) else {
      //handler.sendStatus(ServerStatus.ok)
      return ServerStatus.noRequestData
    }
    //print("received request => '\(requestData)'")
    let requestMessage = try! InputType.parseFrom(data: requestData)

    do {
      return try self.providerBlock(callId, requestMessage, self)
    } catch {
      // Errors thrown by `providerBlock` should be logged in that method;
      // we return the error as a status code to avoid `ServiceServer` logging this as a "really unexpected" error.
      return (error as? ServerStatus) ?? .processingError
    }
  }
  
}