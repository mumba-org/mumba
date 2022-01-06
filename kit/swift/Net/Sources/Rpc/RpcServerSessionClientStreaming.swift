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

public protocol ServerSessionClientStreaming: ServerSession {}

open class ServerSessionClientStreamingBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: ServerSessionBase, ServerSessionClientStreaming, StreamReceiving {
  public typealias ReceivedType = InputType
  
  public typealias ProviderBlock = (Int, ServerSessionClientStreamingBase) throws -> OutputType?
  private var providerBlock: ProviderBlock

  public init(handler: RpcHandler, providerBlock: @escaping ProviderBlock) {
    self.providerBlock = providerBlock
    super.init(handler: handler)
  }
  
  public func sendAndClose(callId: Int, response: OutputType, status: ServerStatus = .ok,
                           completion: (() -> Void)? = nil) throws {
    print("ServerSessionClientStreamingBase.sendAndClose()")
    try handler.sendResponse(callId: callId, message: response.data(), status: status, completion: completion)
  }

  public func sendErrorAndClose(callId: Int, status: ServerStatus, completion: (() -> Void)? = nil) throws {
    print("ServerSessionClientStreamingBase.sendErrorAndClose()")
    handler.sendStatus(callId: callId, status)//, completion: completion)
  }
  
  public override func run(callId: Int) -> ServerStatus? {
    print("ServerSessionClientStreamingBase.run()")
    try! sendInitialMetadataAndWait()
    
    let responseMessage: OutputType
    do {
      guard let handlerResponse = try self.providerBlock(callId, self) else {
        // This indicates that the provider blocks has taken responsibility for sending a response and status, so do
        // nothing.
        return nil
      }
      responseMessage = handlerResponse
    } catch {
      // Errors thrown by `providerBlock` should be logged in that method;
      // we return the error as a status code to avoid `ServiceServer` logging this as a "really unexpected" error.
      return (error as? ServerStatus) ?? .processingError
    }
    
    try! self.sendAndClose(callId: callId, response: responseMessage)
    return nil  // The status will already be sent by `sendAndClose` above.
  }
}
