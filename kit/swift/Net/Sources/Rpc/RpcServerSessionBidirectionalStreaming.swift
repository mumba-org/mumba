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

public protocol ServerSessionBidirectionalStreaming: ServerSession {
  func waitForSendOperationsToFinish()
}

open class ServerSessionBidirectionalStreamingBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: ServerSessionBase, ServerSessionBidirectionalStreaming, StreamReceiving, StreamSending {
  public typealias ReceivedType = InputType
  public typealias SentType = OutputType
  
  public typealias ProviderBlock = (Int, ServerSessionBidirectionalStreamingBase) throws -> ServerStatus?
  private var providerBlock: ProviderBlock

  public init(handler: RpcHandler, providerBlock: @escaping ProviderBlock) {
    self.providerBlock = providerBlock
    super.init(handler: handler)
  }
  
  public override func run(callId: Int) -> ServerStatus? {
    try! sendInitialMetadataAndWait()
    do {
      return try self.providerBlock(callId, self)
    } catch {
      // Errors thrown by `providerBlock` should be logged in that method;
      // we return the error as a status code to avoid `ServiceServer` logging this as a "really unexpected" error.
      return (error as? ServerStatus) ?? .processingError
    }
  }
}