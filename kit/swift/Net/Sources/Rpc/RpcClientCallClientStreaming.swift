/*
 * Copyright 2018, gRPC Authors All rights reserved.
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

public protocol RpcClientCallClientStreaming: RpcClientCall {
  func waitForSendOperationsToFinish()

  // TODO: Move the other, message type-dependent, methods into this protocol. At the moment, this is not possible,
  // as the protocol would then have an associated type requirement (and become pretty much unusable in the process).
}

open class RpcClientCallClientStreamingBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: RpcClientCallBase, RpcClientCallClientStreaming, StreamSending {
  public typealias SentType = InputType

  public var handler: RpcHandler
  
  public init(handler: RpcHandler, channel: RpcChannel) throws {
    self.handler = handler
    try super.init(channel)
  }
  
  /// RpcCall this to start a call. Nonblocking.
  public func start(metadata: RpcMetadata, completion: ((RpcCallResult) -> Void)?) throws -> Self {
    try call.start(.clientStreaming, metadata: metadata) { result in
      withExtendedLifetime(self) {  // retain `self` (and, transitively, the channel) until the call has finished.
        completion?(result)
      }
    }
    return self
  }

  public func closeAndReceive(completion: @escaping (OutputType?) -> Void) throws {
    try call.closeAndReceiveMessage { callResult in
      guard let responseData = callResult.resultData else {
        completion(nil); return
      }

      let bytes = responseData.withUnsafeBytes {
        [UInt8](UnsafeBufferPointer(start: $0, count: responseData.count))
      }
      if let response = try? OutputType.parseFrom(codedInputStream: CodedInputStream(buffer: bytes)) {
        completion(response)
      } else {
        completion(nil)
      }
    }
  }

  public func closeAndReceive() throws -> OutputType? {
    var result: OutputType?
    let sem = DispatchSemaphore(value: 0)
    try closeAndReceive {
      result = $0
      sem.signal()
    }
    _ = sem.wait()
    return result
  }
}

/// Simple fake implementation of RpcClientCallClientStreamingBase that
/// stores sent values for later verification and finally returns a previously-defined result.
open class ClientCallClientStreamingTestStub<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: RpcClientCallClientStreaming {
  open class var method: String { fatalError("needs to be overridden") }

  open var lock = Mutex()
  
  open var inputs: [InputType] = []
  open var output: OutputType?
  
  public init() {}

  open func send(_ message: InputType, completion _: @escaping (Error?) -> Void) throws {
    lock.synchronize { inputs.append(message) }
  }
  
  open func _send(_ message: InputType, timeout: DispatchTime) throws {
    lock.synchronize { inputs.append(message) }
  }

  open func closeAndReceive(completion: @escaping (OutputType?) -> Void) throws {
    completion(output!)
  }

  open func closeAndReceive() throws -> OutputType {
    return output!
  }

  open func waitForSendOperationsToFinish() {}
  
  open func cancel() {}
}
