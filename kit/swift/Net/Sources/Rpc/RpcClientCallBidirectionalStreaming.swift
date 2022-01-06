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

public protocol RpcClientCallBidirectionalStreaming: RpcClientCall {
  func waitForSendOperationsToFinish()
  
  // TODO: Move the other, message type-dependent, methods into this protocol. At the moment, this is not possible,
  // as the protocol would then have an associated type requirement (and become pretty much unusable in the process).
}

open class RpcClientCallBidirectionalStreamingBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: RpcClientCallBase, RpcClientCallBidirectionalStreaming, StreamReceiving, StreamSending {
  public typealias ReceivedType = OutputType
  public typealias SentType = InputType

  public var handler: RpcHandler
  
  public init(handler: RpcHandler, channel: RpcChannel) throws {
    self.handler = handler
    try super.init(channel)
  }
  
  /// RpcCall this to start a call. Nonblocking.
  public func start(metadata: RpcMetadata, completion: ((RpcCallResult) -> Void)?) throws -> Self {
    try call.start(.bidiStreaming, metadata: metadata) { result in
      withExtendedLifetime(self) {  // retain `self` (and, transitively, the channel) until the call has finished.
        completion?(result)
      }
    }
    return self
  }

  public func closeSend(completion: (() -> Void)?) throws {
    try call.close(completion: completion)
  }

  public func closeSend() throws {
    let sem = DispatchSemaphore(value: 0)
    try closeSend {
      sem.signal()
    }
    _ = sem.wait()
  }
}

/// Simple fake implementation of RpcClientCallBidirectionalStreamingBase that returns a previously-defined set of results
/// and stores sent values for later verification.
open class ClientCallBidirectionalStreamingTestStub<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: RpcClientCallBidirectionalStreaming {
  open class var method: String { fatalError("needs to be overridden") }

  open var lock = Mutex()
  
  open var inputs: [InputType] = []
  open var outputs: [OutputType] = []
  
  public init() {}

  open func _receive(timeout: DispatchTime) throws -> OutputType? {
    return lock.synchronize {
      defer { if !outputs.isEmpty { outputs.removeFirst() } }
      return outputs.first
    }
  }
  
  open func receive(completion: @escaping (OutputType?) -> Void) throws {
    completion(try self._receive(timeout: .distantFuture))
  }

  open func send(_ message: InputType, completion _: @escaping (Error?) -> Void) throws {
    lock.synchronize { inputs.append(message) }
  }
  
  open func _send(_ message: InputType, timeout: DispatchTime) throws {
    lock.synchronize { inputs.append(message) }
  }

  open func closeSend(completion: (() -> Void)?) throws { completion?() }

  open func closeSend() throws {}

  open func waitForSendOperationsToFinish() {}

  open func cancel() {}
}
