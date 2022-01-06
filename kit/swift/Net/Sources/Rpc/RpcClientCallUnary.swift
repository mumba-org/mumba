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

public protocol RpcClientCallUnary: RpcClientCall {}

open class RpcClientCallUnaryBase<InputType: GeneratedMessageProtocol, OutputType: GeneratedMessageProtocol>: RpcClientCallBase, RpcClientCallUnary {
  /// Run the call. Blocks until the reply is received.
  /// - Throws: `BinaryEncodingError` if encoding fails. `RpcCallError` if fails to call. `RPCError` if receives no response.
  public func run(request: InputType, metadata: RpcMetadata) throws -> OutputType? {
    let sem = DispatchSemaphore(value: 0)
    var returnCallResult: RpcCallResult!
    var returnResponse: OutputType?
    _ = try start(request: request, metadata: metadata) { response, callResult in
      returnResponse = response
      returnCallResult = callResult
      sem.signal()
    }
    _ = sem.wait()
    
    return returnResponse
  }

  /// Start the call. Nonblocking.
  /// - Throws: `BinaryEncodingError` if encoding fails. `RpcCallError` if fails to call.
  public func start(request: InputType,
                    metadata: RpcMetadata,
                    completion: @escaping ((OutputType?, RpcCallResult) -> Void)) throws -> Self {
    let requestData = try request.data()
    try call.start(.unary, metadata: metadata, message: requestData) { callResult in
      withExtendedLifetime(self) {  // retain `self` (and, transitively, the channel) until the call has finished.
        if let responseData = callResult.resultData {
          let bytes = responseData.withUnsafeBytes {
            [UInt8](UnsafeBufferPointer(start: $0, count: responseData.count))
          }
          completion(try? OutputType.parseFrom(codedInputStream: CodedInputStream(buffer: bytes)), callResult)
        } else {
          completion(nil, callResult)
        }
      }
    }
    return self
  }
}

/// Simple fake implementation of `RpcClientCallUnary`.
open class ClientCallUnaryTestStub: RpcClientCallUnary {
  open class var method: String { fatalError("needs to be overridden") }

  public init() {}

  open func cancel() {}
}
