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
import ProtocolBuffers

public protocol RpcClientCall: class {
  static var method: String { get }

  /// Cancel the call.
  func cancel()
}

open class RpcClientCallBase {
  open class var method: String { fatalError("needs to be overridden") }

  public let call: RpcCall
  internal let channel: RpcChannel  // To ensure that the channel is not deallocated before this call has finished.

  /// Create a call.
  public init(_ channel: RpcChannel) throws {
    self.call = try channel.makeCall(type(of: self).method)
    self.channel = channel
  }
}

extension RpcClientCallBase: RpcClientCall {
  public func cancel() {
    self.call.cancel()
  }
}
