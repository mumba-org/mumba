/*
 * Copyright 2020, gRPC Authors All rights reserved.
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
//import NIO
//import NIOHPACK

/// A container for RPC response parts.
internal struct ResponsePartContainer<Response> {
  /// The type of handler for response message part.
  enum ResponseHandler {
    case unary((Response?, GRPCStatus) -> Void)
    case stream((Response?, GRPCStatus) -> Void)
  }

  var initialMetadata: RpcMetadata?

  /// A handler for response messages.
  let responseHandler: ResponseHandler

  /// A promise for the trailing metadata.
  var trailingMetadataPromise: RpcMetadata?

  /// A promise for the call status.
  //var lazyStatusPromise: LazyEventLoopPromise<GRPCStatus>
  var status: GRPCStatus?

  /// Fail all promises - except for the status promise - with the given error status. Succeed the
  /// status promise.
  mutating func fail(with error: Error, status: GRPCStatus) {
    //self.lazyInitialMetadataPromise(nil, status)

    switch self.responseHandler {
    case let .unary(response):
      response(nil, status)
    case .stream:
      ()
    }
    //self.lazyTrailingMetadataPromise?(nil, status)
    // We always succeed the status.
    //self.lazyStatusPromise.succeed(status)
  }

  /// Make a response container for a unary response.
  init(unaryResponsePromise: @escaping (Response?, GRPCStatus) -> Void) {
    self.responseHandler = .unary(unaryResponsePromise)
  }

  /// Make a response container for a response which is streamed.
  init(streamingResponseHandler: @escaping (Response?, GRPCStatus) -> Void) {
    self.responseHandler = .stream(streamingResponseHandler)
  }
}
