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

/// A bucket of promises for a unary-response RPC.
internal class UnaryResponseParts<Response> {
  /// The `EventLoop` we expect to receive these response parts on.
  //private let eventLoop: EventLoop

  /// A promise for the `Response` message.
  //private let responsePromise: EventLoopPromise<Response>

  /// Lazy promises for the status, initial-, and trailing-metadata.
  //private var initialMetadataPromise: LazyEventLoopPromise<HPACKHeaders>
  //private var trailingMetadataPromise: LazyEventLoopPromise<HPACKHeaders>
  //private var statusPromise: LazyEventLoopPromise<GRPCStatus>

  internal var response: Response?
  internal var initialMetadata: RpcMetadata?
  internal var trailingMetadata: RpcMetadata?
  internal var status: GRPCStatus?

  internal init() {
   
  }

  /// Handle the response part, completing any promises as necessary.
  /// - Important: This *must* be called on `eventLoop`.
  internal func handle(_ part: GRPCClientResponsePart<Response>) {
   // self.eventLoop.assertInEventLoop()

    switch part {
    case let .metadata(metadata):
      self.initialMetadata = metadata

    case let .message(response):
      self.response = response

    case let .end(status, trailers):
      // In case of a "Trailers-Only" RPC (i.e. just the trailers and status), fail the initial
      // metadata and trailers.
      self.initialMetadata = nil
      self.response = nil

      self.trailingMetadata = trailers
      self.status = status
    }
  }

  internal func handleError(_ error: Error) {
    // FIXME
    let status = GRPCStatus.unknown
    self.status = status
  }
}

/// A bucket of promises for a streaming-response RPC.
internal class StreamingResponseParts<Response> {
  /// The `EventLoop` we expect to receive these response parts on.
 // private let eventLoop: EventLoop

  /// A callback for response messages.
  private let responseCallback: (Response) -> Void
  internal var initialMetadata: RpcMetadata?
  internal var trailingMetadata: RpcMetadata?
  internal var status: GRPCStatus?

  internal init(_ responseCallback: @escaping (Response) -> Void) {
    // self.eventLoop = eventLoop
     self.responseCallback = responseCallback
    // self.initialMetadataPromise = eventLoop.makeLazyPromise()
    // self.trailingMetadataPromise = eventLoop.makeLazyPromise()
    // self.statusPromise = eventLoop.makeLazyPromise()
  }

  internal func handle(_ part: GRPCClientResponsePart<Response>) {
    //self.eventLoop.assertInEventLoop()

    switch part {
    case let .metadata(metadata):
      self.initialMetadata = metadata

    case let .message(response):
      self.responseCallback(response)

    case let .end(status, _):
      self.status = status
    }
  }

  internal func handleError(_ error: Error) {
    let status = GRPCStatus(code: .unknown, message: "")
    self.status = status
  }
}

// extension EventLoop {
//   fileprivate func executeOrFlatSubmit<Result>(
//     _ body: @escaping () -> EventLoopFuture<Result>
//   ) -> EventLoopFuture<Result> {
//     if self.inEventLoop {
//       return body()
//     } else {
//       return self.flatSubmit {
//         return body()
//       }
//     }
//   }
// }

extension Error {
  fileprivate func removingContext() -> Error {
    return self
  }

  internal func makeGRPCStatus() -> GRPCStatus {
    if let transformable = self as? GRPCStatusTransformable {
      return transformable.makeGRPCStatus()
    } else {
      return GRPCStatus(code: .unknown, message: String(describing: self))
    }
  }
}
