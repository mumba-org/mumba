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
//import Logging
//import NIO
//import NIOHPACK
//import NIOHTTP2
//import protocol GeneratedMessageProtocol
import ProtocolBuffers

public typealias GRPCPromise = () -> Void
public typealias GRPCPromiseWithStatus = (GRPCStatus) -> Void

/// An object representing a single RPC from the perspective of a client. It allows the caller to
/// send request parts, request a cancellation, and receive response parts in a provided callback.
///
/// The call object sits atop an interceptor pipeline (see `ClientInterceptor`) which allows for
/// request and response streams to be arbitrarily transformed or observed. Requests sent via this
/// call will traverse the pipeline before reaching the network, and responses received will
/// traverse the pipeline having been received from the network.
///
/// This object is a lower-level API than the equivalent wrapped calls (such as `UnaryCall` and
/// `BidirectionalStreamingCall`). The caller is therefore required to do more in order to use this
/// object correctly. Callers must call `invoke(_:)` to start the call and ensure that the correct
/// number of request parts are sent in the correct order (exactly one `metadata`, followed
/// by at most one `message` for unary and server streaming calls, and any number of `message` parts
/// for client streaming and bidirectional streaming calls. All call types must terminate their
/// request stream by sending one `end` message.
///
/// Callers are not able to create `RpcCall` objects directly, rather they must be created via an
/// object conforming to `GRPCChannel` such as `ClientConnection`.
public class RpcCall<Request, Response> {
  @usableFromInline
  internal enum State {
    /// Idle, waiting to be invoked.
    case idle(ClientTransportFactory<Request, Response>)

    /// Invoked, we have a transport on which to send requests. The transport may be closed if the
    /// RPC has already completed.
    case invoked(ClientTransport<Request, Response>)
  }

  /// The current state of the call.
  @usableFromInline
  internal var _state: State

  /// User provided interceptors for the call.
  private let interceptors: [ClientInterceptor<Request, Response>]

  /// Whether compression is enabled on the call.
  private var isCompressionEnabled: Bool {
    return self.options.messageEncoding.enabledForRequests
  }

  /// The `EventLoop` the call is being invoked on.
  //public let eventLoop: EventLoop

  /// The path of the RPC, usually generated from a service definition, e.g. "/echo.Echo/Get".
  public let path: String

  /// The type of the RPC, e.g. unary, bidirectional streaming.
  public let type: GRPCCallType

  /// Options used to invoke the call.
  public let options: CallOptions

  public let client: ClientConnection

  /// A promise for the underlying `RpcChannel`. We only allocate this if the user asks for
  /// the `RpcChannel` and we haven't invoked the transport yet. It's a bit unfortunate.
  //private var channelPromise: EventLoopPromise<RpcChannel>?

  /// Returns a future for the underlying `RpcChannel`.
  internal var channel: RpcChannel {
    return self._channel()!
  }

  // Calls can't be constructed directly: users must make them using a `GRPCChannel`.
  internal init(
    client: ClientConnection,
    path: String,
    type: GRPCCallType,
    options: CallOptions,
    interceptors: [ClientInterceptor<Request, Response>],
    transportFactory: ClientTransportFactory<Request, Response>
  ) {
    self.client = client
    self.path = path
    self.type = type
    self.options = options
    self._state = .idle(transportFactory)
    self.interceptors = interceptors
  }

  /// Starts the call and provides a callback which is invoked on every response part received from
  /// the server.
  ///
  /// This must be called prior to `send(_:promise:)` or `cancel(promise:)`.
  ///
  /// - Parameters:
  ///   - onError: A callback invoked when an error is received.
  ///   - onResponsePart: A callback which is invoked on every response part.
  /// - Important: This function should only be called once. Subsequent calls will be ignored.
  @inlinable
  public func invoke(
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
   // self.options.logger.debug("starting rpc", metadata: ["path": "\(self.path)"], source: "GRPC")

    self._invoke(onError: onError, onResponsePart: onResponsePart)
  }

  /// Send a request part on the RPC.
  /// - Parameters:
  ///   - part: The request part to send.
  ///   - promise: A promise which will be completed when the request part has been handled.
  /// - Note: Sending will always fail if `invoke(_:)` has not been called.
  @inlinable
  public func send(_ part: GRPCClientRequestPart<Request>, _ promise: GRPCPromiseWithStatus?) {
    self._send(part, promise)
  }

  /// Attempt to cancel the RPC.
  /// - Parameter promise: A promise which will be completed once the cancellation request has been
  ///   dealt with.
  /// - Note: Cancellation will always fail if `invoke(_:)` has not been called.
  public func cancel(_ promise: GRPCPromiseWithStatus?) {
    self._cancel(promise)
  }
}

// extension RpcCall {
//   /// Send a request part on the RPC.
//   /// - Parameter part: The request part to send.
//   /// - Returns: A future which will be resolved when the request has been handled.
//   /// - Note: Sending will always fail if `invoke(_:)` has not been called.
//   @inlinable
//   public func send(_ part: GRPCClientRequestPart<Request>, _ promise: GRPCPromise?) {
//     self.send(part, promise)
//   }

//   // /// Attempt to cancel the RPC.
//   // /// - Note: Cancellation will always fail if `invoke(_:)` has not been called.
//   // /// - Returns: A future which will be resolved when the cancellation request has been cancelled.
//   // public func cancel(_ promise: GRPCPromise?) {
//   //   self.cancel(promise)
//   // }
// }

extension RpcCall {
  internal func compress(_ compression: Compression) -> Bool {
    return compression.isEnabled(callDefault: self.isCompressionEnabled)
  }

  internal func sendMessages<Messages>(
    _ messages: Messages,
    compression: Compression,
    _ promise: GRPCPromiseWithStatus?
  ) where Messages: Sequence, Messages.Element == Request {
    // if self.eventLoop.inEventLoop {
      if let promise = promise {
        self._sendMessages(messages, compression: compression, promise)
      } else {
        self._sendMessages(messages, compression: compression)
      }
    // } else {
    //   self.eventLoop.execute {
    //     if let promise = promise {
    //       self._sendMessages(messages, compression: compression, promise: promise)
    //     } else {
    //       self._sendMessages(messages, compression: compression)
    //     }
    //   }
    // }
  }

  // Provide a few convenience methods we need from the wrapped call objects.
  private func _sendMessages<Messages>(
    _ messages: Messages,
    compression: Compression
  ) where Messages: Sequence, Messages.Element == Request {
    //self.eventLoop.assertInEventLoop()
    let compress = self.compress(compression)

    var iterator = messages.makeIterator()
    var maybeNext = iterator.next()
    while let current = maybeNext {
      let next = iterator.next()
      // If there's no next message, then we'll flush.
      let flush = next == nil
      self._send(.message(current, .init(compress: compress, flush: flush)), nil)
      maybeNext = next
    }
  }

  private func _sendMessages<Messages>(
    _ messages: Messages,
    compression: Compression,
    _ promise: GRPCPromiseWithStatus?
  ) where Messages: Sequence, Messages.Element == Request {
    //self.eventLoop.assertInEventLoop()
    let compress = self.compress(compression)

    var iterator = messages.makeIterator()
    var maybeNext = iterator.next()
    while let current = maybeNext {
      let next = iterator.next()
      let isLast = next == nil

      // We're already on the event loop, use the `_` send.
      if isLast {
        // Only flush and attach the promise to the last message.
        self._send(.message(current, .init(compress: compress, flush: true)), promise)
      } else {
        self._send(.message(current, .init(compress: compress, flush: false)), nil)
      }

      maybeNext = next
    }
  }
}

extension RpcCall {
  /// Invoke the RPC with this response part handler.
  /// - Important: This *must* to be called from the `eventLoop`.
  @usableFromInline
  internal func _invoke(
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
    //self.eventLoop.assertInEventLoop()

    switch self._state {
    case let .idle(factory):
      print("RpcCall._invoke -> state = .idle => creating transport")
      let transport = factory.makeConfiguredTransport(
        client: client,
        to: self.path,
        for: self.type,
        withOptions: self.options,
        interceptedBy: self.interceptors,
        onError: onError,
        onResponsePart: onResponsePart
      )
      self._state = .invoked(transport)
    client.onTransportCreated(transport, self.path)
    case .invoked:
      // We can't be invoked twice. Just ignore this.
      ()
    }
  }

  /// Send a request part on the transport.
  /// - Important: This *must* to be called from the `eventLoop`.
  @inlinable
  internal func _send(_ part: GRPCClientRequestPart<Request>, _ promise: GRPCPromiseWithStatus?) {
    print("RpcCall._send")
    //self.eventLoop.assertInEventLoop()

    switch self._state {
    case .idle:
      print("RpcCall._send -> state = .idle")
      promise?(GRPCError.InvalidState("RpcCall must be invoked before sending request parts").makeGRPCStatus())

    case let .invoked(transport):
      print("RpcCall._send -> state = .invoked => transport.send(part, promise)")
      transport.send(part, promise)
    }
  }

  /// Attempt to cancel the call.
  /// - Important: This *must* to be called from the `eventLoop`.
  private func _cancel(_ promise: GRPCPromiseWithStatus?) {
    //self.eventLoop.assertInEventLoop()

    switch self._state {
    case .idle:
      // This is weird: does it make sense to cancel before invoking it?
      let error = GRPCError.InvalidState("RpcCall must be invoked before cancelling it")
      promise?(error.makeGRPCStatus())
      //self.channelPromise?(error)

    case let .invoked(transport):
      transport.cancel(promise)
    }
  }

  /// Get the underlying `RpcChannel` for this call.
  /// - Important: This *must* to be called from the `eventLoop`.
  private func _channel() -> RpcChannel? {
    //self.eventLoop.assertInEventLoop()

    switch self._state {
    // case let (.some(promise), .idle),
    //      let (.some(promise), .invoked):
    //   // We already have a promise, just use that.
    //   return promise.futureResult

    case .idle:
    //   // We need to allocate a promise and ask the transport for the channel later.
    //   let promise = self.eventLoop.makePromise(of: RpcChannel.self)
    //   self.channelPromise = promise
    //   return promise.futureResult
      return nil

    case let (.invoked(transport)):
      // Just ask the transport.
      return transport.getChannel()!
    }
  }
}

extension RpcCall {
  // These helpers are for our wrapping call objects (`UnaryCall`, etc.).

  /// Invokes the call and sends a single request. Sends the metadata, request and closes the
  /// request stream.
  /// - Parameters:
  ///   - request: The request to send.
  ///   - onError: A callback invoked when an error is received.
  ///   - onResponsePart: A callback invoked for each response part received.
  @inlinable
  internal func invokeUnaryRequest(
    _ request: Request,
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
    print("RpcCall.invokeUnaryRequest")
    // if self.eventLoop.inEventLoop {
      self._invokeUnaryRequest(request: request, onError: onError, onResponsePart: onResponsePart)
    // } else {
    //   self.eventLoop.execute {
    //     self._invokeUnaryRequest(request: request, onError: onError, onResponsePart: onResponsePart)
    //   }
    // }
  }

  /// Invokes the call for streaming requests and sends the initial call metadata. Callers can send
  /// additional messages and end the stream by calling `send(_:promise:)`.
  /// - Parameters:
  ///   - onError: A callback invoked when an error is received.
  ///   - onResponsePart: A callback invoked for each response part received.
  @inlinable
  internal func invokeStreamingRequests(
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
    //if self.eventLoop.inEventLoop {
      self._invokeStreamingRequests(onError: onError, onResponsePart: onResponsePart)
    //} else {
    //   self.eventLoop.execute {
    //     self._invokeStreamingRequests(onError: onError, onResponsePart: onResponsePart)
    //   }
    // }
  }

  /// On-`EventLoop` implementation of `invokeUnaryRequest(request:_:)`.
  @usableFromInline
  internal func _invokeUnaryRequest(
    request: Request,
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
    //self.eventLoop.assertInEventLoop()
    assert(self.type == .unary || self.type == .serverStreaming)

    self._invoke(onError: onError, onResponsePart: onResponsePart)
    self._send(.metadata(self.options.customMetadata), nil)
    self._send(
      .message(request, .init(compress: self.isCompressionEnabled, flush: false)), nil
    )
    self._send(.end, nil)
  }

  /// On-`EventLoop` implementation of `invokeStreamingRequests(_:)`.
  @usableFromInline
  internal func _invokeStreamingRequests(
    onError: @escaping (Error) -> Void,
    onResponsePart: @escaping (GRPCClientResponsePart<Response>) -> Void
  ) {
    //self.eventLoop.assertInEventLoop()
    assert(self.type == .clientStreaming || self.type == .bidirectionalStreaming)

    self._invoke(onError: onError, onResponsePart: onResponsePart)
    self._send(.metadata(self.options.customMetadata), nil)
  }
}
