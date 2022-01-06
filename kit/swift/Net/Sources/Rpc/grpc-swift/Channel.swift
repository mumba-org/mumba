//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public enum CloseMode {
  case input
  case output
  case all
}

/// A configuration option that can be set on a `RpcChannel` to configure different behaviour.
public protocol ChannelOption: Equatable {
    /// The type of the `ChannelOption`'s value.
    associatedtype Value
}

public protocol ChannelCore {
    func localAddress0() throws -> IpEndPoint
    func remoteAddress0() throws -> IpEndPoint
    func register0(promise: GRPCPromiseWithStatus?)
    func registerAlreadyConfigured0(promise: GRPCPromiseWithStatus?)
    func bind0(to: IpEndPoint, promise: GRPCPromiseWithStatus?)
    func connect0(to: IpEndPoint, promise: GRPCPromiseWithStatus?)
    func write0(_ data: NIOAny, promise: GRPCPromiseWithStatus?)
    func flush0()
    func read0()
    func close0(error: Error, mode: CloseMode, promise: GRPCPromiseWithStatus?)
    func triggerUserOutboundEvent0(_ event: Any, promise: GRPCPromiseWithStatus?)
    func channelRead0(_ data: NIOAny)
    func errorCaught0(error: Error)
}

// Here we will bind with the inner io rpc runtime
public protocol RpcChannel {
  var allocator: ByteBufferAllocator { get }
  var localAddress: IpEndPoint? { get }
  var remoteAddress: IpEndPoint? { get }
  var _channelCore: ChannelCore { get }
  /// The `ChannelPipeline` which handles all I/O events and requests associated with this `RpcChannel`.
  var pipeline: ChannelPipeline { get }
  func write(_: NIOAny, promise: GRPCPromiseWithStatus?)
  func close()
  func close(mode: CloseMode, promise: GRPCPromiseWithStatus?)
  func flush()
  func fail(_ : GRPCStatus)
}

/// ChannelHandler which will emit data by calling `ChannelHandlerContext.write`.
///
/// We _strongly_ advice against implementing this protocol directly. Please implement `ChannelInboundHandler` or / and `ChannelOutboundHandler`.
public protocol _EmittingChannelHandler {
    /// The type of the outbound data which will be forwarded to the next `ChannelOutboundHandler` in the `ChannelPipeline`.
    associatedtype OutboundOut = Never

    /// Wrap the provided `OutboundOut` that will be passed to the next `ChannelOutboundHandler` by calling `ChannelHandlerContext.write`.
    @inlinable
    func wrapOutboundOut(_ value: OutboundOut) -> NIOAny
}

/// Default implementations for `_EmittingChannelHandler`.
extension _EmittingChannelHandler {
    @inlinable
    public func wrapOutboundOut(_ value: OutboundOut) -> NIOAny {
        return NIOAny(value)
    }
}

///  `ChannelHandler` which handles inbound I/O events for a `RpcChannel`.
///
/// Please refer to `_ChannelInboundHandler` and `_EmittingChannelHandler` for more details on the provided methods.
public protocol ChannelInboundHandler: _ChannelInboundHandler, _EmittingChannelHandler {
    /// The type of the inbound data which is wrapped in `NIOAny`.
    associatedtype InboundIn

    /// The type of the inbound data which will be forwarded to the next `ChannelInboundHandler` in the `ChannelPipeline`.
    associatedtype InboundOut = Never

    /// Unwrap the provided `NIOAny` that was passed to `channelRead`.
    @inlinable
    func unwrapInboundIn(_ value: NIOAny) -> InboundIn

    /// Wrap the provided `InboundOut` that will be passed to the next `ChannelInboundHandler` by calling `ChannelHandlerContext.fireChannelRead`.
    @inlinable
    func wrapInboundOut(_ value: InboundOut) -> NIOAny
}


/// Default implementations for `_EmittingChannelHandler`.
extension ChannelInboundHandler {
  @inlinable
  public func wrapOutboundOut(_ value: OutboundOut) -> NIOAny {
    return NIOAny(value)
  }
  @inlinable
  public func unwrapInboundIn(_ value: NIOAny) -> InboundIn {
      return value.forceAs()
  }

  @inlinable
  public func wrapInboundOut(_ value: InboundOut) -> NIOAny {
      return NIOAny(value)
  }
}

/// `ChannelHandler` which handles outbound I/O events or intercept an outbound I/O operation for a `RpcChannel`.
///
/// Please refer to `_ChannelOutboundHandler` and `_EmittingChannelHandler` for more details on the provided methods.
public protocol ChannelOutboundHandler: _ChannelOutboundHandler, _EmittingChannelHandler {
    /// The type of the outbound data which is wrapped in `NIOAny`.
    associatedtype OutboundIn

    /// Unwrap the provided `NIOAny` that was passed to `write`.
    @inlinable
    func unwrapOutboundIn(_ value: NIOAny) -> OutboundIn
}

/// Default implementations for `ChannelOutboundHandler`.
extension ChannelOutboundHandler {
    @inlinable
    public func unwrapOutboundIn(_ value: NIOAny) -> OutboundIn {
        return value.forceAs()
    }
}

/// A combination of `ChannelInboundHandler` and `ChannelOutboundHandler`.
public typealias ChannelDuplexHandler = ChannelInboundHandler & ChannelOutboundHandler

public protocol ChannelHandler: AnyObject {
  /// Called when this `ChannelHandler` is added to the `ChannelPipeline`.
  ///
  /// - parameters:
  ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
  func handlerAdded(context: ChannelHandlerContext)

  /// Called when this `ChannelHandler` is removed from the `ChannelPipeline`.
  ///
  /// - parameters:
  ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
  func handlerRemoved(context: ChannelHandlerContext)
}

/// Allows users to invoke an "outbound" operation related to a `RpcChannel` that will flow through the `ChannelPipeline` until
/// it will finally be executed by the the `ChannelCore` implementation.
public protocol ChannelOutboundInvoker {

    /// Register on an `EventLoop` and so have all its IO handled.
    ///
    /// - parameters:
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func register(promise: GRPCPromiseWithStatus?)

    /// Bind to a `IpEndPoint`.
    /// - parameters:
    ///     - to: the `IpEndPoint` to which we should bind the `RpcChannel`.
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func bind(to: IpEndPoint, promise: GRPCPromiseWithStatus?)

    /// Connect to a `IpEndPoint`.
    /// - parameters:
    ///     - to: the `IpEndPoint` to which we should connect the `RpcChannel`.
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func connect(to: IpEndPoint, promise: GRPCPromiseWithStatus?)

    /// Write data to the remote peer.
    ///
    /// Be aware that to be sure that data is really written to the remote peer you need to call `flush` or use `writeAndFlush`.
    /// Calling `write` multiple times and then `flush` may allow the `RpcChannel` to `write` multiple data objects to the remote peer with one syscall.
    ///
    /// - parameters:
    ///     - data: the data to write
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func write(_ data: NIOAny, promise: GRPCPromiseWithStatus?)

    /// Flush data that was previously written via `write` to the remote peer.
    func flush()

    /// Shortcut for calling `write` and `flush`.
    ///
    /// - parameters:
    ///     - data: the data to write
    ///     - promise: the `EventLoopPromise` that will be notified once the `write` operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func writeAndFlush(_ data: NIOAny, promise: GRPCPromiseWithStatus?)

    /// Signal that we want to read from the `RpcChannel` once there is data ready.
    ///
    /// If `ChannelOptions.autoRead` is set for a `RpcChannel` (which is the default) this method is automatically invoked by the transport implementation,
    /// otherwise it's the user's responsibility to call this method manually once new data should be read and processed.
    ///
    func read()

    /// Close the `RpcChannel` and so the connection if one exists.
    ///
    /// - parameters:
    ///     - mode: the `CloseMode` that is used
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func close(mode: CloseMode, promise: GRPCPromiseWithStatus?)

    /// Trigger a custom user outbound event which will flow through the `ChannelPipeline`.
    ///
    /// - parameters:
    ///     - promise: the `EventLoopPromise` that will be notified once the operation completes,
    ///                or `nil` if not interested in the outcome of the operation.
    func triggerUserOutboundEvent(_ event: Any, promise: GRPCPromiseWithStatus?)

    /// The `EventLoop` which is used by this `ChannelOutboundInvoker` for execution.
    //var eventLoop: EventLoop { get }
}


/// Fire inbound events related to a `RpcChannel` through the `ChannelPipeline` until its end is reached or it's consumed by a `ChannelHandler`.
public protocol ChannelInboundInvoker {

    /// Called once a `RpcChannel` was registered to its `EventLoop` and so IO will be processed.
    func fireChannelRegistered()

    /// Called once a `RpcChannel` was unregistered from its `EventLoop` which means no IO will be handled for a `RpcChannel` anymore.
    func fireChannelUnregistered()

    /// Called once a `RpcChannel` becomes active.
    ///
    /// What active means depends on the `RpcChannel` implementation and semantics.
    /// For example for TCP it means the `RpcChannel` is connected to the remote peer.
    func fireChannelActive()

    /// Called once a `RpcChannel` becomes inactive.
    ///
    /// What inactive means depends on the `RpcChannel` implementation and semantics.
    /// For example for TCP it means the `RpcChannel` was disconnected from the remote peer and closed.
    func fireChannelInactive()

    /// Called once there is some data read for a `RpcChannel` that needs processing.
    ///
    /// - parameters:
    ///     - data: the data that was read and is ready to be processed.
    func fireChannelRead(_ data: NIOAny)

    /// Called once there is no more data to read immediately on a `RpcChannel`. Any new data received will be handled later.
    func fireChannelReadComplete()

    /// Called when a `RpcChannel`'s writable state changes.
    ///
    /// The writability state of a RpcChannel depends on watermarks that can be set via `RpcChannel.setOption` and how much data
    /// is still waiting to be transferred to the remote peer.
    /// You should take care to enforce some kind of backpressure if the channel becomes unwritable which means `RpcChannel.isWritable`
    /// will return `false` to ensure you do not consume too much memory due to queued writes. What exactly you should do here depends on the
    /// protocol and other semantics. But for example you may want to stop writing to the `RpcChannel` until `RpcChannel.writable` becomes
    /// `true` again or stop reading at all.
    func fireChannelWritabilityChanged()

    /// Called when an inbound operation `Error` was caught.
    ///
    /// Be aware that for inbound operations this method is called while for outbound operations defined in `ChannelOutboundInvoker`
    /// the `EventLoopFuture` or `EventLoopPromise` will be notified.
    ///
    /// - parameters:
    ///     - error: the error we encountered.
    func fireErrorCaught(_ error: Error)

    /// Trigger a custom user inbound event which will flow through the `ChannelPipeline`.
    ///
    /// - parameters:
    ///     - event: the event itself.
    func fireUserInboundEventTriggered(_ event: Any)
}

/// A protocol that signals that outbound and inbound events are triggered by this invoker.
public protocol ChannelInvoker: ChannelOutboundInvoker, ChannelInboundInvoker { }

/// An error that can occur on `RpcChannel` operations.
public enum ChannelError: Error {
    /// Tried to connect on a `RpcChannel` that is already connecting.
    case connectPending

    /// Connect operation timed out
    case connectTimeout(TimeDelta)

    /// Unsupported operation triggered on a `RpcChannel`. For example `connect` on a `ServerSocketChannel`.
    case operationUnsupported

    /// An I/O operation (e.g. read/write/flush) called on a channel that is already closed.
    case ioOnClosedChannel

    /// Close was called on a channel that is already closed.
    case alreadyClosed

    /// Output-side of the channel is closed.
    case outputClosed

    /// Input-side of the channel is closed.
    case inputClosed

    /// A read operation reached end-of-file. This usually means the remote peer closed the socket but it's still
    /// open locally.
    case eof

    /// A `DatagramChannel` `write` was made with a buffer that is larger than the MTU for the connection, and so the
    /// datagram was not written. Either shorten the datagram or manually fragment, and then try again.
    case writeMessageTooLarge

    /// A `DatagramChannel` `write` was made with an address that was not reachable and so could not be delivered.
    case writeHostUnreachable

    /// The local address of the `RpcChannel` could not be determined.
    case unknownLocalAddress

    /// The address family of the multicast group was not valid for this `RpcChannel`.
    case badMulticastGroupAddressFamily

    /// The address family of the provided multicast group join is not valid for this `RpcChannel`.
    case badInterfaceAddressFamily

    /// An attempt was made to join a multicast group that does not correspond to a multicast
    /// address.
    case illegalMulticastAddress(IpEndPoint)

    /// An operation that was inappropriate given the current `RpcChannel` state was attempted.
    case inappropriateOperationForState

    /// An attempt was made to remove a ChannelHandler that is not removable.
    case unremovableHandler
}

extension ChannelError: Equatable { }

public struct NIOAttemptedToRemoveHandlerMultipleTimesError: Error {}


/// Untyped `ChannelHandler` which handles outbound I/O events or intercept an outbound I/O operation.
///
/// Despite the fact that `write` is one of the methods on this `protocol`, you should avoid assuming that "outbound" events are to do with
/// writing to channel sources. Instead, "outbound" events are events that are passed *to* the channel source (e.g. a socket): that is, things you tell
/// the channel source to do. That includes `write` ("write this data to the channel source"), but it also includes `read` ("please begin attempting to read from
/// the channel source") and `bind` ("please bind the following address"), which have nothing to do with sending data.
///
/// We _strongly_ advise against implementing this protocol directly. Please implement `ChannelOutboundHandler`.
public protocol _ChannelOutboundHandler: ChannelHandler {

    /// Called to request that the `RpcChannel` register itself for I/O events with its `EventLoop`.
    /// This should call `context.register` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func register(context: ChannelHandlerContext, promise: GRPCPromiseWithStatus?)

    /// Called to request that the `RpcChannel` bind to a specific `IpEndPoint`.
    ///
    /// This should call `context.bind` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - to: The `IpEndPoint` to which this `RpcChannel` should bind.
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func bind(context: ChannelHandlerContext, to: IpEndPoint, promise: GRPCPromiseWithStatus?)

    /// Called to request that the `RpcChannel` connect to a given `IpEndPoint`.
    ///
    /// This should call `context.connect` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - to: The `IpEndPoint` to which the the `RpcChannel` should connect.
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func connect(context: ChannelHandlerContext, to: IpEndPoint, promise: GRPCPromiseWithStatus?)

    /// Called to request a write operation. The write operation will write the messages through the
    /// `ChannelPipeline`. Those are then ready to be flushed to the actual `RpcChannel` when
    /// `RpcChannel.flush` or `ChannelHandlerContext.flush` is called.
    ///
    /// This should call `context.write` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - data: The data to write through the `RpcChannel`, wrapped in a `NIOAny`.
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func write(context: ChannelHandlerContext, data: NIOAny, promise: GRPCPromiseWithStatus?)

    /// Called to request that the `RpcChannel` flush all pending writes. The flush operation will try to flush out all previous written messages
    /// that are pending.
    ///
    /// This should call `context.flush` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or just
    /// discard it if the flush should be suppressed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func flush(context: ChannelHandlerContext)

    /// Called to request that the `RpcChannel` perform a read when data is ready. The read operation will signal that we are ready to read more data.
    ///
    /// This should call `context.read` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or just
    /// discard it if the read should be suppressed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func read(context: ChannelHandlerContext)

    /// Called to request that the `RpcChannel` close itself down`.
    ///
    /// This should call `context.close` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - mode: The `CloseMode` to apply
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func close(context: ChannelHandlerContext, mode: CloseMode, promise: GRPCPromiseWithStatus?)

    /// Called when an user outbound event is triggered.
    ///
    /// This should call `context.triggerUserOutboundEvent` to forward the operation to the next `_ChannelOutboundHandler` in the `ChannelPipeline` or
    /// complete the `EventLoopPromise` to let the caller know that the operation completed.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - event: The triggered event.
    ///     - promise: The `EventLoopPromise` which should be notified once the operation completes, or nil if no notification should take place.
    func triggerUserOutboundEvent(context: ChannelHandlerContext, event: Any, promise: GRPCPromiseWithStatus?)
}

/// Untyped `ChannelHandler` which handles inbound I/O events.
///
/// Despite the fact that `channelRead` is one of the methods on this `protocol`, you should avoid assuming that "inbound" events are to do with
/// reading from channel sources. Instead, "inbound" events are events that originate *from* the channel source (e.g. the socket): that is, events that the
/// channel source tells you about. This includes things like `channelRead` ("there is some data to read"), but it also includes things like
/// `channelWritabilityChanged` ("this source is no longer marked writable").
///
/// We _strongly_ advise against implementing this protocol directly. Please implement `ChannelInboundHandler`.
public protocol _ChannelInboundHandler: ChannelHandler {

    /// Called when the `RpcChannel` has successfully registered with its `EventLoop` to handle I/O.
    ///
    /// This should call `context.fireChannelRegistered` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelRegistered(context: ChannelHandlerContext)

    /// Called when the `RpcChannel` has unregistered from its `EventLoop`, and so will no longer be receiving I/O events.
    ///
    /// This should call `context.fireChannelUnregistered` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelUnregistered(context: ChannelHandlerContext)

    /// Called when the `RpcChannel` has become active, and is able to send and receive data.
    ///
    /// This should call `context.fireChannelActive` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelActive(context: ChannelHandlerContext)

    /// Called when the `RpcChannel` has become inactive and is no longer able to send and receive data`.
    ///
    /// This should call `context.fireChannelInactive` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelInactive(context: ChannelHandlerContext)

    /// Called when some data has been read from the remote peer.
    ///
    /// This should call `context.fireChannelRead` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - data: The data read from the remote peer, wrapped in a `NIOAny`.
    func channelRead(context: ChannelHandlerContext, data: NIOAny)

    /// Called when the `RpcChannel` has completed its current read loop, either because no more data is available to read from the transport at this time, or because the `RpcChannel` needs to yield to the event loop to process other I/O events for other `RpcChannel`s.
    /// If `ChannelOptions.autoRead` is `false` no further read attempt will be made until `ChannelHandlerContext.read` or `RpcChannel.read` is explicitly called.
    ///
    /// This should call `context.fireChannelReadComplete` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelReadComplete(context: ChannelHandlerContext)

    /// The writability state of the `RpcChannel` has changed, either because it has buffered more data than the writability high water mark, or because the amount of buffered data has dropped below the writability low water mark.
    /// You can check the state with `RpcChannel.isWritable`.
    ///
    /// This should call `context.fireChannelWritabilityChanged` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func channelWritabilityChanged(context: ChannelHandlerContext)

    /// Called when a user inbound event has been triggered.
    ///
    /// This should call `context.fireUserInboundEventTriggered` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the event.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - event: The event.
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any)

    /// An error was encountered earlier in the inbound `ChannelPipeline`.
    ///
    /// This should call `context.fireErrorCaught` to forward the operation to the next `_ChannelInboundHandler` in the `ChannelPipeline` if you want to allow the next handler to also handle the error.
    ///
    /// - parameters:
    ///     - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///     - error: The `Error` that was encountered.
    func errorCaught(context: ChannelHandlerContext, error: Error)
}

//  Default implementations for the ChannelHandler protocol
extension ChannelHandler {

    /// Do nothing by default.
    public func handlerAdded(context: ChannelHandlerContext) {
    }

    /// Do nothing by default.
    public func handlerRemoved(context: ChannelHandlerContext) {
    }
}

/// Provides default implementations for all methods defined by `_ChannelOutboundHandler`.
///
/// These default implementations will just call `context.methodName` to forward to the next `_ChannelOutboundHandler` in
/// the `ChannelPipeline` until the operation is handled by the `RpcChannel` itself.
extension _ChannelOutboundHandler {

    public func register(context: ChannelHandlerContext, promise: GRPCPromiseWithStatus?) {
        context.register(promise: promise)
    }

    public func bind(context: ChannelHandlerContext, to address: IpEndPoint, promise: GRPCPromiseWithStatus?) {
        context.bind(to: address, promise: promise)
    }

    public func connect(context: ChannelHandlerContext, to address: IpEndPoint, promise: GRPCPromiseWithStatus?) {
        context.connect(to: address, promise: promise)
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: GRPCPromiseWithStatus?) {
        context.write(data, promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        context.flush()
    }

    public func read(context: ChannelHandlerContext) {
        context.read()
    }

    public func close(context: ChannelHandlerContext, mode: CloseMode, promise: GRPCPromiseWithStatus?) {
        context.close(mode: mode, promise: promise)
    }

    public func triggerUserOutboundEvent(context: ChannelHandlerContext, event: Any, promise: GRPCPromiseWithStatus?) {
        context.triggerUserOutboundEvent(event, promise: promise)
    }
}

/// Provides default implementations for all methods defined by `_ChannelInboundHandler`.
///
/// These default implementations will just `context.fire*` to forward to the next `_ChannelInboundHandler` in
/// the `ChannelPipeline` until the operation is handled by the `RpcChannel` itself.
extension _ChannelInboundHandler {

    public func channelRegistered(context: ChannelHandlerContext) {
        context.fireChannelRegistered()
    }

    public func channelUnregistered(context: ChannelHandlerContext) {
        context.fireChannelUnregistered()
    }

    public func channelActive(context: ChannelHandlerContext) {
        print("_ChannelInboundHandler.channelActive: context.fireChannelActive()")
        context.fireChannelActive()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.fireChannelReadComplete()
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        context.fireChannelWritabilityChanged()
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        context.fireUserInboundEventTriggered(event)
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.fireErrorCaught(error)
    }
}

/// A `RemovableChannelHandler` is a `ChannelHandler` that can be dynamically removed from a `ChannelPipeline` whilst
/// the `RpcChannel` is operating normally.
/// A `RemovableChannelHandler` is required to remove itself from the `ChannelPipeline` (using
/// `ChannelHandlerContext.removeHandler`) as soon as possible.
///
/// - note: When a `RpcChannel` gets torn down, every `ChannelHandler` in the `RpcChannel`'s `ChannelPipeline` will be
///         removed from the `ChannelPipeline`. Those removals however happen synchronously and are not going through
///         the methods of this protocol.
public protocol RemovableChannelHandler: ChannelHandler {
    /// Ask the receiving `RemovableChannelHandler` to remove itself from the `ChannelPipeline` as soon as possible.
    /// The receiving `RemovableChannelHandler` may elect to remove itself sometime after this method call, rather than
    /// immediately, but if it does so it must take the necessary precautions to handle events arriving between the
    /// invocation of this method and the call to `ChannelHandlerContext.removeHandler` that triggers the actual
    /// removal.
    ///
    /// - note: Like the other `ChannelHandler` methods, this method should not be invoked by the user directly. To
    ///         remove a `RemovableChannelHandler` from the `ChannelPipeline`, use `ChannelPipeline.remove`.
    ///
    /// - parameters:
    ///    - context: The `ChannelHandlerContext` of the `RemovableChannelHandler` to be removed from the `ChannelPipeline`.
    ///    - removalToken: The removal token to hand to `ChannelHandlerContext.removeHandler` to trigger the actual
    ///                    removal from the `ChannelPipeline`.
    func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken)
}

extension RemovableChannelHandler {
    // Implements the default behaviour which is to synchronously remove the handler from the pipeline. Thanks to this,
    // stateless `ChannelHandler`s can just use `RemovableChannelHandler` as a marker-protocol and declare themselves
    // as removable without writing any extra code.
    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        precondition(context.handler === self)
        context.leavePipeline(removalToken: removalToken)
    }
}