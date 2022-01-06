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

import Base

/// A `DeadChannelCore` is a `ChannelCore` for a `DeadChannel`. A `DeadChannel` is used as a replacement `RpcChannel` when
/// the original `RpcChannel` is closed. Given that the original `RpcChannel` is closed the `DeadChannelCore` should fail
/// all operations.
private final class DeadChannelCore: ChannelCore {
    func localAddress0() throws -> IpEndPoint {
        throw ChannelError.ioOnClosedChannel
    }

    func remoteAddress0() throws -> IpEndPoint {
        throw ChannelError.ioOnClosedChannel
    }

    func register0(promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func registerAlreadyConfigured0(promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func bind0(to: IpEndPoint, promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func connect0(to: IpEndPoint, promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func write0(_ data: NIOAny, promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func flush0() {
    }

    func read0() {
    }

    func close0(error: Error, mode: CloseMode, promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.alreadyClosed.makeGRPCStatus())
    }

    func triggerUserOutboundEvent0(_ event: Any, promise: GRPCPromiseWithStatus?) {
        promise?(ChannelError.ioOnClosedChannel.makeGRPCStatus())
    }

    func channelRead0(_ data: NIOAny) {
        // a `DeadChannel` should never be in any running `ChannelPipeline` and therefore the `TailChannelHandler`
        // should never invoke this.
        fatalError("\(#function) called on DeadChannelCore")
    }

    func errorCaught0(error: Error) {
        // a `DeadChannel` should never be in any running `ChannelPipeline` and therefore the `TailChannelHandler`
        // should never invoke this.
        fatalError("\(#function) called on DeadChannelCore")
    }
}

/// This represents a `RpcChannel` which is already closed and therefore all the operations do fail.
/// A `ChannelPipeline` that is associated with a closed `RpcChannel` must be careful to no longer use that original
/// channel as it only holds an unowned reference to the original `RpcChannel`. `DeadChannel` serves as a replacement
/// that can be used when the original `RpcChannel` might no longer be valid.
internal final class DeadChannel: RpcChannel {
    
    let pipeline: ChannelPipeline

    internal init(pipeline: ChannelPipeline) {
        self.pipeline = pipeline
    }

    // This is `RpcChannel` API so must be thread-safe.
    var allocator: ByteBufferAllocator {
        return ByteBufferAllocator()
    }

    var localAddress: IpEndPoint? {
        return nil
    }

    var remoteAddress: IpEndPoint? {
        return nil
    }

    let parent: RpcChannel? = nil

    func setOption<Option: ChannelOption>(_ option: Option, value: Option.Value)  {
        
    }

    func getOption<Option: ChannelOption>(_ option: Option) -> Option.Value? {
        return nil
    }

    func write(_: NIOAny, promise: GRPCPromiseWithStatus?) {}

    func close() {}

    func close(mode: CloseMode, promise: GRPCPromiseWithStatus?) {}

    func flush() {}

    func fail(_ : GRPCStatus) {}

    let isWritable = false
    let isActive = false
    let _channelCore: ChannelCore = DeadChannelCore()
}
