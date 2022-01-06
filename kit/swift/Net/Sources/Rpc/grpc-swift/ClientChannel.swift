// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public class ClientChannelCore : ChannelCore {
  public init() {}
  public func localAddress0() throws -> IpEndPoint {
    return IpEndPoint()
  }
  public func remoteAddress0() throws -> IpEndPoint {
    return IpEndPoint()
  }
  public func register0(promise: GRPCPromiseWithStatus?) {}
  public func registerAlreadyConfigured0(promise: GRPCPromiseWithStatus?) {}
  public func bind0(to: IpEndPoint, promise: GRPCPromiseWithStatus?) {}
  public func connect0(to: IpEndPoint, promise: GRPCPromiseWithStatus?) {}
  public func write0(_ data: NIOAny, promise: GRPCPromiseWithStatus?) {}
  public func flush0() {}
  public func read0() {}
  public func close0(error: Error, mode: CloseMode, promise: GRPCPromiseWithStatus?) {}
  public func triggerUserOutboundEvent0(_ event: Any, promise: GRPCPromiseWithStatus?) {}
  public func channelRead0(_ data: NIOAny) {}
  public func errorCaught0(error: Error) {}
}

// A default client channel over IPC
public class ClientChannel : RpcChannel,
                             RpcSocketDelegate {
  
  public var allocator: ByteBufferAllocator
  
  public var localAddress: IpEndPoint? {
    return try! _channelCore.localAddress0()
  }
  
  public var remoteAddress: IpEndPoint? {
    return try! _channelCore.remoteAddress0()
  }
  public var _channelCore: ChannelCore
  public var pipeline: ChannelPipeline {
    return _pipeline!
  }

  public var _pipeline: ChannelPipeline?
  private let connectionManager: ConnectionManager
  private var socket: RpcSocket?
  
  public init(connectionManager: ConnectionManager) {
    allocator = ByteBufferAllocator()
    self.connectionManager = connectionManager
    _channelCore = ClientChannelCore()
    _pipeline = ChannelPipeline(channel: self)
  }

  public func write(_ anyData: NIOAny, promise: GRPCPromiseWithStatus?) {
    print("ClientChannel.write")
    let data: _GRPCClientRequestPart<ByteBuffer> = anyData.forceAsOther(type: _GRPCClientRequestPart<ByteBuffer>.self)
    switch data {
      case let .head(header):
        print("head: path = \(header.path)")
         let headers = self.makeRequestHeaders(
           method: requestHead.method,
           scheme: requestHead.scheme,
           host: requestHead.host,
           path: requestHead.path,
           timeout: GRPCTimeout(deadline: requestHead.deadline),
           customMetadata: requestHead.customMetadata,
           compression: requestHead.encoding)
        // let framePayload = HTTP2Frame.FramePayload.headers(.init(headers: headers))
        // let count = framePayload.readableBytes
        // framePayload.withUnsafeMutableReadableBytes { bytes in
        //   socket?.write(buffer: bytes.baseAddress!.bindMemory(to: UInt8.self, capacity: count), size: count, address: IpEndPoint())
        // }
      case let .message(context):
        var buffer = context.message
        let count = buffer.readableBytes
        buffer.withUnsafeMutableReadableBytes { bytes in
          print("writing:\n'\(bytes.baseAddress!.bindMemory(to: Int8.self, capacity: count))'")
          socket?.write(buffer: bytes.baseAddress!.bindMemory(to: UInt8.self, capacity: count), size: count, address: IpEndPoint())
        }
      case .end:
        socket?.sendStatus(callId: 1, code: ServerStatus.ok)
        //let empty = context.channel.allocator.buffer(capacity: 0)
        // let framePayload = HTTP2Frame.FramePayload
        //   .data(.init(data: .byteBuffer(empty), endStream: true))
        // framePayload.withUnsafeMutableReadableBytes { bytes in
        //   socket?.write(buffer: bytes.baseAddress!.bindMemory(to: UInt8.self, capacity: count), size: count, address: IpEndPoint())
        // }
    }
  }

   private func makeRequestHeaders(
    method: String,
    scheme: String,
    host: String,
    path: String,
    timeout: GRPCTimeout,
    customMetadata: RpcMetadata,
    compression: ClientMessageEncoding
  ) -> RpcMetadata {
    var headers = RpcMetadata()
    // The 10 is:
    // - 6 which are required and added just below, and
    // - 4 which are possibly added, depending on conditions.
    //headers.reserveCapacity(10 + customMetadata.count())

    // Add the required headers.
    try! headers.add(key: ":method", value: method)
    try! headers.add(key: ":path", value: path)
    try! headers.add(key: ":authority", value: host)
    try! headers.add(key: ":scheme", value: scheme)
    try! headers.add(key: "content-type", value: "application/grpc")
    // Used to detect incompatible proxies, part of the gRPC specification.
    try! headers.add(key: "te", value: "trailers")

    switch compression {
    case let .enabled(configuration):
      // Request encoding.
      if let outbound = configuration.outbound {
        try! headers.add(key: GRPCHeaderName.encoding, value: outbound.name)
      }

      // Response encoding.
      if !configuration.inbound.isEmpty {
        try! headers.add(key: GRPCHeaderName.acceptEncoding, value: configuration.acceptEncodingHeader)
      }

    case .disabled:
      ()
    }

    // Add the timeout header, if a timeout was specified.
    if timeout != .infinite {
      try! headers.add(key: GRPCHeaderName.timeout, value: String(describing: timeout))
    }

    // Add user-defined custom metadata: this should come after the call definition headers.
    // TODO: make header normalization user-configurable.
    // headers.add(contentsOf: customMetadata.lazy.map { name, value, indexing in
    //   (name.lowercased(), value, indexing)
    // })

    for (k, v) in customMetadata.dictionaryRepresentation {
      try! headers.add(key: k, value: v)
    }

    // Add default user-agent value, if `customMetadata` didn't contain user-agent
    //if !customMetadata.contains(name: "user-agent") {
    try! headers.add(key: "user-agent", value: GRPCClientStateMachine.userAgent)
    //}

    return headers
  }

  public func close() {
    print("ClientChannel.close")
    try! socket?.close()
  }

  public func close(mode: CloseMode, promise: GRPCPromiseWithStatus?) {
    print("ClientChannel.close")
    try! socket?.close()
    promise?(GRPCStatus.ok)
  }

  public func flush() {
    print("ClientChannel.flush")
  }

  public func fail(_ : GRPCStatus) {
    print("ClientChannel.fail")
  }

  public func channelActive() {
    print("ClientChannel.channelActive")
    // No state machine action here.
    connectionManager.channelActive(channel: self)
    _pipeline!.fireChannelActive()
  }

  public func onClientConnection(socket incoming: RpcSocket) {
    self.socket = incoming
  }
  
  // RPCSocketDelegate
  public func onRpcBegin(socket: RpcSocket, callId: Int, method: String, caller: String, host: String) {
    print("ClientChannel.onRpcBegin")
  }
  
  public func onRpcStreamRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    print("ClientChannel.onRpcStreamRead")
  }
  
  public func onRpcStreamReadEOF(socket: RpcSocket, callId: Int) {
    print("ClientChannel.onRpcStreamReadEOF")
  }
  
  public func onRpcSendMessageAck(socket: RpcSocket, callId: Int, status: StatusCode) {
    print("ClientChannel.onRpcSendMessageAck")
  }
  
  public func onRpcStreamWrite(socket: RpcSocket, callId: Int) {
    print("ClientChannel.onRpcStreamWrite")
  }
   
  public func onRpcUnaryRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    print("ClientChannel.onRpcUnaryRead")
  }
  
  public func onRpcEnd(socket: RpcSocket, callId: Int) {
    print("ClientChannel.onRpcEnd")
  }

}
