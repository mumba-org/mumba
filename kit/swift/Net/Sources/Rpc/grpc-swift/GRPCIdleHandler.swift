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

import Base

internal final class GRPCIdleHandler: ChannelInboundHandler {
  //typealias InboundIn = HTTP2Frame
  //typealias OutboundOut = HTTP2Frame

  typealias InboundIn = ByteBuffer
  typealias OutboundOut = ByteBuffer

  /// The amount of time to wait before closing the channel when there are no active streams.
  private let idleTimeout: TimeDelta

  /// The ping handler.
  //private var pingHandler: PingHandler

  /// The scheduled task which will close the connection after the keep-alive timeout has expired.
  //private var scheduledClose: Scheduled<Void>?

  /// The scheduled task which will ping.
 // private var scheduledPing: RepeatedTask?

  /// The mode we're operating in.
  private let mode: Mode

  private var context: ChannelHandlerContext?

  /// The mode of operation: the client tracks additional connection state in the connection
  /// manager.
  internal enum Mode {
    //case client(ConnectionManager, HTTP2StreamMultiplexer)
    case client(ConnectionManager)
    case server

    var connectionManager: ConnectionManager? {
      switch self {
      //case let .client(manager, _):
      case let .client(manager):
        return manager
      case .server:
        return nil
      }
    }
  }

  /// The current state.
  //private var stateMachine: GRPCIdleHandlerStateMachine

  init(
    connectionManager: ConnectionManager,
    //multiplexer: HTTP2StreamMultiplexer,
    idleTimeout: TimeDelta,
    keepalive configuration: ClientConnectionKeepalive
  ) {
    self.mode = .client(connectionManager)//, multiplexer)
    self.idleTimeout = idleTimeout
    // self.stateMachine = .init(role: .client, logger: logger)
    // self.pingHandler = PingHandler(
    //   pingCode: 5,
    //   interval: configuration.interval,
    //   timeout: configuration.timeout,
    //   permitWithoutCalls: configuration.permitWithoutCalls,
    //   maximumPingsWithoutData: configuration.maximumPingsWithoutData,
    //   minimumSentPingIntervalWithoutData: configuration.minimumSentPingIntervalWithoutData
    // )
  }

  // init(
  //   idleTimeout: TimeAmount,
  //   keepalive configuration: ServerConnectionKeepalive,
  // ) {
  //   self.mode = .server
  //   self.stateMachine = .init(role: .server)
  //   self.idleTimeout = idleTimeout
  //   self.pingHandler = PingHandler(
  //     pingCode: 10,
  //     interval: configuration.interval,
  //     timeout: configuration.timeout,
  //     permitWithoutCalls: configuration.permitWithoutCalls,
  //     maximumPingsWithoutData: configuration.maximumPingsWithoutData,
  //     minimumSentPingIntervalWithoutData: configuration.minimumSentPingIntervalWithoutData,
  //     minimumReceivedPingIntervalWithoutData: configuration.minimumReceivedPingIntervalWithoutData,
  //     maximumPingStrikes: configuration.maximumPingStrikes
  //   )
  // }

  func channelActive(context: ChannelHandlerContext) {
    print("GRPCIdleHandler.channelActive")
    // No state machine action here.
    switch self.mode {
    case let .client(connectionManager):
      connectionManager.channelActive(channel: context.channel)
    case .server:
      ()
    }
    context.fireChannelActive()
  }

  func channelInactive(context: ChannelHandlerContext) {
    print("GRPCIdleHandler.channelInactive")
    //self.perform(operations: self.stateMachine.channelInactive())
    // self.scheduledPing?.cancel()
    // self.scheduledClose?.cancel()
    // self.scheduledPing = nil
    // self.scheduledClose = nil
    context.fireChannelInactive()
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    print("GRPCIdleHandler.channelRead")
    // let frame = self.unwrapInboundIn(data)

    // switch frame.payload {
    // case .goAway:
    //   self.perform(operations: self.stateMachine.receiveGoAway())
    // case let .settings(.settings(settings)):
    //   self.perform(operations: self.stateMachine.receiveSettings(settings))
    // case let .ping(data, ack):
    //   self.handlePingAction(self.pingHandler.read(pingData: data, ack: ack))
    // default:
    //   // We're not interested in other events.
    //   ()
    // }

    // context.fireChannelRead(data)
  }

}