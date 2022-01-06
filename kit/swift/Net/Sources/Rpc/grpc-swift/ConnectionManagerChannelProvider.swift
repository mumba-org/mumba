/*
 * Copyright 2021, gRPC Authors All rights reserved.
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

internal protocol ConnectionManagerChannelProvider {
  /// Make an `EventLoopFuture<RpcChannel>`.
  ///
  /// - Parameters:
  ///   - connectionManager: The `ConnectionManager` requesting the `RpcChannel`.
  ///   - eventLoop: The `EventLoop` to use for the`RpcChannel`.
  ///   - connectTimeout: Optional connection timeout when starting the connection.
  ///   - logger: A logger.
  func makeChannel(
    managedBy connectionManager: ConnectionManager,
    connectTimeout: TimeDelta?
  ) -> RpcChannel?
}

internal struct DefaultChannelProvider: ConnectionManagerChannelProvider {
  internal var connectionTarget: ConnectionTarget
  internal var connectionKeepalive: ClientConnectionKeepalive
  internal var connectionIdleTimeout: TimeDelta

  internal var errorDelegate: Optional<ClientErrorDelegate>
  
  internal init(
    connectionTarget: ConnectionTarget,
    connectionKeepalive: ClientConnectionKeepalive,
    connectionIdleTimeout: TimeDelta,
    errorDelegate: ClientErrorDelegate?) {
    self.connectionTarget = connectionTarget
    self.connectionKeepalive = connectionKeepalive
    self.connectionIdleTimeout = connectionIdleTimeout
    self.errorDelegate = errorDelegate
  }

  internal init(configuration: ClientConnection.Configuration) {
    // Making a `NIOSSLContext` is expensive and we should only do it (at most) once per TLS
    // configuration. We do it now and surface any error during channel creation (we're limited by
    // our API in when we can throw any error).
    self.init(
      connectionTarget: configuration.target,
      connectionKeepalive: configuration.connectionKeepalive,
      connectionIdleTimeout: configuration.connectionIdleTimeout,
      errorDelegate: configuration.errorDelegate
    )
  }

  private var serverHostname: String? {
    let hostname = self.connectionTarget.host
    return hostname.isIPAddress ? nil : hostname
  }

  private var hasTLS: Bool {
    return false//self.sslContext != nil
  }

  // private func requiresZeroLengthWorkaround(eventLoop: EventLoop) -> Bool {
  //   return PlatformSupport.requiresZeroLengthWriteWorkaround(group: eventLoop, hasTLS: self.hasTLS)
  // }

  internal func makeChannel(
    managedBy connectionManager: ConnectionManager,
    connectTimeout: TimeDelta?
  ) -> RpcChannel? {
    print("DefaultChannelProvider.makeChannel")
    //let hostname = self.serverHostname
    let bootstrap = ClientBootstrap(connectionManager: connectionManager)
    bootstrap.onChannelInitialize { channel in
      let sync = channel.pipeline.syncOperations
      try! sync.configureGRPCClient(
        channel: channel,
        connectionManager: connectionManager,
        connectionKeepalive: self.connectionKeepalive,
        connectionIdleTimeout: self.connectionIdleTimeout,
        errorDelegate: self.errorDelegate
      )
    }
        
    // if let connectTimeout = connectTimeout {
    //   _ = bootstrap.connectTimeout(connectTimeout)
    // }

    return bootstrap.connect(to: self.connectionTarget)
  }
}

public protocol ClientBootstrapProtocol {
  func onChannelInitialize(_ initializer: @escaping (_: RpcChannel) -> Void)
  func connect(to: IpEndPoint) -> RpcChannel?
  func connect(to: ConnectionTarget) -> RpcChannel?
  func connect(host: String, port: Int) -> RpcChannel?
}


public typealias ClientBootstrapInitializer = (_: RpcChannel) -> Void

public class ClientBootstrap : ClientBootstrapProtocol {

  private var initializer: ClientBootstrapInitializer?
  private var channel: ClientChannel?
  private var connectionManager: ConnectionManager

  public init(connectionManager: ConnectionManager) {
    self.connectionManager = connectionManager
  }
  
  public func connect(to: IpEndPoint) -> RpcChannel? {
    self.channel = ClientChannel(connectionManager: connectionManager)
    initializer?(channel!)
    return channel
  }
  
  public func connect(host: String, port: Int) -> RpcChannel? {
    self.channel = ClientChannel(connectionManager: connectionManager)
    initializer?(channel!)
    return channel
  }

  public func connect(to: ConnectionTarget) -> RpcChannel? {
    print("ClientBootstrap.connect: \(to.host) \(to.port)")
    self.channel = ClientChannel(connectionManager: connectionManager)
    initializer?(channel!)
    return channel
  }

  public func onChannelInitialize(_ initializer: @escaping ClientBootstrapInitializer) {
    self.initializer = initializer
  }

}
