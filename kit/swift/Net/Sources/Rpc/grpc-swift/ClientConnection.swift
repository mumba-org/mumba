/*
 * Copyright 2019, gRPC Authors All rights reserved.
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
import Foundation
import Base
import ProtocolBuffers

public class ClientConnection : ConnectivityStateDelegate {
  private var connectionManager: ConnectionManager!

  /// HTTP multiplexer from the underlying channel handling gRPC calls.
  internal func startConnecting() {
    self.connectionManager.startConnecting()
  }

  /// The configuration for this client.
  internal let configuration: Configuration

  /// The scheme of the URI for each RPC, i.e. 'http' or 'https'.
  internal let scheme: String

  /// The authority of the URI for each RPC.
  internal let authority: String

  /// A monitor for the connectivity state.
  public var connectivity: ConnectivityStateMonitor!

  private var toActivate: ClientChannel?

  /// The `EventLoop` this connection is using.
  // public var eventLoop: EventLoop {
  //   return self.connectionManager.eventLoop
  // }

  /// Creates a new connection from the given configuration. Prefer using
  /// `ClientConnection.secure(group:)` to build a connection secured with TLS or
  /// `ClientConnection.insecure(group:)` to build a plaintext connection.
  ///
  /// - Important: Users should prefer using `ClientConnection.secure(group:)` to build a connection
  ///   with TLS, or `ClientConnection.insecure(group:)` to build a connection without TLS.
  public init(configuration: Configuration) {
    self.configuration = configuration
    self.scheme = "http"
    self.authority = configuration.target.host

    let monitor = ConnectivityStateMonitor(
      delegate: self)

    self.connectivity = monitor
    self.connectionManager = ConnectionManager(
      configuration: configuration,
      connectivityDelegate: monitor
    )
  }

  public init(host: String, port: Int) {
    self.configuration = Configuration(host: host, port: port)
    self.scheme = "http"//configuration.tls == nil ? "http" : "https"
    self.authority = configuration.target.host

    let monitor = ConnectivityStateMonitor(
      delegate: self
    )

    self.connectivity = monitor
    self.connectionManager = ConnectionManager(
      configuration: configuration,
      connectivityDelegate: monitor)
  }

  /// Closes the connection to the server.
  public func close(_ promise: @escaping GRPCPromiseWithStatus) {
    self.connectionManager.shutdown()
  }

  public func connectivityStateDidChange(from oldState: ConnectivityState, to newState: ConnectivityState) {
    // switch connectionManager.state {
    //   case let .connecting(state):
    //     print("connectivityStateDidChange: connecting")
    //     let channel = state.candidate as? ClientChannel
    //     // mumba: this was being forced here
    //     //channel!.channelActive()
    //   default:
    //     break
    // }
  }

  internal func onTransportCreated<Request, Response>(_ transport: ClientTransport<Request, Response>, _ path: String) {
    print("ClientConnection.onTransportCreated: startConnecting()")
    startConnecting()
    switch connectionManager.state {
      case let .connecting(state):
        //print("ClientConnection.onTransportCreated: connecting")
        let channel = state.candidate as? ClientChannel
        channel!.pipeline.addHandler(transport)
        toActivate = channel
        RpcSocket.connect(delegate: channel!, host: "127.0.0.1", port: 8081, path: path, self.onRpcConnection)
      default:
        break
    }
  }

  private func onRpcConnection(_ socket: RpcSocket?) {
    if let s = socket {
      toActivate!.onClientConnection(socket: s)
      toActivate!.channelActive()
    }
  }

  /// Populates the logger in `options` and appends a request ID header to the metadata, if
  /// configured.
  /// - Parameter options: The options containing the logger to populate.
  private func populateLogger(in options: inout CallOptions) {
    // Get connection metadata.
    //self.connectionManager.appendMetadata(to: &options.logger)

    // Attach a request ID.
    let requestID = options.requestIDProvider.requestID()
    if let requestID = requestID {
      //options.logger[metadataKey: MetadataKey.requestID] = "\(requestID)"
      // Add the request ID header too.
      if let requestIDHeader = options.requestIDHeader {
        try! options.customMetadata.add(key: requestIDHeader, value: requestID)
      }
    }
  }
}

extension ClientConnection: GRPCChannel {
  public func makeCall<Request: GeneratedMessageProtocol, Response: GeneratedMessageProtocol>(
    path: String,
    type: GRPCCallType,
    callOptions: CallOptions,
    interceptors: [ClientInterceptor<Request, Response>]
  ) -> RpcCall<Request, Response> {
    var options = callOptions
    self.populateLogger(in: &options)
    //startConnecting()
    return RpcCall(
      client: self,
      path: path,
      type: type,
      options: options,
      interceptors: interceptors,
      transportFactory: .http2(
        authority: self.authority,
        scheme: self.scheme,
        errorDelegate: self.configuration.errorDelegate
      )
    )
  }

  public func makeCall<Request: GRPCPayload, Response: GRPCPayload>(
    path: String,
    type: GRPCCallType,
    callOptions: CallOptions,
    interceptors: [ClientInterceptor<Request, Response>]
  ) -> RpcCall<Request, Response> {
    var options = callOptions
    self.populateLogger(in: &options)
   // startConnecting()
    return RpcCall(
      client: self,
      path: path,
      type: type,
      options: options,
      interceptors: interceptors,
      transportFactory: .http2(
        authority: self.authority,
        scheme: self.scheme,
        errorDelegate: self.configuration.errorDelegate
      )
    )
  }
}

// MARK: - Configuration structures

/// A target to connect to.
public struct ConnectionTarget {
  internal enum Wrapped {
    case hostAndPort(String, Int)
    case unixDomainSocket(String)
    case socketAddress(IpEndPoint)
  }

  internal var wrapped: Wrapped
  private init(_ wrapped: Wrapped) {
    self.wrapped = wrapped
  }

  /// The host and port.
  public static func hostAndPort(_ host: String, _ port: Int) -> ConnectionTarget {
    return ConnectionTarget(.hostAndPort(host, port))
  }

  /// The path of a Unix domain socket.
  public static func unixDomainSocket(_ path: String) -> ConnectionTarget {
    return ConnectionTarget(.unixDomainSocket(path))
  }

  /// A NIO socket address.
  public static func socketAddress(_ address: IpEndPoint) -> ConnectionTarget {
    return ConnectionTarget(.socketAddress(address))
  }

  var host: String {
    switch self.wrapped {
    case let .hostAndPort(host, _):
      return host
    case let .socketAddress(_):
      //FIXME
      return "localhost"
    case .unixDomainSocket:
      return "localhost"
    }
  }

  var port: Int {
    switch self.wrapped {
    case let .hostAndPort(_, port):
      return port
    case let .socketAddress(_):
      //FIXME
      return -1
    case .unixDomainSocket:
      return -1
    }
  }
}

/// The connectivity behavior to use when starting an RPC.
public struct CallStartBehavior: Hashable {
  internal enum Behavior: Hashable {
    case waitsForConnectivity
    case fastFailure
  }

  internal var wrapped: Behavior
  private init(_ wrapped: Behavior) {
    self.wrapped = wrapped
  }

  /// Waits for connectivity (that is, the 'ready' connectivity state) before attempting to start
  /// an RPC. Doing so may involve multiple connection attempts.
  ///
  /// This is the preferred, and default, behaviour.
  public static let waitsForConnectivity = CallStartBehavior(.waitsForConnectivity)

  /// The 'fast failure' behaviour is intended for cases where users would rather their RPC failed
  /// quickly rather than waiting for an active connection. The behaviour depends on the current
  /// connectivity state:
  ///
  /// - Idle: a connection attempt will be started and the RPC will fail if that attempt fails.
  /// - Connecting: a connection attempt is already in progress, the RPC will fail if that attempt
  ///     fails.
  /// - Ready: a connection is already active: the RPC will be started using that connection.
  /// - Transient failure: the last connection or connection attempt failed and gRPC is waiting to
  ///     connect again. The RPC will fail immediately.
  /// - Shutdown: the connection is shutdown, the RPC will fail immediately.
  public static let fastFailure = CallStartBehavior(.fastFailure)
}

extension ClientConnection {
  /// Configuration for a `ClientConnection`. Users should prefer using one of the
  /// `ClientConnection` builders: `ClientConnection.secure(_:)` or `ClientConnection.insecure(_:)`.
  public struct Configuration {
    /// The target to connect to.
    public var target: ConnectionTarget

    /// The event loop group to run the connection on.
    //public var eventLoopGroup: EventLoopGroup

    /// An error delegate which is called when errors are caught. Provided delegates **must not
    /// maintain a strong reference to this `ClientConnection`**. Doing so will cause a retain
    /// cycle. Defaults to `LoggingClientErrorDelegate`.
    public var errorDelegate: ClientErrorDelegate?

    /// A delegate which is called when the connectivity state is changed. Defaults to `nil`.
    public var connectivityStateDelegate: ConnectivityStateDelegate?

    /// The `DispatchQueue` on which to call the connectivity state delegate. If a delegate is
    /// provided but the queue is `nil` then one will be created by gRPC. Defaults to `nil`.
    //public var connectivityStateDelegateQueue: DispatchQueue?

    /// TLS configuration for this connection. `nil` if TLS is not desired.
   // public var tls: TLS?

    /// The connection backoff configuration. If no connection retrying is required then this should
    /// be `nil`.
    public var connectionBackoff: ConnectionBackoff? = ConnectionBackoff()

    /// The connection keepalive configuration.
    public var connectionKeepalive = ClientConnectionKeepalive()

    /// The amount of time to wait before closing the connection. The idle timeout will start only
    /// if there are no RPCs in progress and will be cancelled as soon as any RPCs start.
    ///
    /// If a connection becomes idle, starting a new RPC will automatically create a new connection.
    ///
    /// Defaults to 30 minutes.
    public var connectionIdleTimeout: TimeDelta = TimeDelta(seconds: 30 * 60)

    /// The behavior used to determine when an RPC should start. That is, whether it should wait for
    /// an active connection or fail quickly if no connection is currently available.
    ///
    /// Defaults to `waitsForConnectivity`.
    public var callStartBehavior: CallStartBehavior = .waitsForConnectivity

    /// The HTTP/2 flow control target window size. Defaults to 65535.
   // public var httpTargetWindowSize = 65535

    /// The HTTP protocol used for this connection.
    // public var httpProtocol: HTTP2FramePayloadToHTTP1ClientCodec.HTTPProtocol {
    //   return self.tls == nil ? .http : .https
    // }

    /// A logger for background information (such as connectivity state). A separate logger for
    /// requests may be provided in the `CallOptions`.
    ///
    /// Defaults to a no-op logger.
    // public var backgroundActivityLogger = Logger(
    //   label: "io.grpc",
    //   factory: { _ in SwiftLogNoOpLogHandler() }
    // )

    // /// A channel initializer which will be run after gRPC has initialized each channel. This may be
    // /// used to add additional handlers to the pipeline and is intended for debugging.
    // ///
    // /// - Warning: The initializer closure may be invoked *multiple times*.
    // public var debugChannelInitializer: ((RpcChannel) -> EventLoopFuture<Void>)?


    private init(target: ConnectionTarget) {
      //self.eventLoopGroup = eventLoopGroup
      self.target = target
    }

    public init(host: String, port: Int) {
      //self.eventLoopGroup = eventLoopGroup
      self.target =  ConnectionTarget.hostAndPort(host, port)
    }

    /// Make a new configuration using default values.
    ///
    /// - Parameters:
    ///   - target: The target to connect to.
    ///   - eventLoopGroup: The `EventLoopGroup` providing an `EventLoop` for the connection to
    ///       run on.
    /// - Returns: A configuration with default values set.
    public static func `default`(
      target: ConnectionTarget//,
      //eventLoopGroup: EventLoopGroup
    ) -> Configuration {
      return .init(target: target)
    }
  }
}

// MARK: - Configuration helpers/extensions

//extension ClientBootstrapProtocol {
  /// Connect to the given connection target.
  ///
  /// - Parameter target: The target to connect to.
  // func connect(to target: ConnectionTarget) -> RpcChannel {
  //   switch target.wrapped {
  //   case let .hostAndPort(host, port):
  //     return self.connect(host: host, port: port)

  //   case let .unixDomainSocket(path):
  //     return self.connect(unixDomainSocketPath: path)

  //   case let .socketAddress(address):
  //     return self.connect(to: address)
  //   }
  // }
//}

extension ChannelPipeline.SynchronousOperations {
  internal func configureGRPCClient(
    channel: RpcChannel,
    connectionManager: ConnectionManager,
    connectionKeepalive: ClientConnectionKeepalive,
    connectionIdleTimeout: TimeDelta,
    errorDelegate: ClientErrorDelegate?
  ) throws {
    print("ChannelPipeline.SynchronousOperations.configureGRPCClient")
    // #if canImport(Network)
    // // This availability guard is arguably unnecessary, but we add it anyway.
    // if requiresZeroLengthWriteWorkaround,
    //   #available(OSX 10.14, iOS 12.0, tvOS 12.0, watchOS 6.0, *) {
    //   try self.addHandler(NIOFilterEmptyWritesHandler())
    // }
    // #endif

    // if let sslContext = try sslContext?.get() {
    //   let sslClientHandler: NIOSSLClientHandler
    //   if let customVerificationCallback = customVerificationCallback {
    //     sslClientHandler = try NIOSSLClientHandler(
    //       context: sslContext,
    //       serverHostname: tlsServerHostname,
    //       customVerificationCallback: customVerificationCallback
    //     )
    //   } else {
    //     sslClientHandler = try NIOSSLClientHandler(
    //       context: sslContext,
    //       serverHostname: tlsServerHostname
    //     )
    //   }
    //   try self.addHandler(sslClientHandler)
    //   try self.addHandler(TLSVerificationHandler(logger: logger))
    // }

    // We could use 'configureHTTP2Pipeline' here, but we need to add a few handlers between the
    // two HTTP/2 handlers so we'll do it manually instead.
    // try self.addHandler(NIOHTTP2Handler(mode: .client))

    // let h2Multiplexer = HTTP2StreamMultiplexer(
    //   mode: .client,
    //   channel: channel,
    //   targetWindowSize: httpTargetWindowSize,
    //   inboundStreamInitializer: nil
    // )

    // // The multiplexer is passed through the idle handler so it is only reported on
    // // successful channel activation - with happy eyeballs multiple pipelines can
    // // be constructed so it's not safe to report just yet.

    // try self.addHandler(h2Multiplexer)
    // try self.addHandler(DelegatingErrorHandler(delegate: errorDelegate))



    // try self.addHandler(GRPCIdleHandler(
    //   connectionManager: connectionManager,
    //   //multiplexer: h2Multiplexer,
    //   idleTimeout: connectionIdleTimeout,
    //   keepalive: connectionKeepalive
    // ))
  }

}

// extension RpcChannel {
//   func configureGRPCClient(
//     errorDelegate: ClientErrorDelegate?
//   ) -> GRPCPromise {
//     return self.configureHTTP2Pipeline(mode: .client, inboundStreamInitializer: nil).flatMap { _ in
//       self.pipeline.addHandler(DelegatingErrorHandler(delegate: errorDelegate))
//     }
//   }
// }

// extension TimeAmount {
//   /// Creates a new `TimeAmount` from the given time interval in seconds.
//   ///
//   /// - Parameter timeInterval: The amount of time in seconds
//   static func seconds(timeInterval: TimeInterval) -> TimeAmount {
//     return .nanoseconds(Int64(timeInterval * 1_000_000_000))
//   }
// }

extension String {
  var isIPAddress: Bool {
    // We need some scratch space to let inet_pton write into.
    var ipv4Addr = in_addr()
    var ipv6Addr = in6_addr()

    return self.withCString { ptr in
      inet_pton(AF_INET, ptr, &ipv4Addr) == 1 ||
        inet_pton(AF_INET6, ptr, &ipv6Addr) == 1
    }
  }
}
