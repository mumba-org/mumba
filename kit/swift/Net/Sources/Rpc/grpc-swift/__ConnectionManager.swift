internal final class ConnectionManager {

  public init() {}


  public func shutdown(_ promise: GRPCPromiseWithStatus?) {

  }
}

internal protocol ConnectionManagerConnectivityDelegate {
  /// The state of the connection changed.
  ///
  /// - Parameters:
  ///   - connectionManager: The connection manager reporting the change of state.
  ///   - oldState: The previous `ConnectivityState`.
  ///   - newState: The current `ConnectivityState`.
  func connectionStateDidChange(
    _ connectionManager: ConnectionManager,
    from oldState: ConnectivityState,
    to newState: ConnectivityState
  )

  /// The connection is quiescing.
  ///
  /// - Parameters:
  ///   - connectionManager: The connection manager whose connection is quiescing.
  func connectionIsQuiescing(_ connectionManager: ConnectionManager)
}