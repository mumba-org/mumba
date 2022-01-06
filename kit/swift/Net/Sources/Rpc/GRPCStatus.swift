public struct GRPCStatus {
  public var code: StatusCode = .ok
  public var message: String = String()

  public static let ok = GRPCStatus(code: .ok, message: "OK")
  public static let cancelled = GRPCStatus(code: .cancelled, message: "Cancelled")
  public static let unknown = GRPCStatus(code: .unknown, message: "Unknown Status")
}

extension GRPCStatus: Equatable {
  public static func == (lhs: GRPCStatus, rhs: GRPCStatus) -> Bool {
    return lhs.code == rhs.code && lhs.message == rhs.message
  }
}

extension GRPCStatus: CustomStringConvertible {
  public var description: String {
    if !message.isEmpty {
      return "\(self.code): \(message)"
    } else {
      return "\(self.code)"
    }
  }
}

/// This protocol serves as a customisation point for error types so that gRPC calls may be
/// terminated with an appropriate status.
public protocol GRPCStatusTransformable: Error {
  /// Make a `GRPCStatus` from the underlying error.
  ///
  /// - Returns: A `GRPCStatus` representing the underlying error.
  func makeGRPCStatus() -> GRPCStatus
}

extension GRPCStatus: GRPCStatusTransformable {
  public func makeGRPCStatus() -> GRPCStatus {
    return self
  }
}
