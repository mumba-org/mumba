// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct ServerStatus: Error {
  public let code: StatusCode
  public let message: String
  public let trailingMetadata: RpcMetadata

  public init(code: StatusCode, message: String, trailingMetadata: RpcMetadata = RpcMetadata()) {
    self.code = code
    self.message = message
    self.trailingMetadata = trailingMetadata
  }

  public static let ok = ServerStatus(code: .ok, message: "OK")
  public static let unknown = ServerStatus(code: .unknown, message: "Unknown")
  public static let processingError = ServerStatus(code: .internalError, message: "unknown error processing request")
  public static let noRequestData = ServerStatus(code: .invalidArgument, message: "no request data received")
  public static let sendingInitialMetadataFailed = ServerStatus(code: .internalError, message: "sending initial metadata failed")
}