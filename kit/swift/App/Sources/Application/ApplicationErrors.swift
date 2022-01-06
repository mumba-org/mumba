// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct ApplicationException {
  public let code: Int
  public let message: String

  public static let NotEnoughPermissions = ApplicationException(code: 1001, message: "Enter sandbox: not enough permissions")
  public static let ChrootFailed = ApplicationException(code: 1002, message: "Enter sandbox: chroot failed")
  public static let IPCConnectionFailed = ApplicationException(code: 1002, message: "IPC connection: connection failed")

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}

public enum ApplicationError : Error {
  case OnEnterSandbox(exception: ApplicationException)
  case OnIPCConnection(exception: ApplicationException)
}
