// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum StatusCode : Int {
  case Unknown = -1
  case Ok = 0
  case Failed = 1
}

public struct Status {
  public let code: StatusCode
  public let message: String

  public static func OK() -> Status {
    return Status(code: StatusCode.Ok, message: "")
  }
  
  public static func OK(message: String) -> Status {
    return Status(code: StatusCode.Ok, message: message)
  }

  public static func Failed(message: String) -> Status {
    return Status(code: StatusCode.Failed, message: message)
  }

  public var isOk: Bool {
    return code == StatusCode.Ok
  }

}
