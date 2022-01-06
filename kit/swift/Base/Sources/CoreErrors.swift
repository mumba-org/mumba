// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct RuntimeException {
  public let code: Int
  public let message: String

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}

public struct SystemException {
  public let code: Int
  public let function: String

  public init(code: Int, function: String) {
    self.code = code
    self.function = function
  }
}

public enum RuntimeError : Error {
  case Unknown(code: Int, message: String)
  case IOMessagePumpInitError(code: Int, message: String)
  case MessageLoopAlreadySet(code: Int, message: String)
}

public enum SystemError : Error {
  case OSError(code: Int32, function: String)
  case IOError(code: Int32, reason: String)
}
