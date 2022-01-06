// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum IOError : Error {
  case unitialized(String)
  case notConnected(String)
  case taskSchedulerNotInitialized(String)
}

// public enum RpcError : Error, Equatable {
//   case notHandledMethodTypeError(String)
// }

// extension RpcError : CustomStringConvertible {
//   public var description: String {
//     switch self {
//       case .notHandledMethodTypeError(let m): return "notHandledMethodType: \(m)"
//     }
//   }
// }