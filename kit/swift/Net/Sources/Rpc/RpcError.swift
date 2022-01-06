// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

// public struct RpcCallResult: CustomStringConvertible {
//   public let success: Bool
//   public let statusCode: StatusCode
//   public let statusMessage: String?
//   //public let resultData: Data?
//   public let resultData: Data?
//   public let initialMetadata: RpcMetadata?
//   public let trailingMetadata: RpcMetadata?
  
//   init(_ op: RpcOperationGroup) {
//     success = op.success
//     if let statusCodeRawValue = op.receivedStatusCode(),
//       let statusCode = StatusCode(rawValue: statusCodeRawValue) {
//       self.statusCode = statusCode
//     } else {
//       statusCode = .unknown
//     }
//     statusMessage = op.receivedStatusMessage()
//     //resultData = op.receivedMessage()?.data()
//     resultData = op.receivedMessage()
//     initialMetadata = op.receivedInitialMetadata()
//     trailingMetadata = op.receivedTrailingMetadata()
//   }
  
//   fileprivate init(success: Bool, statusCode: StatusCode, statusMessage: String?, resultData: Data?,
//                    initialMetadata: RpcMetadata?, trailingMetadata: RpcMetadata?) {
//     self.success = success
//     self.statusCode = statusCode
//     self.statusMessage = statusMessage
//     self.resultData = resultData
//     self.initialMetadata = initialMetadata
//     self.trailingMetadata = trailingMetadata
//   }
  
//   public var description: String {
//     var result = "\(success ? "successful" : "unsuccessful"), status \(statusCode)"
//     if let statusMessage = self.statusMessage {
//       result += ": " + statusMessage
//     }
//     if let resultData = self.resultData {
//       result += "\nresultData: "
//       result += resultData.description
//     }
//     if let initialMetadata = self.initialMetadata {
//       result += "\ninitialMetadata: "
//       result += initialMetadata.dictionaryRepresentation.description
//     }
//     if let trailingMetadata = self.trailingMetadata {
//       result += "\ntrailingMetadata: "
//       result += trailingMetadata.dictionaryRepresentation.description
//     }
//     return result
//   }
  
//   static let fakeOK = RpcCallResult(success: true, statusCode: .ok, statusMessage: "OK", resultData: nil,
//                                  initialMetadata: nil, trailingMetadata: nil)
// }

/// Type for errors thrown from generated client code.
public enum RpcError: Error {
  case invalidMessageReceived
  case timedOut
  case writeError
  //case callError(RpcCallResult)
}

// public extension RpcError {
//   var callResult: RpcCallResult? {
//     switch self {
//     case .invalidMessageReceived, .timedOut, .writeError: return nil
//     case .callError(let callResult): return callResult
//     }
//   }
// }


public enum ResultOrRpcError<ResultType> {
  case result(ResultType)
  case error(RpcError)
}

public extension ResultOrRpcError {
  var result: ResultType? {
    switch self {
    case .result(let result): return result
    case .error: return nil
    }
  }
  
  var error: RpcError? {
    switch self {
    case .result: return nil
    case .error(let error): return error
    }
  }
}

