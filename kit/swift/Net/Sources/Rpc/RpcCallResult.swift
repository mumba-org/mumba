/*
 * Copyright 2016, gRPC Authors All rights reserved.
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
import MumbaShims
import Dispatch
import Foundation

public struct RpcCallResult: CustomStringConvertible {
  public let success: Bool
  public let statusCode: StatusCode
  public let statusMessage: String?
  public let resultData: Data?
  public let initialMetadata: RpcMetadata?
  public let trailingMetadata: RpcMetadata?

  public static func error(
    statusCode: StatusCode = .unknown,
    statusMessage: String? = nil,
    initialMetadata: RpcMetadata? = nil,
    trailingMetadata: RpcMetadata? = nil
  ) -> RpcCallResult {
    return RpcCallResult(
      success: false,
      statusCode: statusCode,
      statusMessage: statusMessage,
      resultData: nil,
      initialMetadata: initialMetadata,
      trailingMetadata: trailingMetadata)
  }

  public static func success(
    resultData: Data,
    initialMetadata: RpcMetadata? = nil,
    trailingMetadata: RpcMetadata? = nil
  ) -> RpcCallResult {
    return RpcCallResult(
      success: true,
      statusCode: .ok,
      statusMessage: "OK",
      resultData: resultData,
      initialMetadata: initialMetadata,
      trailingMetadata: trailingMetadata)
  }
  
  init(_ op: RpcOperationGroup) {
    success = op.success
    if let statusCodeRawValue = op.receivedStatusCode(),
      let statusCode = StatusCode(rawValue: statusCodeRawValue) {
      self.statusCode = statusCode
    } else {
      statusCode = .unknown
    }
    statusMessage = op.receivedStatusMessage()
    resultData = op.receivedMessage()?.data()
    initialMetadata = op.receivedInitialMetadata()
    trailingMetadata = op.receivedTrailingMetadata()
  }
  
  // This method is only public for use by test stubs. Please do not use for other purposes.
  public init(success: Bool, statusCode: StatusCode, statusMessage: String?, resultData: Data?,
              initialMetadata: RpcMetadata?, trailingMetadata: RpcMetadata?) {
    self.success = success
    self.statusCode = statusCode
    self.statusMessage = statusMessage
    self.resultData = resultData
    self.initialMetadata = initialMetadata
    self.trailingMetadata = trailingMetadata
  }
  
  public var description: String {
    var result = "\(success ? "successful" : "unsuccessful"), status \(statusCode)"
    if let statusMessage = self.statusMessage {
      result += ": " + statusMessage
    }
    if let resultData = self.resultData {
      result += "\nresultData: "
      result += resultData.description
    }
    if let initialMetadata = self.initialMetadata {
      result += "\ninitialMetadata: "
      result += initialMetadata.dictionaryRepresentation.description
    }
    if let trailingMetadata = self.trailingMetadata {
      result += "\ntrailingMetadata: "
      result += trailingMetadata.dictionaryRepresentation.description
    }
    return result
  }
  
  static let fakeOK = RpcCallResult(success: true, statusCode: .ok, statusMessage: "OK", resultData: nil,
                                 initialMetadata: nil, trailingMetadata: nil)
}
