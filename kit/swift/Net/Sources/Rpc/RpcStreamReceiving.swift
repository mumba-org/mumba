/*
 * Copyright 2018, gRpc Authors All rights reserved.
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

import Base
import Foundation
import ProtocolBuffers

public protocol StreamReceiving {
  associatedtype ReceivedType: GeneratedMessageProtocol
  
  //var callId: Int { get }
  var handler: RpcHandler { get }
}

extension StreamReceiving {
  public func receive(callId: Int, completion: @escaping (ResultOrRpcError<ReceivedType?>) -> Void) throws {
    //try call.receiveMessage { callResult in 
    try handler.receiveMessage(callId: callId, method: .serverStream) { resultData in //callResult in
      guard let responseData = resultData else {
        //if callResult.success {
        completion(.result(nil))
        //} else {
        //  completion(.error(.callError(callResult)))
        //}
        return
      }
      if let response = try? ReceivedType.parseFrom(data: responseData) {//(serializedData: responseData) {
        completion(.result(response))
      } else {
        completion(.error(.invalidMessageReceived))
      }
    }
  }

  // public func receive(callId: Int, completion: @escaping (ResultOrRpcError<ReceivedType?>) -> Void) throws {
  //   //print("*FIXME* using receive without call id. probably it will not work. *FIXME*")
  //   return try receive(callId: callId, completion: completion)
  // }
  
  public func _receive(callId: Int, timeout: TimeDelta) throws -> ReceivedType? {
    var result: ResultOrRpcError<ReceivedType?>?
    let sem = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    try receive(callId: callId) {
      result = $0
      sem.signal()
    }
    if sem.timedWait(waitDelta: timeout) {
      throw RpcError.timedOut
    }
    switch result! {
    case .result(let response): return response
    case .error(let error): throw error
    }
  }

  // public func _receive(callId: Int, timeout: TimeDelta) throws -> ReceivedType? {
  //   //print("*FIXME* using _receive without call id. probably it will not work. *FIXME*")
  //   return try _receive(callId: callId, timeout: timeout)
  // }
}
