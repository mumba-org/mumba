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

import Dispatch
import Foundation
import ProtocolBuffers
import Base

public protocol StreamSending {
  associatedtype SentType: GeneratedMessageProtocol
  
  //var callId: Int { get }
  var handler: RpcHandler { get }
}

extension StreamSending {

  public func send(_ message: SentType, callId: Int, completion: ((Error?) -> Void)?) throws {
    try handler.sendMessage(callId: callId, data: message.data(), method: .serverStream, completion: completion)
  }
  
  public func _send(_ message: SentType, callId: Int, timeout: TimeDelta) throws {
    var resultError: Error?
    let sem = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)//DispatchSemaphore(value: 0)
    try send(message, callId: callId) {
      resultError = $0
      sem.signal()
    }

    if sem.timedWait(waitDelta: timeout) {
      throw RpcError.timedOut 
    }
    if let resultError = resultError {
      throw resultError
    }
  }
  
  public func waitForSendOperationsToFinish() {
    //call.messageQueueEmpty.wait()
  }
}

//extension StreamSending where Self: ServerSessionBase {
//  public func close(withStatus status: ServerStatus = .ok, completion: (() -> Void)? = nil) throws {
//    try handler.sendStatus(status, completion: completion)
//  }
//}
