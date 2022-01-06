// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base

public class RpcHandler {
  /// Pointer to underlying C representation
  //fileprivate let underlyingHandler: UnsafeMutableRawPointer

  /// Completion queue for handler response operations
  //let completionQueue: CompletionQueue

  /// RpcMetadata received with the request
  public static var messageQueueMaxLength: Int? = nil

  public let requestMetadata: RpcMetadata

  private var receiveMessageCompletion: ((Data?) -> Void)?

  /// A RpcCall object that can be used to respond to the request
  //public private(set) lazy var call: RpcCall = {
  //  RpcCall()//underlyingCall: cgrpc_handler_get_call(self.underlyingHandler),
         //owned: true,
         //completionQueue: self.completionQueue)
  //}()

  /// The host name sent with the request
  public var host: String

  /// The method name sent with the request
  public var method: String

  /// The caller address associated with the request
  public var caller: String

  //public var callId: Int

  public var shouldSendStatus: Bool

  private var socket: RpcSocket

  private var sendMessageSync: WaitableEvent

  //private var messageQueue: [(dataToSend: Data, completion: ((Error?) -> Void)?)] = []
  private var completions: [Int : ((Error?) -> Void)] = [:]

  private var callSendResults: [Int: StatusCode] = [:]

  //private var writing: Bool

  /// Initializes a RpcHandler
  ///
  /// - Parameter underlyingServer: the underlying C representation of the associated server
  init(socket: RpcSocket, method: String, caller: String, host: String) {
    //underlyingHandler = cgrpc_handler_create_with_server(underlyingServer)
    requestMetadata = RpcMetadata()
    self.host = host
    self.caller = caller
    self.method = method
    self.socket = socket
    //self.callId = callId
    self.shouldSendStatus = false
    sendMessageSync = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    //writing = false
    //completionQueue = CompletionQueue(
    //  underlyingCompletionQueue: cgrpc_handler_get_completion_queue(underlyingHandler), name: "RpcHandler")

  }

  //deinit {
    // Technically unnecessary, because the handler only gets released once the completion queue has already been
    // shut down, but it doesn't hurt to keep this here.
    //completionQueue.shutdown()
    //cgrpc_handler_destroy(self.underlyingHandler)
  //}

  /// Requests a call for the handler
  ///
  /// Fills the handler properties with information about the received request
  ///
  func requestCall(tag: Int) throws {
    //let error = cgrpc_handler_request_call(underlyingHandler,
    //                                       try requestMetadata.getUnderlyingArrayAndTransferFieldOwnership(),
    //                                       UnsafeMutableRawPointer(bitPattern: tag))
    //if error != GRpc_ALL_OK {
    //  throw RpcCallError.callError(grpcCallError: error)
   // }
  }
  
  /// Shuts down the handler's completion queue
  public func shutdown() {
    //completionQueue.shutdown()
  }
  
  /// Send initial metadata in response to a connection
  ///
  /// - Parameter initialMetadata: initial metadata to send
  /// - Parameter completion: a completion handler to call after the metadata has been sent
  public func sendMetadata(initialMetadata: RpcMetadata,
                           completion: ((Bool) -> Void)? = nil) throws {
    //try call.perform(RpcOperationGroup(
    //  call: call,
    //  operations: [.sendInitialMetadata(initialMetadata.copy())]))//,
      //completion: completion != nil
       // ? { operationGroup in completion?(operationGroup.success) }
       // : nil))
  }

  /// Receive the message sent with a call
  ///
  public func receiveMessage(callId: Int,
                             method: RpcMethodType,
                             completion: @escaping (Data?) -> Void) throws {
    //print("RpcHandler.receiveMessage: added completion for callId: \(callId)")
    receiveMessageCompletion = completion
    socket.receiveMessage(callId: callId, method: method)
    //completion(data)
  
    // TODO: we need access to the RpcSocket here so we can send the IpC
    //       and receive the result
    //try call.perform(RpcOperationGroup(
    //  call: call,
    //  operations: [
    //    .sendInitialMetadata(initialMetadata.copy()),
    //    .receiveMessage
    //]) { operationGroup in
    //  if operationGroup.success {
    //    completion(operationGroup.receivedMessage())
    //  } else {
    //    completion(nil)
    //  }
    //})
  }
  public func onReceiveMessage(callId: Int, data: Data?) {
    guard let completion = receiveMessageCompletion else {
      //print("RpcHandler.onReceiveMessage: really bad.. theres no completion")
      return
    }
    //print("RpcHandler.onReceiveMessage: executing completion on callId: \(callId)")
    completion(data)
    //receiveMessageCompletion = nil
  }

  // public func sendMessage(callId: Int, data: Data, method: RpcMethodType, completion: ((Error?) -> Void)? = nil) throws {
  //   // try sendMutex.synchronize {
  //      if writing {
  //        if let messageQueueMaxLength = RpcHandler.messageQueueMaxLength,
  //          messageQueue.count >= messageQueueMaxLength {
  //          throw RpcCallWarning.blocked
  //        }
  //        messageQueue.append((dataToSend: data, completion: completion))
  //      } else {
  //        writing = true
  //        try sendWithoutBlocking(callId: callId, data: data, method: method, completion: completion)
  //      }
  //      //messageQueueEmpty.enter()
  //   // }
  // }

  // private func sendWithoutBlocking(callId: Int, data: Data, method: RpcMethodType, completion: ((Error?) -> Void)?) throws {
  //   socket.sendMessage(callId: callId, data: data, method: method)
  //   if self.messageQueue.count > 0 {
  //     let (nextMessage, nextCompletionHandler) = self.messageQueue.removeFirst()
  //     do {
  //       try self.sendWithoutBlocking(callId: callId, data: nextMessage, method: method, completion: nextCompletionHandler)
  //     } catch {
  //       nextCompletionHandler?(error)
  //     }
  //   } else {
  //     self.writing = false
  //   }
  //   completion?(nil)
  // }

  public func sendMessage(callId: Int, data: Data, method: RpcMethodType, now: Bool = false, completion: ((Error?) -> Void)? = nil) throws {     
    socket.sendMessage(callId: callId, data: data, method: method, now: now)
    if method == .normal {
      completion?(nil)
    } else {
    //   //print("RpcHandler.sendMessage: waiting for call \(callId) reply...")
    //   //sendMessageSync.timedWait(waitDelta: TimeDelta.from(seconds: 2))
    //   //print("RpcHandler.sendMessage: \(callId) done. calling completion")    
    //   //completion?(nil)
      if let c = completion {
         completions[callId] = c
      }
    }
  }

  public func sendMessage(callId: Int, data: Data, size: Int, method: RpcMethodType, now: Bool = false, completion: ((Error?) -> Void)? = nil) throws {     
    socket.sendMessage(callId: callId, data: data, size: size, method: method, now: now)
    if method == .normal {
      completion?(nil)
    } else {
    //   //print("RpcHandler.sendMessage: waiting for call \(callId) reply...")
    //   //sendMessageSync.timedWait(waitDelta: TimeDelta.from(seconds: 2))
    //   //print("RpcHandler.sendMessage: \(callId) done. calling completion")    
    //   //completion?(nil)
      if let c = completion {
         completions[callId] = c
      }
    }
  }

  public func sendMessage(callId: Int, bytes: UnsafeRawPointer?, size: Int, method: RpcMethodType, now: Bool = false, completion: ((Error?) -> Void)? = nil) throws {     
    socket.sendMessage(callId: callId, bytes: bytes, size: size, method: method, now: now)
    if method == .normal {
      completion?(nil)
    } else {
    //   //print("RpcHandler.sendMessage: waiting for call \(callId) reply...")
    //   //sendMessageSync.timedWait(waitDelta: TimeDelta.from(seconds: 2))
    //   //print("RpcHandler.sendMessage: \(callId) done. calling completion")    
    //   //completion?(nil)
      if let c = completion {
         completions[callId] = c
      }
    }
  }

  public func onSendMessageAck(callId: Int, status: StatusCode) {
    callSendResults[callId] = status
    if let completion = completions[callId] {
      completion(nil)
      completions.removeValue(forKey: callId)
    } //else {
     // print("RpcHandler.onSendMessageAck: \(callId) done. no completion found")
    //}
    //sendMessageSync.signal()
    //sendMessageSync.reset()
  }
  /// Sends the response to a request.
  /// The completion handler does not take an argument because operations containing `.receiveCloseOnServer` always succeed.
  public func sendResponse(callId: Int, message: Data, status: ServerStatus,
                           completion: (() -> Void)? = nil) throws {
    //let messageBuffer = ByteBuffer(data: message)
    // try call.perform(RpcOperationGroup(
    //   call: call,
    //   operations: [
    //     .sendMessage(message),
    //     .receiveCloseOnServer,
    //     .sendStatusFromServer(status.code, status.message, status.trailingMetadata.copy())
    // ]) { _ in
    //   completion?()
    //   self.shutdown()
    // })
  }

  /// Send final status to the client.
  /// The completion handler does not take an argument because operations containing `.receiveCloseOnServer` always succeed.
  public func sendStatus(callId: Int, _ status: ServerStatus) {//, completion: (() -> Void)? = nil) throws {
  //   try call.perform(RpcOperationGroup(
  //     call: call,
  //     operations: [
  //       .receiveCloseOnServer,
  //       .sendStatusFromServer(status.code, status.message, status.trailingMetadata.copy())
  //   ]) { _ in
  //     completion?()
  //     self.shutdown()
  //   })
    socket.sendStatus(callId: callId, code: status)
  }
}