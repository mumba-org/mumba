// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Foundation

public typealias HandlerFunc = (RpcHandler, Int) -> Void

public class RpcServer : RpcSocketDelegate,
                         RpcServerSocketDelegate {

  public let port: Int

  //public var isShuttingDown: Bool {
  //  return eventWatcher.isShuttingDown
  //}
  //public private(set) var eventWatcher: RpcEventWatcher
  private var socket: RpcServerSocket?
  //private var eventLoopTaskRunner: SingleThreadTaskRunner?
  public private(set) var sockets: [RpcSocket] = []
  private var handlerFunction: HandlerFunc?
  private var handlers: [Int : RpcHandler] = [:]
  private var serviceName: String

  public init(serviceName: String, port: Int) throws {
    self.port = port
    let context = NetworkHost.instance.containerContext!
    self.serviceName = serviceName
    socket = RpcServerSocket(context: context, delegate: self)
  }

  public func run(handlerFunction: @escaping HandlerFunc) {
    socket!.listen(serviceName: self.serviceName, port: port)
    // save it to dispatch only 
    self.handlerFunction = handlerFunction
  }

  public func close() throws {
    if let conn = socket {
      try conn.close()
    }
  }
  
  public func onListen(status: Int) {
    
  }
  
  public func onAccept(incoming: SocketHandleRef, socketId: Int) -> Int {
    let context = NetworkHost.instance.containerContext!
    let socket = RpcSocket(delegate: self, context: context, handle: incoming, id: socketId)
    registerSocket(socket)
    //postDelayedTask({
    //  let str = "\nhello world!\n"
    //  str.withCString { strbuf in
    //    strbuf.withMemoryRebound(to: UInt8.self, capacity: str.count) { (ptr: UnsafePointer<UInt8>) in
    //      socket.write(buffer: ptr, size: str.count, address: IpEndPoint())
    //    }
    //  }
    //}, delay: TimeDelta.from(seconds: 3))
    return 0
  }
  
  public func onError() {
    print("RpcServer.onError")
  }

  public func onRpcBegin(socket: RpcSocket, callId: Int, method: String, caller: String, host: String) {
    self.handlers[callId] = RpcHandler(socket: socket, method: method, caller: caller, host: host)
    if let handlerFn = handlerFunction {
      postTask {
        // TODO: usar o handler de alguma forma aqui.. iniciar.. rodar ops iniciais, etc..
        handlerFn(self.handlers[callId]!, callId)
      }
    }
  }

  public func onRpcStreamRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
     if let handler = handlers[callId] {
      if let pointer = data?.baseAddress {
        var innerData = Data()
        innerData.append(pointer, count: Int(size))
        handler.onReceiveMessage(callId: callId, data: innerData)
      } else {
        handler.onReceiveMessage(callId: callId, data: nil)
      }
    }
  }

  public func onRpcStreamReadEOF(socket: RpcSocket, callId: Int) {
    if let handler = handlers[callId] {
      handler.onReceiveMessage(callId: callId, data: nil)
    }
  }

  public func onRpcSendMessageAck(socket: RpcSocket, callId: Int, status: StatusCode) {     
    if let handler = handlers[callId] {
      handler.onSendMessageAck(callId: callId, status: status)
    }
  }
 
  public func onRpcStreamWrite(socket: RpcSocket, callId: Int) {
    print("RpcServer.onRpcStreamWrite: nothing here..")
  }
  
  public func onRpcUnaryRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {    
    if let handler = handlers[callId] {
      if let pointer = data?.baseAddress {
        var innerData = Data()
        innerData.append(pointer, count: Int(size))
        handler.onReceiveMessage(callId: callId,data: innerData)
      } else {
        handler.onReceiveMessage(callId: callId, data: nil)
      }
    }
  }
  
  public func onRpcEnd(socket: RpcSocket, callId: Int) {     
    if let handler = handlers[callId] {
      handler.shutdown()
    }
    handlers.removeValue(forKey: callId)
  }

  private func registerSocket(_ socket: RpcSocket) {
    addSocket(socket)
    //if let handle = socket.handle {
    //  try! watcher.register(watchable: handle)
    //}
  }

  private func unregisterSocket(_ socket: RpcSocket) {
    //if let handle = socket.handle {
    //  try! watcher.unregister(watchable: handle)
    //}
    removeSocket(socket)
  }

  private func addSocket(_ socket: RpcSocket) {
    sockets.append(socket)
  }
  
  private func removeSocket(_ socket: RpcSocket) {
    if let index = sockets.firstIndex(where: { socket === $0 }) {
      sockets.remove(at: index)
    }
  }
  
}