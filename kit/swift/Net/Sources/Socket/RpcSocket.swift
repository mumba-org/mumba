// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Foundation

public enum RpcMethodType : Int {
  case normal = 0
  case clientStream = 1
  case serverStream = 2
  case bidiStream = 3
}

public protocol RpcSocketDelegate : class {
  func onRpcBegin(socket: RpcSocket, callId: Int, method: String, caller: String, host: String)
  func onRpcStreamRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64)
  func onRpcStreamReadEOF(socket: RpcSocket, callId: Int)
  func onRpcSendMessageAck(socket: RpcSocket, callId: Int, status: StatusCode)
  func onRpcStreamWrite(socket: RpcSocket, callId: Int)
  func onRpcUnaryRead(socket: RpcSocket, callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64)
  func onRpcEnd(socket: RpcSocket, callId: Int)
}

public class RpcSocket : Socket {
  
  public internal(set) var handle: SocketHandle?
  public internal(set) var id: Int = -1
  public internal(set) var delegate: RpcSocketDelegate
  var context: ShellContextRef

  public static func connect(delegate: RpcSocketDelegate, host: String, port: Int, path: String,  _ onConnection: (RpcSocket?) -> Void) {
    onConnection(RpcSocket(delegate: delegate, context: NetworkHost.instance.containerContext!, host: host, port: port, path: path))
  }

  internal init(delegate: RpcSocketDelegate, context: ShellContextRef, handle: SocketHandleRef) {
    self.context = context
    self.delegate = delegate
    
    self.handle = SocketHandle.acceptRpcClient(
        context: context, 
        handle: handle, 
        instance: self,
        onError: {
          (ptr: UnsafeMutableRawPointer?) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcSocket.self)
            state.onError()
        },
        onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcSocket.self)
            let address = IpEndPoint()
            address.port = Int(addrPort)
            // TODO: this is very ammateurish.. better to make a full byte copy
            if addrSize == 4 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3])
            } else if addrSize == 16 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3],
                                          bytes[4], bytes[5], bytes[6], bytes[7],
                                          bytes[8], bytes[9], bytes[10], bytes[11],
                                          bytes[12], bytes[13], bytes[14], bytes[15])
            }
            if let bytes = dataBytes {
              state.onDataReceived(address: address, data: UnsafeBufferPointer<UInt8>(start: bytes, count: Int(dataSize)), size: dataSize)
            } else {
              state.onDataReceived(address: address, data: nil, size: dataSize)
            }
        },
      onRpcBegin: { (ptr: UnsafeMutableRawPointer?, callId: CInt, method: UnsafePointer<Int8>?, caller: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcBegin(callId: Int(callId), method: String(cString: method!), caller: String(cString: caller!), host: String(cString: host!)) 
      },
      onRpcStreamRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcStreamReadEOF: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamReadEOF(callId: Int(callId))
      },
      onRpcSendMessageAck: { (ptr: UnsafeMutableRawPointer?, callId: CInt, status: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcSendMessageAck(callId: Int(callId), status: StatusCode(rawValue: Int(status))!)
      },
      onRpcStreamWrite: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamWrite(callId: Int(callId))
      },
      onRpcUnaryRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcUnaryRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcEnd: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcEnd(callId: Int(callId))
      })
  }

  internal init(delegate: RpcSocketDelegate, context: ShellContextRef, handle: SocketHandleRef, id: Int) {
    self.context = context
    self.id = id
    self.delegate = delegate
    
    self.handle = SocketHandle.acceptRpcClient(
      context: context, 
      handle: handle, 
      instance: self,
      onError: { (ptr: UnsafeMutableRawPointer?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onError()
      },
      onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcSocket.self)
            let address = IpEndPoint()
            address.port = Int(addrPort)
            // TODO: this is very ammateurish.. better to make a full byte copy
            if addrSize == 4 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3])
            } else if addrSize == 16 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3],
                                          bytes[4], bytes[5], bytes[6], bytes[7],
                                          bytes[8], bytes[9], bytes[10], bytes[11],
                                          bytes[12], bytes[13], bytes[14], bytes[15])
            }
            if let bytes = dataBytes {
              state.onDataReceived(address: address, data: UnsafeBufferPointer<UInt8>(start: bytes, count: Int(dataSize)), size: dataSize)
            } else {
              state.onDataReceived(address: address, data: nil, size: dataSize)
            }
      },
      onRpcBegin: { (ptr: UnsafeMutableRawPointer?, callId: CInt, method: UnsafePointer<Int8>?, caller: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcBegin(callId: Int(callId), method: String(cString: method!), caller: String(cString: caller!), host: String(cString: host!))
      },
      onRpcStreamRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcStreamReadEOF: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamReadEOF(callId: Int(callId))
      },
      onRpcSendMessageAck: { (ptr: UnsafeMutableRawPointer?, callId: CInt, status: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        print("RpcSocket.onRpcSendMessageAck: status: \(status)")
        state.onRpcSendMessageAck(callId: Int(callId), status: StatusCode(rawValue: Int(status))!)
      },
      onRpcStreamWrite: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamWrite(callId: Int(callId))
      },
      onRpcUnaryRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcUnaryRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcEnd: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcEnd(callId: Int(callId))
      })
  }

  internal init(delegate: RpcSocketDelegate, context: ShellContextRef, host: String, port: Int, path: String) {
    self.context = context
    self.delegate = delegate
    let names = path.components(separatedBy: ".")
    self.handle = SocketHandle.createRpcClient(
        context: context,
        host: host,
        port: port,
        instance: self,
        package: names[0],
        name: names[1],
        onError: {
          (ptr: UnsafeMutableRawPointer?) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcSocket.self)
            state.onError()
        },
        onSocketCreated: { (ptr: UnsafeMutableRawPointer?, id: CInt, errcode: CInt) in
          guard ptr != nil else {
            return
          }
          let state = unsafeBitCast(ptr, to: RpcSocket.self)
          state.onSocketCreated(errcode: Int(errcode), id: Int(id))
        },
        onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcSocket.self)
            let address = IpEndPoint()
            address.port = Int(addrPort)
            // TODO: this is very ammateurish.. better to make a full byte copy
            if addrSize == 4 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3])
            } else if addrSize == 16 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3],
                                          bytes[4], bytes[5], bytes[6], bytes[7],
                                          bytes[8], bytes[9], bytes[10], bytes[11],
                                          bytes[12], bytes[13], bytes[14], bytes[15])
            }
            if let bytes = dataBytes {
              state.onDataReceived(address: address, data: UnsafeBufferPointer<UInt8>(start: bytes, count: Int(dataSize)), size: dataSize)
            } else {
              state.onDataReceived(address: address, data: nil, size: dataSize)
            }
        },
      onRpcBegin: { (ptr: UnsafeMutableRawPointer?, callId: CInt, method: UnsafePointer<Int8>?, caller: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcBegin(callId: Int(callId), method: String(cString: method!), caller: String(cString: caller!), host: String(cString: host!)) 
      },
      onRpcStreamRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcStreamReadEOF: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamReadEOF(callId: Int(callId))
      },
      onRpcSendMessageAck: { (ptr: UnsafeMutableRawPointer?, callId: CInt, status: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcSendMessageAck(callId: Int(callId), status: StatusCode(rawValue: Int(status))!)
      },
      onRpcStreamWrite: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcStreamWrite(callId: Int(callId))
      },
      onRpcUnaryRead: { (ptr: UnsafeMutableRawPointer?, callId: CInt, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcUnaryRead(callId: Int(callId), data: UnsafeBufferPointer<UInt8>(start: dataBytes, count: Int(dataSize)), size: dataSize)
      },
      onRpcEnd: { (ptr: UnsafeMutableRawPointer?, callId: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcSocket.self)
        state.onRpcEnd(callId: Int(callId))
      })
  }

  public func close() throws {
    if let conn = handle {
      try conn.close()
    }
  }

  public func onError() {
    if let conn = handle {
      conn.onError()
    }
    //if let server = owner {
      // this should call our own destructor
    //  server.unregisterClient(self)
    //}
  }

  public func onSocketCreated(errcode: Int, id: Int) {
    print("RpcSocket.onSocketCreated")
  }

  public func onDataReceived(address: IpEndPoint, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    if let buf = data {
      let str = String(cString: buf.baseAddress!)
      print("received [\(size)]:\n\"\(str)\"")
      //write(buffer: buf.baseAddress!, size: Int(size), address: address)
    }// else {
     // print("client received: [\(size)] - null")
    //}
  }

  public func write(buffer: UnsafePointer<UInt8>, size: Int, address: IpEndPoint) {
    if let conn = handle {
      conn.write(buffer: buffer, size: size, address: address)
    }
  }

  public func receiveMessage(callId: Int, method: RpcMethodType) {
    if let conn = handle {
      conn.receiveRPCMessage(callId: callId, method: method)
    }
  }

  public func sendMessage(callId: Int, data: Data, method: RpcMethodType, now: Bool = false) {
    if let conn = handle {
      data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> Void in
        if now {
          conn.sendRPCMessageNow(callId: callId, buffer: ptr, size: data.count, method: method)
        } else {
          conn.sendRPCMessage(callId: callId, buffer: ptr, size: data.count, method: method)
        }
      }
    }
  }

  public func sendMessage(callId: Int, data: Data, size: Int, method: RpcMethodType, now: Bool = false) {
    if let conn = handle {
      data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> Void in
        if now {
          conn.sendRPCMessageNow(callId: callId, buffer: ptr, size: size, method: method)
        } else {
          conn.sendRPCMessage(callId: callId, buffer: ptr, size: size, method: method)
        }
      }
    }
  }

  public func sendMessage(callId: Int, bytes: UnsafeRawPointer?, size: Int, method: RpcMethodType, now: Bool = false) {
    if let conn = handle {
      if now {
        conn.sendRPCMessageNow(callId: callId, buffer: bytes!.bindMemory(to: UInt8.self, capacity: size), size: size, method: method)
      } else {
        conn.sendRPCMessage(callId: callId, buffer: bytes!.bindMemory(to: UInt8.self, capacity: size), size: size, method: method)
      }
    }
  }

  public func sendStatus(callId: Int, code: ServerStatus) {
    if let conn = handle {
      conn.sendRpcStatus(callId: callId, code: code.code)
    } 
  }

  func onRpcBegin(callId: Int, method: String, caller: String, host: String) {
    self.delegate.onRpcBegin(socket: self, callId: callId, method: method, caller: caller, host: host)
  }

  func onRpcStreamRead(callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    self.delegate.onRpcStreamRead(socket: self, callId: callId, data: data, size: size)
  }

  func onRpcStreamReadEOF(callId: Int) {
    self.delegate.onRpcStreamReadEOF(socket: self, callId: callId)
  }

  func onRpcSendMessageAck(callId: Int, status: StatusCode) {
    self.delegate.onRpcSendMessageAck(socket: self, callId: callId, status: status)
  }

  func onRpcStreamWrite(callId: Int) {
    self.delegate.onRpcStreamWrite(socket: self, callId: callId)
  }

  func onRpcUnaryRead(callId: Int, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    self.delegate.onRpcUnaryRead(socket: self, callId: callId, data: data, size: size)
  }

  func onRpcEnd(callId: Int) {
    self.delegate.onRpcEnd(socket: self, callId: callId)
  }

}

public protocol RpcServerSocketDelegate : class {
  func onListen(status: Int)
  func onAccept(incoming: SocketHandleRef, socketId: Int) -> Int
  func onError()
}

public class RpcServerSocket : Socket {

  public internal(set) var handle: SocketHandle?
  public internal(set) var isConnected: Bool = false
  public internal(set) var id: Int = -1
  public internal(set) var localAddress: String = String()
  public internal(set) var localPort: Int = 0
  public internal(set) var isListening: Bool = false
  public internal(set) weak var delegate: RpcServerSocketDelegate?
  var context: ShellContextRef

  internal init(context: ShellContextRef, delegate: RpcServerSocketDelegate) {
    self.context = context
    self.delegate = delegate
  }

  //public init(context: ShellContextRef, delegate: RpcServerSocketDelegate) {
    //self.context = context
    //self.delegate = delegate
  //}

  deinit {
    if isConnected {
      try! close()
    }
  }

  public func close() throws {
    if let conn = handle {
      try conn.close()
    }
  }
  
  public func listen(serviceName: String, port: Int) {
    let serviceItems = serviceName.components(separatedBy: ".")
    self.handle = SocketHandle.createRpcServer(
      context: context, 
      port: port, 
      instance: self,
      package: serviceItems[0],
      name: serviceItems[1],
      onError: { (ptr: UnsafeMutableRawPointer?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcServerSocket.self)
        state.onError()
      },
      onSocketCreated: { (ptr: UnsafeMutableRawPointer?, id: CInt, errcode: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: RpcServerSocket.self)
        state.onSocketCreated(errcode: Int(errcode), id: Int(id))
      },
      onAccept: { (ptr: UnsafeMutableRawPointer?, socket: UnsafeMutableRawPointer?, clientId: CInt) -> CInt in
        guard ptr != nil else {
          return -1
        }
        let state = unsafeBitCast(ptr, to: RpcServerSocket.self)
        return CInt(state.onAccept(incoming: socket!, socketId: Int(clientId)))
      },
      onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: RpcServerSocket.self)
            let address = IpEndPoint()
            address.port = Int(addrPort)
            // TODO: this is very ammateurish.. better to make a full byte copy
            if addrSize == 4 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3])
            } else if addrSize == 16 {
              let bytes = addrBytes!
              address.address = IpAddress(bytes[0], bytes[1], bytes[2], bytes[3],
                                          bytes[4], bytes[5], bytes[6], bytes[7],
                                          bytes[8], bytes[9], bytes[10], bytes[11],
                                          bytes[12], bytes[13], bytes[14], bytes[15])
            }
            if let bytes = dataBytes {
              state.onDataReceived(address: address, data: UnsafeBufferPointer<UInt8>(start: bytes, count: Int(dataSize)), size: dataSize)
            } else {
              state.onDataReceived(address: address, data: nil, size: dataSize)
            }
      })
  }

  public func onSocketCreated(errcode: Int, id: Int) {
    if errcode == 0 {
      self.id = id
      isListening = true
      isConnected = true
    }

    delegate!.onListen(status: errcode)
  }

  public func onAccept(incoming: SocketHandleRef, socketId: Int) -> Int {
    return delegate!.onAccept(incoming: incoming, socketId: socketId)
  }

  public func onError() {
    delegate!.onError()
  }

  public func onDataReceived(address: IpEndPoint, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    if let buf = data {
      let str = String(cString: buf.baseAddress!)
      //print("server received: [\(size)] - \"\(str)\"")
      //write(buffer: buf.baseAddress!, size: Int(size), address: address)
    } //else {
      //print("server received: [\(size)] - null")
    //}
  }

}