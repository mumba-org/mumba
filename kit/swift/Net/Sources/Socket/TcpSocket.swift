// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public protocol TcpServerSocketDelegate : class {
  func onListen(status: Int)
  func onAccept(incoming: SocketHandleRef, socketId: Int) -> Int
  func onError()
}

public protocol TcpSocketOwner : class {
  func unregisterClient(_ connection: TcpSocket)
}

public class TcpSocket : Socket {
  
  public internal(set) var handle: SocketHandle?
  public internal(set) var id: Int = -1
  public weak var owner: TcpSocketOwner?
  var context: ShellContextRef

  internal init(context: ShellContextRef) {
    self.context = context 
  }

  internal init(context: ShellContextRef, handle: SocketHandleRef, owner: TcpSocketOwner) {
    self.context = context 
    self.owner = owner
    
    self.handle = SocketHandle.createTcpClient(
        context: context, 
        handle: handle, 
        instance: self,
        onError: {
          (ptr: UnsafeMutableRawPointer?) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: TcpSocket.self)
            state.onError()
        },
        onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: TcpSocket.self)
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

  internal init(context: ShellContextRef, handle: SocketHandleRef, id: Int, owner: TcpSocketOwner) {
    self.context = context
    self.id = id
    self.owner = owner
    
    self.handle = SocketHandle.createTcpClient(
      context: context, 
      handle: handle, 
      instance: self,
      onError: { (ptr: UnsafeMutableRawPointer?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: TcpSocket.self)
        state.onError()
      },
      onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: TcpSocket.self)
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

  public func close() throws {
    if let conn = handle {
      try conn.close()
    }
  }

  public func onError() {
    if let conn = handle {
      conn.onError()
    }
    if let server = owner {
      // this should call our own destructor
      server.unregisterClient(self)
    }
  }

  public func onDataReceived(address: IpEndPoint, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    //print("TcpSocket.onDataReceived")
    if let buf = data {
      //let str = String(cString: buf.baseAddress!)
      //print("server received: [\(size)] - \"\(str)\"")
      write(buffer: buf.baseAddress!, size: Int(size), address: address)
    } //else {
      //print("server received: [\(size)] - null")
    //}
  }

  public func write(buffer: UnsafePointer<UInt8>, size: Int, address: IpEndPoint) {
    if let conn = handle {
      conn.write(buffer: buffer, size: size, address: address)
    }
  }

}

public class TcpServerSocket : Socket {

  public internal(set) var handle: SocketHandle?
  public internal(set) var isConnected: Bool = false
  public internal(set) var id: Int = -1
  public internal(set) var localAddress: String = String()
  public internal(set) var localPort: Int = 0
  public internal(set) var isListening: Bool = false
  public internal(set) weak var delegate: TcpServerSocketDelegate?
  var context: ShellContextRef

  internal init(context: ShellContextRef) {
    self.context = context 
  }

  public init(context: ShellContextRef, delegate: TcpServerSocketDelegate) {
    self.context = context
    self.delegate = delegate
  }

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
  
  public func listen(port: Int) {
    self.handle = SocketHandle.createTcpServer(
      context: context, 
      port: port, 
      instance: self,
      onError: { (ptr: UnsafeMutableRawPointer?) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: TcpServerSocket.self)
        state.onError()
      },
      onSocketCreated: { (ptr: UnsafeMutableRawPointer?, id: CInt, errcode: CInt) in
        guard ptr != nil else {
          return
        }
        let state = unsafeBitCast(ptr, to: TcpServerSocket.self)
        state.onSocketCreated(errcode: Int(errcode), id: Int(id))
      },
      onAccept: { (ptr: UnsafeMutableRawPointer?, socket: UnsafeMutableRawPointer?, id: CInt) -> CInt in
        guard ptr != nil else {
          return -1
        }
        let state = unsafeBitCast(ptr, to: TcpServerSocket.self)
        return CInt(state.onAccept(incoming: socket!, socketId: Int(id)))
      },
      onDataReceived: {
          (ptr: UnsafeMutableRawPointer?, addrBytes: UnsafePointer<UInt8>?, addrSize: CInt, addrPort: UInt16, dataBytes: UnsafePointer<UInt8>?, dataSize: Int64) in
            guard ptr != nil else {
              return
            }
            let state = unsafeBitCast(ptr, to: TcpServerSocket.self)
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
    return delegate!.onAccept(incoming: incoming, socketId: id)
  }

  public func onError() {
    delegate!.onError()
  }

  public func onDataReceived(address: IpEndPoint, data: UnsafeBufferPointer<UInt8>?, size: Int64) {
    //print("TcpServerSocket.onDataReceived")
    
    //if data != nil {
    //  print("server received: [\(size)] - \"\(data!)\"")
    //} else {
     // print("server received: [\(size)] - null")
    //}
  }

}

public class PlatformSocketEventWatcher : EventWatcher {
  
  public typealias Watched = PlatformFile

  internal let allEvents: EventPollEventSet

  public private(set) var eventPoll: PlatformEventPoll<PlatformRegistration>

  public init() throws {
    eventPoll = try PlatformEventPoll()
    allEvents = EventPollEventSet(rawValue:
                  EventPollEventSet.read.rawValue | EventPollEventSet.write.rawValue |
                  EventPollEventSet.readEOF.rawValue | EventPollEventSet.reset.rawValue)
  }

  public func register(watchable: PlatformFile) throws {
    try eventPoll.register(watchable: watchable, interested: self.allEvents, 
      makeRegistration: { evset in 
        return .clientSocket(watchable, evset)
      }) 
  }
  
  public func unregister(watchable: PlatformFile) throws {
    try eventPoll.deregister(watchable: watchable)
  }

}

public class SocketEventWatcher : EventWatcher {
  
  public typealias Watched = SocketHandle

  public init() throws {
  }

  public func register(watchable: SocketHandle) throws {
  }
  
  public func unregister(watchable: SocketHandle) throws {
  }

}