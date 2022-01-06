// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation
import Base

public enum SocketType : Int {
  case udp = 0
  case tcpServer = 1
  case stunTcpServer = 2
  case tpcClient = 3
  case stunTcpClient = 4
  case sslTcpClient = 5
  case stunSslTcpClient = 6
  case tlsClient = 7
  case stunTlsClient = 8
  case rpcServer = 9
  case rpcClient = 10
}

//public protocol SocketHandle : Watchable {
 // func write(buffer: UnsafePointer<UInt8>, size: Int, address: IpEndPoint)
 // func onError()
//}

// public class PlatfomSocketHandle : SocketHandle {

//   public var isOpen: Bool {
//     return handle.isOpen
//   }

//   internal var handle: PlatformFile

//   public init(_ handle: PlatformFile) {
//     self.handle = handle
//   }

//   public func close() throws {
//     try handle.close()
//   }

//   public func write(buffer: UnsafePointer<UInt8>, size: Int, address: IpEndPoint) {

//   }

//   public func onError() {
//     try! handle.close()
//   }

// }

//public class ManagedSocketHandle : SocketHandle {
public class SocketHandle {

  public static func createTcpClient<Instance: AnyObject>(
    context: ShellContextRef, 
    handle: SocketHandleRef, 
    instance: Instance,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?) -> (),
    onDataReceived: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, CInt, UInt16, UnsafePointer<UInt8>?, Int64) -> ()) -> SocketHandle {
    var callbacks = SocketCallbacks()

    callbacks.OnError = onError
    callbacks.OnDataReceived = onDataReceived
    
    let state = unsafeBitCast(Unmanaged.passUnretained(instance).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    SocketSetStateAndCallbacks(handle, state, callbacks)

    return SocketHandle(handle)
  }
  
  public static func createTcpServer<Instance: AnyObject>(
    context: ShellContextRef, 
    port: Int, 
    instance: Instance,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?) -> (),
    onSocketCreated: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, CInt) -> (),
    onAccept: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, CInt) -> CInt,
    onDataReceived: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, CInt, UInt16, UnsafePointer<UInt8>?, Int64) -> ()) -> SocketHandle {
    
    let localAddress = IpEndPoint(address: IpAddress.ipv4AllZeros, port: port)
    let remoteAddress = IpEndPoint(address: IpAddress.ipv4AllZeros, port: 0)
    
    var callbacks = SocketCallbacks()
    callbacks.OnSocketCreate = onSocketCreated
    callbacks.OnAccept = onAccept
    callbacks.OnError = onError
    callbacks.OnDataReceived = onDataReceived

    let selfState = unsafeBitCast(Unmanaged.passUnretained(instance).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    let handle: SocketHandleRef =  localAddress.address.bytes.withUnsafeBufferPointer { localBuf in
      return remoteAddress.address.bytes.withUnsafeBufferPointer { remoteBuf in
        return SocketCreate(
          context,
          callbacks,
          selfState,
          CInt(SocketType.tcpServer.rawValue),
          localBuf.baseAddress,
          CInt(localAddress.port),
          UInt16(0), 
          UInt16(0),
          remoteBuf.baseAddress,
          CInt(remoteAddress.port))
      }
    }

    //return ManagedSocketHandle(handle)
    return SocketHandle(handle)
  }

  public static func createRpcServer<Instance: AnyObject>(
    context: ShellContextRef, 
    port: Int, 
    instance: Instance,
    package: String,
    name: String,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?) -> (),
    onSocketCreated: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, CInt) -> (),
    onAccept: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, CInt) -> CInt,
    onDataReceived: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, CInt, UInt16, UnsafePointer<UInt8>?, Int64) -> ()) -> SocketHandle {
    
    let localAddress = IpEndPoint(address: IpAddress.ipv4AllZeros, port: port)
    let remoteAddress = IpEndPoint(address: IpAddress.ipv4AllZeros, port: 0)
    
    var callbacks = SocketCallbacks()
    callbacks.OnSocketCreate = onSocketCreated
    callbacks.OnAccept = onAccept
    callbacks.OnError = onError
    callbacks.OnDataReceived = onDataReceived
   
    let selfState = unsafeBitCast(Unmanaged.passUnretained(instance).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    let handle: SocketHandleRef = localAddress.address.bytes.withUnsafeBufferPointer { localBuf in
      return remoteAddress.address.bytes.withUnsafeBufferPointer { remoteBuf in
        return package.withCString { packageBuf in
          return name.withCString { nameBuf in
            return SocketCreateRPC(
              context,
              callbacks,
              selfState,
              CInt(SocketType.rpcServer.rawValue),
              localBuf.baseAddress,
              CInt(localAddress.port),
              UInt16(0), 
              UInt16(0),
              remoteBuf.baseAddress,
              CInt(remoteAddress.port),
              packageBuf,
              CInt(package.count),
              nameBuf,
              CInt(name.count))
          }
        }
      }
    }

    return SocketHandle(handle)
  }

  public static func createRpcClient<Instance: AnyObject>(
    context: ShellContextRef,
    host: String,
    port: Int, 
    instance: Instance,
    package: String,
    name: String,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?) -> (),
    onSocketCreated: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, CInt) -> (),
    onDataReceived: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, CInt, UInt16, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcBegin: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<Int8>?, UnsafePointer<Int8>?, UnsafePointer<Int8>?) -> (),
    onRpcStreamRead: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcStreamReadEOF: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> (),
    onRpcSendMessageAck: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, CInt) -> (),
    onRpcStreamWrite: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> (),
    onRpcUnaryRead: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcEnd: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> ()) -> SocketHandle {
    
    let localAddress = IpEndPoint(address: IpAddress.ipv4AllZeros, port: 0)
    // FIXME: always going for localhost
    let remoteAddress = IpEndPoint(address: IpAddress.ipv4LocalHost, port: port)
    
    var callbacks = SocketCallbacks()

    callbacks.OnSocketCreate = onSocketCreated
    callbacks.OnError = onError
    callbacks.OnDataReceived = onDataReceived
    callbacks.OnRPCBegin = onRpcBegin
    callbacks.OnRPCStreamRead = onRpcStreamRead
    callbacks.OnRPCStreamReadEOF = onRpcStreamReadEOF
    callbacks.OnRPCSendMessageAck = onRpcSendMessageAck
    callbacks.OnRPCStreamWrite = onRpcStreamWrite
    callbacks.OnRPCUnaryRead = onRpcUnaryRead
    callbacks.OnRPCEnd = onRpcEnd
   
    let selfState = unsafeBitCast(Unmanaged.passUnretained(instance).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)

    let handle: SocketHandleRef = localAddress.address.bytes.withUnsafeBufferPointer { (localBuf) -> SocketHandleRef in
      return remoteAddress.address.bytes.withUnsafeBufferPointer { (remoteBuf) -> SocketHandleRef in
        return host.withCString { (chost) -> SocketHandleRef in
          return package.withCString { (packageBuf) -> SocketHandleRef in
            return name.withCString { (nameBuf) -> SocketHandleRef in
              return SocketCreateRPCWithHost(
                  context,
                  callbacks,
                  selfState,
                  CInt(SocketType.rpcClient.rawValue),
                  chost,
                  localBuf.baseAddress,
                  CInt(localAddress.port),
                  UInt16(0), 
                  UInt16(0),
                  remoteBuf.baseAddress,
                  CInt(remoteAddress.port),
                  packageBuf,
                  CInt(package.count),
                  nameBuf,
                  CInt(name.count))
            }
          }
        }
      }
    }

    return SocketHandle(handle)
  }


  public static func acceptRpcClient<Instance: AnyObject>(
    context: ShellContextRef, 
    handle: SocketHandleRef, 
    instance: Instance,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?) -> (),
    onDataReceived: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, CInt, UInt16, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcBegin: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<Int8>?, UnsafePointer<Int8>?, UnsafePointer<Int8>?) -> (),
    onRpcStreamRead: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcStreamReadEOF: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> (),
    onRpcSendMessageAck: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, CInt) -> (),
    onRpcStreamWrite: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> (),
    onRpcUnaryRead: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt, UnsafePointer<UInt8>?, Int64) -> (),
    onRpcEnd: @escaping @convention(c) (UnsafeMutableRawPointer?, CInt) -> ()) -> SocketHandle {
    
    var callbacks = SocketCallbacks()

    callbacks.OnError = onError
    callbacks.OnDataReceived = onDataReceived
    callbacks.OnRPCBegin = onRpcBegin
    callbacks.OnRPCStreamRead = onRpcStreamRead
    callbacks.OnRPCStreamReadEOF = onRpcStreamReadEOF
    callbacks.OnRPCSendMessageAck = onRpcSendMessageAck
    callbacks.OnRPCStreamWrite = onRpcStreamWrite
    callbacks.OnRPCUnaryRead = onRpcUnaryRead
    callbacks.OnRPCEnd = onRpcEnd

    let state = unsafeBitCast(Unmanaged.passUnretained(instance).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    SocketSetStateAndCallbacks(handle, state, callbacks)

    return SocketHandle(handle)
  }

  public internal(set) var isOpen: Bool = false
  internal var handle: SocketHandleRef
  
  public init(_ handle: SocketHandleRef) {
    self.handle = handle
  }

  deinit { 
    if isOpen {
      try! close()
    }
    SocketDestroy(handle)
  }

  public func close() throws {
    guard isOpen else {
      return
    }
    SocketClose(handle)
    isOpen = false
  }

  public func write(buffer: UnsafePointer<UInt8>, size: Int, address: IpEndPoint) {
    address.address.bytes.withUnsafeBufferPointer { addrbuf in
      SocketWriteWithAddress(handle, buffer, CInt(size), addrbuf.baseAddress, CInt(address.address.bytes.count), CInt(address.port))
    }
  }

  public func receiveRPCMessage(callId: Int, method: RpcMethodType) {
    //print("Socket.receiveRPCMessage")
    SocketReceiveRPCMessage(handle, CInt(callId), CInt(method.rawValue))
  }

  public func sendRPCMessage(callId: Int, buffer: UnsafePointer<UInt8>, size: Int, method: RpcMethodType) {
    SocketSendRPCMessage(handle, CInt(callId), buffer, CInt(size), CInt(method.rawValue))
  }

  public func sendRPCMessageNow(callId: Int, buffer: UnsafePointer<UInt8>, size: Int, method: RpcMethodType) {
    SocketSendRPCMessageNow(handle, CInt(callId), buffer, CInt(size), CInt(method.rawValue))
  }

  public func sendRpcStatus(callId: Int, code: StatusCode) {
    //print("Socket.sendRpcStatus")
    SocketSendRPCStatus(handle, CInt(callId), CInt(code.rawValue))
  }

  public func onError() {
    // treat as if it was closed
    isOpen = false
  }

}

public protocol Socket {
  var handle: SocketHandle? { get }
  var isConnected: Bool { get }
}

extension Socket {

  public var isConnected: Bool {
    if let conn = self.handle {
      return conn.isOpen
    }
    return false
  }

}

public protocol Connectable {
  func connect(remoteAddress: String, onConnect: @escaping (_: Bool) -> ())
}

public protocol Listener {
  var isListening: Bool { get }

  func listen(port: Int) throws
}