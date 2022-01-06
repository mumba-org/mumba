// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class TCPClientSocket {
  public init() {}
}

extension TCPClientSocket: ClientSocket {
 
 public var type: SocketType { 
   return .TCP 
 }
 
 public var hostname: String {
   get{
     return ""
   }
   set {

   }
 }
 
 public var isConnected: Bool { return false }
 
 public var peerAddress: IPEndPoint { return IPEndPoint() }
 
 public var localAddress: IPEndPoint { return IPEndPoint() }
 
 public func connect(address: AddressList, callback: CompletionCallback) {

 }
 
 public func close() {

 }

 public func read(count: Int, callback: ReadCompletionCallback) {

 }
 
 public func write(buffer: ByteBuffer, byteCount: Int, callback: CompletionCallback) {

 }

 public func recvFrom(count: Int, callback: RecvFromCompletionCallback) {

 }

 public func sendTo(buffer: ByteBuffer,
             byteCount: Int,
             address: IPEndPoint,
             callback: CompletionCallback) {

 }

 public func setKeepAlive(enable: Bool, delay: Int) -> Bool {
   return false
 }
 
 public func setNoDelay(noDelay: Bool) -> Bool {
   return false
 }

}
