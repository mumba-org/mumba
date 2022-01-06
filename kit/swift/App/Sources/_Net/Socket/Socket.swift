// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum SocketType {
  case TCP
  case UDP
  case TLS
}

// for now
public typealias ReadCompletionCallback = Int

public typealias RecvFromCompletionCallback = Int

public typealias AcceptCompletionCallback = Int

public protocol Socket {
 
 var type: SocketType { get }
 var hostname: String { get set }
 var isConnected: Bool { get }
 var peerAddress: IPEndPoint { get }
 var localAddress: IPEndPoint { get }
 
 func close()
 func read(count: Int, callback: ReadCompletionCallback)
 func write(buffer: ByteBuffer, byteCount: Int, callback: CompletionCallback)

 func recvFrom(count: Int, callback: RecvFromCompletionCallback)

 func sendTo(buffer: ByteBuffer,
             byteCount: Int,
             address: IPEndPoint,
             callback: CompletionCallback)

 func setKeepAlive(enable: Bool, delay: Int) -> Bool
 func setNoDelay(noDelay: Bool) -> Bool
 
}

public protocol ClientSocket : Socket {
  func connect(address: AddressList, callback: CompletionCallback)  
}

public protocol SocketListener {
  
  func listen(address: String,
              port: UInt16,
              backlog: Int,
              errorMsg: inout String) -> Int
}

public protocol ServerSocket : Socket,
                               SocketListener {
 
 func bind(address: String, port: UInt16) -> Int
 func accept(callback: AcceptCompletionCallback)                                

}
