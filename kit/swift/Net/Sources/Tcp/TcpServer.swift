// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol TcpServerDelegate : class {
  func onListen(status: Int)
  func onAccept(connection: TcpSocket) -> Int
  func onError()
}

public class TcpServer : Listener, TcpServerSocketDelegate, TcpSocketOwner {
  
  public private(set) var socket: TcpServerSocket?
  
  public var isListening: Bool {
    return socket?.isListening ?? false
  }

  public var isConnected: Bool {
    return socket?.isConnected ?? false
  }

  public var port: Int = -1
  
  private weak var delegate: TcpServerDelegate?
  private var watcher: SocketEventWatcher
  public private(set) var sockets: [TcpSocket] = []

  public init(delegate: TcpServerDelegate) {
    self.delegate = delegate
    watcher = try! SocketEventWatcher()
  }

  public func listen(port: Int) {
    let context = NetworkHost.instance.containerContext!
    socket = TcpServerSocket(context: context, delegate: self)
    socket!.listen(port: port)
    self.port = port
  }

  public func close() throws {
    if let conn = socket {
      try conn.close()
    }
  }

  public func onListen(status: Int) {
    delegate!.onListen(status: status)
  }

  public func onAccept(incoming: SocketHandleRef, socketId: Int) -> Int {
    let context = NetworkHost.instance.containerContext!
    let socket = TcpSocket(context: context, handle: incoming, id: socketId, owner: self)
    registerSocket(socket)
    return delegate!.onAccept(connection: socket)
  }

  public func onError() {
    print("onError: probably a client that disconnected.. but which one?")
    delegate!.onError()
  }

  private func registerSocket(_ socket: TcpSocket) {
    addSocket(socket)
    if let handle = socket.handle {
      try! watcher.register(watchable: handle)
    }
  }

  private func unregisterSocket(_ socket: TcpSocket) {
    if let handle = socket.handle {
      try! watcher.unregister(watchable: handle)
    }
    removeSocket(socket)
  }

  public func unregisterClient(_ socket: TcpSocket) {
    unregisterSocket(socket)
  }

  private func addSocket(_ socket: TcpSocket) {
    sockets.append(socket)
  }
  
  private func removeSocket(_ socket: TcpSocket) {
    if let index = sockets.firstIndex(where: { socket === $0 }) {
      sockets.remove(at: index)
    }
  }

}
