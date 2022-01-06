// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class TcpClient : Connectable {
  
  public private(set) var socket: TcpSocket?

  public var isConnected: Bool {
    return socket?.isConnected ?? false
  }
  
  public init() {}
  
  public func connect(remoteAddress: String, onConnect: @escaping (_: Bool) -> ()) {

  }
}
