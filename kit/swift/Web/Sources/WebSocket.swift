// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public enum ClosingHandshakeCompletionStatus : Int {
  case closingHandshakeIncomplete = 0
  case closingHandshakeComplete = 1
}

public protocol WebSocketDelegate : class {
  func onConnect(subprotocol: String, extensions: String)
  func onReceiveTextMessage(_: String)
  func onReceiveBinaryMessage(_: Data)
  func onError()
  func onConsumeBufferedAmount(consumed: UInt64)
  func onStartClosingHandshake()
  func onClose(status: ClosingHandshakeCompletionStatus, code: UInt16, reason: String)
}

public class WebSocket {

  public var subprotocol: String {
    if _subprotocol == nil {
      var len: CInt = 0
      let str = WebSocketGetSubprotocol(reference, &len)
      _subprotocol = String(bytesNoCopy: str!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
    return _subprotocol!
  }

  private weak var delegate: WebSocketDelegate!  
  private var _subprotocol: String?
  private var document: WebDocument?
  private var scope: ServiceWorkerGlobalScope?
  private var worker: WebWorker?
  internal var reference: WebSocketRef!

  public init(delegate: WebSocketDelegate, document: WebDocument) {
    self.delegate = delegate
    self.document = document
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let callbacks = createCallbacks()
    reference = WebSocketCreate(self.document!.reference, state, callbacks)
  }

  public init(delegate: WebSocketDelegate, scope: ServiceWorkerGlobalScope) {
    self.delegate = delegate
    self.scope = scope
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let callbacks = createCallbacks()
    reference = WebSocketCreateForServiceWorker(self.scope!.reference, state, callbacks)
  }

  public init(delegate: WebSocketDelegate, worker: WebWorker) {
    self.delegate = delegate
    self.worker = worker
    let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let callbacks = createCallbacks()
    reference = WebSocketCreateForWorker(self.worker!.reference, state, callbacks)
  }

  deinit {
    WebSocketDestroy(reference)
  }

  public func connect(url: String, `protocol` p: String) {
    url.withCString { curl in
      p.withCString { purl in
        WebSocketConnect(reference, curl, purl)
      }
    }
  }

  public func send(text: String) {
    text.withCString { cstr in 
      return WebSocketSendText(reference, cstr)
    }
  }

  public func send(arrayBuffer: ArrayBuffer) {
    WebSocketSendArrayBuffer(reference, arrayBuffer.reference, 0, Int(arrayBuffer.byteLength))
  }

  public func send(arrayBuffer: ArrayBuffer, offset: Int) {
    WebSocketSendArrayBuffer(reference, arrayBuffer.reference, offset, Int(arrayBuffer.byteLength))
  }

  public func send(arrayBuffer: ArrayBuffer, offset: Int, end: Int) {
    WebSocketSendArrayBuffer(reference, arrayBuffer.reference, offset, end)
  }

  public func close(code: Int, reason: String) {
    reason.withCString {
      WebSocketClose(reference, CInt(code), $0)
    }
  }
  
  public func fail(reason: String) {
    reason.withCString {
      WebSocketFail(reference, $0)
    }
  }
  
  public func disconnect() {
    WebSocketDisconnect(reference)
  }

  public func onConnect(subprotocol: String, extensions: String) {
    delegate.onConnect(subprotocol: subprotocol, extensions: extensions)
  }

  public func onReceiveTextMessage(_ message: String) {
    delegate.onReceiveTextMessage(message)
  }
  
  public func onReceiveBinaryMessage(_ message: Data) {
    delegate.onReceiveBinaryMessage(message)
  }
  
  public func onError() {
    delegate.onError()
  }
  
  public func onConsumeBufferedAmount(consumed: UInt64) {
    delegate.onConsumeBufferedAmount(consumed: consumed)
  }
  
  public func onStartClosingHandshake() {
    delegate.onStartClosingHandshake()
  }
  
  public func onClose(status: ClosingHandshakeCompletionStatus, code: UInt16, reason: String) {
    delegate.onClose(status: status, code: code, reason: reason)
  }

  internal func deallocateBinaryMessage(ptr: UnsafeMutableRawPointer, size: Int) {
    WebSocketReleaseBinaryMessage(reference, ptr, CInt(size))
  }

  private func createCallbacks() -> WebSocketCallbacks {

    var callbacks = WebSocketCallbacks()
    memset(&callbacks, 0, MemoryLayout<WebSocketCallbacks>.stride)

    callbacks.on_connect = { (handle: UnsafeMutableRawPointer?, subprotocol: UnsafePointer<CChar>?, extensions: UnsafePointer<CChar>?) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onConnect(subprotocol: String(cString: subprotocol!), extensions: String(cString: extensions!))
    }
    
    callbacks.on_receive_text_message = { (handle: UnsafeMutableRawPointer?, message: UnsafePointer<CChar>?) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onReceiveTextMessage(String(cString: message!))
    }
    
    callbacks.on_receive_binary_message = { (handle: UnsafeMutableRawPointer?, data: UnsafeMutableRawPointer?, byteLength: CInt) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onReceiveBinaryMessage(Data(bytesNoCopy: data!, count: Int(byteLength), deallocator: .custom(this.deallocateBinaryMessage)))
    }
    
    callbacks.on_error = { (handle: UnsafeMutableRawPointer?) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onError()
    }
    
    callbacks.on_consume_buffered_amount =  { (handle: UnsafeMutableRawPointer?, consumed: UInt64) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onConsumeBufferedAmount(consumed: consumed)
    }
    
    callbacks.on_start_closing_handshake = { (handle: UnsafeMutableRawPointer?) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onStartClosingHandshake()
    }

    callbacks.on_close = { (handle: UnsafeMutableRawPointer?, code: UInt16, reason: UnsafePointer<CChar>?) in
        let this = unsafeBitCast(handle, to: WebSocket.self)
        this.onClose(status: ClosingHandshakeCompletionStatus.closingHandshakeComplete, code: code, reason: String(cString: reason!))
    }

    return callbacks
  }

}