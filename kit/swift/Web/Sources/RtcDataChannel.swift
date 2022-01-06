// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct RtcDataChannelOptions {
  public var ordered: Bool = true
  public var maxRetransmitTime: UInt16 = 0
  public var maxRetransmits: UInt16 = 0
  public var `protocol`: String = String()
  public var negotiated: Bool = false
  public var id: UInt16 = 0
}

public enum RtcDataChannelState : Int {
  case connecting
  case open
  case closing
  case closed
}

public protocol RtcDataChannelDelegate {
  func onOpen()
  func onBufferedAmountLow()
  func onError()
  func onClose()
  func onMessage()
}

public class RtcDataChannel {
  
  public weak var delegate: RtcDataChannelDelegate?
  public var label: String = String()
  public var ordered: Bool = true
  public private(set) var maxRetransmitTime: UInt16 = 0
  public private(set) var maxRetransmits: UInt16 = 0
  public var `protocol`: String = String()
  public var negotiated: Bool = false
  public var id: UInt16 = 0
  public var readyState: RTCDataChannelState
  public var bufferedAmount: UInt64
  public var bufferedAmountLowThreshold: UInt64
  public var binaryType: String
  public var reliable: Bool

  public init(delegate: RtcDataChannelDelegate, options: RtcDataChannelOptions) {

  }

  public func close() {

  }
    
  public func send(data: String) {

  }
  
  public func send(data: Blob) {

  }
  
  public func send(data: ArrayBuffer) {

  }
  
  public func send(data: ArrayBufferView) {

  }
  
}