// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol RtcDtmfSenderDelegate {
  func onToneChange()
}

public class RtcDtmfSender {
    
    public var canInsertDTMF: Bool
    public var track: MediaStreamTrack
    public var toneBuffer: String
    public var duration: Int64
    public var interToneGap: Int64

    public init() {
        
    }

    public func insertDTMF(DOMString tones, optional long duration, optional long interToneGap) {

    }

}