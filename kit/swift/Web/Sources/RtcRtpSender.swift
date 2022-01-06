// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct RTCRtpSender {
    public var private(set) track: MediaStreamTrack {

    }

    public var private(set) dtmf: RTCDTMFSender? {

    }

    public var parameters: RtcRtpParameters? {
      get {

      }
      set {

      }
    }
    
    public func replaceTrack(withTrack: MediaStreamTrack?: _ done: () -> ()) {
      
    }
    
    public func getStats(_ callback: (RTCStatsReport?) -> ()) {
      
    }
}