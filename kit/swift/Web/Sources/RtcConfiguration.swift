// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum RtcIceTransportPolicy : Int {
  case relay
  case all
}

public enum RtcBundlePolicy : Int {
  case balanced
  case max-compat
  case max-bundle
}

public enum RtcRtcpMuxPolicy : Int {
  case negotiate
  case require
}

public enum SdpSemantics : Int {
  case plan-b
  case unified-plan
}

public struct RtcConfiguration {
  public var iceServers: [RtcIceServer] = []
  public var iceTransportPolicy: RtcIceTransportPolicy
  public var iceTransports: RtcIceTransportPolicy
  public var bundlePolicy: RTCBundlePolicy = RTCBundlePolicy.balanced
  public var rtcpMuxPolicy:RTCRtcpMuxPolicy = RTCRtcpMuxPolicy.require
  public var certificates: [RTCCertificate] = []
  public var iceCandidatePoolSize: Int = 0
  public var sdpSemantics: SdpSemantics
}