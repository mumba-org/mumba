// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum RtcSignalingState {
  case stable
  case have-local-offer
  case have-remote-offer
  case have-local-pranswer
  case have-remote-pranswer
  case closed
}

public enum RtcIceGatheringState {
  case new
  case gathering
  case complete
}

public enum RtcIceConnectionState {
  case new
  case checking
  case connected
  case completed
  case failed
  case disconnected
  case closed
}

public protocol RtcPeerConnectionDelegate {
  func onNegotiationNeeded()
  func onIceCandidate()
  func onSignalingStateChange()
  func onIceConnectionStateChange()
  func onIceGatheringStateChange()
  func onTrack()
  func onDataChannel()
  func onAddStream()
  func onRemoveStream()
}

public class RtcPeerConnection {

    public private(set) var id: String = String()
    public private(set) var localDescription: RtcSessionDescription?
    public private(set) var remoteDescription: RtcSessionDescription?
    public private(set) var signalingState: RtcSignalingState
    public private(set) var iceGatheringState: RtcIceGatheringState
    public private(set) var iceConnectionState: RtcIceConnectionState
    public private(set) var localStreams: [MediaStream] = []
    public private(set) var remoteStreams: [MediaStream] = []
    public private(set) var senders: [RtcRtpSender] = []
    public private(set) var receivers: [RtcRtpReceiver] = []

    static public func generateCertificate(keygenAlgorithm: AlgorithmIdentifier, _ callback: (RtcCertificate?) -> Void) {

    }
    
    public init() {

    }

    public func createOffer(options: RtcOfferOptions?, _ callback: (RtcSessionDescription) -> ()) {

    }

    public func createOffer(onSuccess: (RtcSessionDescription) -> (), onError: (Int) -> (), RtcOfferOptions: [String: String]?) {
      
    }

    public func createAnswer(options: RtcAnswerOptions, _ callback: (RtcSessionDescription) -> ()) {

    }

    public func createAnswer(onSuccess: (RtcSessionDescription) -> (), onError: (Int) -> (), mediaConstraints: [String: String]?) {


    }

    public func addIceCandidate(candidate: RtcIceCandidate) {

    }

    public func addIceCandidate(candidate: RtcIceCandidate, onSuccess: () -> (), onError: (Int) -> ()) {

    }
    
    public func setLocalDescription(description: RtcSessionDescriptionInit) {

    }
    
    public func setLocalDescription(description: RtcSessionDescriptionInit, onSuccess: () -> (), onError: ((Int) -> ())?) {

    }
    
    public func setRemoteDescription(description: RtcSessionDescriptionInit) {

    }

    public func setRemoteDescription(description: RtcSessionDescriptionInit, onSuccess: () -> (), onError: ((Int) -> ())?) {

    }

    public func setConfiguration(configuration: RtcConfiguration) {

    }

    public func close() {

    }
    
    public func getStats((RtcStatsResponse) -> (), selector: MediaStreamTrack?) {

    }
    
    public func addTrack(track: MediaStreamTrack, streams: MediaStream...) -> RtcRtpSender {

    }

    public func removeTrack(sender: RtcRtpSender) {

    }
    
    public func createDataChannel(label: String, dataChannelDict: RtcDataChannelInit?) -> RtcDataChannel {

    }
    
    public func addStream(stream: MediaStream, mediaConstraints: [String: String]?) {

    }

    public func removeStream(stream: MediaStream) {

    }

    public func createDtmfSender(track: MediaStreamTrack) -> RtcDtmfFSender {

    }
}
