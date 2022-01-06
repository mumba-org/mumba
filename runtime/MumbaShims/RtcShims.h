// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ROUTE_RTC_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ROUTE_RTC_SHIMS_H_

#include "Globals.h"

typedef void* RtcPeerConnectionRef;
typedef void* RtcRtpReceiverRef;
typedef void* RtcRtpSenderRef;
typedef void* RtcDataChannelRef;
typedef void* RtcDtmfSenderRef;

// RtcPeerConnection
EXPORT char* _RtcPeerConnectionGetId(RtcPeerConnectionRef handle, int* size);
EXPORT void _RtcPeerConnectionGetLocalDescription(RtcPeerConnectionRef handle, int* type, char** sdp, int* sdp_size);
EXPORT void _RtcPeerConnectionGetRemoteDescription(RtcPeerConnectionRef handle, int* type, char** sdp, int* sdp_size);

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


#endif