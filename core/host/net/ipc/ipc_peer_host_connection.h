// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_IPC_PEER_HOST_CONNECTION_H_
#define MUMBA_HOST_IPC_IPC_PEER_HOST_CONNECTION_H_

#include "base/macros.h"
#include "third_party/webrtc/api/peerconnectioninterface.h"

namespace host {

class IPCPeerHostConnection : public webrtc::PeerConnectionInterface {
 public:
  IPCPeerHostConnection();
  ~IPCPeerHostConnection() override;

  rtc::scoped_refptr<webrtc::StreamCollectionInterface> local_streams() override;
  rtc::scoped_refptr<webrtc::StreamCollectionInterface> remote_streams() override;
  bool AddStream(webrtc::MediaStreamInterface* stream) override;
  void RemoveStream(webrtc::MediaStreamInterface* stream) override;
  bool RemoveTrack(webrtc::RtpSenderInterface* sender) override;

  bool GetStats(webrtc::StatsObserver* observer,
                webrtc::MediaStreamTrackInterface* track,  // Optional
                StatsOutputLevel level) override;
 
  rtc::scoped_refptr<webrtc::DataChannelInterface> CreateDataChannel(
      const std::string& label,
      const webrtc::DataChannelInit* config) override;

  rtc::scoped_refptr<webrtc::DtmfSenderInterface> CreateDtmfSender(
    webrtc::AudioTrackInterface* track) override;

  const webrtc::SessionDescriptionInterface* local_description() const override;
  const webrtc::SessionDescriptionInterface* remote_description() const override;
 
  void CreateOffer(webrtc::CreateSessionDescriptionObserver* observer,
                   const webrtc::MediaConstraintsInterface* constraints) override;
  
  void CreateAnswer(webrtc::CreateSessionDescriptionObserver* observer,
                    const RTCOfferAnswerOptions& options) override;

  void SetLocalDescription(webrtc::SetSessionDescriptionObserver* observer,
                                   webrtc::SessionDescriptionInterface* desc) override;
  
  void SetRemoteDescription(
      std::unique_ptr<webrtc::SessionDescriptionInterface> desc,
      rtc::scoped_refptr<webrtc::SetRemoteDescriptionObserverInterface> observer) override;

 
  webrtc::PeerConnectionInterface::RTCConfiguration GetConfiguration() override;

  bool SetConfiguration(
      const webrtc::PeerConnectionInterface::RTCConfiguration& config,
      webrtc::RTCError* error) override;
  
  bool AddIceCandidate(const webrtc::IceCandidateInterface* candidate) override;

  void RegisterUMAObserver(webrtc::UMAObserver* observer) override;

  webrtc::RTCError SetBitrate(const BitrateParameters& bitrate) override;

  SignalingState signaling_state() override;

  IceConnectionState ice_connection_state() override;

  IceGatheringState ice_gathering_state() override;

  bool StartRtcEventLog(std::unique_ptr<webrtc::RtcEventLogOutput> output,
                        int64_t output_period_ms) override;

  void StopRtcEventLog() override;

  void Close() override;


private:
  // rtc::RefCountInterface implementation.
  void AddRef() const override;
  rtc::RefCountReleaseStatus Release() const override;

  // Reference count; implementation copied from rtc::RefCountedObject.
  mutable volatile int ref_count_ = 0;
  
  DISALLOW_COPY_AND_ASSIGN(IPCPeerHostConnection);
};

}

#endif