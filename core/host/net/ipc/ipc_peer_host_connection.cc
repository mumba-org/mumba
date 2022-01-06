// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ipc/ipc_peer_host_connection.h"

#include "core/host/ipc/ipc_data_channel.h"

namespace host {

IPCPeerHostConnection::IPCPeerHostConnection() {

}

IPCPeerHostConnection::~IPCPeerHostConnection() {

}

rtc::scoped_refptr<webrtc::StreamCollectionInterface> IPCPeerHostConnection::local_streams() {
  return {};
}

rtc::scoped_refptr<webrtc::StreamCollectionInterface> IPCPeerHostConnection::remote_streams() {
  return {};
}

bool IPCPeerHostConnection::AddStream(webrtc::MediaStreamInterface* stream) {
  return false;
}

void IPCPeerHostConnection::RemoveStream(webrtc::MediaStreamInterface* stream) {}

bool IPCPeerHostConnection::RemoveTrack(webrtc::RtpSenderInterface* sender) {
  return false;
}

bool IPCPeerHostConnection::GetStats(webrtc::StatsObserver* observer,
              webrtc::MediaStreamTrackInterface* track,  // Optional
              StatsOutputLevel level) {
  return false;
}

rtc::scoped_refptr<webrtc::DataChannelInterface> IPCPeerHostConnection::CreateDataChannel(
    const std::string& label,
    const webrtc::DataChannelInit* config) {
  return rtc::scoped_refptr<webrtc::DataChannelInterface>(new IPCDataChannel());
}

rtc::scoped_refptr<webrtc::DtmfSenderInterface> IPCPeerHostConnection::CreateDtmfSender(
  webrtc::AudioTrackInterface* track) {
  return {};
}

const webrtc::SessionDescriptionInterface* IPCPeerHostConnection::local_description() const {
  return nullptr;
}

const webrtc::SessionDescriptionInterface* IPCPeerHostConnection::remote_description() const {
  return nullptr;
}

void IPCPeerHostConnection::CreateOffer(webrtc::CreateSessionDescriptionObserver* observer,
                 const webrtc::MediaConstraintsInterface* constraints) {}



void IPCPeerHostConnection::CreateAnswer(webrtc::CreateSessionDescriptionObserver* observer,
                  const RTCOfferAnswerOptions& options) {}

void IPCPeerHostConnection::SetLocalDescription(webrtc::SetSessionDescriptionObserver* observer,
                                 webrtc::SessionDescriptionInterface* desc) {}

void IPCPeerHostConnection::SetRemoteDescription(
    std::unique_ptr<webrtc::SessionDescriptionInterface> desc,
    rtc::scoped_refptr<webrtc::SetRemoteDescriptionObserverInterface> observer) {}


webrtc::PeerConnectionInterface::RTCConfiguration IPCPeerHostConnection::GetConfiguration() {
  return webrtc::PeerConnectionInterface::RTCConfiguration();
}


bool IPCPeerHostConnection::SetConfiguration(
    const webrtc::PeerConnectionInterface::RTCConfiguration& config,
    webrtc::RTCError* error) {
  return false;
}

bool IPCPeerHostConnection::AddIceCandidate(const webrtc::IceCandidateInterface* candidate) {
  return false;
}

void IPCPeerHostConnection::RegisterUMAObserver(webrtc::UMAObserver* observer) {

}

webrtc::RTCError IPCPeerHostConnection::SetBitrate(const BitrateParameters& bitrate) {
  return webrtc::RTCError();
}

IPCPeerHostConnection::SignalingState IPCPeerHostConnection::signaling_state() {
  return (IPCPeerHostConnection::SignalingState)0;
}

IPCPeerHostConnection::IceConnectionState IPCPeerHostConnection::ice_connection_state() {
  return (IPCPeerHostConnection::IceConnectionState)0;
}

IPCPeerHostConnection::IceGatheringState IPCPeerHostConnection::ice_gathering_state() {
  return (IPCPeerHostConnection::IceGatheringState)0;
}

bool IPCPeerHostConnection::StartRtcEventLog(
  std::unique_ptr<webrtc::RtcEventLogOutput> output,
  int64_t output_period_ms) {
  
  return false;
}

void IPCPeerHostConnection::StopRtcEventLog() {

}

void IPCPeerHostConnection::Close() {

}

void IPCPeerHostConnection::AddRef() const {
  rtc::AtomicOps::Increment(&ref_count_);
}

rtc::RefCountReleaseStatus IPCPeerHostConnection::Release() const {
  if (rtc::AtomicOps::Decrement(&ref_count_) == 0) {
    delete this;
    return rtc::RefCountReleaseStatus::kDroppedLastRef;
  }
  return rtc::RefCountReleaseStatus::kOtherRefsRemained;
}

}