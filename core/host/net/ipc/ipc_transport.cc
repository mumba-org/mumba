// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ipc/ipc_transport.h"

#include <string>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/callback_helpers.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/optional.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/task_runner_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/host/net/authenticator.h"
#include "core/host/net/port_allocator_factory.h"
#include "core/host/net/sdp_message.h"
#include "core/host/net/stream_message_pipe_adapter.h"
#include "core/host/net/transport_context.h"
#include "core/host/ipc/ipc_peer_connection.h"
#include "core/host/ipc/ipc_data_stream_adapter.h"
#include "core/host/ipc/ipc_peer_host_connection.h"
#include "third_party/libjingle_xmpp/xmllite/xmlelement.h"
#include "third_party/libjingle_xmpp/xmllite/xmlelement.h"
#include "third_party/webrtc/api/audio_codecs/audio_decoder_factory_template.h"
#include "third_party/webrtc/api/audio_codecs/audio_encoder_factory_template.h"
#include "third_party/webrtc/api/audio_codecs/opus/audio_decoder_opus.h"
#include "third_party/webrtc/api/audio_codecs/opus/audio_encoder_opus.h"
#include "third_party/webrtc/api/test/fakeconstraints.h"

namespace host {

namespace {
// Delay after candidate creation before sending transport-info message to
// accumulate multiple candidates. This is an optimization to reduce number of
// transport-info messages.
//const int kTransportInfoSendDelayMs = 20;

// XML namespace for the transport elements.
//const char kTransportNamespace[] = "google:remoting:webrtc";

}

class IPCTransport::PeerConnectionWrapper : public webrtc::PeerConnectionObserver {
 public:
  PeerConnectionWrapper(
      //rtc::Thread* worker_thread,
      base::WeakPtr<IPCTransport> transport)
      : transport_(transport) {

    // peer_connection_factory_ = webrtc::CreatePeerConnectionFactory(
    //     worker_thread, rtc::Thread::Current(), nullptr,//audio_module_.get(),
    //     webrtc::CreateAudioEncoderFactory<webrtc::AudioEncoderOpus>(),
    //     webrtc::CreateAudioDecoderFactory<webrtc::AudioDecoderOpus>(),
    //     encoder_factory.release(), nullptr);

    // webrtc::FakeConstraints constraints;
    // constraints.AddMandatory(webrtc::MediaConstraintsInterface::kEnableDtlsSrtp,
    //                          webrtc::MediaConstraintsInterface::kValueTrue);

    // webrtc::PeerConnectionInterface::RTCConfiguration rtc_config;

    // // Set bundle_policy and rtcp_mux_policy to ensure that all channels are
    // // multiplexed over a single channel.
    // rtc_config.bundle_policy =
    //     webrtc::PeerConnectionInterface::kBundlePolicyMaxBundle;
    // rtc_config.rtcp_mux_policy =
    //     webrtc::PeerConnectionInterface::kRtcpMuxPolicyRequire;

    // rtc_config.media_config.video.periodic_alr_bandwidth_probing = true;

   // peer_connection_ = peer_connection_factory_->CreatePeerConnection(
    //   rtc_config, &constraints, std::move(port_allocator), nullptr, this);

    peer_connection_ = new IPCPeerHostConnection();
  }

  ~PeerConnectionWrapper() override {
    // PeerConnection creates threads internally, which are stopped when the
    // connection is closed. Thread.Stop() is a blocking operation.
    // See crbug.com/660081.
     base::ThreadRestrictions::ScopedAllowIO allow_io;
     peer_connection_->Close();
     peer_connection_ = nullptr;
    // peer_connection_factory_ = nullptr;
    //audio_module_ = nullptr;
  }

  //WebrtcAudioModule* audio_module() {
    //return audio_module_.get();
  //  return nullptr;
  //}

  webrtc::PeerConnectionInterface* peer_connection() {
    return peer_connection_.get();
  }

  //webrtc::PeerConnectionFactoryInterface* peer_connection_factory() {
  // return peer_connection_factory_.get();
  //}

  // webrtc::PeerConnectionObserver interface.
  void OnSignalingChange(
      webrtc::PeerConnectionInterface::SignalingState new_state) override {
    //if (transport_)
     // transport_->OnSignalingChange(new_state);
  }

  void OnAddStream(
      rtc::scoped_refptr<webrtc::MediaStreamInterface> stream) override {
//    if (transport_)
 //     transport_->OnAddStream(stream);
  }

  void OnRemoveStream(
      rtc::scoped_refptr<webrtc::MediaStreamInterface> stream) override {
  //  if (transport_)
  //    transport_->OnRemoveStream(stream);
  }

  void OnDataChannel(
      rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel) override {
    if (transport_)
      transport_->OnDataChannel(data_channel);
  }

  void OnRenegotiationNeeded() {
    //if (transport_)
    //  transport_->OnRenegotiationNeeded();
  }

  void OnIceConnectionChange(
      webrtc::PeerConnectionInterface::IceConnectionState new_state) override {
    //if (transport_)
    //  transport_->OnIceConnectionChange(new_state);
  }

  void OnIceGatheringChange(
      webrtc::PeerConnectionInterface::IceGatheringState new_state) override {
    //if (transport_)
    //  transport_->OnIceGatheringChange(new_state);
  }

  void OnIceCandidate(const webrtc::IceCandidateInterface* candidate) override {
    //if (transport_)
    //  transport_->OnIceCandidate(candidate);
  }

 private:
  //scoped_refptr<WebrtcAudioModule> audio_module_;
  //scoped_refptr<webrtc::PeerConnectionFactoryInterface>
  //    peer_connection_factory_;
  scoped_refptr<webrtc::PeerConnectionInterface> peer_connection_;

  base::WeakPtr<IPCTransport> transport_;

  DISALLOW_COPY_AND_ASSIGN(PeerConnectionWrapper);
};


IPCTransport::IPCTransport(scoped_refptr<TransportContext> transport_context,
                           EventHandler* event_handler):
                          transport_context_(transport_context),
                          event_handler_(event_handler),
                          handshake_hmac_(crypto::HMAC::SHA256),
                          weak_factory_(this) {

 // Takes ownership of video_encoder_factory_.
  peer_connection_wrapper_.reset(new PeerConnectionWrapper(
      //worker_thread,
      //std::move(port_allocator), 
    weak_factory_.GetWeakPtr()));
}
  
IPCTransport::~IPCTransport() {
  Close(OK);
}

webrtc::PeerConnectionInterface* IPCTransport::peer_connection() {
  return peer_connection_wrapper_->peer_connection();
}

void IPCTransport::Start(Authenticator* authenticator,
                         SendTransportInfoCallback send_transport_info_callback) {
  event_handler_->OnIPCTransportConnecting();

  //if (transport_context_->role() == TransportRole::SERVER)
  //  RequestNegotiation();
}

bool IPCTransport::ProcessTransportInfo(buzz::XmlElement* transport_info) {
//   if (transport_info->Name() != QName(kTransportNamespace, "transport"))
//     return false;

//   if (!peer_connection())
//     return false;

//   XmlElement* session_description = transport_info->FirstNamed(
//       QName(kTransportNamespace, "session-description"));
//   if (session_description) {
//     webrtc::PeerConnectionInterface::SignalingState expected_state =
//         transport_context_->role() == TransportRole::CLIENT
//             ? webrtc::PeerConnectionInterface::kStable
//             : webrtc::PeerConnectionInterface::kHaveLocalOffer;
//     if (peer_connection()->signaling_state() != expected_state) {
//       LOG(ERROR) << "Received unexpected WebRTC session_description.";
//       return false;
//     }

//     std::string type = session_description->Attr(QName(std::string(), "type"));
//     std::string raw_sdp = session_description->BodyText();
//     if (!IsValidSessionDescriptionType(type) || raw_sdp.empty()) {
//       LOG(ERROR) << "Incorrect session description format.";
//       return false;
//     }

//     SdpMessage sdp_message(raw_sdp);

//     std::string signature_base64 =
//         session_description->Attr(QName(std::string(), "signature"));
//     std::string signature;
//     if (!base::Base64Decode(signature_base64, &signature) ||
//         !handshake_hmac_.Verify(
//             type + " " + sdp_message.NormalizedForSignature(), signature)) {
//       LOG(WARNING) << "Received session-description with invalid signature.";
//       bool ignore_error = false;
// #if !defined(NDEBUG)
//       ignore_error = base::CommandLine::ForCurrentProcess()->HasSwitch(
//           kDisableAuthenticationSwitchName);
// #endif
//       if (!ignore_error) {
//         Close(AUTHENTICATION_FAILED);
//         return true;
//       }
//     }

//     UpdateCodecParameters(&sdp_message, /*incoming=*/true);

//     webrtc::SdpParseError error;
//     std::unique_ptr<webrtc::SessionDescriptionInterface> session_description(
//         webrtc::CreateSessionDescription(type, sdp_message.ToString(), &error));
//     if (!session_description) {
//       LOG(ERROR) << "Failed to parse the session description: "
//                  << error.description << " line: " << error.line;
//       return false;
//     }

//     peer_connection()->SetRemoteDescription(
//         SetSessionDescriptionObserver::Create(
//             base::Bind(&WebrtcTransport::OnRemoteDescriptionSet,
//                        weak_factory_.GetWeakPtr(),
//                        type == webrtc::SessionDescriptionInterface::kOffer)),
//         session_description.release());
//   }

//   XmlElement* candidate_element;
//   QName candidate_qname(kTransportNamespace, "candidate");
//   for (candidate_element = transport_info->FirstNamed(candidate_qname);
//        candidate_element;
//        candidate_element = candidate_element->NextNamed(candidate_qname)) {
//     std::string candidate_str = candidate_element->BodyText();
//     std::string sdp_mid =
//         candidate_element->Attr(QName(std::string(), "sdpMid"));
//     std::string sdp_mlineindex_str =
//         candidate_element->Attr(QName(std::string(), "sdpMLineIndex"));
//     int sdp_mlineindex;
//     if (candidate_str.empty() || sdp_mid.empty() ||
//         !base::StringToInt(sdp_mlineindex_str, &sdp_mlineindex)) {
//       LOG(ERROR) << "Failed to parse incoming candidates.";
//       return false;
//     }

//     webrtc::SdpParseError error;
//     std::unique_ptr<webrtc::IceCandidateInterface> candidate(
//         webrtc::CreateIceCandidate(sdp_mid, sdp_mlineindex, candidate_str,
//                                    &error));
//     if (!candidate) {
//       LOG(ERROR) << "Failed to parse incoming candidate: " << error.description
//                  << " line: " << error.line;
//       return false;
//     }

//     if (peer_connection()->signaling_state() ==
//         webrtc::PeerConnectionInterface::kStable) {
//       if (!peer_connection()->AddIceCandidate(candidate.get())) {
//         LOG(ERROR) << "Failed to add incoming ICE candidate.";
//         return false;
//       }
//     } else {
//       pending_incoming_candidates_.push_back(std::move(candidate));
//     }
//   }

  return true;
}

void IPCTransport::OnLocalSessionDescriptionCreated(
    std::unique_ptr<webrtc::SessionDescriptionInterface> description,
    const std::string& error) {
  //DCHECK(thread_checker_.CalledOnValidThread());

  // if (!peer_connection())
  //   return;

  // if (!description) {
  //   LOG(ERROR) << "PeerConnection offer creation failed: " << error;
  //   Close(CHANNEL_CONNECTION_ERROR);
  //   return;
  // }

  // std::string description_sdp;
  // if (!description->ToString(&description_sdp)) {
  //   LOG(ERROR) << "Failed to serialize description.";
  //   Close(CHANNEL_CONNECTION_ERROR);
  //   return;
  // }

  // SdpMessage sdp_message(description_sdp);
  // UpdateCodecParameters(&sdp_message, /*incoming=*/false);
  // if (preferred_video_codec_.empty()) {
  //   sdp_message.PreferVideoCodec("VP8");
  // } else {
  //   sdp_message.PreferVideoCodec(preferred_video_codec_);
  // }
  // description_sdp = sdp_message.ToString();
  // webrtc::SdpParseError parse_error;
  // description.reset(webrtc::CreateSessionDescription(
  //     description->type(), description_sdp, &parse_error));
  // if (!description) {
  //   LOG(ERROR) << "Failed to parse the session description: "
  //              << parse_error.description << " line: " << parse_error.line;
  //   Close(CHANNEL_CONNECTION_ERROR);
  //   return;
  // }

  // // Format and send the session description to the peer.
  // std::unique_ptr<XmlElement> transport_info(
  //     new XmlElement(QName(kTransportNamespace, "transport"), true));
  // XmlElement* offer_tag =
  //     new XmlElement(QName(kTransportNamespace, "session-description"));
  // transport_info->AddElement(offer_tag);
  // offer_tag->SetAttr(QName(std::string(), "type"), description->type());
  // offer_tag->SetBodyText(description_sdp);

  // std::string digest;
  // digest.resize(handshake_hmac_.DigestLength());
  // CHECK(handshake_hmac_.Sign(
  //     description->type() + " " + sdp_message.NormalizedForSignature(),
  //     reinterpret_cast<uint8_t*>(&(digest[0])), digest.size()));
  // std::string digest_base64;
  // base::Base64Encode(digest, &digest_base64);
  // offer_tag->SetAttr(QName(std::string(), "signature"), digest_base64);

  // send_transport_info_callback_.Run(std::move(transport_info));

  // peer_connection()->SetLocalDescription(
  //     SetSessionDescriptionObserver::Create(base::Bind(
  //         &IPCTransport::OnLocalDescriptionSet, weak_factory_.GetWeakPtr())),
  //     description.release());
}

void IPCTransport::Close(ErrorCode error) {
  if (!peer_connection_wrapper_)
    return;

  weak_factory_.InvalidateWeakPtrs();

  // Close and delete PeerConnection asynchronously. PeerConnection may be on
  // the stack and so it must be destroyed later.
  base::ThreadTaskRunnerHandle::Get()->DeleteSoon(
      FROM_HERE, peer_connection_wrapper_.release());

  if (error != OK)
    event_handler_->OnIPCTransportError(error);
}

void IPCTransport::RequestNegotiation() {
  DCHECK(transport_context_->role() == TransportRole::SERVER);

  if (!negotiation_pending_) {
    negotiation_pending_ = true;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&IPCTransport::SendOffer, weak_factory_.GetWeakPtr()));
  }
}

std::unique_ptr<protocol::MessagePipe> IPCTransport::CreateOutgoingChannel(
    const std::string& name) {
  webrtc::DataChannelInit config;
  config.reliable = true;
  return std::make_unique<IPCDataStreamAdapter>(
      peer_connection()->CreateDataChannel(name, &config));
}

void IPCTransport::SendOffer() {
  DCHECK(transport_context_->role() == TransportRole::SERVER);

  DCHECK(negotiation_pending_);
  negotiation_pending_ = false;

  //webrtc::FakeConstraints offer_config;
  // offer_config.AddMandatory(
  //     webrtc::MediaConstraintsInterface::kOfferToReceiveVideo,
  //     webrtc::MediaConstraintsInterface::kValueTrue);
  // offer_config.AddMandatory(
  //     webrtc::MediaConstraintsInterface::kOfferToReceiveAudio,
  //     webrtc::MediaConstraintsInterface::kValueFalse);
  // offer_config.AddMandatory(webrtc::MediaConstraintsInterface::kEnableDtlsSrtp,
  //                           webrtc::MediaConstraintsInterface::kValueTrue);
  // if (want_ice_restart_) {
  //   offer_config.AddMandatory(webrtc::MediaConstraintsInterface::kIceRestart,
  //                             webrtc::MediaConstraintsInterface::kValueTrue);
  //   want_ice_restart_ = false;
  // }
  // peer_connection()->CreateOffer(
  //     CreateSessionDescriptionObserver::Create(
  //         base::Bind(&IPCTransport::OnLocalSessionDescriptionCreated,
  //                    weak_factory_.GetWeakPtr())),
  //     &offer_config);
}

void IPCTransport::OnDataChannel(
    rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel) {
  //DCHECK(thread_checker_.CalledOnValidThread());
  event_handler_->OnIPCTransportIncomingDataChannel(
      data_channel->label(),
      std::make_unique<IPCDataStreamAdapter>(data_channel));
}

}