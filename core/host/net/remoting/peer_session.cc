// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/peer_session.h"

#include "core/host/net/session.h"

namespace host {

PeerSession::PeerSession(
  PeerSession::EventHandler* event_handler,
  std::unique_ptr<PeerConnection> connection,
  const base::TimeDelta& max_duration): 
    event_handler_(event_handler),
    connection_(std::move(connection)),
    max_duration_(max_duration),
    peer_jid_(connection_->session()->jid()),
    is_authenticated_(false),
    channels_connected_(false),
    weak_factory_(this) {
  
}

PeerSession::~PeerSession() {

}

PeerSessionControl* PeerSession::session_control() {
  return nullptr;
}

uint32_t PeerSession::desktop_session_id() const {
  return 0;
}

const std::string& PeerSession::peer_jid() const {
  return peer_jid_;
}

void PeerSession::DisconnectSession(ErrorCode error) {

}

void PeerSession::OnConnectionAuthenticating() {
  event_handler_->OnSessionAuthenticating(this);
}

void PeerSession::OnConnectionAuthenticated() {
 // DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
 // DCHECK(!audio_stream_);
 // DCHECK(!desktop_environment_);
 // DCHECK(!input_injector_);
 // DCHECK(!screen_controls_);
 // DCHECK(!video_stream_);

  is_authenticated_ = true;

  if (max_duration_ > base::TimeDelta()) {
    max_duration_timer_.Start(
        FROM_HERE, max_duration_,
        base::Bind(&PeerSession::DisconnectSession, base::Unretained(this),
                   MAX_SESSION_LENGTH));
  }

  // Notify EventHandler.
  event_handler_->OnSessionAuthenticated(this);

  //const SessionOptions session_options;//
    //  host_experiment_session_plugin_.configuration());

  //connection_->ApplySessionOptions(session_options);

  //DesktopEnvironmentOptions options = desktop_environment_options_;
  //options.ApplySessionOptions(session_options);
  // Create the desktop environment. Drop the connection if it could not be
  // created for any reason (for instance the curtain could not initialize).
  //desktop_environment_ =
  //    desktop_environment_factory_->Create(weak_factory_.GetWeakPtr(), options);
  //if (!desktop_environment_) {
  //  DisconnectSession(protocol::HOST_CONFIGURATION_ERROR);
  //  return;
  //}

  // Connect host stub.
  connection_->set_host_stub(this);

  // Collate the set of capabilities to offer the client, if it supports them.
  //host_capabilities_ = desktop_environment_->GetCapabilities();
  //if (!host_capabilities_.empty())
  //  host_capabilities_.append(" ");
  //host_capabilities_.append(extension_manager_->GetCapabilities());

  // Create the object that controls the screen resolution.
  //screen_controls_ = desktop_environment_->CreateScreenControls();

  // Create the event executor.
  //input_injector_ = desktop_environment_->CreateInputInjector();

  // Connect the host input stubs.
  //connection_->set_input_stub(&disable_input_filter_);
  //host_input_filter_.set_input_stub(input_injector_.get());

  // Connect the clipboard stubs.
  //connection_->set_clipboard_stub(&disable_clipboard_filter_);
  //clipboard_echo_filter_.set_host_stub(input_injector_.get());
  //clipboard_echo_filter_.set_client_stub(connection_->client_stub());
}

// void PeerSession::CreateMediaStreams() {
//   DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

//   // Create a VideoStream to pump frames from the capturer to the client.
//   video_stream_ = connection_->StartVideoStream(
//       desktop_environment_->CreateVideoCapturer());

//   // Create a AudioStream to pump audio from the capturer to the client.
//   std::unique_ptr<protocol::AudioSource> audio_capturer =
//       desktop_environment_->CreateAudioCapturer();
//   if (audio_capturer) {
//     audio_stream_ = connection_->StartAudioStream(std::move(audio_capturer));
//   }

//   video_stream_->SetObserver(this);

//   // Apply video-control parameters to the new stream.
//   video_stream_->SetLosslessEncode(lossless_video_encode_);
//   video_stream_->SetLosslessColor(lossless_video_color_);

//   // Pause capturing if necessary.
//   video_stream_->Pause(pause_video_);

//   if (event_timestamp_source_for_tests_)
//     video_stream_->SetEventTimestampsSource(event_timestamp_source_for_tests_);
// }

void PeerSession::OnConnectionChannelsConnected() {
  //DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  //DCHECK(!channels_connected_);
  channels_connected_ = true;

  // Negotiate capabilities with the client.
  //VLOG(1) << "Host capabilities: " << host_capabilities_;
  //Capabilities capabilities;
  //capabilities.set_capabilities(host_capabilities_);
  //connection_->client_stub()->SetCapabilities(capabilities);

  // Start the event executor.
  //input_injector_->Start(CreateClipboardProxy());
  //SetDisableInputs(false);

  // Create MouseShapePump to send mouse cursor shape.
  //mouse_shape_pump_.reset(
  //    new MouseShapePump(desktop_environment_->CreateMouseCursorMonitor(),
  //                       connection_->client_stub()));

  //if (pending_video_layout_message_) {
  //  connection_->client_stub()->SetVideoLayout(*pending_video_layout_message_);
  //  pending_video_layout_message_.reset();
  //}

  // Notify the event handler that all our channels are now connected.
  event_handler_->OnSessionChannelsConnected(this);
}

void PeerSession::OnConnectionClosed(ErrorCode error) {
  //DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  //HOST_LOG << "Client disconnected: " << client_jid_ << "; error = " << error;

  // Ignore any further callbacks.
  weak_factory_.InvalidateWeakPtrs();

  // If the client never authenticated then the session failed.
  if (!is_authenticated_)
    event_handler_->OnSessionAuthenticationFailed(this);

  // Ensure that any pressed keys or buttons are released.
  //input_tracker_.ReleaseAll();

  // Stop components access the client, audio or video stubs, which are no
  // longer valid once ConnectionToClient calls OnConnectionClosed().
  //audio_stream_.reset();
  //video_stream_.reset();
  //mouse_shape_pump_.reset();
  //client_clipboard_factory_.InvalidateWeakPtrs();
  //input_injector_.reset();
  //screen_controls_.reset();
  //desktop_environment_.reset();

  // Notify the ChromotingHost that this client is disconnected.
  event_handler_->OnSessionClosed(this);
}

void PeerSession::OnChannelChange(const std::string& channel_name,
                                  const TransportRoute& route) {
  //DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  event_handler_->OnSessionRouteChange(this, channel_name, route);
}

void PeerSession::OnIncomingDataChannel(
    const std::string& channel_name,
    std::unique_ptr<protocol::MessagePipe> pipe) {
  data_channel_manager_.OnIncomingDataChannel(channel_name, std::move(pipe));
}

void PeerSession::RequestPairing(const protocol::PairingRequest& pairing_request) {

}

void PeerSession::RegisterCreateHandlerCallback(
  const std::string& prefix,
  DataChannelManager::CreateHandlerCallback constructor) {

}

}