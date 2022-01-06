// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_WEBRTC_CONNECTION_TO_CLIENT_H_
#define MUMBA_HOST_NET_WEBRTC_CONNECTION_TO_CLIENT_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "core/host/net/channel_dispatcher_base.h"
#include "core/host/net/peer_connection.h"
#include "core/host/net/peer_session.h"
#include "core/host/net/session.h"
#include "core/host/net/webrtc_transport.h"

namespace host {

class HostControlDispatcher;
//class HostEventDispatcher;

class WebrtcPeerConnection : public PeerConnection,
                             public Session::EventHandler,
                             public WebrtcTransport::EventHandler,
                             public ChannelDispatcherBase::EventHandler {
 public:
  WebrtcPeerConnection(
      std::unique_ptr<Session> session,
      scoped_refptr<TransportContext> transport_context);//,
      //scoped_refptr<base::SingleThreadTaskRunner> video_encode_task_runner,
      //scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner);
  ~WebrtcPeerConnection() override;

  // ConnectionToClient interface.
  void SetEventHandler(
      PeerConnection::EventHandler* event_handler) override;
  Session* session() const override;
  void Disconnect(ErrorCode error) override;
  //std::unique_ptr<VideoStream> StartVideoStream(
  //    std::unique_ptr<webrtc::DesktopCapturer> desktop_capturer) override;
  //std::unique_ptr<AudioStream> StartAudioStream(
  //    std::unique_ptr<AudioSource> audio_source) override;
  ClientStub* client_stub() override;
  //void set_clipboard_stub(ClipboardStub* clipboard_stub) override;
  void set_host_stub(HostStub* host_stub) override;
  //void set_input_stub(InputStub* input_stub) override;
  void ApplySessionOptions(const SessionOptions& options) override;

  // Session::EventHandler interface.
  void OnSessionStateChange(Session::State state) override;

  // WebrtcTransport::EventHandler interface
  void OnWebrtcTransportConnecting() override;
  void OnWebrtcTransportConnected() override;
  void OnWebrtcTransportError(ErrorCode error) override;
  void OnWebrtcTransportIncomingDataChannel(
      const std::string& name,
      std::unique_ptr<protocol::MessagePipe> pipe) override;
  //void OnWebrtcTransportMediaStreamAdded(
  //    scoped_refptr<webrtc::MediaStreamInterface> stream) override;
  //void OnWebrtcTransportMediaStreamRemoved(
  //    scoped_refptr<webrtc::MediaStreamInterface> stream) override;

  // ChannelDispatcherBase::EventHandler interface.
  void OnChannelInitialized(ChannelDispatcherBase* channel_dispatcher) override;
  void OnChannelClosed(ChannelDispatcherBase* channel_dispatcher) override;

 private:
  base::ThreadChecker thread_checker_;

  // Event handler for handling events sent from this object.
  PeerConnection::EventHandler* event_handler_ = nullptr;

  std::unique_ptr<WebrtcTransport> transport_;

  std::unique_ptr<Session> session_;

  //scoped_refptr<base::SingleThreadTaskRunner> video_encode_task_runner_;
  //scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner_;

  SessionOptions session_options_;

  std::unique_ptr<HostControlDispatcher> control_dispatcher_;
  //std::unique_ptr<HostEventDispatcher> event_dispatcher_;
  
  base::WeakPtrFactory<WebrtcPeerConnection> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(WebrtcPeerConnection);
};

}  // namespace protocol

#endif  // REMOTING_PROTOCOL_WEBRTC_CONNECTION_TO_CLIENT_H_
