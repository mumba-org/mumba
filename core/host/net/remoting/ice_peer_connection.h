// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_ICE_CONNECTION_TO_CLIENT_H_
#define MUMBA_HOST_NET_ICE_CONNECTION_TO_CLIENT_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "core/host/net/channel_dispatcher_base.h"
#include "core/host/net/peer_connection.h"
#include "core/host/net/ice_transport.h"
#include "core/host/net/session.h"

namespace host {
//class AudioWriter;
class HostControlDispatcher;
//class HostEventDispatcher;
//class HostVideoDispatcher;

// This class represents a remote viewer connection to the chromoting
// host. It sets up all protocol channels and connects them to the
// stubs.
class IcePeerConnection : public PeerConnection,
                          public Session::EventHandler,
                          public IceTransport::EventHandler,
                          public ChannelDispatcherBase::EventHandler {
 public:
  IcePeerConnection(
      std::unique_ptr<Session> session,
      scoped_refptr<TransportContext> transport_context);//,
      //scoped_refptr<base::SingleThreadTaskRunner> video_encode_task_runner,
      //scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner);
  ~IcePeerConnection() override;

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
//  void set_clipboard_stub(ClipboardStub* clipboard_stub) override;
  void set_host_stub(HostStub* host_stub) override;
  //void set_input_stub(InputStub* input_stub) override;

 private:
  // Session::EventHandler interface.
  void OnSessionStateChange(Session::State state) override;

  // IceTransport::EventHandler interface.
  void OnIceTransportRouteChange(const std::string& channel_name,
                                 const TransportRoute& route) override;
  void OnIceTransportError(ErrorCode error) override;

  // ChannelDispatcherBase::EventHandler interface.
  void OnChannelInitialized(ChannelDispatcherBase* channel_dispatcher) override;
  void OnChannelClosed(ChannelDispatcherBase* channel_dispatcher) override;

  // Callback passed to |event_dispatcher_|
  void OnInputEventReceived(int64_t timestamp);

  void NotifyIfChannelsReady();

  void CloseChannels();

  base::ThreadChecker thread_checker_;

  // Event handler for handling events sent from this object.
  PeerConnection::EventHandler* event_handler_;

  std::unique_ptr<Session> session_;

  //scoped_refptr<base::SingleThreadTaskRunner> video_encode_task_runner_;
  //scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner_;

  IceTransport transport_;

  std::unique_ptr<HostControlDispatcher> control_dispatcher_;
  //std::unique_ptr<HostEventDispatcher> event_dispatcher_;
  //std::unique_ptr<HostVideoDispatcher> video_dispatcher_;
  //std::unique_ptr<AudioWriter> audio_writer_;

  DISALLOW_COPY_AND_ASSIGN(IcePeerConnection);
};

}  // namespace host

#endif  // REMOTING_PROTOCOL_ICE_CONNECTION_TO_CLIENT_H_
