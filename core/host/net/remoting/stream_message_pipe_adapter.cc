// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/stream_message_pipe_adapter.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "net/base/net_errors.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "core/host/net/buffered_socket_writer.h"
#include "core/common/protocol/compound_buffer.h"
#include "core/common/protocol/message_serialization.h"
#include "core/common/protocol/peer_stream_socket.h"
#include "core/host/net/stream_channel_factory.h"

namespace host {

StreamMessagePipeAdapter::StreamMessagePipeAdapter(
    std::unique_ptr<protocol::PeerStreamSocket> socket,
    const ErrorCallback& error_callback)
    : socket_(std::move(socket)), error_callback_(error_callback) {
  DCHECK(socket_);
  DCHECK(error_callback_);
}

StreamMessagePipeAdapter::~StreamMessagePipeAdapter() = default;

void StreamMessagePipeAdapter::Start(EventHandler* event_handler) {
  DCHECK(event_handler);
  event_handler_ = event_handler;

  writer_ = std::make_unique<BufferedSocketWriter>();
  writer_->Start(
      base::Bind(&protocol::PeerStreamSocket::Write, base::Unretained(socket_.get())),
      base::Bind(&StreamMessagePipeAdapter::CloseOnError,
                 base::Unretained(this)));

  reader_ = std::make_unique<protocol::MessageReader>();
  reader_->StartReading(socket_.get(),
                        base::Bind(&EventHandler::OnMessageReceived,
                                   base::Unretained(event_handler_)),
                        base::Bind(&StreamMessagePipeAdapter::CloseOnError,
                                   base::Unretained(this)));

  event_handler_->OnMessagePipeOpen();
}

void StreamMessagePipeAdapter::Send(const google::protobuf::MessageLite& message,
                                    const base::Closure& done) {
  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("stream_message_pipe_adapter", R"(
        semantics {
          sender: "Stream Message Pipe Adapter"
          description: "Chrome Remote Desktop P2P channel."
          trigger: "Initiating a Chrome Remote Desktop connection."
          data:
            "Chrome Remote Desktop session data, including video and input "
            "events."
          destination: OTHER
          destination_other:
            "The Chrome Remote Desktop client/host that user is connecting to."
        }
        policy {
          cookies_allowed: NO
          setting:
            "This request cannot be stopped in settings, but will not be sent "
            "if user does not use Chrome Remote Desktop."
          policy_exception_justification:
            "Not implemented. 'RemoteAccessHostClientDomainList' and "
            "'RemoteAccessHostDomainList' policies can limit the domains to "
            "which a connection can be made, but they cannot be used to block "
            "the request to all domains. Please refer to help desk for other "
            "approaches to manage this feature."
        })");
  if (writer_)
    writer_->Write(protocol::SerializeAndFrameMessage(message), done,
                   traffic_annotation);
}

void StreamMessagePipeAdapter::CloseOnError(int error) {
  // Stop reading and writing on error.
  writer_.reset();
  reader_.reset();

  if (error == 0) {
    event_handler_->OnMessagePipeClosed();
  } else if (error_callback_) {
    base::ResetAndReturn(&error_callback_).Run(error);
  }
}

StreamMessageChannelFactoryAdapter::StreamMessageChannelFactoryAdapter(
    StreamChannelFactory* stream_channel_factory,
    const ErrorCallback& error_callback)
    : stream_channel_factory_(stream_channel_factory),
      error_callback_(error_callback) {}

StreamMessageChannelFactoryAdapter::~StreamMessageChannelFactoryAdapter() =
    default;

void StreamMessageChannelFactoryAdapter::CreateChannel(
    const std::string& name,
    const ChannelCreatedCallback& callback) {
  stream_channel_factory_->CreateChannel(
      name, base::Bind(&StreamMessageChannelFactoryAdapter::OnChannelCreated,
                       base::Unretained(this), callback));
}

void StreamMessageChannelFactoryAdapter::CancelChannelCreation(
    const std::string& name) {
  stream_channel_factory_->CancelChannelCreation(name);
}

void StreamMessageChannelFactoryAdapter::OnChannelCreated(
    const ChannelCreatedCallback& callback,
    std::unique_ptr<protocol::PeerStreamSocket> socket) {
  if (!socket) {
    error_callback_.Run(net::ERR_FAILED);
    return;
  }
  callback.Run(std::make_unique<StreamMessagePipeAdapter>(std::move(socket),
                                                          error_callback_));
}

}  //
