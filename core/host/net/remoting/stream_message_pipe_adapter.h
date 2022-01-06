// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STREAM_MESSAGE_PIPE_ADAPTER_H_
#define MUMBA_HOST_STREAM_MESSAGE_PIPE_ADAPTER_H_

#include "base/callback.h"
#include "core/common/protocol/message_channel_factory.h"
#include "core/common/protocol/message_pipe.h"
#include "core/common/protocol/message_reader.h"

namespace protocol {
class PeerStreamSocket;  
}

namespace host {
class BufferedSocketWriter;
class StreamChannelFactory;

// MessagePipe implementation that sends and receives messages over a
// P2PStreamSocket.
class StreamMessagePipeAdapter : public protocol::MessagePipe {
 public:
  typedef base::Callback<void(int)> ErrorCallback;

  StreamMessagePipeAdapter(std::unique_ptr<protocol::PeerStreamSocket> socket,
                           const ErrorCallback& error_callback);
  ~StreamMessagePipeAdapter() override;

  // MessagePipe interface.
  void Start(EventHandler* event_handler) override;
  void Send(const google::protobuf::MessageLite& message,
            const base::Closure& done) override;

 private:
  void CloseOnError(int error);

  EventHandler* event_handler_ = nullptr;

  std::unique_ptr<protocol::PeerStreamSocket> socket_;
  ErrorCallback error_callback_;

  std::unique_ptr<protocol::MessageReader> reader_;
  std::unique_ptr<BufferedSocketWriter> writer_;

  DISALLOW_COPY_AND_ASSIGN(StreamMessagePipeAdapter);
};

class StreamMessageChannelFactoryAdapter : public protocol::MessageChannelFactory {
 public:
  typedef base::Callback<void(int)> ErrorCallback;

  StreamMessageChannelFactoryAdapter(
      StreamChannelFactory* stream_channel_factory,
      const ErrorCallback& error_callback);
  ~StreamMessageChannelFactoryAdapter() override;

  // MessageChannelFactory interface.
  void CreateChannel(const std::string& name,
                     const ChannelCreatedCallback& callback) override;
  void CancelChannelCreation(const std::string& name) override;

 private:
  void OnChannelCreated(const ChannelCreatedCallback& callback,
                        std::unique_ptr<protocol::PeerStreamSocket> socket);

  StreamChannelFactory* stream_channel_factory_;
  ErrorCallback error_callback_;

  DISALLOW_COPY_AND_ASSIGN(StreamMessageChannelFactoryAdapter);
};

}  // namespace host

#endif  // REMOTING_PROTOCOL_STREAM_MESSAGE_PIPE_ADAPTER_H_
