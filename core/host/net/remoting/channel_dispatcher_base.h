// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_CHANNEL_DISPATCHER_BASE_H_
#define MUMBA_HOST_NET_CHANNEL_DISPATCHER_BASE_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/macros.h"
#include "core/host/net/errors.h"
#include "core/common/protocol/message_pipe.h"

namespace protocol {
class CompoundBuffer;
class MessageChannelFactory;
}

namespace host {

// Base class for channel message dispatchers. It's responsible for
// creating the named channel. Derived dispatchers then dispatch
// incoming messages on this channel as well as send outgoing
// messages.
class ChannelDispatcherBase : public protocol::MessagePipe::EventHandler {
 public:
  class EventHandler {
   public:
    EventHandler() {}
    virtual ~EventHandler() {}

    // Called after the channel is initialized.
    virtual void OnChannelInitialized(
        ChannelDispatcherBase* channel_dispatcher) = 0;

    // Called after the channel is closed.
    virtual void OnChannelClosed(ChannelDispatcherBase* channel_dispatcher) = 0;
  };

  ~ChannelDispatcherBase() override;

  // Creates and connects the channel using |channel_factory|.
  void Init(protocol::MessageChannelFactory* channel_factory,
            EventHandler* event_handler);

  // Initializes the channel using |message_pipe| that's already connected.
  void Init(std::unique_ptr<protocol::MessagePipe> message_pipe,
            EventHandler* event_handler);

  const std::string& channel_name() { return channel_name_; }

  // Returns true if the channel is currently connected.
  bool is_connected() { return is_connected_; }

 protected:
  explicit ChannelDispatcherBase(const std::string& channel_name);

  protocol::MessagePipe* message_pipe() { return message_pipe_.get(); }

  // Child classes must override this method to handle incoming messages.
  virtual void OnIncomingMessage(std::unique_ptr<protocol::CompoundBuffer> message) = 0;

 private:
  void OnChannelReady(std::unique_ptr<protocol::MessagePipe> message_pipe);

  // MessagePipe::EventHandler interface.
  void OnMessagePipeOpen() override;
  void OnMessageReceived(std::unique_ptr<protocol::CompoundBuffer> message) override;
  void OnMessagePipeClosed() override;

  std::string channel_name_;
  protocol::MessageChannelFactory* channel_factory_ = nullptr;
  EventHandler* event_handler_ = nullptr;
  bool is_connected_ = false;

  std::unique_ptr<protocol::MessagePipe> message_pipe_;

  DISALLOW_COPY_AND_ASSIGN(ChannelDispatcherBase);
};

}

#endif  // REMOTING_PROTOCOL_CHANNEL_DISPATCHER_BASE_H_
