// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/channel_dispatcher_base.h"

#include <utility>

#include "base/bind.h"
#include "core/common/protocol/compound_buffer.h"
#include "core/common/protocol/message_channel_factory.h"
#include "core/common/protocol/message_pipe.h"

namespace host {

ChannelDispatcherBase::ChannelDispatcherBase(const std::string& channel_name)
    : channel_name_(channel_name) {}

ChannelDispatcherBase::~ChannelDispatcherBase() {
  if (channel_factory_)
    channel_factory_->CancelChannelCreation(channel_name_);
}

void ChannelDispatcherBase::Init(protocol::MessageChannelFactory* channel_factory,
                                 EventHandler* event_handler) {
  channel_factory_ = channel_factory;
  event_handler_ = event_handler;

  channel_factory_->CreateChannel(channel_name_, base::Bind(
      &ChannelDispatcherBase::OnChannelReady, base::Unretained(this)));
}

void ChannelDispatcherBase::Init(std::unique_ptr<protocol::MessagePipe> message_pipe,
                                 EventHandler* event_handler) {
  event_handler_ = event_handler;
  OnChannelReady(std::move(message_pipe));
}

void ChannelDispatcherBase::OnChannelReady(
    std::unique_ptr<protocol::MessagePipe> message_pipe) {
  channel_factory_ = nullptr;
  message_pipe_ = std::move(message_pipe);
  message_pipe_->Start(this);
}

void ChannelDispatcherBase::OnMessagePipeOpen() {
  DCHECK(!is_connected_);
  is_connected_ = true;
  event_handler_->OnChannelInitialized(this);
}

void ChannelDispatcherBase::OnMessageReceived(
    std::unique_ptr<protocol::CompoundBuffer> message) {
  OnIncomingMessage(std::move(message));
}

void ChannelDispatcherBase::OnMessagePipeClosed() {
  is_connected_ = false;
  message_pipe_.reset();
  event_handler_->OnChannelClosed(this);
}

}
