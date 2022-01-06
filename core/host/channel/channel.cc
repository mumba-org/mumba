// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/channel/channel.h"

#include "core/host/channel/channel_client.h"
#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

namespace host {

char Channel::kClassName[] = "channel";    

// static 
std::unique_ptr<Channel> Channel::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Channel channel_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!channel_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Channel>(new Channel(std::move(channel_proto)));
}

Channel::Channel(protocol::Channel channel_proto):
  id_(reinterpret_cast<const uint8_t *>(channel_proto.uuid().data())),
  channel_proto_(std::move(channel_proto)),
  managed_(false) {
  
}

Channel::~Channel() {
  
}

const std::string& Channel::name() const {
  return channel_proto_.name();
}

const std::string& Channel::scheme() const {
  return channel_proto_.scheme();
}

scoped_refptr<net::IOBufferWithSize> Channel::Serialize() const {
  return protocol::SerializeMessage(channel_proto_);
}

void Channel::AddClient(std::unique_ptr<ChannelClient> client) {
  clients_.push_back(std::move(client));
}

ChannelClient* Channel::GetClient(size_t index) const {
  DCHECK(index < clients_.size());
  return clients_[index].get();
}

}
