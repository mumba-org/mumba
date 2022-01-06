// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/channel/channel_client.h"

#include "core/host/channel/channel_manager.h"

namespace host {

ChannelClient::ChannelClient(
  ChannelManager* manager, 
  const base::UUID& id, 
  const std::string& scheme,
  const std::string& name,
  common::mojom::ChannelClientAssociatedPtrInfo client,
  common::mojom::ChannelClientAssociatedRequest connection):
 manager_(manager),
 id_(id),
 scheme_(scheme),
 name_(name),
 binding_(this, std::move(connection)) {
  client_.Bind(std::move(client));
}

ChannelClient::~ChannelClient() {
  
}

void ChannelClient::OnMessage(common::CloneableMessage message) {
  manager_->ReceivedMessageOnChannel(this, std::move(message));
}

void ChannelClient::MessageToClient(const common::CloneableMessage& message) const {
  client_->OnMessage(message.ShallowClone());
} 

}