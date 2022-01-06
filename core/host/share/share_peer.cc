// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_peer.h"

#include "core/host/share/share_service.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

char SharePeer::kClassName[] = "share_peer";

// static 
std::unique_ptr<SharePeer> SharePeer::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::SharePeer share_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!share_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<SharePeer> handle(new SharePeer(std::move(share_proto)));

  return handle;
} 

SharePeer::SharePeer(protocol::SharePeer peer_proto): 
  id_(reinterpret_cast<const uint8_t *>(peer_proto.uuid().data())),
  peer_proto_(std::move(peer_proto)),
  managed_(false) {
  
}

SharePeer::SharePeer(): 
  managed_(false) {
  id_ = base::UUID::generate();
  peer_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

SharePeer::~SharePeer() {
  
}

void SharePeer::set_ip_address(const std::string& ip_address) {
  ip_address_ = ip_address;
}

scoped_refptr<net::IOBufferWithSize> SharePeer::Serialize() const {
  return protocol::SerializeMessage(peer_proto_);
}

}
