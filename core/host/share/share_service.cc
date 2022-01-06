// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_service.h"

#include "core/common/protocol/message_serialization.h"

namespace host {

char ShareService::kClassName[] = "share_service";

// static 
std::unique_ptr<ShareService> ShareService::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::ShareService share_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!share_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<ShareService> handle(new ShareService(std::move(share_proto)));

  return handle;
} 

ShareService::ShareService(protocol::ShareService service_proto): 
  id_(reinterpret_cast<const uint8_t *>(service_proto.uuid().data())),
  service_proto_(std::move(service_proto)),
  managed_(false) {
  
}

ShareService::ShareService(): 
  managed_(false) {
  id_ = base::UUID::generate();
  service_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

ShareService::~ShareService() {
  
}

void ShareService::set_ip_address(const std::string& ip_address) {
  ip_address_ = ip_address;  
}

void ShareService::set_transport(protocol::ShareTransport transport) {
  DCHECK(false);
  //service_proto_.set_transport(transport); 
}

scoped_refptr<net::IOBufferWithSize> ShareService::Serialize() const {
  return protocol::SerializeMessage(service_proto_);
}

}