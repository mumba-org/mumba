// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/device/device.h"

#include "base/callback.h"
#include "base/strings/string_util.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

char Device::kClassName[] = "device";  

// static 
std::unique_ptr<Device> Device::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Device device_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!device_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Device>(new Device(std::move(device_proto)));
}

Device::Device(protocol::Device device_proto):
 device_proto_(std::move(device_proto)),
 managed_(false) {

 id_ = base::UUID(reinterpret_cast<const uint8_t *>(device_proto_.uuid().data()));
}

Device::~Device() {

}

const std::string& Device::type() const {
  return device_proto_.type();
}

const std::string& Device::name() const {
  return device_proto_.name();
}  

scoped_refptr<net::IOBufferWithSize> Device::Serialize() const {
  return protocol::SerializeMessage(device_proto_);
}

}
