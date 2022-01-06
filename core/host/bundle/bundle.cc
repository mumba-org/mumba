// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

namespace host {

char Bundle::kClassName[] = "bundle";    

// static 
std::unique_ptr<Bundle> Bundle::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Bundle bundle_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!bundle_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Bundle>(new Bundle(std::move(bundle_proto)));
}

Bundle::Bundle(const std::string& name, const base::FilePath& path, const std::string& executable_path, const std::string& resources_path):
  path_(path),
  managed_(false) {
  
  id_ = base::UUID::generate();
  bundle_proto_.set_uuid(id_.data, 16);
  bundle_proto_.set_name(name);
  bundle_proto_.set_path(path.value());
  bundle_proto_.set_executable_path(executable_path);
  bundle_proto_.set_resources_path(resources_path);
}

Bundle::Bundle(protocol::Bundle bundle_proto):
  id_(reinterpret_cast<const uint8_t *>(bundle_proto.uuid().data())),
  bundle_proto_(std::move(bundle_proto)),
  managed_(false)  {

  path_ = base::FilePath(bundle_proto_.path());
}

Bundle::~Bundle() {
  
}

const std::string& Bundle::name() const {
  return bundle_proto_.name();
}

void Bundle::set_name(const std::string& name) {
  bundle_proto_.set_name(name);
}

const std::string& Bundle::executable_path() const {
  return bundle_proto_.executable_path();
}

const std::string& Bundle::resources_path() const {
  return bundle_proto_.resources_path();
}

void Bundle::set_path(const base::FilePath& path) {
  bundle_proto_.set_path(path.value());
  path_ = path;
}

void Bundle::set_executable_path(const std::string& executable_path) {
  bundle_proto_.set_executable_path(executable_path);
}

void Bundle::set_resources_path(const std::string& resources_path) {
  bundle_proto_.set_resources_path(resources_path);
}

scoped_refptr<net::IOBufferWithSize> Bundle::Serialize() const {
  return protocol::SerializeMessage(bundle_proto_);
}

}
