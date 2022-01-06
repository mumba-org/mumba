// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/identity/credential_key.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

char CredentialKey::kClassName[] = "credential_key";  

// static 
std::unique_ptr<CredentialKey> CredentialKey::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::CredentialKey key_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!key_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<CredentialKey> handle(new CredentialKey(std::move(key_proto)));

  return handle;
} 

CredentialKey::CredentialKey(protocol::CredentialKey credential_key_proto): 
  id_(reinterpret_cast<const uint8_t *>(credential_key_proto.uuid().data())),
  credential_key_proto_(std::move(credential_key_proto)),
  managed_(false) {
}

CredentialKey::CredentialKey(): managed_(false) {
  id_ = base::UUID::generate();
  credential_key_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

CredentialKey::~CredentialKey() {
  
}

const std::string& CredentialKey::public_key() const {
  return credential_key_proto_.public_key();
}

const std::string& CredentialKey::public_key_type() const {
  return credential_key_proto_.public_key_type();
}

const std::string& CredentialKey::public_key_encoding() const {
  return credential_key_proto_.public_key_encoding();
}

scoped_refptr<net::IOBufferWithSize> CredentialKey::Serialize() const {
  return protocol::SerializeMessage(credential_key_proto_);
}

}