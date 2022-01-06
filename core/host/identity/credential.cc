// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/identity/credential.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/identity/credential_key.h"

namespace host {

char Credential::kClassName[] = "credential";  

// static 
std::unique_ptr<Credential> Credential::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Credential credential_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!credential_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<Credential> handle(new Credential(std::move(credential_proto)));

  return handle;
} 

Credential::Credential(protocol::Credential credential_proto): 
  id_(reinterpret_cast<const uint8_t *>(credential_proto.uuid().data())),
  credential_proto_(std::move(credential_proto)),
  managed_(false) {
}

Credential::Credential(): managed_(false) {
  id_ = base::UUID::generate();
  credential_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

Credential::~Credential() {
  
}

protocol::CredentialType Credential::type() const {
  return credential_proto_.type();
}

const std::string& Credential::identifier() const {
  return credential_proto_.identifier();
}

const std::string& Credential::user() const {
  return credential_proto_.user();
}

const std::string& Credential::login() const {
  return credential_proto_.login();
}

const std::string& Credential::password() const {
  return credential_proto_.password();
}

const std::string& Credential::provider() const {
  return credential_proto_.provider();
}

const std::string& Credential::description() const {
  return credential_proto_.description();
}

const std::string& Credential::public_key() const {
  DCHECK(credential_key_);
  return credential_key_->public_key();
}

const std::string& Credential::public_key_type() const {
  DCHECK(credential_key_);
  return credential_key_->public_key_type();
}

const std::string& Credential::public_key_encoding() const {
  DCHECK(credential_key_);
  return credential_key_->public_key_encoding();
}

scoped_refptr<net::IOBufferWithSize> Credential::Serialize() const {
  return protocol::SerializeMessage(credential_proto_);
}

}