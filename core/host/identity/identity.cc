// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/identity/identity.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"
#include "core/host/identity/identity_manager.h"
#include "core/host/identity/credential.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

char Identity::kClassName[] = "identity";  

// static 
std::unique_ptr<Identity> Identity::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Identity identity_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!identity_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<Identity> handle(new Identity(std::move(identity_proto)));

  return handle;
} 

Identity::Identity(protocol::Identity identity_proto): 
  id_(reinterpret_cast<const uint8_t *>(identity_proto.uuid().data())),
  identity_proto_(std::move(identity_proto)),
  managed_(false) {
}

Identity::Identity(): managed_(false) {
  id_ = base::UUID::generate();
  identity_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

Identity::~Identity() {
  
}

const std::string& Identity::name() const {
  return identity_proto_.name();
}

const std::string& Identity::login() const {
  return identity_proto_.login(); 
}

const std::string& Identity::description() const {
  return identity_proto_.description(); 
}

scoped_refptr<net::IOBufferWithSize> Identity::Serialize() const {
  return protocol::SerializeMessage(identity_proto_);
}

std::vector<Credential*> Identity::GetCredentials() {
  base::AutoLock lock(credentials_lock_);
  std::vector<Credential*> credentials;
  for (auto it = credentials_.begin(); it != credentials_.end(); it++) {
    credentials.push_back(it->get());
  }
  return credentials;
}

Credential* Identity::GetCredential(base::UUID& credential_id) {
  base::AutoLock lock(credentials_lock_);
  for (auto it = credentials_.begin(); it != credentials_.end(); it++) {
    Credential* current = it->get();
    if (current->id() == credential_id) {
      return current;
    }
  }
  return nullptr;
}

Credential* Identity::GetCredential(const std::string& identifier) {
  base::AutoLock lock(credentials_lock_);
  for (auto it = credentials_.begin(); it != credentials_.end(); it++) {
    Credential* current = it->get();
    if (current->identifier() == identifier) {
      return current;
    }
  }
  return nullptr;
}
  
void Identity::AddCredential(std::unique_ptr<Credential> credential) {
  base::AutoLock lock(credentials_lock_);
  //identity_proto_.add_credential(credential->credential_proto_);
  AddCredentialToProto(credential.get());
  credentials_.push_back(std::move(credential));
}

void Identity::RemoveCredential(base::UUID& credential_id) {
  base::AutoLock lock(credentials_lock_);
  std::string credential_id_str = credential_id.to_string();
  for (auto it = credentials_.begin(); it != credentials_.end(); it++) {
    Credential* current = it->get();
    if (current->id() == credential_id) {
      RemoveCredentialFromProtoByUUID(credential_id_str);
      credentials_.erase(it);
      return;
    }
  }
}

void Identity::RemoveCredential(const std::string& identifier) {
  base::AutoLock lock(credentials_lock_);
  for (auto it = credentials_.begin(); it != credentials_.end(); it++) {
    Credential* current = it->get();
    if (current->identifier() == identifier) {
      RemoveCredentialFromProtoByIdentifier(identifier);
      credentials_.erase(it);
      return;
    }
  }
}

void Identity::AddCredentialToProto(Credential* credential) {
  protocol::Credential* credential_proto = identity_proto_.add_credentials();
  credential_proto->CopyFrom(credential->credential_proto_);
}

void Identity::RemoveCredentialFromProtoByUUID(const std::string& uuid) {
  auto* credentials_proto = identity_proto_.mutable_credentials();
  for (auto proto_it = credentials_proto->begin(); proto_it != credentials_proto->end(); ++proto_it) {
    if (uuid == proto_it->uuid()) {
      credentials_proto->erase(proto_it);
      return;
    }
  }
}

void Identity::RemoveCredentialFromProtoByIdentifier(const std::string& identifier) {
  auto* credentials_proto = identity_proto_.mutable_credentials();
  for (auto proto_it = credentials_proto->begin(); proto_it != credentials_proto->end(); ++proto_it) {
    if (identifier == proto_it->identifier()) {
      credentials_proto->erase(proto_it);
      return;
    }
  }
}


}