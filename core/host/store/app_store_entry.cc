// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/store/app_store_entry.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/hash.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "net/base/io_buffer.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

char AppStoreEntry::kClassName[] = "app_store";

std::unique_ptr<AppStoreEntry> AppStoreEntry::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::AppStoreEntry app_entry;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!app_entry.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  return std::unique_ptr<AppStoreEntry>(new AppStoreEntry(std::move(app_entry)));
}

AppStoreEntry::AppStoreEntry(protocol::AppStoreEntry app_proto):
  id_(reinterpret_cast<const uint8_t *>(app_proto.uuid().data())),
  app_proto_(std::move(app_proto)),
  supported_platforms_populated_(false),
  supported_languages_populated_(false),
  managed_(false) {
}

AppStoreEntry::AppStoreEntry():
  supported_platforms_populated_(false),
  supported_languages_populated_(false),
  managed_(false) {
  id_ = base::UUID::generate();
  app_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

AppStoreEntry::~AppStoreEntry() {
  
}

const std::string& AppStoreEntry::name() const {
  return app_proto_.name();
}

const std::string& AppStoreEntry::description() const {
  return app_proto_.description();
}

const std::string& AppStoreEntry::version() const {
  return app_proto_.version();
}

const std::string& AppStoreEntry::license() const {
  return app_proto_.license();
}

const std::string& AppStoreEntry::publisher() const {
  return app_proto_.publisher();
}

const std::string& AppStoreEntry::publisher_url() const {
  return app_proto_.publisher_url();
}

base::StringPiece AppStoreEntry::publisher_public_key() const {
  return app_proto_.publisher_public_key();
}

const std::string& AppStoreEntry::logo_path() const {
  return app_proto_.logo_path();
}

uint64_t AppStoreEntry::size() const {
  return app_proto_.size();
}

const base::UUID& AppStoreEntry::repo_uuid() {
  if (repo_uuid_.IsNull()) {
    repo_uuid_ = base::UUID(reinterpret_cast<const uint8_t *>(app_proto_.repo_uuid().data()));
  }
  return repo_uuid_;
}

base::StringPiece AppStoreEntry::repo_public_key() const {
  return app_proto_.repo_public_key();
}

protocol::AppStoreInstallState AppStoreEntry::install_state() const {
  return app_proto_.install_state();
}

protocol::AppStoreAvailabilityState AppStoreEntry::availability_state() const {
  return app_proto_.availability_state();
}

uint64_t AppStoreEntry::install_counter() const {
  return app_proto_.install_counter();
}

uint32_t AppStoreEntry::rating() const {
  return app_proto_.rating();
}

base::StringPiece AppStoreEntry::app_public_key() const {
  return app_proto_.app_public_key();
}

const std::vector<protocol::AppStoreSupportedPlatform>& AppStoreEntry::supported_platforms() {
  if (!supported_platforms_populated_) {
    for (int i = 0; i < app_proto_.supported_platforms_size(); i++) {
      supported_platforms_.push_back(app_proto_.supported_platforms(i));
    }
    supported_platforms_populated_ = true;
  }
  return supported_platforms_;
}

const std::vector<std::string>& AppStoreEntry::supported_languages() {
  if (!supported_languages_populated_) {
    for (int i = 0; i < app_proto_.supported_languages_size(); i++) {
      supported_languages_.push_back(app_proto_.supported_languages(i));
    }
    supported_languages_populated_ = true;
  }
  return supported_languages_;
}

scoped_refptr<net::IOBufferWithSize> AppStoreEntry::Serialize() const {
  return protocol::SerializeMessage(app_proto_);
}

}
