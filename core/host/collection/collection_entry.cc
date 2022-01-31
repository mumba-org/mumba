// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/collection/collection_entry.h"

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

namespace {

std::string GetPlatformString(protocol::BundlePlatform platform) {
  bool is_mac = platform == protocol::PLATFORM_MACOS;
  bool is_ios = platform == protocol::PLATFORM_IOS;
  bool is_android = platform == protocol::PLATFORM_ANDROID;
  bool is_linux = platform == protocol::PLATFORM_LINUX;
  bool is_web = platform == protocol::PLATFORM_WEB;
  bool is_windows = platform == protocol::PLATFORM_WINDOWS;
  if (is_mac) {
    return "MACOS";
  } else if (is_ios) {
    return "IOS";
  } else if (is_android) {
    return "ANDROID";
  } else if (is_linux) {
    return "LINUX";
  } else if (is_web) {
    return "WEB";
  } else if (is_windows) {
    return "WINDOWS";
  }
  return "WEB";
}

std::string GetArchitectureString(protocol::BundleArchitecture platform) {
  bool is_x86 = platform == protocol::ARCH_X86;
  bool is_arm = platform == protocol::ARCH_ARM;
  bool is_x64 = platform == protocol::ARCH_X64;
  bool is_neutral = platform == protocol::ARCH_NEUTRAL;
  bool is_arm64 = platform == protocol::ARCH_ARM64;
  if (is_x86) {
    return "X86";
  } else if (is_arm) {
    return "ARM";
  } else if (is_x64) {
    return "x64";
  } else if (is_neutral) {
    return "NEUTRAL";
  } else if (is_arm64) {
    return "ARM64";
  }
  return "x64";
}      

}

char CollectionEntry::kClassName[] = "collection";

std::unique_ptr<CollectionEntry> CollectionEntry::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::CollectionEntry app_entry;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!app_entry.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  return std::unique_ptr<CollectionEntry>(new CollectionEntry(std::move(app_entry)));
}

CollectionEntry::CollectionEntry(protocol::CollectionEntry app_proto):
  id_(reinterpret_cast<const uint8_t *>(app_proto.uuid().data())),
  app_proto_(std::move(app_proto)),
  supported_platforms_populated_(false),
  supported_languages_populated_(false),
  managed_(false) {
}

CollectionEntry::CollectionEntry():
  supported_platforms_populated_(false),
  supported_languages_populated_(false),
  managed_(false) {
  id_ = base::UUID::generate();
  app_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
}

CollectionEntry::~CollectionEntry() {
  
}

const std::string& CollectionEntry::name() const {
  return app_proto_.name();
}

const std::string& CollectionEntry::description() const {
  return app_proto_.description();
}

const std::string& CollectionEntry::version() const {
  return app_proto_.version();
}

const std::string& CollectionEntry::license() const {
  return app_proto_.license();
}

const std::string& CollectionEntry::publisher() const {
  return app_proto_.publisher();
}

const std::string& CollectionEntry::publisher_url() const {
  return app_proto_.publisher_url();
}

base::StringPiece CollectionEntry::publisher_public_key() const {
  return app_proto_.publisher_public_key();
}

const std::string& CollectionEntry::logo_path() const {
  return app_proto_.logo_path();
}

uint64_t CollectionEntry::size() const {
  return app_proto_.size();
}

const base::UUID& CollectionEntry::repo_uuid() {
  if (repo_uuid_.IsNull()) {
    repo_uuid_ = base::UUID(reinterpret_cast<const uint8_t *>(app_proto_.repo_uuid().data()));
  }
  return repo_uuid_;
}

base::StringPiece CollectionEntry::repo_public_key() const {
  return app_proto_.repo_public_key();
}

protocol::CollectionEntryInstallState CollectionEntry::install_state() const {
  return app_proto_.install_state();
}

protocol::CollectionEntryAvailabilityState CollectionEntry::availability_state() const {
  return app_proto_.availability_state();
}

uint64_t CollectionEntry::install_counter() const {
  return app_proto_.install_counter();
}

uint32_t CollectionEntry::rating() const {
  return app_proto_.rating();
}

base::StringPiece CollectionEntry::public_key() const {
  return app_proto_.public_key();
}

const std::vector<protocol::CollectionSupportedPlatform>& CollectionEntry::supported_platforms() {
  if (!supported_platforms_populated_) {
    for (int i = 0; i < app_proto_.supported_platforms_size(); i++) {
      supported_platforms_.push_back(app_proto_.supported_platforms(i));
    }
    supported_platforms_populated_ = true;
  }
  return supported_platforms_;
}

const std::vector<std::string>& CollectionEntry::supported_languages() {
  if (!supported_languages_populated_) {
    for (int i = 0; i < app_proto_.supported_languages_size(); i++) {
      supported_languages_.push_back(app_proto_.supported_languages(i));
    }
    supported_languages_populated_ = true;
  }
  return supported_languages_;
}

scoped_refptr<net::IOBufferWithSize> CollectionEntry::Serialize() const {
  return protocol::SerializeMessage(app_proto_);
}

common::mojom::CollectionEntryPtr CollectionEntry::ToMojom() {
  common::mojom::CollectionEntryPtr result = common::mojom::CollectionEntry::New();
  result->uuid = id().to_string();
  result->name = name();
  result->description = description();
  result->version = version();
  result->license = license();
  result->publisher = publisher();
  result->publisher_url = publisher_url();
  result->publisher_public_key = publisher_public_key().as_string();
  result->logo_path = logo_path();
  result->size = size();
  result->repo_uuid = repo_uuid().to_string();
  result->repo_public_key = repo_public_key().as_string();
  result->install_state = static_cast<common::mojom::CollectionEntryInstallState>(install_state());
  result->availability_state = static_cast<common::mojom::CollectionEntryAvailabilityState>(availability_state());
  result->install_counter = install_counter();
  result->rating = rating();
  result->app_public_key = public_key().as_string();
  for (auto it = supported_platforms().begin(); it != supported_platforms().end(); ++it) {
    const protocol::CollectionSupportedPlatform& platform = *it;
    result->supported_platforms.push_back(
      GetPlatformString(platform.platforms()) + "-" + GetArchitectureString(platform.architectures())
    );
  }
  for (auto it = supported_languages().begin(); it != supported_languages().end(); ++it) {
    result->supported_languages.push_back(*it);
  }
  return result;
}

}
