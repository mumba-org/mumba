// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo.h"

#include "base/strings/string_util.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

// static 
std::unique_ptr<Repo> Repo::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Repo repo_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!repo_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Repo>(new Repo(std::move(repo_proto)));
}

// static 
std::unique_ptr<Repo> Repo::FromRepoEntry(common::mojom::RepoEntryPtr entry) {
  auto repo = std::make_unique<Repo>();
  repo->Clone(std::move(entry));
  return repo;
}

char Repo::kClassName[] = "repo";

Repo::Repo():
  managed_(false),
  should_sync_(false),
  state_(RepoState::kINVALID) {

}

Repo::Repo(protocol::Repo repo_proto):
  id_(reinterpret_cast<const uint8_t *>(repo_proto.uuid().data())),
  root_tree_(reinterpret_cast<const uint8_t *>(repo_proto_.root_tree().data())),
  repo_proto_(std::move(repo_proto)),
  managed_(false),
  should_sync_(false),
  state_(RepoState::kINVALID) {
  
}

Repo::~Repo() {

}

const std::string& Repo::name() const {
  return repo_proto_.name();
}

void Repo::set_name(const std::string& name) {
  repo_proto_.set_name(name);
}

protocol::RepoType Repo::type() const {
  return repo_proto_.type();
}

void Repo::set_type(protocol::RepoType type) {
  repo_proto_.set_type(type);
}

const std::string& Repo::address() const {
  return repo_proto_.address();
}

void Repo::set_address(const std::string& address) {
  repo_proto_.set_address(address);
}

protocol::AddressFormat Repo::address_format() const {
  return repo_proto_.address_format();
}

void Repo::set_address_format(protocol::AddressFormat format) {
  repo_proto_.set_address_format(format);
}

const std::string& Repo::address_format_version() const {
  return repo_proto_.address_format_version();
}

void Repo::set_address_format_version(const std::string& address_format_version) {
  repo_proto_.set_address_format_version(address_format_version);
} 

const std::string& Repo::public_key() const {
  return repo_proto_.public_key();
}

void Repo::set_public_key(const std::string& key) {
  repo_proto_.set_public_key(key);
}

protocol::PKCryptoFormat Repo::pk_crypto_format() const {
  return repo_proto_.pk_crypto_format();
}

void Repo::set_pk_crypto_format(protocol::PKCryptoFormat format) {
  repo_proto_.set_pk_crypto_format(format);
}

const base::UUID& Repo::root_tree() const {
  return root_tree_;
}

void Repo::set_root_tree(base::UUID& root_tree) {
  repo_proto_.set_root_tree(reinterpret_cast<const char*>(root_tree.data), 16);
  root_tree_ = root_tree;
}

const std::string& Repo::creator() const {
  return repo_proto_.creator();
}

void Repo::set_creator(const std::string& creator) {
  repo_proto_.set_creator(creator);
}

void Repo::mark_sync() {
  should_sync_ = true;
}

common::mojom::RepoEntryPtr Repo::ToRepoEntry() {
  common::mojom::RepoEntryPtr entry = common::mojom::RepoEntry::New();
  //entry->name = name();
  //entry->type = type();
  //entry->address = address();
  //entry->address_format = address_format();
  //entry->address_format_version = address_format_version();
  //entry->public_key = public_key();
  //entry->pk_crypto_format = pk_crypto_format();
  //entry->root_tree = std::string(reinterpret_cast<const char*>(root_tree().data), 16);
  //entry->creator = creator();
  return entry;
}

scoped_refptr<net::IOBufferWithSize> Repo::Serialize() const {
  return protocol::SerializeMessage(repo_proto_);
}

void Repo::Clone(common::mojom::RepoEntryPtr entry) {
  //set_name(entry->name);
  //set_type(entry->type);
  //set_address(entry->address);
  //set_address_format(entry->format);
 // set_address_format_version(entry->address_format_version);
  //set_public_key(entry->key);
  //set_pk_crypto_format(entry->format);
  //set_root_tree(base::UUID(static_cast<const uint8_t*>(entry->root_tree)));
  //set_creator(entry->creator);
}

}
