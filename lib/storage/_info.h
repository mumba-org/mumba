// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_INFO_H_
#define MUMBA_STORAGE_INFO_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "url/gurl.h"
#include "net/base/io_buffer.h"

namespace storage {

/* Note about infos: 
 * 
 * we need to make them in a way where they dont need to be in disk already
 * and only be references to torrents to be syncronized
 *
 * This is were the tree inodes might fit in..
 * as we form tree nodes from torrent infos
 * we can compose them into one disk 
 * 
 * TODO: we need an observer callback system
 *       so when trees are added or remove
 *       third parties know and can act about it
 */

class Info {
public:
  ~Info();

  const storage_proto::HeaderVersion& version() const {
    return handle_->version();
  }

  storage_proto::HeaderVersion* mutable_version() {
    return handle_->mutable_version();
  }

  storage_proto::Info* parent() {
    return handle_->mutable_parent();
  }

  void set_parent(Info* parent) {
    handle_->set_allocated_parent(parent->info_proto_.get());
  }

  void set_parent(storage_proto::Info* parent) {
    handle_->set_allocated_parent(parent);
  }

  const std::string& path() const {
    return handle_->path();
  }

  void set_path(const std::string& path) {
    handle_->set_path(path);
  }

  storage_proto::InfoKind type() const {
    return handle_->kind();
  }

  void set_type(storage_proto::InfoKind type) const {
    return handle_->set_kind(type);
  }

  int64_t size() const {
    return handle_->size();
  }

  void set_size(int64_t size) {
    handle_->set_size(size);
  }

  int64_t modified_time() const {
    return handle_->modified_time();
  }

  void set_modified_time(int64_t modified_time) {
    handle_->set_modified_time(modified_time);
  }

  const std::string& info_hash() const {
    return handle_->info_hash();
  }

  void set_info_hash(const std::string& info_hash) {
    handle_->set_info_hash(info_hash);
  }

  void set_info_hash(const void* data, size_t size) {
    handle_->set_info_hash(data, size);
  }
  
  // a sort of inner disk 'content-type'
  storage_proto::ResourceKind resource_type() const {
    return handle_->resource_type();
  }

  void set_resource_type(storage_proto::ResourceKind resource_type) {
    handle_->set_resource_type(resource_type);
  }
  
  const std::string& content_type() const {
    return handle_->content_type();
  }

  void set_content_type(const std::string& content_type) {
    handle_->set_content_type(content_type);
  }

  size_t ComputeEncodedSize() const {
    return handle_->ByteSizeLong();
  }
  
  scoped_refptr<net::IOBufferWithSize> Serialize();
  bool SerializeTo(net::IOBuffer* io_buffer);

  bool Deserialize(const void* data, size_t len);

protected:
  Info(storage_proto::InfoKind type);
  Info(std::unique_ptr<storage_proto::Info> info_proto);
  // unowned version
  Info(storage_proto::Info* info_proto);
  
  storage_proto::Info* handle_;
  std::unique_ptr<storage_proto::Info> info_proto_; 

private:

  DISALLOW_COPY_AND_ASSIGN(Info);
};

}

#endif