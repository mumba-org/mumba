// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/volume/volume.h"

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_piece.h"
#include "base/hash.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/backend/manifest.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "net/base/io_buffer.h"
#include "core/host/workspace/volume_storage.h"
#include "core/host/volume/volume_source.h"
#include "core/host/bundle/bundle.h"
#include "core/common/protocol/message_serialization.h"

namespace host {
// namespace {

// const int kReadBufSize = 16 * 1024;  

// }

char Volume::kClassName[] = "volume";

std::unique_ptr<Volume> Volume::Deserialize(storage::Storage* volume_storage, Bundle* bundle, net::IOBuffer* buffer, int size) {
  protocol::Volume volume_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!volume_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<Volume> handle(new Volume(volume_storage, bundle, std::move(volume_proto)));

  std::string pubkey_hex = base::HexEncode(handle->pubkey().data(), handle->pubkey().size());

  printf("Deserialized volume:\n name: %s\n id: %s\n root tree: %s\n path: %s\n size: %ld\n creator: %s\n public key: %s\n",
    handle->name().c_str(),
    handle->id().to_string().c_str(),
    handle->root_tree().to_string().c_str(),
#if defined(OS_WIN)
    base::UTF16ToASCII(handle->path().value()).c_str(),
    static_cast<long>(handle->size()),
#else
    handle->path().value().c_str(),
    handle->size(),
#endif
    handle->creator().c_str(),
    pubkey_hex.c_str());

  return handle;
}

// static 
std::unique_ptr<Volume> Volume::New(storage::Storage* volume_storage, Bundle* bundle) {
  std::unique_ptr<Volume> volume = std::make_unique<Volume>(volume_storage, bundle); 
  return volume;
}

Volume::Volume(storage::Storage* volume_storage, Bundle* bundle):
  volume_storage_(volume_storage),
  bundle_(bundle),
  id_(base::UUID::generate()),
  state_(VolumeState::kINIT),
  source_(nullptr),
  valid_(true),
  managed_(false) {

  const storage::Manifest* manifest = volume_storage_->GetManifest(); 
  base::StringPiece root_tree_str = manifest->GetProperty(storage::Manifest::TREE);
  base::StringPiece pub_key_str = manifest->GetProperty(storage::Manifest::PUBKEY);
  base::StringPiece creator_str = manifest->GetProperty(storage::Manifest::CREATOR);

  base::UUID root_tree_uuid(reinterpret_cast<const uint8_t *>(root_tree_str.data()));
  volume_proto_.set_uuid(std::string(reinterpret_cast<const char *>(id_.data), 16));
  volume_proto_.set_name(volume_storage->GetName());
  volume_proto_.set_root_tree(root_tree_uuid.string());
#if defined(OS_WIN)  
  volume_proto_.set_path(base::UTF16ToASCII(volume_storage->GetPath().value()));
#else  
  volume_proto_.set_path(volume_storage->GetPath().value());
#endif
  volume_proto_.set_size(volume_storage->GetAllocatedSize());
  volume_proto_.set_pubkey(pub_key_str.data(), pub_key_str.size());
  volume_proto_.set_creator(creator_str.data(), creator_str.size()); 

  root_tree_ = std::move(root_tree_uuid);
}

Volume::Volume(storage::Storage* volume_storage, Bundle* bundle, protocol::Volume volume_proto):
 volume_storage_(volume_storage),
 bundle_(bundle),
 id_(reinterpret_cast<const uint8_t *>(volume_proto.uuid().data())),
 root_tree_(reinterpret_cast<const uint8_t *>(volume_proto.root_tree().data())),
 volume_proto_(std::move(volume_proto)),
 state_(VolumeState::kINIT),
 source_(nullptr),
 valid_(true),
 managed_(false) {

}

Volume::~Volume(){

}

bool Volume::GetUUID(const std::string& name, base::UUID* id) {
  return volume_storage_->GetUUID(name, id);
}

scoped_refptr<net::IOBufferWithSize> Volume::Serialize() const {
  return protocol::SerializeMessage(volume_proto_);
}

void Volume::CheckoutApp(const base::FilePath& to,
                         storage::CompletionCallback callback) {
  CheckoutEntry(name(), to, std::move(callback));
}

void Volume::CheckoutEntry(const std::string& name,
                           const base::FilePath& to,
                           storage::CompletionCallback callback) {
  base::UUID torrent_uuid;
  if (!GetUUID(name, &torrent_uuid)) {
    DLOG(ERROR) << "failed to resolve torrent uuid from name '" << name << "'";
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  scoped_refptr<storage::Torrent> torrent = volume_storage_->manager()->GetTorrent(torrent_uuid);

  if (!torrent) {
    torrent = volume_storage_->manager()->NewTorrent(volume_storage_, torrent_uuid);
  }
  
  volume_storage_->CopyEntry(torrent, to, std::move(callback)); 
}

void Volume::Shutdown(storage::CompletionCallback on_volume_shutdown) {
  if (!volume_storage_->shutting_down()) {
    volume_storage_->Stop(std::move(on_volume_shutdown));
  }
}


}
