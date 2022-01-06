// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/backend/manifest.h"

namespace {

const int32_t kStorageSignature = 0x494E414D; // ASCII for 'MANI'

struct OnStorageManifest {
  int32_t signature;
  int size;
  // pointer to the head entry
  storage::StorageAddr head;
  int data_sizes[storage::Manifest::kDataSizesLength];
  char values[storage::Manifest::kDataSizesLength][storage::Manifest::kMaxValueSize];
};

static_assert(sizeof(OnStorageManifest) < 2048, "struct size overflow > 2048");

bool VerifyManifest(OnStorageManifest* manifest) {
  if (manifest->signature != kStorageSignature) {
    return false;
  }

  if (static_cast<unsigned int>(manifest->size) > sizeof(*manifest)) {
    memset(manifest, 0, sizeof(*manifest));
    manifest->signature = kStorageSignature;
  } else if (static_cast<unsigned int>(manifest->size) != sizeof(*manifest)) {
    size_t delta = sizeof(*manifest) - static_cast<unsigned int>(manifest->size);
    memset(reinterpret_cast<char*>(manifest) + manifest->size, 0, delta);
    manifest->size = sizeof(*manifest);
  }

  return true;
}

}

namespace storage {

Manifest::Manifest() {

}

Manifest::~Manifest() {

}

bool Manifest::Init(InitParams params, void* data, int num_bytes, Addr address) {
  OnStorageManifest local_manifest;
  OnStorageManifest* manifest = &local_manifest;
  if (!num_bytes) {
    if (params.root_tree.IsNull()) {
      if (!params.is_owner) {
        LOG(ERROR) << "failed on disk manifest creation (cloned): the root tree uuid cannot be null";
        return false;
      } else {
        params.root_tree = base::UUID::generate();
      }
    }
    DLOG(INFO) << "creating manifest..";
    memset(manifest, 0, sizeof(local_manifest));
    local_manifest.signature = kStorageSignature;
    local_manifest.size = sizeof(local_manifest);

    memcpy(manifest->values[storage::Manifest::ADDRESS], params.base32_address.data(), params.base32_address.size());
    manifest->data_sizes[storage::Manifest::ADDRESS] = params.base32_address.size();
    memcpy(manifest->values[storage::Manifest::PUBKEY], params.public_key.bytes.data(), 32);
    manifest->data_sizes[storage::Manifest::PUBKEY] = 32;
    if (params.is_owner) {
      memcpy(manifest->values[storage::Manifest::PRIVKEY], params.private_key.bytes.data(), 64);
      manifest->data_sizes[storage::Manifest::PRIVKEY] = 64;
    } else {
      manifest->data_sizes[storage::Manifest::PRIVKEY] = 0;
    }
    memcpy(manifest->values[storage::Manifest::TREE], params.root_tree.data, 16);
    // size of a uuid as expressed in bytes
    manifest->data_sizes[storage::Manifest::TREE] = 16;
    memcpy(manifest->values[storage::Manifest::VERSION], "0.0.1\0", 6);
    manifest->data_sizes[storage::Manifest::VERSION] = 6;
    memcpy(manifest->values[storage::Manifest::CREATOR], params.creator.data(), params.creator.size());
    manifest->data_sizes[storage::Manifest::CREATOR] = params.creator.size();

  } else if (num_bytes >= static_cast<int>(sizeof(*manifest))) {
    DLOG(INFO) << "loading manifest..";
    manifest = reinterpret_cast<OnStorageManifest*>(data);
    if (!VerifyManifest(manifest)) {
      DLOG(INFO) << "manifest verification failed.";
      memset(&local_manifest, 0, sizeof(local_manifest));
      if (memcmp(manifest, &local_manifest, sizeof(local_manifest))) {
        return false;
      } else {
        // The storage is empty which means that Serialize() was never
        // called on the last run. Just re-initialize everything.
        local_manifest.signature = kStorageSignature;
        local_manifest.size = sizeof(local_manifest);
        manifest = &local_manifest;
      }
    }
  } else {
    return false;
  }

  storage_addr_ = address;

  memcpy(data_sizes_, manifest->data_sizes, sizeof(data_sizes_));
  memcpy(values_, manifest->values, sizeof(values_));
  DLOG(INFO) << "manifest initialization ok.";
  return true;
}

int Manifest::StorageSize() {
  static_assert(sizeof(OnStorageManifest) < 2048, "struct size overflow > 2048");
  return 1024 * 2;
}

int Manifest::Serialize(void* data, int num_bytes, Addr* address) {
  DLOG(INFO) << "Manifest::Serialize";
  OnStorageManifest* manifest = reinterpret_cast<OnStorageManifest*>(data);
  if (num_bytes < static_cast<int>(sizeof(*manifest))) {
    DLOG(INFO) << "Manifest::Serialize: error. sizes dont match. num_bytes (" << num_bytes << ") < sizeof(*manifest) (" << sizeof(*manifest) << ")";
    return 0;
  }

  base::StringPiece root_tree = GetProperty(TREE);
  base::UUID uuid(reinterpret_cast<const uint8_t *>(root_tree.data())); 
  DLOG(INFO) << " root tree on serialization is " << uuid.to_string();

  manifest->signature = kStorageSignature;
  manifest->size = sizeof(*manifest);
  memcpy(manifest->data_sizes, data_sizes_, sizeof(data_sizes_));
  memcpy(manifest->values, values_, sizeof(values_));

  *address = storage_addr_;
  return sizeof(*manifest);
}

}