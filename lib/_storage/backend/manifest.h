// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BACKEND_MANIFEST_H_
#define MUMBA_STORAGE_BACKEND_MANIFEST_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_split.h"
#include "base/strings/string_piece.h"
#include "storage/storage_export.h"
#include "storage/backend/addr.h"
#include "libtorrent/kademlia/ed25519.hpp"

namespace storage {

class STORAGE_EXPORT_PRIVATE Manifest {
public:
  static const int kDataSizesLength = 6;
  static const int32_t kMaxValueSize = 255;

  enum Properties {
    MIN_COUNTER = 0,
    VERSION = MIN_COUNTER,
    ADDRESS,
    PUBKEY,
    PRIVKEY,
    CREATOR,
    TREE,
    MAX_COUNTER
  };

  struct InitParams {
    std::string creator;
    std::string base32_address;
    libtorrent::dht::public_key public_key;
    libtorrent::dht::secret_key private_key;
    base::UUID root_tree;
    bool is_owner = false;
  };

  Manifest();
  ~Manifest();

  bool Init(InitParams params, void* data, int num_bytes, Addr address);
  int StorageSize();

  int Serialize(void* data, int num_bytes, Addr* address);

  base::StringPiece GetProperty(Properties property) const {
    return base::StringPiece(values_[property]);
  }

  int GetSize(Properties property) const {
    return data_sizes_[property];
  }

  bool is_dirty() const {
    return dirty_;
  }

  void set_dirty(bool dirty) {
    dirty_ = dirty;
  }

private:

  int data_sizes_[kDataSizesLength];
  char values_[kDataSizesLength][kMaxValueSize];

  Addr storage_addr_;
  bool dirty_ = false;

  DISALLOW_COPY_AND_ASSIGN(Manifest);
};

}

#endif