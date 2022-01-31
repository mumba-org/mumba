// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_CONTROLLER_H_
#define MUMBA_HOST_STORE_COLLECTION_CONTROLLER_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/callback.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/database_policy.h"

namespace host {
class CollectionEntry;
class Collection;
class ShareController;

class CollectionController {
public:
  CollectionController(Collection* collection, ShareController* share_controller);
  ~CollectionController();
  
  Collection* store() const {
    return store_;
  }

  // with side-effects
  void InsertEntryByDHTAddress(const std::string& base64_address, base::Callback<void(int)> callback);
  void InsertEntryByInfohashAddress(const std::string& infohash, base::Callback<void(int)> callback);

  // without side-effects
  void InsertEntry(std::unique_ptr<CollectionEntry> entry);
  bool RemoveEntry(CollectionEntry* entry);
  bool RemoveEntry(const base::UUID& uuid);
  bool RemoveEntry(const std::string& address);
  CollectionEntry* LookupEntry(const std::string& address) const;
  CollectionEntry* LookupEntryByName(const std::string& name) const;
  CollectionEntry* LookupEntryByUUID(const base::UUID& uuid) const;
  bool HaveEntry(const std::string& address) const;
  bool HaveEntryByName(const std::string& name) const;
  bool HaveEntryByUUID(const base::UUID& uuid) const;
  std::vector<CollectionEntry*> ListEntries() const;
  size_t GetEntryCount() const;

private:

  void OnStorageCloned(base::Callback<void(int)> callback, int result);
  void OnShareCreated(base::Callback<void(int)> callback, int64_t result);

  Collection* store_;
  ShareController* share_controller_;
  
  DISALLOW_COPY_AND_ASSIGN(CollectionController);
};

}

#endif