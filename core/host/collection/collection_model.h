// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_MODEL_H_
#define MUMBA_HOST_STORE_COLLECTION_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"
#include "core/host/collection/collection_entry.h"

namespace host {
class ShareDatabase;

class CollectionModel : public DatabasePolicyObserver {
public:
  CollectionModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~CollectionModel();

  const std::vector<std::unique_ptr<CollectionEntry>>& entries() const {
    return entries_;
  }

  std::vector<std::unique_ptr<CollectionEntry>>& entries() {
    return entries_;
  }

  size_t entry_count() const {
    return entries_.size();
  }

  void Load(base::Callback<void(int, int)> cb);
  bool EntryExists(const base::UUID& id);
  bool EntryExists(const std::string& name);
  bool EntryExists(CollectionEntry* entry);
  CollectionEntry* GetEntryById(const base::UUID& id);
  CollectionEntry* GetEntryByName(const std::string& name);
  void InsertEntry(std::unique_ptr<CollectionEntry> entry, bool persist = true);
  bool RemoveEntry(const base::UUID& id);
 
  void Close();

private:
  
  void InsertEntryInternal(std::unique_ptr<CollectionEntry> entry, bool persist);
  bool RemoveEntryInternal(const base::UUID& id);

  void InsertEntryToDB(CollectionEntry* entry);
  void RemoveEntryFromDB(CollectionEntry* entry);

  void AddToCache(std::unique_ptr<CollectionEntry> entry);
  bool RemoveFromCache(const base::UUID& id);
  bool RemoveFromCache(CollectionEntry* entry);

  void LoadEntriesFromDB(base::Callback<void(int, int)> cb);

  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  base::Lock entries_vector_lock_;
  std::vector<std::unique_ptr<CollectionEntry>> entries_;

private:

 DISALLOW_COPY_AND_ASSIGN(CollectionModel);
};

}

#endif