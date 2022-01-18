// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_MODEL_H_
#define MUMBA_HOST_STORE_APP_STORE_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class AppStoreEntry;
class ShareDatabase;

class AppStoreModel : public DatabasePolicyObserver {
public:
  AppStoreModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~AppStoreModel();

  const std::vector<AppStoreEntry *>& entries() const {
    return entries_;
  }

  std::vector<AppStoreEntry *>& entries() {
    return entries_;
  }

  void Load(base::Callback<void(int, int)> cb);
  bool EntryExists(const base::UUID& id);
  bool EntryExists(const std::string& name);
  bool EntryExists(AppStoreEntry* entry);
  AppStoreEntry* GetEntryById(const base::UUID& id);
  AppStoreEntry* GetEntryByName(const std::string& name);
  void InsertEntry(AppStoreEntry* entry, bool persist = true);
  void RemoveEntry(const base::UUID& id);
 
  void Close();

private:
  
  void InsertEntryInternal(AppStoreEntry* entry, bool persist);
  void RemoveEntryInternal(const base::UUID& id);

  void InsertEntryToDB(AppStoreEntry* entry);
  void RemoveEntryFromDB(AppStoreEntry* entry);

  void AddToCache(AppStoreEntry* entry);
  void RemoveFromCache(const base::UUID& id, bool should_delete = true);
  void RemoveFromCache(AppStoreEntry* entry, bool should_delete = true);

  void LoadEntriesFromDB(base::Callback<void(int, int)> cb);

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  base::Lock entries_vector_lock_;
  std::vector<AppStoreEntry *> entries_;

private:

 DISALLOW_COPY_AND_ASSIGN(AppStoreModel);
};

}

#endif