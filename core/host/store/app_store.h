// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_H_
#define MUMBA_HOST_STORE_APP_STORE_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/database_policy.h"

namespace host {
class AppStoreEntry;
class AppStoreModel;
class AppStoreObserver;
class ShareDatabase;

class AppStore {
public:
  AppStore();
  ~AppStore();
  
  AppStoreModel* model() const {
    return entries_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  bool EntryExists(const base::UUID& id);
  bool EntryExists(const std::string& name);
  bool EntryExists(AppStoreEntry* entry);
  AppStoreEntry* GetEntryById(const base::UUID& id);
  AppStoreEntry* GetEntryByName(const std::string& name);
  void InsertEntry(std::unique_ptr<AppStoreEntry> entry, bool persist = true);
  bool RemoveEntry(AppStoreEntry* entry);
  bool RemoveEntry(const base::UUID& uuid);
  const std::vector<AppStoreEntry *>& GetEntries();
  size_t GetEntryCount();

  void AddObserver(AppStoreObserver* observer);
  void RemoveObserver(AppStoreObserver* observer);

private:

  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyEntryAdded(AppStoreEntry* entry);
  void NotifyEntryRemoved(AppStoreEntry* entry);
  void NotifyEntriesLoad(int r, int count);

  std::unique_ptr<AppStoreModel> entries_;  
  std::vector<AppStoreObserver*> observers_;

  base::WeakPtrFactory<AppStore> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(AppStore);
};

}

#endif