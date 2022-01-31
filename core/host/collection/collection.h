// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_H_
#define MUMBA_HOST_STORE_COLLECTION_H_

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
class CollectionEntry;
class CollectionModel;
class CollectionObserver;
class ShareDatabase;

class Collection {
public:
  Collection();
  ~Collection();
  
  CollectionModel* model() const {
    return entries_.get();
  }

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  void Shutdown();

  bool EntryExists(const base::UUID& id);
  bool EntryExists(const std::string& name);
  bool EntryExists(CollectionEntry* entry);
  CollectionEntry* GetEntryById(const base::UUID& id);
  CollectionEntry* GetEntryByName(const std::string& name);
  void InsertEntry(std::unique_ptr<CollectionEntry> entry, bool persist = true);
  bool RemoveEntry(CollectionEntry* entry);
  bool RemoveEntry(const base::UUID& uuid);
  const std::vector<std::unique_ptr<CollectionEntry>>& GetEntries() const;
  size_t GetEntryCount();

  void AddObserver(CollectionObserver* observer);
  void RemoveObserver(CollectionObserver* observer);

private:

  void InitImpl();
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifyEntryAdded(CollectionEntry* entry);
  void NotifyEntryRemoved(CollectionEntry* entry);
  void NotifyEntriesLoad(int r, int count);

  std::unique_ptr<CollectionModel> entries_;  
  std::vector<CollectionObserver*> observers_;

  base::WeakPtrFactory<Collection> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(Collection);
};

}

#endif