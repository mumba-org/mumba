// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/collection/collection_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/collection/collection_entry.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"
#include "storage/db/db.h"

namespace host {

CollectionModel::CollectionModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
 policy_(policy),
 db_(db) {

}

CollectionModel::~CollectionModel() {
  db_ = nullptr;
}

void CollectionModel::Load(base::Callback<void(int, int)> cb) {
  LoadEntriesFromDB(std::move(cb));
}

bool CollectionModel::EntryExists(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false; 
}

bool CollectionModel::EntryExists(const std::string& name) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

bool CollectionModel::EntryExists(CollectionEntry* entry) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->get() == entry) {
      return true;
    }
  }
  return false; 
}

CollectionEntry* CollectionModel::GetEntryById(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

CollectionEntry* CollectionModel::GetEntryByName(const std::string& name) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

void CollectionModel::InsertEntry(std::unique_ptr<CollectionEntry> entry, bool persist) {
  InsertEntryInternal(std::move(entry), persist);
}

bool CollectionModel::RemoveEntry(const base::UUID& id) {
  return RemoveEntryInternal(id);
} 

void CollectionModel::Close() {}

void CollectionModel::InsertEntryInternal(std::unique_ptr<CollectionEntry> entry, bool persist) {
  if (!EntryExists(entry.get())) {
    if (persist) {
      InsertEntryToDB(entry.get());
    }
    AddToCache(std::move(entry));
  } else {
    LOG(ERROR) << "Failed to add entry " << entry->id().to_string() << " to DB. Already exists";
  }
}

bool CollectionModel::RemoveEntryInternal(const base::UUID& id) {
  CollectionEntry* entry = GetEntryById(id);
  if (entry) {
    RemoveEntryFromDB(entry);
    return RemoveFromCache(entry);
  } else {
    LOG(ERROR) << "Failed to remove app store entry. Entry with id " << id.to_string() << " not found.";
  }
  return false;
}

void CollectionModel::InsertEntryToDB(CollectionEntry* entry) {
  scoped_refptr<net::IOBufferWithSize> data = entry->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, CollectionEntry::kClassName, entry->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void CollectionModel::RemoveEntryFromDB(CollectionEntry* entry) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, CollectionEntry::kClassName, entry->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void CollectionModel::AddToCache(std::unique_ptr<CollectionEntry> entry) {
  entries_.push_back(std::move(entry));
  entry->set_managed(true);
}

bool CollectionModel::RemoveFromCache(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  bool found = false;
  CollectionEntry* entry = nullptr;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->id() == id) {
      entry = it->get();
      (*it)->set_managed(false);
      entries_.erase(it);
      found = true;
      break;
    }
  }
  return found;
}

bool CollectionModel::RemoveFromCache(CollectionEntry* entry) {
  base::AutoLock lock(entries_vector_lock_);
  bool found = false;
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->get() == entry) {
      (*it)->set_managed(false);
      entries_.erase(it);
      found = true;
      break;
    }
  }
  return found;
}

void CollectionModel::LoadEntriesFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(CollectionEntry::kClassName);
  if (!it) {
    DLOG(ERROR) << "CollectionModel::LoadEntriesFromDB: creating cursor for 'app store' failed.";
    std::move(cb).Run(net::ERR_FAILED, 0);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<CollectionEntry> p = CollectionEntry::Deserialize(buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        entries_vector_lock_.Acquire();
        entries_.push_back(std::move(p));
        entries_vector_lock_.Release();
      } else {
        LOG(ERROR) << "failed to deserialize entry";
      }
    } else {
      LOG(ERROR) << "failed to deserialize entry: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

void CollectionModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    db_->Open();
  }
}

void CollectionModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void CollectionModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}