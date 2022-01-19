// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/store/app_store_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/store/app_store_entry.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"
#include "storage/db/db.h"

namespace host {

AppStoreModel::AppStoreModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
 policy_(policy),
 db_(db) {

}

AppStoreModel::~AppStoreModel() {
  db_ = nullptr;
}

void AppStoreModel::Load(base::Callback<void(int, int)> cb) {
  LoadEntriesFromDB(std::move(cb));
}

bool AppStoreModel::EntryExists(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false; 
}

bool AppStoreModel::EntryExists(const std::string& name) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

bool AppStoreModel::EntryExists(AppStoreEntry* entry) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if (it->get() == entry) {
      return true;
    }
  }
  return false; 
}

AppStoreEntry* AppStoreModel::GetEntryById(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

AppStoreEntry* AppStoreModel::GetEntryByName(const std::string& name) {
  base::AutoLock lock(entries_vector_lock_);
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;
}

void AppStoreModel::InsertEntry(std::unique_ptr<AppStoreEntry> entry, bool persist) {
  InsertEntryInternal(std::move(entry), persist);
}

bool AppStoreModel::RemoveEntry(const base::UUID& id) {
  return RemoveEntryInternal(id);
} 

void AppStoreModel::Close() {}

void AppStoreModel::InsertEntryInternal(std::unique_ptr<AppStoreEntry> entry, bool persist) {
  if (!EntryExists(entry.get())) {
    if (persist) {
      InsertEntryToDB(entry.get());
    }
    AddToCache(std::move(entry));
  } else {
    LOG(ERROR) << "Failed to add entry " << entry->id().to_string() << " to DB. Already exists";
  }
}

bool AppStoreModel::RemoveEntryInternal(const base::UUID& id) {
  AppStoreEntry* entry = GetEntryById(id);
  if (entry) {
    RemoveEntryFromDB(entry);
    return RemoveFromCache(entry);
  } else {
    LOG(ERROR) << "Failed to remove app store entry. Entry with id " << id.to_string() << " not found.";
  }
  return false;
}

void AppStoreModel::InsertEntryToDB(AppStoreEntry* entry) {
  scoped_refptr<net::IOBufferWithSize> data = entry->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, AppStoreEntry::kClassName, entry->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void AppStoreModel::RemoveEntryFromDB(AppStoreEntry* entry) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, AppStoreEntry::kClassName, entry->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void AppStoreModel::AddToCache(std::unique_ptr<AppStoreEntry> entry) {
  entries_.push_back(std::move(entry));
  entry->set_managed(true);
}

bool AppStoreModel::RemoveFromCache(const base::UUID& id) {
  base::AutoLock lock(entries_vector_lock_);
  bool found = false;
  AppStoreEntry* entry = nullptr;
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

bool AppStoreModel::RemoveFromCache(AppStoreEntry* entry) {
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

void AppStoreModel::LoadEntriesFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(AppStoreEntry::kClassName);
  if (!it) {
    DLOG(ERROR) << "AppStoreModel::LoadEntriesFromDB: creating cursor for 'app store' failed.";
    std::move(cb).Run(net::ERR_FAILED, 0);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<AppStoreEntry> p = AppStoreEntry::Deserialize(buffer.get(), kv.second.size());
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

void AppStoreModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    db_->Open();
  }
}

void AppStoreModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void AppStoreModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}