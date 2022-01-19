// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/volume/volume_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/volume/volume.h"
#include "core/host/workspace/volume_storage.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "core/host/bundle/bundle_manager.h"
#include "core/host/bundle/bundle.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

VolumeModel::VolumeModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  policy_(policy),
  db_(db) {
  
}

VolumeModel::~VolumeModel() {
  lock_.Acquire();
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    delete *it;
  }
  volumes_.clear();
  lock_.Release();
  db_ = nullptr;
}

void VolumeModel::Load(VolumeStorage* store, BundleManager* bundle_manager, base::Callback<void(int, int)> cb) {
  LoadVolumesFromDB(store, bundle_manager, std::move(cb));
}

void VolumeModel::InsertVolume(const base::UUID& id, Volume* volume) {
  InsertVolumeInternal(id, volume);
}

void VolumeModel::RemoveVolume(const base::UUID& id) {
  RemoveVolumeInternal(id);
}

void VolumeModel::InsertVolumeInternal(const base::UUID& id, Volume* volume) {
  // after is added to the db, add it to the cache
  if (!VolumeExists(id)) {
    InsertVolumeToDB(id, volume);
    AddToCache(id, volume);
  } else {
    LOG(ERROR) << "Failed to add volume " << id.to_string() << " to DB. Already exists";
  }
}

void VolumeModel::RemoveVolumeInternal(const base::UUID& id) {
  Volume* volume = GetVolumeById(id);
  if (volume) {
    RemoveVolumeFromDB(volume);
    RemoveFromCache(volume);
  } else {
    LOG(ERROR) << "Failed to remove volume. Volume with id " << id.to_string() << " not found.";
  }
}

void VolumeModel::InsertVolumeToDB(const base::UUID& id, Volume* volume) {
  scoped_refptr<net::IOBufferWithSize> data = volume->Serialize();
  if (data) {
    //LOG(INFO) << "inserting volume " << volume->name() << " '" << data->data() << "'";
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Volume::kClassName, volume->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    if (!ok) {
      DLOG(ERROR) << "inserting volume " << volume->name() << " failed";
    }// else {
      //LOG(INFO) << "inserting volume " << volume->name() << " succeded";
    //}
    MaybeClose();
  }
}

void VolumeModel::RemoveVolumeFromDB(Volume* volume) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Volume::kClassName, volume->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void VolumeModel::LoadVolumesFromDB(VolumeStorage* storage, BundleManager* bundle_manager, base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Volume::kClassName);
  if (!it) {
    DLOG(ERROR) << "VolumeModel::LoadVolumesFromDB: creating cursor for 'volume' failed.";
    std::move(cb).Run(net::ERR_FAILED, 0);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      storage::Storage* volume_store = storage->GetStorage(kv.first.as_string());
      Bundle* bundle = bundle_manager->GetBundle(kv.first.as_string());
      if (volume_store && bundle) {
        // even if this is small.. having to heap allocate here is not cool
        scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
        std::unique_ptr<Volume> volume = Volume::Deserialize(volume_store, bundle, buffer.get(), kv.second.size());
        if (volume) {
          volume->set_managed(true);
          lock_.Acquire();
          volumes_.push_back(volume.release());
          lock_.Release();        
        } else {
          LOG(ERROR) << "failed to deserialize volume";
        }
      } else {
        DLOG(ERROR) << "trying to get storage named '" << kv.first << "' (or bundle) failed. cannot load volume.";
      }
    } else {
      LOG(ERROR) << "failed insert volume with cursor: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

Volume* VolumeModel::GetVolumeById(const base::UUID& id) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->id() == id) {
      return *it;
    }
  }
  return nullptr;
}

Volume* VolumeModel::GetVolumeByName(const std::string& name) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->name() == name) {
      return *it;
    }
  }
  return nullptr;
}

bool VolumeModel::VolumeExists(Volume* volume) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->name() == volume->name()) {
      return true;
    }
  }
  return false;
}

bool VolumeModel::VolumeExists(const base::UUID& id) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false;
}


bool VolumeModel::VolumeExists(const std::string& name) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

// bool VolumeModel::VolumeExists(const std::string& hash, base::UUID* id) {
//   base::AutoLock lock(lock_);
//   for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
//     if ((*it)->root_hash() == hash) {
//       *id = (*it)->id();
//       return true;
//     }
//   }
//   return false; 
// }

void VolumeModel::AddToCache(const base::UUID& id, Volume* volume) {
  lock_.Acquire();
  volumes_.push_back(volume);
  lock_.Release();
  volume->set_managed(true);
}

void VolumeModel::RemoveFromCache(const base::UUID& id, bool should_delete) {
  base::AutoLock lock(lock_);
  Volume* found = nullptr;
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if ((*it)->id() == id) {
      found = *it;
      found->set_managed(false);
      volumes_.erase(it);
      break;
    }
  }
  if (found && should_delete) {
    delete found;
  }
}

void VolumeModel::RemoveFromCache(Volume* volume, bool should_delete) {
  base::AutoLock lock(lock_);
  for (auto it = volumes_.begin(); it != volumes_.end(); ++it) {
    if (*it == volume) {
      (*it)->set_managed(false);
      volumes_.erase(it);
      break;
    }
  }
  if (should_delete) {
    delete volume;
  }
}

void VolumeModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "VolumeModel::MaybeOpen: db is not open, reopening...";
    db_->Open();
  }
}

void VolumeModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void VolumeModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}