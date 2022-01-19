// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/volume/volume_source_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/volume/volume_source.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"
#include "storage/db/db.h"

namespace host {

VolumeSourceModel::VolumeSourceModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  policy_(policy),
  db_(db) {
  
}

VolumeSourceModel::~VolumeSourceModel() {
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    delete *it;
  }
  sources_.clear();
}

void VolumeSourceModel::Load() {
  //db_context_->io_task_runner()->PostTask(
  //  FROM_HERE,
  //  base::Bind(
  //    &VolumeSourceModel::LoadVolumeSourcesFromDB,
  //      base::Unretained(this)));
  LoadVolumeSourcesFromDB();
}

bool VolumeSourceModel::VolumeSourceExists(VolumeSource* source) const {
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    if ((*it)->name() == source->name()) {
      return true;
    }
  }
  return false;
}

void VolumeSourceModel::InsertVolumeSource(const base::UUID& id, VolumeSource* source) {
  InsertVolumeSourceInternal(id, source);
}

void VolumeSourceModel::RemoveVolumeSource(const base::UUID& id) {
  RemoveVolumeSourceInternal(id);
}

void VolumeSourceModel::InsertVolumeSourceInternal(const base::UUID& id, VolumeSource* source) {
  if (!VolumeSourceExists(source)) {
    //if (InsertVolumeSourceToDB(id, source)) {
    InsertVolumeSourceToDB(id, source);
    AddToCache(id, source);
    source->set_managed(true);
    //} else {
    //  LOG(ERROR) << "Failed to add source " << id.to_string() << " to DB";
    //}
  } else {
    DLOG(INFO) << "VolumeSource " << source->name() << " already exists. Not adding it again";
  }
}

void VolumeSourceModel::RemoveVolumeSourceInternal(const base::UUID& id) {
  VolumeSource* source = GetVolumeSourceById(id);
  if (source) {
    //if (RemoveVolumeSourceFromDB(source)) {
    RemoveVolumeSourceFromDB(source);
    RemoveFromCache(source);
    //} else {
    //  LOG(ERROR) << "Failed to remove source from DB. id " << id.to_string() << ".";
    //}
  } else {
    LOG(ERROR) << "Failed to remove VolumeSource. VolumeSource with id " << id.to_string() << " not found.";
  }
}

void VolumeSourceModel::LoadVolumeSourcesFromDB() {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  auto it = trans->CreateCursor("source");//db_->iterator(VolumeDatabase::kVolumeSourceTable);
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<VolumeSource> s = VolumeSource::Deserialize(buffer.get(), kv.second.size());
      if (s) {
        sources_.push_back(s.release());
      } else {
        LOG(ERROR) << "failed to deserialize source";
      }
    }
    it->Next();
  }
  trans->Commit();
  MaybeClose();
}

void VolumeSourceModel::InsertVolumeSourceToDB(const base::UUID& id, VolumeSource* source) {
  scoped_refptr<net::IOBufferWithSize> data = source->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, "source", source->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void VolumeSourceModel::RemoveVolumeSourceFromDB(VolumeSource* source) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, "source", source->name());//, base::Bind(&VolumeSourceModel::OnRemoveReply, base::Unretained(this)));
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

VolumeSource* VolumeSourceModel::GetVolumeSourceById(const base::UUID& id) {
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    if ((*it)->id() == id) {
      return *it;
    }
  }
  return nullptr;
}

void VolumeSourceModel::AddToCache(const base::UUID& id, VolumeSource* source) {
  sources_.push_back(source);
}

void VolumeSourceModel::RemoveFromCache(const base::UUID& id, bool should_delete) {
  VolumeSource* found = nullptr;
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    if ((*it)->id() == id) {
      found = *it;
      sources_.erase(it);
      break;
    }
  }
  if (found && should_delete) {
    delete found;
  }
}

void VolumeSourceModel::RemoveFromCache(VolumeSource* source, bool should_delete) {
  for (auto it = sources_.begin(); it != sources_.end(); ++it) {
    if (*it == source) {
      sources_.erase(it);
      break;
    }
  }
  if (should_delete) {
    delete source;
  }
}

void VolumeSourceModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "VolumeSourceModel::MaybeOpen: db is not open, reopening...";
    db_->Open();
  }
}

void VolumeSourceModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void VolumeSourceModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}