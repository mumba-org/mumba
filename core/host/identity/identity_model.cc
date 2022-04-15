// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/identity/identity_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/identity/identity.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

IdentityModel::IdentityModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  policy_(policy),
  db_(db) {
  
}

IdentityModel::~IdentityModel() {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    delete *it;
  }
  identities_.clear();
  db_ = nullptr;
}

void IdentityModel::Load(base::Callback<void(int, int)> cb) {
  LoadIdentitiesFromDB(std::move(cb));
}

void IdentityModel::Close() {
 //db_->Close();
}

void IdentityModel::InsertIdentity(const base::UUID& id, Identity* identity, bool persist) {
  InsertIdentityInternal(id, identity, persist);
}

void IdentityModel::RemoveIdentity(const base::UUID& id) {
  RemoveIdentityInternal(id);
}

void IdentityModel::InsertIdentityInternal(const base::UUID& id, Identity* identity, bool persist) {
  // after is added to the db, add it to the cache
  if (!IdentityExists(identity)) {
    //if (InsertIdentityToDB(id, identity)) {
      InsertIdentityToDB(id, identity);
      AddToCache(id, identity);
    //} else {
    //  LOG(ERROR) << "Failed to add identity " << id.to_string() << " to DB";
    //}
  } else {
    LOG(ERROR) << "Failed to add identity " << id.to_string() << " to DB. Already exists";
  }
}

void IdentityModel::RemoveIdentityInternal(const base::UUID& id) {
  // after is removed from the db, remove it from cache
  Identity* identity = GetIdentityById(id);
  if (identity) {
    //if (RemoveIdentityFromDB(identity)) {
      RemoveIdentityFromDB(identity);
      RemoveFromCache(identity);
    //} else {
    //  LOG(ERROR) << "Failed to remove identity from DB. id " << id.to_string() << ".";
    //}
  } else {
    LOG(ERROR) << "Failed to remove identity. Identity with id " << id.to_string() << " not found.";
  }
}

void IdentityModel::InsertIdentityToDB(const base::UUID& id, Identity* identity) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = identity->Serialize();
  if (data) {
    MaybeOpen();
    LOG(INFO) << "inserting identity " << identity->name() << " '" << data->data() << "'";
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Identity::kClassName, identity->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void IdentityModel::RemoveIdentityFromDB(Identity* identity) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Identity::kClassName, identity->name());
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void IdentityModel::LoadIdentitiesFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Identity::kClassName);
  if (!it) {
    DLOG(ERROR) << "IdentityModel::LoadIdentitiesFromDB: creating cursor for 'identity' failed.";
    std::move(cb).Run(net::ERR_FAILED, count);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      // even if this is small.. having to heap allocate here is not cool
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Identity> p = Identity::Deserialize(buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        identities_.push_back(p.release());
      } else {
        LOG(ERROR) << "failed to deserialize identity";
      }
    } else {
      LOG(ERROR) << "failed to deserialize identity: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

Identity* IdentityModel::GetIdentityById(const base::UUID& id) {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if ((*it)->id() == id) {
      return *it;
    }
  }
  return nullptr;
}

Identity* IdentityModel::GetIdentityByName(const std::string& name) {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if ((*it)->name() == name) {
      return *it;
    }
  }
  return nullptr;
}

bool IdentityModel::IdentityExists(Identity* identity) const {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if (*it == identity) {
      return true;
    }
  }
  return false; 
}

bool IdentityModel::IdentityExists(const base::UUID& id) const {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if ((*it)->id() == id) {
      return true;
    }
  }
  return false; 
}

bool IdentityModel::IdentityExists(const std::string& name) const {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if ((*it)->name() == name) {
      return true;
    }
  }
  return false; 
}

void IdentityModel::AddToCache(const base::UUID& id, Identity* identity) {
  identities_.push_back(identity);
  identity->set_managed(true);
}

void IdentityModel::RemoveFromCache(const base::UUID& id, bool should_delete) {
  Identity* found = nullptr;
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if ((*it)->id() == id) {
      found = *it;
      found->set_managed(false);
      identities_.erase(it);
      break;
    }
  }
  if (found && should_delete) {
    delete found;
  }
}

void IdentityModel::RemoveFromCache(Identity* identity, bool should_delete) {
  for (auto it = identities_.begin(); it != identities_.end(); ++it) {
    if (*it == identity) {
      (*it)->set_managed(false);
      identities_.erase(it);
      break;
    }
  }
  if (should_delete) {
    delete identity;
  }
}

void IdentityModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "IdentityModel::MaybeOpen: db is not open, reopening...";
    db_->Open(true);
  }
}

void IdentityModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void IdentityModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
