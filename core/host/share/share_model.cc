// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/share/share.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

ShareModel::ShareModel(ShareManager* manager, scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  manager_(manager),
  policy_(policy),
  db_(db) {
  
}

ShareModel::~ShareModel() {
  shares_.clear();
  db_ = nullptr;
}

void ShareModel::Load(base::Callback<void(int, int)> cb) {
  LoadSharesFromDB(std::move(cb));
}

void ShareModel::Close() {
 //db_->Close();
}

void ShareModel::InsertShare(const base::UUID& id, std::unique_ptr<Share> share, bool persist) {
  InsertShareInternal(id, std::move(share), persist);
}

void ShareModel::RemoveShare(const base::UUID& id) {
  RemoveShareInternal(id);
}

void ShareModel::InsertShareInternal(const base::UUID& id, std::unique_ptr<Share> share, bool persist) {
  // after is added to the db, add it to the cache
  if (!ShareExists(share.get())) {
    //if (InsertShareToDB(id, share)) {
      //InsertShareToDB(id, share.get());
      AddToCache(id, std::move(share));
    //} else {
    //  LOG(ERROR) << "Failed to add share " << id.to_string() << " to DB";
    //}
  } else {
    LOG(ERROR) << "Failed to add share " << id.to_string() << " to DB. Already exists";
  }
}

void ShareModel::RemoveShareInternal(const base::UUID& id) {
  // after is removed from the db, remove it from cache
  Share* share = GetShareById(id);
  if (share) {
    //if (RemoveShareFromDB(share)) {
      //RemoveShareFromDB(share);
      RemoveFromCache(share);
    //} else {
    //  LOG(ERROR) << "Failed to remove share from DB. id " << id.to_string() << ".";
    //}
  } else {
    LOG(ERROR) << "Failed to remove share. Share with id " << id.to_string() << " not found.";
  }
}

void ShareModel::InsertShareToDB(const base::UUID& id, Share* share) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = share->Serialize();
  if (data) {
    MaybeOpen();
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Share::kClassName, share->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void ShareModel::RemoveShareFromDB(Share* share) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Share::kClassName, share->name());//, base::Bind(&ShareModel::OnRemoveReply, base::Unretained(this)));
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void ShareModel::LoadSharesFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Share::kClassName);
  if (!it) {
    DLOG(ERROR) << "ShareModel::LoadSharesFromDB: creating cursor for 'share' failed.";
    std::move(cb).Run(net::ERR_FAILED, 0);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      // even if this is small.. having to heap allocate here is not cool
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Share> p = Share::Deserialize(manager_, false, buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        shares_.push_back(std::move(p));
      } else {
        LOG(ERROR) << "failed to deserialize share";
      }
    } else {
      LOG(ERROR) << "failed to deserialize share: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

Share* ShareModel::GetShare(const std::string& domain, const std::string& name) {
  for (auto it = shares_.begin(); it != shares_.end(); ++it) {
    if ((*it)->domain() == domain && (*it)->name() == name) {
      return it->get();
    }
  }
  return nullptr;  
}

Share* ShareModel::GetShareById(const base::UUID& id) {
  for (auto it = shares_.begin(); it != shares_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

bool ShareModel::ShareExists(Share* share) const {
  for (auto it = shares_.begin(); it != shares_.end(); ++it) {
    if ((*it)->id() == share->id()) {
      return true;
    }
  }
  return false; 
}

void ShareModel::AddToCache(const base::UUID& id, std::unique_ptr<Share> share) {
  share->set_managed(true);
  shares_.push_back(std::move(share));
}

void ShareModel::RemoveFromCache(const base::UUID& id) {
  for (auto it = shares_.begin(); it != shares_.end(); ++it) {
    if ((*it)->id() == id) {
      shares_.erase(it);
      return;
    }
  }
}

void ShareModel::RemoveFromCache(Share* share) {
  for (auto it = shares_.begin(); it != shares_.end(); ++it) {
    if (it->get() == share) {
      shares_.erase(it);
      return;
    }
  }
}

void ShareModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "ShareModel::MaybeOpen: db is not open, reopening...";
    db_->Open(true);
  }
}

void ShareModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void ShareModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
