// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/repo/repo.h"
#include "core/host/workspace/workspace.h"
#include "storage/db/db.h"
#include "storage/torrent.h"
#include "core/host/share/share_database.h"

namespace host {

RepoModel::RepoModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy): 
  policy_(policy),
  db_(db) {
  
}

RepoModel::~RepoModel() {
  repos_.clear();
  db_ = nullptr;
}

void RepoModel::Load(base::Callback<void(int, int)> cb) {
  LoadReposFromDB(std::move(cb));
}

void RepoModel::Close() {
 //db_->Close();
}

void RepoModel::InsertRepo(const base::UUID& id, std::unique_ptr<Repo> repo, bool persist) {
  InsertRepoInternal(id, std::move(repo), persist);
}

void RepoModel::RemoveRepo(const base::UUID& id) {
  RemoveRepoInternal(id);
}

void RepoModel::InsertRepoInternal(const base::UUID& id, std::unique_ptr<Repo> repo, bool persist) {
  // after is added to the db, add it to the cache
  if (!RepoExists(repo.get())) {
    //if (InsertRepoToDB(id, repo)) {
      InsertRepoToDB(id, repo.get());
      AddToCache(id, std::move(repo));
    //} else {
    //  LOG(ERROR) << "Failed to add repo " << id.to_string() << " to DB";
    //}
  } else {
    LOG(ERROR) << "Failed to add repo " << id.to_string() << " to DB. Already exists";
  }
}

void RepoModel::RemoveRepoInternal(const base::UUID& id) {
  // after is removed from the db, remove it from cache
  Repo* repo = GetRepoById(id);
  if (repo) {
    //if (RemoveRepoFromDB(repo)) {
      RemoveRepoFromDB(repo);
      RemoveFromCache(repo);
    //} else {
    //  LOG(ERROR) << "Failed to remove repo from DB. id " << id.to_string() << ".";
    //}
  } else {
    LOG(ERROR) << "Failed to remove repo. Repo with id " << id.to_string() << " not found.";
  }
}

void RepoModel::InsertRepoToDB(const base::UUID& id, Repo* repo) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = repo->Serialize();
  if (data) {
    MaybeOpen();
    LOG(INFO) << "inserting repo " << repo->name() << " '" << data->data() << "'";
    //result = db_->Insert(RepoDatabase::kRepoTable, repo->name(), data);
    //db_context_->Insert("repo", repo->name(), data, base::Bind(&RepoModel::OnInsertReply, base::Unretained(this)))
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Repo::kClassName, repo->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
  }
}

void RepoModel::RemoveRepoFromDB(Repo* repo) {
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Repo::kClassName, repo->name());//, base::Bind(&RepoModel::OnRemoveReply, base::Unretained(this)));
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
}

void RepoModel::LoadReposFromDB(base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Repo::kClassName);
  if (!it) {
    DLOG(ERROR) << "RepoModel::LoadReposFromDB: creating cursor for 'repo' failed.";
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
      std::unique_ptr<Repo> p = Repo::Deserialize(buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        repos_.push_back(std::move(p));
      } else {
        LOG(ERROR) << "failed to deserialize repo";
      }
    } else {
      LOG(ERROR) << "failed to deserialize repo: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
}

Repo* RepoModel::GetRepoById(const base::UUID& id) {
  for (auto it = repos_.begin(); it != repos_.end(); ++it) {
    if ((*it)->id() == id) {
      return it->get();
    }
  }
  return nullptr;
}

bool RepoModel::RepoExists(Repo* repo) const {
  for (auto it = repos_.begin(); it != repos_.end(); ++it) {
    if ((*it)->name() == repo->name()) {
      return true;
    }
  }
  return false; 
}

void RepoModel::AddToCache(const base::UUID& id, std::unique_ptr<Repo> repo) {
  repo->set_managed(true);
  repos_.push_back(std::move(repo));
}

void RepoModel::RemoveFromCache(const base::UUID& id) {
  for (auto it = repos_.begin(); it != repos_.end(); ++it) {
    if ((*it)->id() == id) {
      repos_.erase(it);
      return;
    }
  }
}

void RepoModel::RemoveFromCache(Repo* repo) {
  for (auto it = repos_.begin(); it != repos_.end(); ++it) {
    if (it->get() == repo) {
      repos_.erase(it);
      return;
    }
  }
}

void RepoModel::OnInsertReply(bool result) {
  DLOG(INFO) << "inserting repo on db: " << (result ? "true" : "false");
}

void RepoModel::OnRemoveReply(bool result) {
  DLOG(INFO) << "removing repo on db: " << (result ? "true" : "false");
}

void RepoModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    DLOG(INFO) << "RepoModel::MaybeOpen: db is not open, reopening...";
    db_->Open();
  }
}

void RepoModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void RepoModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
