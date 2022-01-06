// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_MODEL_H_
#define MUMBA_HOST_REPO_REPO_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class Repo;
class ShareDatabase;

class RepoModel : public DatabasePolicyObserver {
public:
  RepoModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~RepoModel();

  const std::vector<std::unique_ptr<Repo>>& repos() const {
    return repos_;
  }

  std::vector<std::unique_ptr<Repo>>& repos() {
    return repos_;
  }

  void Load(base::Callback<void(int, int)> cb);
  bool RepoExists(Repo* repo) const;
  Repo* GetRepoById(const base::UUID& id);
  void InsertRepo(const base::UUID& id, std::unique_ptr<Repo> repo, bool persist = true);
  void RemoveRepo(const base::UUID& id);
 
  void Close();

private:
  
  void InsertRepoInternal(const base::UUID& id, std::unique_ptr<Repo> repo, bool persist);
  void RemoveRepoInternal(const base::UUID& id);

  void InsertRepoToDB(const base::UUID& id, Repo* repo);
  void RemoveRepoFromDB(Repo* repo);

  void AddToCache(const base::UUID& id, std::unique_ptr<Repo> repo);
  void RemoveFromCache(const base::UUID& id);
  void RemoveFromCache(Repo* repo);

  void LoadReposFromDB(base::Callback<void(int, int)> cb);

  void OnInsertReply(bool result);
  void OnRemoveReply(bool result);
  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  std::vector<std::unique_ptr<Repo>> repos_;

private:

 DISALLOW_COPY_AND_ASSIGN(RepoModel);
};

}

#endif